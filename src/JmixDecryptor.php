<?php

declare(strict_types=1);

namespace AuraBox\Jmix;

use AuraBox\Jmix\Assertions\AssertionBuilder;
use AuraBox\Jmix\Encryption\PayloadEncryptor;
use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Validation\SchemaValidator;

/**
 * Handles decryption and extraction of JMIX envelopes
 */
class JmixDecryptor
{
    private PayloadEncryptor $payloadEncryptor;
    private ?string $schemaPath;

    public function __construct(?string $schemaPath = null)
    {
        $this->payloadEncryptor = new PayloadEncryptor();
        $this->schemaPath = $schemaPath;
    }

    /**
     * Decrypt a JMIX envelope and extract its contents
     *
     * @param string $envelopePath Path to the .JMIX envelope directory
     * @param string $recipientPrivateKey Base64-encoded private key for decryption
     * @param string $outputPath Path where decrypted contents should be extracted
     * @return array Envelope contents (manifest, audit, metadata)
     * @throws JmixException
     */
    public function decryptEnvelope(string $envelopePath, string $recipientPrivateKey, string $outputPath): array
    {
        if (!is_dir($envelopePath)) {
            throw new JmixException("Envelope directory does not exist: {$envelopePath}");
        }

        // Read manifest and audit files
        $manifest = $this->readJsonFile($envelopePath . '/manifest.json');
        $audit = $this->readJsonFile($envelopePath . '/audit.json');

        // Check if envelope is encrypted
        if (!isset($manifest['security']['encryption'])) {
            throw new JmixException('Envelope is not encrypted - use regular file extraction instead');
        }

        $encryptedPayloadFile = $envelopePath . '/payload.encrypted';
        if (!file_exists($encryptedPayloadFile)) {
            throw new JmixException('Encrypted payload file not found: payload.encrypted');
        }

        // Read encrypted payload
        $encryptedData = file_get_contents($encryptedPayloadFile);
        if ($encryptedData === false) {
            throw new JmixException('Failed to read encrypted payload file');
        }

        // Create output directory
        if (!is_dir($outputPath)) {
            if (!mkdir($outputPath, 0755, true) && !is_dir($outputPath)) {
                throw new JmixException("Failed to create output directory: {$outputPath}");
            }
        }

        // Extract payload to temporary directory first
        $payloadOutputPath = $outputPath . '/payload';
        if (!mkdir($payloadOutputPath, 0755, true) && !is_dir($payloadOutputPath)) {
            throw new JmixException("Failed to create payload output directory: {$payloadOutputPath}");
        }

        // Decrypt payload
        $this->payloadEncryptor->decryptPayload(
            $encryptedData,
            $recipientPrivateKey,
            $manifest['security']['encryption'],
            $payloadOutputPath
        );

        // Verify payload hash if present
        if (isset($manifest['security']['payload_hash'])) {
            $this->verifyPayloadHash($encryptedPayloadFile, $manifest['security']['payload_hash']);
        }

        // Note: We don't verify decrypted payload hash against encrypted payload hash
        // as they use different algorithms (directory structure vs file hash)

        // Copy manifest and audit to output directory
        $this->writeJsonFile($outputPath . '/manifest.json', $manifest);
        $this->writeJsonFile($outputPath . '/audit.json', $audit);

        // Read decrypted metadata
        $metadataFile = $payloadOutputPath . '/metadata.json';
        if (!file_exists($metadataFile)) {
            throw new JmixException('Metadata file not found in decrypted payload');
        }

        $metadata = $this->readJsonFile($metadataFile);

        // Validate decrypted components against schemas (fix metadata only for validation)
        $validator = new SchemaValidator($this->schemaPath);
        $validator->validateManifest($manifest);
        $validator->validateMetadata($this->fixMetadataObjects($metadata));
        $validator->validateAudit($audit);

        // Verify cryptographic assertions if present
        $this->verifyAssertions($manifest);

        return [
            'manifest' => $manifest,
            'audit' => $audit,
            'metadata' => $metadata,
            'payload_path' => $payloadOutputPath
        ];
    }

    /**
     * Extract an unencrypted JMIX envelope
     *
     * @param string $envelopePath Path to the .JMIX envelope directory
     * @param string $outputPath Path where contents should be extracted
     * @return array Envelope contents (manifest, audit, metadata)
     * @throws JmixException
     */
    public function extractEnvelope(string $envelopePath, string $outputPath): array
    {
        if (!is_dir($envelopePath)) {
            throw new JmixException("Envelope directory does not exist: {$envelopePath}");
        }

        // Read manifest and audit files
        $manifest = $this->readJsonFile($envelopePath . '/manifest.json');
        $audit = $this->readJsonFile($envelopePath . '/audit.json');

        // Check if envelope is encrypted
        if (isset($manifest['security']['encryption'])) {
            throw new JmixException('Envelope is encrypted - use decryptEnvelope() instead');
        }

        $payloadDir = $envelopePath . '/payload';
        if (!is_dir($payloadDir)) {
            throw new JmixException('Payload directory not found in envelope');
        }

        // Create output directory
        if (!is_dir($outputPath)) {
            if (!mkdir($outputPath, 0755, true) && !is_dir($outputPath)) {
                throw new JmixException("Failed to create output directory: {$outputPath}");
            }
        }

        // Copy all files to output directory
        $this->copyDirectory($envelopePath, $outputPath);

        // Verify payload hash if present (for unencrypted envelopes only)
        if (isset($manifest['security']['payload_hash'])) {
            $this->verifyDecryptedPayloadHash($outputPath . '/payload', $manifest['security']['payload_hash']);
        }

        // Read metadata
        $metadataFile = $outputPath . '/payload/metadata.json';
        if (!file_exists($metadataFile)) {
            throw new JmixException('Metadata file not found in payload');
        }

        $metadata = $this->readJsonFile($metadataFile);

        // Validate extracted components against schemas (fix metadata only for validation)
        $validator = new SchemaValidator($this->schemaPath);
        $validator->validateManifest($manifest);
        $validator->validateMetadata($this->fixMetadataObjects($metadata));
        $validator->validateAudit($audit);

        // Verify cryptographic assertions if present
        $this->verifyAssertions($manifest);

        return [
            'manifest' => $manifest,
            'audit' => $audit,
            'metadata' => $metadata,
            'payload_path' => $outputPath . '/payload'
        ];
    }

    /**
     * Analyze a JMIX envelope without extracting it
     *
     * @param string $envelopePath Path to the .JMIX envelope directory
     * @return array Envelope information
     * @throws JmixException
     */
    public function analyzeEnvelope(string $envelopePath): array
    {
        if (!is_dir($envelopePath)) {
            throw new JmixException("Envelope directory does not exist: {$envelopePath}");
        }

        // Read manifest and audit files
        $manifest = $this->readJsonFile($envelopePath . '/manifest.json');
        $audit = $this->readJsonFile($envelopePath . '/audit.json');

        $isEncrypted = isset($manifest['security']['encryption']);
        $hasPayloadHash = isset($manifest['security']['payload_hash']);

        $analysis = [
            'envelope_id' => $manifest['id'] ?? 'unknown',
            'timestamp' => $manifest['timestamp'] ?? 'unknown',
            'is_encrypted' => $isEncrypted,
            'has_payload_hash' => $hasPayloadHash,
            'sender' => $manifest['sender'] ?? null,
            'requester' => $manifest['requester'] ?? null,
            'receivers' => $manifest['receiver'] ?? [],
        ];

        if ($isEncrypted) {
            $analysis['encryption'] = $manifest['security']['encryption'];
        }

        if ($hasPayloadHash) {
            $analysis['payload_hash'] = $manifest['security']['payload_hash'];
        }

        // Check what files/directories exist
        $analysis['files'] = [
            'manifest' => file_exists($envelopePath . '/manifest.json'),
            'audit' => file_exists($envelopePath . '/audit.json'),
            'payload_directory' => is_dir($envelopePath . '/payload'),
            'payload_encrypted' => file_exists($envelopePath . '/payload.encrypted'),
        ];

        return $analysis;
    }

    /**
     * Verify payload hash
     * @throws JmixException
     */
    private function verifyPayloadHash(string $payloadFile, string $expectedHash): void
    {
        if (!str_starts_with($expectedHash, 'sha256:')) {
            throw new JmixException('Unsupported payload hash format: ' . $expectedHash);
        }

        $actualHash = 'sha256:' . hash_file('sha256', $payloadFile);
        if (!hash_equals($expectedHash, $actualHash)) {
            throw new JmixException('Payload hash verification failed - data may be corrupted');
        }
    }

    /**
     * Verify decrypted payload hash by recomputing directory structure hash
     * @throws JmixException
     */
    private function verifyDecryptedPayloadHash(string $payloadDir, string $expectedHash): void
    {
        if (!str_starts_with($expectedHash, 'sha256:')) {
            throw new JmixException('Unsupported payload hash format: ' . $expectedHash);
        }

        if (!is_dir($payloadDir)) {
            throw new JmixException("Payload directory does not exist: {$payloadDir}");
        }

        // Recompute payload hash using same algorithm as EnvelopeWriter
        $recalculatedHash = $this->calculatePayloadDirectoryHash($payloadDir);
        
        if (!hash_equals($expectedHash, $recalculatedHash)) {
            throw new JmixException('Decrypted payload hash verification failed - content integrity compromised');
        }
    }

    /**
     * Calculate SHA-256 hash of payload directory structure (matches EnvelopeWriter logic)
     * @throws JmixException
     */
    private function calculatePayloadDirectoryHash(string $payloadPath): string
    {
        $entries = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($payloadPath, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $payloadPath = rtrim($payloadPath, '/');

        // Collect all entries (files and directories) with their metadata
        foreach ($iterator as $entry) {
            $relativePath = substr($entry->getPathname(), strlen($payloadPath) + 1);

            if ($entry->isDir()) {
                // For directories, include path and type
                $entries[$relativePath] = 'dir:' . $relativePath;
            } elseif ($entry->isFile()) {
                // For files, include path, size, and content hash
                $fileSize = $entry->getSize();
                $fileHash = hash_file('sha256', $entry->getPathname());
                $entries[$relativePath] = 'file:' . $relativePath . ':' . $fileSize . ':' . $fileHash;
            }
        }

        // Sort by path for consistent hash calculation
        ksort($entries);

        // Create a manifest of the entire directory structure
        $manifest = '';
        foreach ($entries as $path => $metadata) {
            $manifest .= $metadata . "\n";
        }


        // Return SHA-256 hash prefixed with algorithm identifier
        return 'sha256:' . hash('sha256', $manifest);
    }

    /**
     * Verify cryptographic assertions in the manifest
     * @throws JmixException
     */
    private function verifyAssertions(array $manifest): void
    {
        // Check if any assertions are present
        $hasAssertions = false;
        if (isset($manifest['sender']['assertion'])) {
            $hasAssertions = true;
        }
        if (isset($manifest['requester']['assertion'])) {
            $hasAssertions = true;
        }
        if (isset($manifest['receiver'])) {
            foreach ($manifest['receiver'] as $receiver) {
                if (isset($receiver['assertion'])) {
                    $hasAssertions = true;
                    break;
                }
            }
        }

        // If no assertions are present, skip verification
        if (!$hasAssertions) {
            return;
        }

        // Verify all assertions
        $assertionBuilder = new AssertionBuilder();
        $envelope = ['manifest' => $manifest];
        $verificationResults = $assertionBuilder->verifyEnvelopeAssertions($envelope);
        
        if (!$verificationResults['valid']) {
            $errorMessage = 'Cryptographic assertion verification failed';
            if (!empty($verificationResults['errors'])) {
                $errorMessage .= ': ' . implode(', ', $verificationResults['errors']);
            }
            throw new JmixException($errorMessage);
        }
    }

    /**
     * Fix metadata objects that were converted to empty arrays during JSON processing
     */
    private function fixMetadataObjects(array $metadata): array
    {
        // Fix studies field - should be an object, but becomes empty array when empty
        if (isset($metadata['studies']) && is_array($metadata['studies']) && empty($metadata['studies'])) {
            $metadata['studies'] = new \stdClass();
        }
        
        // Fix extensions field - should be an object
        if (isset($metadata['extensions']) && is_array($metadata['extensions']) && empty($metadata['extensions'])) {
            $metadata['extensions'] = new \stdClass();
        }
        
        return $metadata;
    }

    /**
     * Read and parse JSON file
     * @throws JmixException
     * @throws \JsonException
     */
    private function readJsonFile(string $filePath): array
    {
        if (!file_exists($filePath)) {
            throw new JmixException("File not found: {$filePath}");
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new JmixException("Failed to read file: {$filePath}");
        }

        /** @noinspection JsonEncodingApiUsageInspection */
        $data = json_decode($content, true, 512);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JmixException("Invalid JSON in file {$filePath}: " . json_last_error_msg());
        }

        return $data;
    }

    /**
     * Write JSON data to file
     * @throws JmixException
     */
    private function writeJsonFile(string $filePath, array $data): void
    {
        /** @noinspection JsonEncodingApiUsageInspection */
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (file_put_contents($filePath, $json) === false) {
            throw new JmixException("Failed to write file: {$filePath}");
        }
    }

    /**
     * Recursively copy directory
     * @throws JmixException
     */
    private function copyDirectory(string $source, string $destination): void
    {
        if (!is_dir($destination) && !mkdir($destination, 0755, true) && !is_dir($destination)) {
            throw new JmixException("Failed to create directory: {$destination}");
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            $targetPath = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();

            if ($item->isDir()) {
                if (!mkdir($targetPath, 0755, true) && !is_dir($targetPath)) {
                    throw new JmixException("Failed to create directory: {$targetPath}");
                }
            } elseif (!copy($item->getPathname(), $targetPath)) {
                throw new JmixException("Failed to copy file: {$item->getPathname()} to {$targetPath}");
            }
        }
    }
}
