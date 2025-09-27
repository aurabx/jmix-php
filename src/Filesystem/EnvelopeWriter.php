<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Filesystem;

use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Encryption\PayloadEncryptor;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Handles writing JMIX envelopes to the correct directory structure
 */
class EnvelopeWriter
{
    private string $envelopeRoot;
    private string $payloadPath;
    private bool $isEncrypted = false;

    public function __construct(string $outputPath, string $envelopeId)
    {
        $this->envelopeRoot = rtrim($outputPath, '/') . '/' . $envelopeId . '.JMIX';
        $this->payloadPath = $this->envelopeRoot . '/payload';

        $this->createDirectories();
    }

    /**
     * Get the envelope root directory path
     */
    public function getEnvelopeRoot(): string
    {
        return $this->envelopeRoot;
    }

    /**
     * Write JSON data to a file relative to the envelope root
     */
    public function writeJson(string $relativePath, array $data): void
    {
        $fullPath = $this->envelopeRoot . '/' . ltrim($relativePath, '/');

        // Ensure directory exists
        $dir = dirname($fullPath);
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                throw new JmixException("Failed to create directory: {$dir}");
            }
        }

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JmixException('Failed to encode JSON: ' . json_last_error_msg());
        }

        if (file_put_contents($fullPath, $json) === false) {
            throw new JmixException("Failed to write JSON file: {$fullPath}");
        }
    }

    /**
     * Copy a file to the envelope with the given relative path
     */
    public function copyFile(string $sourcePath, string $relativePath): void
    {
        $destPath = $this->envelopeRoot . '/' . ltrim($relativePath, '/');

        // Ensure directory exists
        $dir = dirname($destPath);
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                throw new JmixException("Failed to create directory: {$dir}");
            }
        }

        if (!copy($sourcePath, $destPath)) {
            throw new JmixException("Failed to copy file from {$sourcePath} to {$destPath}");
        }

        // Set file permissions
        chmod($destPath, 0644);
    }

    /**
     * Copy an entire DICOM directory tree to payload/dicom/
     */
    public function copyDicomTree(string $dicomPath): void
    {
        if (!is_dir($dicomPath)) {
            throw new JmixException("DICOM path is not a directory: {$dicomPath}");
        }

        $dicomDestPath = $this->payloadPath . '/dicom';
        if (!is_dir($dicomDestPath)) {
            if (!mkdir($dicomDestPath, 0755, true) && !is_dir($dicomDestPath)) {
                throw new JmixException("Failed to create DICOM directory: {$dicomDestPath}");
            }
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dicomPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        $dicomPath = rtrim($dicomPath, '/');

        foreach ($iterator as $file) {
            $relativePath = substr($file->getPathname(), strlen($dicomPath) + 1);

            if ($file->isDir()) {
                $targetDir = $dicomDestPath . '/' . $relativePath;
                if (!is_dir($targetDir)) {
                    if (!mkdir($targetDir, 0755, true) && !is_dir($targetDir)) {
                        throw new JmixException("Failed to create directory: {$targetDir}");
                    }
                }
            } elseif ($file->isFile()) {
                $this->copyFile($file->getPathname(), 'payload/dicom/' . $relativePath);
            }
        }
    }

    /**
     * Generate files.json for the payload/files/ directory
     */
    public function generateFilesManifest(): array
    {
        $filesPath = $this->payloadPath . '/files';

        if (!is_dir($filesPath)) {
            return [];
        }

        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($filesPath, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        $filesPath = rtrim($filesPath, '/');

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $relativePath = 'files/' . substr($file->getPathname(), strlen($filesPath) + 1);

                $files[] = [
                    'file' => $relativePath,
                    'size_bytes' => $file->getSize(),
                    'hash' => 'sha256:' . hash_file('sha256', $file->getPathname()),
                ];
            }
        }

        // Sort by file path for consistency
        usort(
            $files,
            function ($a, $b) {
                return strcmp($a['file'], $b['file']);
            }
        );

        return $files;
    }

    /**
     * Check if payload/files/ directory exists and has files
     */
    public function hasFiles(): bool
    {
        $filesPath = $this->payloadPath . '/files';

        if (!is_dir($filesPath)) {
            return false;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($filesPath, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Encrypt the payload directory and replace it with encrypted file
     *
     * @param string $recipientPublicKey Base64-encoded recipient public key
     * @return array Encryption parameters for manifest
     * @throws JmixException
     */
    public function encryptPayloadDirectory(string $recipientPublicKey): array
    {
        if ($this->isEncrypted) {
            throw new JmixException('Payload is already encrypted');
        }

        $encryptor = new PayloadEncryptor();
        $encryptionResult = $encryptor->encryptPayload($this->payloadPath, $recipientPublicKey);

        // Remove the original payload directory
        $this->removeDirectory($this->payloadPath);

        // Write the encrypted payload as a single file
        $encryptedPayloadFile = $this->envelopeRoot . '/payload.encrypted';
        if (file_put_contents($encryptedPayloadFile, $encryptionResult['encrypted_data']) === false) {
            throw new JmixException('Failed to write encrypted payload file');
        }

        $this->isEncrypted = true;

        // Return encryption parameters (without encrypted_data)
        unset($encryptionResult['encrypted_data']);
        return $encryptionResult;
    }

    /**
     * Check if the payload is encrypted
     */
    public function isPayloadEncrypted(): bool
    {
        return $this->isEncrypted;
    }

    /**
     * Calculate SHA-256 hash of the payload directory (entire directory structure)
     */
    public function calculatePayloadHash(): string
    {
        // Handle encrypted payload
        if ($this->isEncrypted) {
            $encryptedFile = $this->envelopeRoot . '/payload.encrypted';
            if (!file_exists($encryptedFile)) {
                throw new JmixException("Encrypted payload file does not exist: {$encryptedFile}");
            }
            return 'sha256:' . hash_file('sha256', $encryptedFile);
        }

        if (!is_dir($this->payloadPath)) {
            throw new JmixException("Payload directory does not exist: {$this->payloadPath}");
        }

        $entries = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->payloadPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        $payloadPath = rtrim($this->payloadPath, '/');

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
     * Recursively remove a directory and all its contents
     */
    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $filePath = $dir . '/' . $file;
            if (is_dir($filePath)) {
                $this->removeDirectory($filePath);
            } else {
                unlink($filePath);
            }
        }
        rmdir($dir);
    }

    /**
     * Create the necessary directory structure
     */
    private function createDirectories(): void
    {
        $directories = [
            $this->envelopeRoot,
            $this->payloadPath,
            $this->payloadPath . '/dicom',
        ];

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                    throw new JmixException("Failed to create directory: {$dir}");
                }
            }
        }
    }
}
