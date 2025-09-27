<?php /** @noinspection PhpConditionCheckedByNextConditionInspection */

declare(strict_types=1);

namespace AuraBox\Jmix;

use AuraBox\Jmix\Dicom\DicomProcessor;
use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Filesystem\EnvelopeWriter;
use AuraBox\Jmix\Validation\SchemaValidator;
use Ramsey\Uuid\Uuid;

/**
 * Main class for building JMIX envelopes from DICOM files and configuration
 */
class JmixBuilder
{
    private DicomProcessor $dicomProcessor;
    private SchemaValidator $validator;
    private string $lastDicomPath = '';

    public function __construct(?string $schemaPath = null)
    {
        $this->dicomProcessor = new DicomProcessor();
        $this->validator = new SchemaValidator($schemaPath);
    }

    /**
     * Build a complete JMIX envelope from a DICOM folder and configuration
     *
     * @param  string $dicomPath Path to folder containing DICOM files
     * @param  array  $config    Configuration array with sender, receiver, etc.
     * @return array Complete JMIX envelope with manifest, metadata, and audit
     * @throws JmixException
     */
    public function buildFromDicom(string $dicomPath, array $config): array
    {
        if (!is_dir($dicomPath)) {
            throw new JmixException("DICOM path does not exist or is not a directory: {$dicomPath}");
        }

        // Store the DICOM path for later use in saveToFiles
        $this->lastDicomPath = $dicomPath;

        // Generate unique ID and timestamp for this transmission
        $transmissionId = Uuid::uuid4()->toString();
        $timestamp = date('Y-m-d\TH:i:s\Z');

        // Process DICOM files to extract metadata
        $dicomMetadata = $this->dicomProcessor->processDicomFolder($dicomPath, $config);

        // Build the three main components
        $manifest = $this->buildManifest($transmissionId, $timestamp, $config, $dicomMetadata);
        $metadata = $this->buildMetadata($transmissionId, $timestamp, $config, $dicomMetadata);
        $audit = $this->buildAudit($transmissionId, $timestamp, $config);

        // Validate metadata and audit schemas now (manifest will be validated after payload hash is calculated)
        $this->validator->validateMetadata($metadata);
        $this->validator->validateAudit($audit);

        return [
            'manifest' => $manifest,
            'metadata' => $metadata,
            'audit' => $audit,
        ];
    }

    /**
     * Build just the manifest component
     */
    private function buildManifest(string $id, string $timestamp, array $config, array $dicomMetadata): array
    {
        return [
            'version' => $config['version'] ?? '1.0',
            'id' => $id,
            'timestamp' => $timestamp,
            'sender' => $this->buildEntity($config['sender']),
            'requester' => $this->buildEntity($config['requester']),
            'receiver' => array_map([$this, 'buildEntity'], $config['receivers']),
            'security' => $this->buildSecurity($config['security'] ?? []),
            'extensions' => [
                'custom_tags' => $config['custom_tags'] ?? [],
            ],
        ];
    }

    /**
     * Build metadata component from DICOM data and config
     */
    private function buildMetadata(string $id, string $timestamp, array $config, array $dicomMetadata): array
    {
        return [
            'version' => $config['version'] ?? '1.0',
            'id' => $id,
            'timestamp' => $timestamp,
            'patient' => $this->buildPatient($config['patient'], $dicomMetadata),
            'report' => [
                'file' => $config['report']['file'] ?? '',
            ],
            'studies' => $this->buildStudies($dicomMetadata),
            'extensions' => $this->buildMetadataExtensions($config),
        ];
    }

    /**
     * Build audit trail
     */
    private function buildAudit(string $id, string $timestamp, array $config): array
    {
        return [
            'audit' => [
                [
                    'event' => 'created',
                    'by' => [
                        'id' => $config['sender']['id'],
                        'name' => $config['sender']['name'],
                    ],
                    'timestamp' => $timestamp,
                ],
            ],
        ];
    }

    /**
     * Build an entity (sender, requester, receiver)
     */
    private function buildEntity(array $entityConfig): array
    {
        return [
            'name' => $entityConfig['name'],
            'id' => $entityConfig['id'],
            'contact' => $entityConfig['contact'],
        ];
    }


    /**
     * Build security configuration
     */
    private function buildSecurity(array $securityConfig): array
    {
        $security = [
            'classification' => $securityConfig['classification'] ?? 'confidential',
            'payload_hash' => '', // Will be calculated after payload is written
        ];

        // Only include signature if provided in config
        if (isset($securityConfig['signature'])) {
            $security['signature'] = $securityConfig['signature'];
        }

        // Encryption block will be added later if encryption is enabled
        return $security;
    }

    /**
     * Build patient information from config and DICOM data
     */
    private function buildPatient(array $patientConfig, array $dicomMetadata): array
    {
        // Parse name from config or DICOM
        $configName = $patientConfig['name'] ?? null;
        $dicomName = $dicomMetadata['patient_name'] ?? null;

        if ($configName) {
            // Use config name as-is (not DICOM format)
            $nameString = $configName;
            $nameParts = explode(' ', $nameString);
            $family = array_pop($nameParts); // Last name is family
            $given = $nameParts; // Everything else is given names
        } elseif ($dicomName) {
            // Parse DICOM format: Family^Given^Middle^Prefix^Suffix
            $nameParts = explode('^', $dicomName);
            $family = $nameParts[0] ?? '';
            $given = isset($nameParts[1]) ? [$nameParts[1]] : [];
            $nameString = $family . ($given ? ', ' . implode(' ', $given) : '');
        } else {
            $family = '';
            $given = [];
            $nameString = '';
        }

        $patient = [
            'id' => $patientConfig['id'] ?? $dicomMetadata['patient_id'] ?? 'urn:uuid:' . Uuid::uuid4()->toString(),
            'name' => [
                'family' => $family,
                'given' => $given,
                'text' => $nameString,
            ],
            'dob' => $patientConfig['dob'] ?? $dicomMetadata['patient_dob'] ?? null,
            'sex' => $patientConfig['sex'] ?? $dicomMetadata['patient_sex'] ?? null,
        ];

        // Only add identifiers if provided in config
        if (isset($patientConfig['identifiers'])) {
            $patient['identifiers'] = $patientConfig['identifiers'];
        }

        // Only add verification if provided in config
        if (isset($patientConfig['verification'])) {
            $patient['verification'] = $patientConfig['verification'];
        }

        return $patient;
    }

    /**
     * Build metadata extensions from config
     */
    private function buildMetadataExtensions(array $config): object
    {
        $extensions = new \stdClass();

        // Add custom tags if provided
        if (isset($config['custom_tags']) && !empty($config['custom_tags'])) {
            $extensions->custom_tags = $config['custom_tags'];
        }

        // Add de-identification keys if provided
        if (isset($config['deid_keys']) && !empty($config['deid_keys'])) {
            $extensions->deid = (object) [
                'keys' => $config['deid_keys'],
            ];
        }

        // Add consent information if provided
        if (isset($config['consent'])) {
            $extensions->consent = (object) $config['consent'];
        }

        return $extensions;
    }

    /**
     * Build studies information from DICOM metadata
     */
    private function buildStudies(array $dicomMetadata): object
    {
        $studies = new \stdClass();

        // Only add study description if available
        if (!empty($dicomMetadata['study_description'])) {
            $studies->study_description = $dicomMetadata['study_description'];
        }

        // Only add study UID if available
        if (!empty($dicomMetadata['study_uid'])) {
            $studies->study_uid = $dicomMetadata['study_uid'];
        }

        // Only add series if available and not empty
        if (!empty($dicomMetadata['series'])) {
            $studies->series = $dicomMetadata['series'];
        }

        // Note: instance_count should be at series level, not studies level
        // The total instance count is calculated by summing series instance_count values

        return $studies;
    }

    /**
     * Save JMIX envelope to the correct directory structure
     *
     * @param  array  $envelope  The envelope data
     * @param  string  $outputPath  Base output directory
     * @param  array|null  $config  Optional configuration for file handling
     * @return string The path to the created envelope directory
     * @throws JmixException
     */
    public function saveToFiles(array $envelope, string $outputPath, ?array $config = null): string
    {
        // Get the envelope ID from the manifest
        $envelopeId = $envelope['manifest']['id'];

        // Create the envelope writer
        $writer = new EnvelopeWriter($outputPath, $envelopeId);

        // Write initial JSON files (without a manifest yet - we need to calculate payload hash first)
        $writer->writeJson('audit.json', $envelope['audit']);
        $writer->writeJson('payload/metadata.json', $envelope['metadata']);

        // Write optional manifest.jws if present
        if (isset($envelope['manifest_jws'])) {
            $writer->writeJson('manifest.jws', $envelope['manifest_jws']);
        }

        // Copy DICOM files to payload/dicom/
        if (!empty($this->lastDicomPath) && is_dir($this->lastDicomPath)) {
            $writer->copyDicomTree($this->lastDicomPath);
        }

        // Handle report files and other attachments
        if ($config) {
            $this->handleAttachments($writer, $config);
        }

        // Generate files.json if payload/files/ has content (BEFORE encryption)
        if ($writer->hasFiles()) {
            $filesManifest = $writer->generateFilesManifest();
            if (!empty($filesManifest)) {
                // Validate files manifest against schema
                $this->validator->validateFiles($filesManifest);

                $writer->writeJson('payload/files.json', $filesManifest);
            }
        }

        // Encrypt payload if a recipient public key is provided
        $encryptionParams = null;
        if ($config && isset($config['encryption']['recipient_public_key'])) {
            $encryptionParams = $writer->encryptPayloadDirectory($config['encryption']['recipient_public_key']);
        }

        // Calculate payload hash after all payload content is written
        $payloadHash = $writer->calculatePayloadHash();

        // Update the manifest with the payload hash and encryption parameters
        $manifest = $envelope['manifest'];
        $manifest['security']['payload_hash'] = $payloadHash;

        // Add encryption parameters if payload was encrypted
        if ($encryptionParams) {
            $manifest['security']['encryption'] = $encryptionParams;
        }

        // Validate the completed manifest with payload hash
        $this->validator->validateManifest($manifest);

        // Now write the final manifest with the payload hash
        $writer->writeJson('manifest.json', $manifest);

        return $writer->getEnvelopeRoot();
    }

    /**
     * Handle copying attachments like reports and other files
     * @throws JmixException
     */
    private function handleAttachments(EnvelopeWriter $writer, array $config): void
    {
        // Handle report file if specified
        if (isset($config['report']['file']) && file_exists($config['report']['file'])) {
            $reportFile = $config['report']['file'];
            $basename = basename($reportFile);
            $writer->copyFile($reportFile, 'payload/files/' . $basename);
        }

        // Handle additional files if specified in config
        if (isset($config['files']) && is_array($config['files'])) {
            foreach ($config['files'] as $file) {
                if (is_string($file) && file_exists($file)) {
                    $basename = basename($file);
                    $writer->copyFile($file, 'payload/files/' . $basename);
                } elseif (is_array($file) && isset($file['path']) && file_exists($file['path'])) {
                    $basename = $file['name'] ?? basename($file['path']);
                    $writer->copyFile($file['path'], 'payload/files/' . $basename);
                }
            }
        }
    }
}
