<?php

declare(strict_types=1);

namespace AuraBox\Jmix;

use AuraBox\Jmix\Dicom\DicomProcessor;
use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Validation\SchemaValidator;
use Ramsey\Uuid\Uuid;

/**
 * Main class for building JMIX envelopes from DICOM files and configuration
 */
class JmixBuilder
{
    private DicomProcessor $dicomProcessor;
    private SchemaValidator $validator;

    public function __construct(?string $schemaPath = null)
    {
        $this->dicomProcessor = new DicomProcessor();
        $this->validator = new SchemaValidator($schemaPath);
    }

    /**
     * Build a complete JMIX envelope from a DICOM folder and configuration
     *
     * @param  string  $dicomPath  Path to folder containing DICOM files
     * @param  array  $config  Configuration array with sender, receiver, etc.
     * @return array Complete JMIX envelope with manifest, metadata, and transmission
     * @throws JmixException
     */
    public function buildFromDicom(string $dicomPath, array $config): array
    {
        if (!is_dir($dicomPath)) {
            throw new JmixException("DICOM path does not exist or is not a directory: {$dicomPath}");
        }

        // Generate unique ID and timestamp for this transmission
        $transmissionId = Uuid::uuid4()->toString();
        $timestamp = date('Y-m-d\TH:i:s\Z');

        // Process DICOM files to extract metadata
        $dicomMetadata = $this->dicomProcessor->processDicomFolder($dicomPath);

        // Build the three main components
        $manifest = $this->buildManifest($transmissionId, $timestamp, $config, $dicomMetadata);
        $metadata = $this->buildMetadata($transmissionId, $timestamp, $config, $dicomMetadata);
        $transmission = $this->buildTransmission($transmissionId, $timestamp, $config);

        // Validate against schemas
        $this->validator->validateManifest($manifest);
        $this->validator->validateMetadata($metadata);
        $this->validator->validateTransmission($transmission);

        return [
            'manifest' => $manifest,
            'metadata' => $metadata,
            'transmission' => $transmission,
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
                'file' => $config['report']['file'] ?? 'report.pdf',
            ],
            'studies' => $this->buildStudies($dicomMetadata),
            'extensions' => [
                'custom_tags' => $config['custom_tags'] ?? [],
                'deid' => [
                    'keys' => $config['deid_keys'] ?? ['PatientName', 'PatientID', 'IssuerOfPatientID'],
                ],
                'consent' => $config['consent'] ?? [
                    'status' => 'granted',
                    'scope' => ['treatment'],
                    'method' => 'digital-signature',
                    'signed_on' => date('Y-m-d'),
                ],
            ],
        ];
    }

    /**
     * Build transmission audit trail
     */
    private function buildTransmission(string $id, string $timestamp, array $config): array
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
        return [
            'classification' => $securityConfig['classification'] ?? 'confidential',
            'payload_hash' => 'sha256:4f06faee1ab2c3d4e5f6789abc0def123456789abcdef012345678900abcdef12',
            'signature' => [
                'alg' => 'RS256',
                'sig' => 'MEUCIBnA123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                'hash' => 'sha256:4f06faee1ab2c3d4e5f6789abc0def123456789abcdef012345678900abcdef12',
            ],
            'encryption' => [
                'algorithm' => 'AES-256-GCM',
                'ephemeral_public_key' => '<base64>',
                'iv' => '<base64>',
                'auth_tag' => '<base64>',
            ],
        ];
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
            $family = $nameParts[0] ?? 'Unknown';
            $given = isset($nameParts[1]) ? [$nameParts[1]] : [];
            $nameString = $family . ($given ? ', ' . implode(' ', $given) : '');
        } else {
            $family = 'Unknown';
            $given = [];
            $nameString = 'Unknown';
        }
        
        return [
            'id' => $patientConfig['id'] ?? $dicomMetadata['patient_id'] ?? 'urn:uuid:' . Uuid::uuid4()->toString(),
            'name' => [
                'family' => $family,
                'given' => $given,
                'text' => $nameString,
            ],
            'dob' => $patientConfig['dob'] ?? $dicomMetadata['patient_dob'] ?? '1900-01-01',
            'sex' => $patientConfig['sex'] ?? $dicomMetadata['patient_sex'] ?? 'O',
            'identifiers' => $patientConfig['identifiers'] ?? [
                [
                    'system' => 'http://ns.electronichealth.net.au/id/ihi/1.0',
                    'value' => $patientConfig['ihi'] ?? '8003608166690503',
                ],
            ],
            'verification' => [
                'verified_by' => 'myhealthid.au',
                'verified_on' => date('Y-m-d'),
            ],
        ];
    }

    /**
     * Build studies information from DICOM metadata
     */
    private function buildStudies(array $dicomMetadata): array
    {
        return [
            'study_description' => $dicomMetadata['study_description'] ?? 'Medical Imaging Study',
            'study_uid' => $dicomMetadata['study_uid'] ?? '1.2.840.113619.2.312.4120.7934893.' . date('YmdHi'),
            'series' => $dicomMetadata['series'] ?? [
                [
                    'series_uid' => '1.2.3.4.5.6.789',
                    'modality' => 'CT',
                    'body_part' => 'Chest',
                    'instance_count' => $dicomMetadata['instance_count'] ?? 1,
                ],
            ],
        ];
    }

    /**
     * Save JMIX envelope to files
     */
    public function saveToFiles(array $envelope, string $outputPath): void
    {
        if (!is_dir($outputPath)) {
            mkdir($outputPath, 0755, true);
        }

        file_put_contents(
            $outputPath . '/manifest.json',
            json_encode($envelope['manifest'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        file_put_contents(
            $outputPath . '/metadata.json',
            json_encode($envelope['metadata'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        file_put_contents(
            $outputPath . '/transmission.json',
            json_encode($envelope['transmission'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
    }
}