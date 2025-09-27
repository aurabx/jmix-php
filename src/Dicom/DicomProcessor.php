<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Dicom;

use AuraBox\Jmix\Exceptions\JmixException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Processes DICOM files to extract metadata for JMIX envelopes
 */
class DicomProcessor
{
    /**
     * Process a folder of DICOM files and extract relevant metadata
     * @throws JmixException
     */
    public function processDicomFolder(string $dicomPath, ?array $config = null): array
    {
        $dicomFiles = $this->findDicomFiles($dicomPath);

        if (empty($dicomFiles)) {
            throw new JmixException("No DICOM files found in: {$dicomPath}");
        }

        $metadata = [
            'patient_name' => null,
            'patient_id' => null,
            'patient_dob' => null,
            'patient_sex' => null,
            'study_description' => null,
            'study_uid' => null,
            'modalities' => [],
            'series' => [],
            'instance_count' => 0,
        ];

        foreach ($dicomFiles as $file) {
            $fileMetadata = $this->processDicomFile($file, $config);
            $metadata = $this->mergeMetadata($metadata, $fileMetadata);
        }

        $metadata['instance_count'] = count($dicomFiles);

        return $metadata;
    }

    /**
     * Find all DICOM files in a directory (recursive)
     */
    private function findDicomFiles(string $path): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                // Check if it might be a DICOM file
                if ($this->isDicomFile($file->getPathname())) {
                    $files[] = $file->getPathname();
                }
            }
        }

        return $files;
    }

    /**
     * Simple DICOM file detection
     */
    private function isDicomFile(string $filePath): bool
    {
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return false;
        }

        // Read the first 132 bytes
        $data = fread($handle, 132);
        fclose($handle);

        // Check for DICOM magic number at offset 128
        return strlen($data) >= 132 && substr($data, 128, 4) === 'DICM';
    }

    /**
     * Process a single DICOM file to extract metadata
     * This is a simplified version - in production you'd use a proper DICOM library
     */
    private function processDicomFile(string $filePath, ?array $config = null): array
    {
        // Try to use dcmdump if available, otherwise return placeholder data
        if ($this->isDcmdumpAvailable()) {
            $dcmData = $this->extractWithDcmdump($filePath);
            if (!empty($dcmData)) {
                return $dcmData;
            }
        }

        // Fallback: use config data if available, otherwise null
        return [
            'patient_name' => $config['patient']['name'] ?? null,
            'patient_id' => $config['patient']['id'] ?? null,
            'patient_dob' => $config['patient']['dob'] ?? null,
            'patient_sex' => $config['patient']['sex'] ?? null,
            'study_description' => $config['study']['description'] ?? null,
            'study_uid' => $config['study']['uid'] ?? null,
            'series_uid' => null, // No fallback - should come from actual DICOM data
            'modality' => $config['study']['modality'] ?? null,
            'body_part' => $config['study']['body_part'] ?? null,
        ];
    }

    /**
     * Merge metadata from multiple DICOM files
     */
    private function mergeMetadata(array $existing, array $new): array
    {
        // Take the first non-null value for patient data
        $existing['patient_name'] = $existing['patient_name'] ?? ($new['patient_name'] ?? null);
        $existing['patient_id'] = $existing['patient_id'] ?? ($new['patient_id'] ?? null);
        $existing['patient_dob'] = $existing['patient_dob'] ?? ($new['patient_dob'] ?? null);
        $existing['patient_sex'] = $existing['patient_sex'] ?? ($new['patient_sex'] ?? null);
        $existing['study_description'] = $existing['study_description'] ?? ($new['study_description'] ?? null);
        $existing['study_uid'] = $existing['study_uid'] ?? ($new['study_uid'] ?? null);

        // Collect unique modalities
        if (isset($new['modality']) && !in_array($new['modality'], $existing['modalities'], true)) {
            $existing['modalities'][] = $new['modality'];
        }

        // Add series information
        if (isset($new['series_uid'])) {
            $seriesExists = false;
            $seriesIndex = -1;

            // Check if series already exists
            foreach ($existing['series'] as $index => $series) {
                if ($series['series_uid'] === $new['series_uid']) {
                    $seriesExists = true;
                    $seriesIndex = $index;
                    break;
                }
            }

            if (!$seriesExists) {
                $existing['series'][] = [
                    'series_uid' => $new['series_uid'],
                    'modality' => $new['modality'] ?? '',
                    'body_part' => $new['body_part'] ?? '',
                    'instance_count' => 1,
                ];
            } else {
                // Increment instance count for existing series
                $existing['series'][$seriesIndex]['instance_count']++;
                // Update modality and body_part if they were missing
                if (empty($existing['series'][$seriesIndex]['modality']) && isset($new['modality'])) {
                    $existing['series'][$seriesIndex]['modality'] = $new['modality'];
                }
                if (empty($existing['series'][$seriesIndex]['body_part']) && isset($new['body_part'])) {
                    $existing['series'][$seriesIndex]['body_part'] = $new['body_part'];
                }
            }
        }

        return $existing;
    }

    /**
     * Extract DICOM metadata using dcmdump (if available)
     * This is an alternative implementation using DCMTK tools
     */
    private function extractWithDcmdump(string $filePath): array
    {
        if (!$this->isDcmdumpAvailable()) {
            return [];
        }

        $output = shell_exec("dcmdump +P 0008,0060 +P 0010,0010 +P 0010,0020 +P 0010,0030 +P 0010,0040 +P 0008,1030 +P 0020,000D +P 0020,000E +P 0018,0015 " . escapeshellarg($filePath));

        if (!$output) {
            return [];
        }

        // Parse dcmdump output
        $metadata = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            if (preg_match('/\(0010,0010\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['patient_name'] = trim($matches[1]);
            }
            if (preg_match('/\(0010,0020\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['patient_id'] = trim($matches[1]);
            }
            if (preg_match('/\(0010,0030\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['patient_dob'] = $this->formatDicomDate(trim($matches[1]));
            }
            if (preg_match('/\(0010,0040\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['patient_sex'] = trim($matches[1]);
            }
            if (preg_match('/\(0008,1030\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['study_description'] = trim($matches[1]);
            }
            if (preg_match('/\(0020,000[dD]\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['study_uid'] = trim($matches[1]);
            }
            if (preg_match('/\(0020,000[eE]\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['series_uid'] = trim($matches[1]);
            }
            if (preg_match('/\(0008,0060\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['modality'] = trim($matches[1]);
            }
            if (preg_match('/\(0018,0015\).*?\[(.*?)\]/', $line, $matches)) {
                $metadata['body_part'] = trim($matches[1]);
            }
        }

        return $metadata;
    }

    /**
     * Check if dcmdump is available
     */
    private function isDcmdumpAvailable(): bool
    {
        // Cross-platform dcmdump detection
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: use 'where' command
            $output = shell_exec('where dcmdump 2>nul');
        } else {
            // Unix-like systems (Linux, macOS, etc.): use 'which' command
            $output = shell_exec('which dcmdump 2>/dev/null');
        }
        
        return !empty($output) && trim($output) !== '';
    }

    /**
     * Format DICOM date (YYYYMMDD) to ISO format (YYYY-MM-DD)
     */
    private function formatDicomDate(string $dicomDate): string
    {
        if (strlen($dicomDate) === 8 && ctype_digit($dicomDate)) {
            return substr($dicomDate, 0, 4) . '-' . substr($dicomDate, 4, 2) . '-' . substr($dicomDate, 6, 2);
        }
        return $dicomDate;
    }
}
