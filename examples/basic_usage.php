<?php

require_once __DIR__ . '/../vendor/autoload.php';

use AuraBox\Jmix\JmixBuilder;

// Configuration for JMIX envelope
$config = [
    'version' => '1.0',
    'sender' => [
        'name' => 'Radiology Clinic A',
        'id' => 'org:au.gov.health.123456',
        'contact' => 'imaging@clinica.org.au',
        'assertion' => [
            'alg' => 'Ed25519',
            'public_key' => '<base64_public_key>',
            'fingerprint' => 'SHA256:<hex_fingerprint>',
        ],
    ],
    'requester' => [
        'name' => 'Dr John Smith',
        'id' => 'org:au.gov.health.55555',
        'contact' => 'smith@clinicb.org.au',
    ],
    'receivers' => [
        [
            'name' => 'Radiology Clinic B',
            'id' => 'org:au.gov.health.987654',
            'contact' => [
                'system' => 'phone',
                'value' => '+61049555555',
            ],
        ],
    ],
    'patient' => [
        'name' => 'Jane Doe',
        'dob' => '1975-02-14',
        'sex' => 'F',
        'ihi' => '8003608166690503',
        'identifiers' => [
            [
                'system' => 'http://ns.electronichealth.net.au/id/ihi/1.0',
                'value' => '8003608166690503',
            ],
            [
                'system' => 'urn:oid:1.2.36.146.595.217.0.1',
                'value' => 'MRN123456',
            ],
        ],
    ],
    'report' => [
        'file' => 'files/report.pdf',
        'url' => 'https://some.url.with.a.report',
    ],
    'files' => [
        'file' => 'files/report.pdf',
        'url' => 'https://some.url.with.a.report',
    ],
    'custom_tags' => [
        'teaching',
        'priority-review',
    ],
    'security' => [
        'classification' => 'confidential',
    ],
];

try {
    // Initialize the JMIX builder
    $jmixBuilder = new JmixBuilder();

    // Path to DICOM files (you would replace this with actual DICOM folder)
    $dicomPath = '/path/to/dicom/files';
    
    // For demonstration, create a dummy DICOM folder
    $dummyDicomPath = __DIR__ . '/dummy_dicom';
    if (!is_dir($dummyDicomPath)) {
        if (!mkdir($dummyDicomPath, 0755, true) && !is_dir($dummyDicomPath)) {
            throw new \RuntimeException(sprintf('Directory "%s" was not created', $dummyDicomPath));
        }
        
        // Create a dummy DICOM file with magic bytes
        $dummyFile = $dummyDicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyFile, $dummyData);
    }

    // Build JMIX envelope from DICOM files
    echo "Building JMIX envelope from DICOM files...\n";
    $envelope = $jmixBuilder->buildFromDicom($dummyDicomPath, $config);

    // Save to output files
    $outputPath = __DIR__ . '/output';
    $envelopePath = $jmixBuilder->saveToFiles($envelope, $outputPath, $config);

    echo "JMIX envelope created successfully!\n";
    echo "Envelope directory: {$envelopePath}\n";
    echo "Structure:\n";
    echo "- manifest.json\n";
    echo "- audit.json\n";
    echo "- payload/\n";
    echo "  - metadata.json\n";
    echo "  - dicom/\n";
    if (is_dir($envelopePath . '/payload/files')) {
        echo "  - files/\n";
    }

    // Display a summary
    echo "\nEnvelope Summary:\n";
    echo "ID: {$envelope['manifest']['id']}\n";
    echo "Timestamp: {$envelope['manifest']['timestamp']}\n";
    echo "Patient: {$envelope['metadata']['patient']['name']['text']}\n";
    echo "Study: {$envelope['metadata']['studies']['study_description']}\n";
    echo "Instance Count: {$envelope['metadata']['studies']['series'][0]['instance_count']}\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    
    if (method_exists($e, 'getErrors')) {
        echo "Validation errors:\n";
        foreach ($e->getErrors() as $error) {
            echo "  - {$error}\n";
        }
    }
}