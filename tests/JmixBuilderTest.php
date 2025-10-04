<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Tests;

use AuraBox\Jmix\Assertions\EntityAssertion;
use AuraBox\Jmix\JmixBuilder;
use AuraBox\Jmix\Exceptions\JmixException;
use PHPUnit\Framework\TestCase;

class JmixBuilderTest extends TestCase
{
    private JmixBuilder $builder;
    private string $tempDir;

    protected function setUp(): void
    {
        $schemaPath = dirname(__DIR__) . '/../jmix/schemas';
        $this->builder = new JmixBuilder($schemaPath);
        $this->tempDir = sys_get_temp_dir() . '/jmix_test_' . uniqid('', true);
        mkdir($this->tempDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->cleanupDirectory($this->tempDir);
    }

    public function testBuildFromDicomWithValidConfig(): void
    {
        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);

        $this->assertIsArray($envelope);
        $this->assertArrayHasKey('manifest', $envelope);
        $this->assertArrayHasKey('metadata', $envelope);
        $this->assertArrayHasKey('audit', $envelope);

        // Check manifest structure
        $manifest = $envelope['manifest'];
        $this->assertEquals('1.0', $manifest['version']);
        $this->assertNotEmpty($manifest['id']);
        $this->assertNotEmpty($manifest['timestamp']);
        $this->assertEquals('Radiology Clinic A', $manifest['sender']['name']);

        // Check metadata structure
        $metadata = $envelope['metadata'];
        $this->assertIsArray($metadata['patient']['name']);
        $this->assertEquals('Jane Doe', $metadata['patient']['name']['text']);
        $this->assertEquals('Doe', $metadata['patient']['name']['family']);
        $this->assertEquals(['Jane'], $metadata['patient']['name']['given']);
        $this->assertEquals('1975-02-14', $metadata['patient']['dob']);
        $this->assertIsObject($metadata['studies']);
        // Studies and extensions should be objects (may be empty when no data is available)

        // Check audit structure (renamed from transmission)
        $audit = $envelope['audit'];
        $this->assertIsArray($audit['audit']);
        $this->assertNotEmpty($audit['audit']);
        $this->assertEquals('created', $audit['audit'][0]['event']);
    }

    public function testBuildFromDicomWithNonExistentPath(): void
    {
        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('DICOM path does not exist');

        $config = $this->getValidConfig();
        $this->builder->buildFromDicom('/non/existent/path', $config);
    }

    public function testBuildFromDicomWithEmptyFolder(): void
    {
        $emptyPath = $this->tempDir . '/empty';
        mkdir($emptyPath, 0755, true);

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('No DICOM files found');

        $config = $this->getValidConfig();
        $this->builder->buildFromDicom($emptyPath, $config);
    }

    public function testSaveToFiles(): void
    {
        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        $config = $this->getValidConfig();
        $envelope = $this->builder->buildFromDicom($dicomPath, $config);

        $outputPath = $this->tempDir . '/output';
        $envelopePath = $this->builder->saveToFiles($envelope, $outputPath, $config);

        // Check envelope directory structure
        $this->assertDirectoryExists($envelopePath);
        $this->assertFileExists($envelopePath . '/manifest.json');
        $this->assertFileExists($envelopePath . '/audit.json');
        $this->assertDirectoryExists($envelopePath . '/payload');
        $this->assertFileExists($envelopePath . '/payload/metadata.json');
        $this->assertDirectoryExists($envelopePath . '/payload/dicom');

        // Check that DICOM files were copied
        $this->assertFileExists($envelopePath . '/payload/dicom/test.dcm');

        // Verify JSON structure
        $manifestJson = json_decode(file_get_contents($envelopePath . '/manifest.json'), true);
        $this->assertIsArray($manifestJson);
        $this->assertEquals('Radiology Clinic A', $manifestJson['sender']['name']);

        // Verify audit.json (renamed from transmission.json)
        $auditJson = json_decode(file_get_contents($envelopePath . '/audit.json'), true);
        $this->assertIsArray($auditJson);
        $this->assertArrayHasKey('audit', $auditJson);

        // Verify metadata.json is in payload/
        $metadataJson = json_decode(file_get_contents($envelopePath . '/payload/metadata.json'), true);
        $this->assertIsArray($metadataJson);
        $this->assertEquals('Jane Doe', $metadataJson['patient']['name']['text']);

        // Verify payload hash is calculated and included in manifest
        $this->assertArrayHasKey('payload_hash', $manifestJson['security']);
        $this->assertStringStartsWith('sha256:', $manifestJson['security']['payload_hash']);
        $this->assertNotEmpty($manifestJson['security']['payload_hash']);
        $this->assertNotEquals('sha256:', $manifestJson['security']['payload_hash']); // Ensure it's not just the prefix
    }

    public function testSaveToFilesWithEncryption(): void
    {
        // Check if sodium extension is available
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        // Generate test keypair
        $keypair = \AuraBox\Jmix\Encryption\PayloadEncryptor::generateKeypair();

        $config = $this->getValidConfig();
        $config['encryption'] = [
            'recipient_public_key' => $keypair['public_key'],
        ];

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);

        $outputPath = $this->tempDir . '/output';
        $envelopePath = $this->builder->saveToFiles($envelope, $outputPath, $config);

        // Check envelope directory structure
        $this->assertDirectoryExists($envelopePath);
        $this->assertFileExists($envelopePath . '/manifest.json');
        $this->assertFileExists($envelopePath . '/audit.json');

        // With encryption, payload should be a single encrypted file, not a directory
        $this->assertFileExists($envelopePath . '/payload.encrypted');
        $this->assertDirectoryDoesNotExist($envelopePath . '/payload');

        // Verify manifest contains encryption parameters
        $manifestJson = json_decode(file_get_contents($envelopePath . '/manifest.json'), true);
        $this->assertArrayHasKey('encryption', $manifestJson['security']);
        $this->assertEquals('AES-256-GCM', $manifestJson['security']['encryption']['algorithm']);
        $this->assertArrayHasKey('ephemeral_public_key', $manifestJson['security']['encryption']);
        $this->assertArrayHasKey('iv', $manifestJson['security']['encryption']);
        $this->assertArrayHasKey('auth_tag', $manifestJson['security']['encryption']);

        // Verify payload hash is calculated for encrypted file
        $this->assertArrayHasKey('payload_hash', $manifestJson['security']);
        $this->assertStringStartsWith('sha256:', $manifestJson['security']['payload_hash']);
    }

    public function testBuildFromDicomWithAssertions(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        // Generate keypairs for assertions
        $senderKeypair = EntityAssertion::generateKeypair();
        $requesterKeypair = EntityAssertion::generateKeypair();

        $config = $this->getValidConfig();
        
        // Add assertions to config
        $config['sender']['assertion'] = [
            'public_key' => $senderKeypair['public_key'],
            'private_key' => $senderKeypair['private_key'],
            'key_reference' => 'test://sender#key',
            'expires_at' => '2025-12-31T23:59:59Z'
        ];
        
        $config['requester']['assertion'] = [
            'public_key' => $requesterKeypair['public_key'],
            'private_key' => $requesterKeypair['private_key'],
            'key_reference' => 'test://requester#key',
            'expires_at' => '2025-12-31T23:59:59Z'
        ];
        
        // Enable assertion verification
        $config['verifyAssertions'] = true;

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);

        // Verify envelope structure with assertions
        $this->assertIsArray($envelope);
        $this->assertArrayHasKey('manifest', $envelope);
        $this->assertArrayHasKey('metadata', $envelope);
        $this->assertArrayHasKey('audit', $envelope);

        // Check that assertions were added to manifest
        $manifest = $envelope['manifest'];
        $this->assertArrayHasKey('assertion', $manifest['sender']);
        $this->assertArrayHasKey('assertion', $manifest['requester']);
        
        // Verify sender assertion structure
        $senderAssertion = $manifest['sender']['assertion'];
        $this->assertArrayHasKey('signing_key', $senderAssertion);
        $this->assertArrayHasKey('signed_fields', $senderAssertion);
        $this->assertArrayHasKey('signature', $senderAssertion);
        $this->assertEquals('Ed25519', $senderAssertion['signing_key']['alg']);
        $this->assertEquals($senderKeypair['public_key'], $senderAssertion['signing_key']['public_key']);
        $this->assertStringStartsWith('SHA256:', $senderAssertion['signing_key']['fingerprint']);
        $this->assertEquals('test://sender#key', $senderAssertion['key_reference']);
        $this->assertNotEmpty($senderAssertion['signature']);
        
        // Verify requester assertion structure
        $requesterAssertion = $manifest['requester']['assertion'];
        $this->assertArrayHasKey('signing_key', $requesterAssertion);
        $this->assertArrayHasKey('signed_fields', $requesterAssertion);
        $this->assertArrayHasKey('signature', $requesterAssertion);
        $this->assertEquals('Ed25519', $requesterAssertion['signing_key']['alg']);
        $this->assertEquals($requesterKeypair['public_key'], $requesterAssertion['signing_key']['public_key']);
        $this->assertEquals('test://requester#key', $requesterAssertion['key_reference']);
        $this->assertNotEmpty($requesterAssertion['signature']);
        
        // Verify signed fields contain expected values
        $this->assertContains('sender.id', $senderAssertion['signed_fields']);
        $this->assertContains('sender.name', $senderAssertion['signed_fields']);
        $this->assertContains('id', $senderAssertion['signed_fields']);
        $this->assertContains('timestamp', $senderAssertion['signed_fields']);
        
        $this->assertContains('requester.id', $requesterAssertion['signed_fields']);
        $this->assertContains('requester.name', $requesterAssertion['signed_fields']);
        $this->assertContains('id', $requesterAssertion['signed_fields']);
        $this->assertContains('timestamp', $requesterAssertion['signed_fields']);
    }

    public function testBuildFromDicomWithAssertionsValidationFailure(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        $keypair = EntityAssertion::generateKeypair();
        $config = $this->getValidConfig();
        
        // Add malformed assertion config
        $config['sender']['assertion'] = [
            'public_key' => 'invalid-base64!',
            'private_key' => $keypair['private_key']
        ];
        
        $this->expectException(JmixException::class);
        $this->builder->buildFromDicom($dicomPath, $config);
    }

    private function getValidConfig(): array
    {
        return [
            'sender' => [
                'name' => 'Radiology Clinic A',
                'id' => 'org:au.gov.health.123456',
                'contact' => 'imaging@clinica.org.au',
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
                ],
            ],
        ];
    }

    private function cleanupDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $filePath = $dir . '/' . $file;
            if (is_dir($filePath)) {
                $this->cleanupDirectory($filePath);
            } else {
                unlink($filePath);
            }
        }
        rmdir($dir);
    }
}
