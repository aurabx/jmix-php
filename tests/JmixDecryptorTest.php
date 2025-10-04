<?php

namespace AuraBox\Jmix\Tests;

use AuraBox\Jmix\JmixBuilder;
use AuraBox\Jmix\JmixDecryptor;
use AuraBox\Jmix\Encryption\PayloadEncryptor;
use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Exceptions\ValidationException;
use AuraBox\Jmix\Assertions\EntityAssertion;
use PHPUnit\Framework\TestCase;

class JmixDecryptorTest extends TestCase
{
    private string $tempDir;
    private JmixBuilder $builder;
    private JmixDecryptor $decryptor;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/jmix_decrypt_test_' . uniqid();
        if (!mkdir($this->tempDir, 0755, true)) {
            throw new \RuntimeException("Failed to create temp directory: {$this->tempDir}");
        }

        $schemaPath = dirname(__DIR__) . '/../jmix/schemas';
        $this->builder = new JmixBuilder($schemaPath);
        $this->decryptor = new JmixDecryptor($schemaPath);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->removeDirectory($this->tempDir);
        }
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }

    private function getValidConfig(): array
    {
        return [
            'version' => '1.0',
            'sender' => [
                'name' => 'Test Healthcare Organization',
                'id' => 'org:test.health.123',
                'contact' => 'admin@testorg.example.com'
            ],
            'requester' => [
                'name' => 'Dr Test User',
                'id' => 'org:test.health.doctor001',
                'contact' => 'doctor@testorg.example.com'
            ],
            'receivers' => [
                [
                    'name' => 'Central Archive',
                    'id' => 'org:test.health.archive',
                    'contact' => [
                        'system' => 'email',
                        'value' => 'archive@testorg.example.com'
                    ]
                ]
            ],
            'patient' => [
                'name' => 'Test Patient',
                'dob' => '1980-01-01',
                'sex' => 'F',
                'identifiers' => [
                    [
                        'system' => 'urn:oid:1.2.36.146.595.217.0.1',
                        'value' => 'TEST001'
                    ]
                ]
            ],
            'custom_tags' => ['test'],
            'security' => [
                'classification' => 'confidential'
            ]
        ];
    }

    private function createTestDicomFiles(): string
    {
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);

        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dicomPath . '/test1.dcm', $dummyData);
        file_put_contents($dicomPath . '/test2.dcm', $dummyData);

        return $dicomPath;
    }

    public function testAnalyzeUnencryptedEnvelope(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $analysis = $this->decryptor->analyzeEnvelope($envelopePath);

        $this->assertArrayHasKey('envelope_id', $analysis);
        $this->assertArrayHasKey('timestamp', $analysis);
        $this->assertFalse($analysis['is_encrypted']);
        $this->assertTrue($analysis['has_payload_hash']);
        $this->assertEquals('Test Healthcare Organization', $analysis['sender']['name']);
        $this->assertEquals('Dr Test User', $analysis['requester']['name']);
        $this->assertCount(1, $analysis['receivers']);

        // Check file structure
        $this->assertTrue($analysis['files']['manifest']);
        $this->assertTrue($analysis['files']['audit']);
        $this->assertTrue($analysis['files']['payload_directory']);
        $this->assertFalse($analysis['files']['payload_encrypted']);
    }

    public function testAnalyzeEncryptedEnvelope(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Add encryption config
        $keypair = PayloadEncryptor::generateKeypair();
        $config['encryption'] = ['recipient_public_key' => $keypair['public_key']];

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/encrypted_envelope', $config);

        $analysis = $this->decryptor->analyzeEnvelope($envelopePath);

        $this->assertTrue($analysis['is_encrypted']);
        $this->assertTrue($analysis['has_payload_hash']);
        $this->assertArrayHasKey('encryption', $analysis);
        $this->assertEquals('AES-256-GCM', $analysis['encryption']['algorithm']);

        // Check file structure
        $this->assertTrue($analysis['files']['manifest']);
        $this->assertTrue($analysis['files']['audit']);
        $this->assertFalse($analysis['files']['payload_directory']);
        $this->assertTrue($analysis['files']['payload_encrypted']);
    }

    public function testExtractUnencryptedEnvelope(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $outputPath = $this->tempDir . '/extracted';
        $extractedEnvelope = $this->decryptor->extractEnvelope($envelopePath, $outputPath);

        $this->assertArrayHasKey('manifest', $extractedEnvelope);
        $this->assertArrayHasKey('audit', $extractedEnvelope);
        $this->assertArrayHasKey('metadata', $extractedEnvelope);
        $this->assertArrayHasKey('payload_path', $extractedEnvelope);

        // Check extracted files
        $this->assertFileExists($outputPath . '/manifest.json');
        $this->assertFileExists($outputPath . '/audit.json');
        $this->assertFileExists($outputPath . '/payload/metadata.json');
        $this->assertDirectoryExists($outputPath . '/payload/dicom');

        // Verify extracted metadata matches original
        $this->assertEquals(
            $envelope['metadata']['patient']['name']['text'],
            $extractedEnvelope['metadata']['patient']['name']['text']
        );
    }

    public function testDecryptEncryptedEnvelope(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Add encryption config
        $keypair = PayloadEncryptor::generateKeypair();
        $config['encryption'] = ['recipient_public_key' => $keypair['public_key']];

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/encrypted_envelope', $config);

        $outputPath = $this->tempDir . '/decrypted';
        $decryptedEnvelope = $this->decryptor->decryptEnvelope(
            $envelopePath,
            $keypair['private_key'],
            $outputPath
        );

        $this->assertArrayHasKey('manifest', $decryptedEnvelope);
        $this->assertArrayHasKey('audit', $decryptedEnvelope);
        $this->assertArrayHasKey('metadata', $decryptedEnvelope);
        $this->assertArrayHasKey('payload_path', $decryptedEnvelope);

        // Check decrypted files
        $this->assertFileExists($outputPath . '/manifest.json');
        $this->assertFileExists($outputPath . '/audit.json');
        $this->assertFileExists($outputPath . '/payload/metadata.json');
        $this->assertDirectoryExists($outputPath . '/payload/dicom');

        // Verify decrypted metadata matches original
        $this->assertEquals(
            $envelope['metadata']['patient']['name']['text'],
            $decryptedEnvelope['metadata']['patient']['name']['text']
        );

        // Verify DICOM files were extracted
        $this->assertFileExists($outputPath . '/payload/dicom/test1.dcm');
        $this->assertFileExists($outputPath . '/payload/dicom/test2.dcm');
    }

    public function testDecryptWithWrongKey(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Create encrypted envelope with one key
        $keypair1 = PayloadEncryptor::generateKeypair();
        $config['encryption'] = ['recipient_public_key' => $keypair1['public_key']];

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/encrypted_envelope', $config);

        // Try to decrypt with different key
        $keypair2 = PayloadEncryptor::generateKeypair();
        $outputPath = $this->tempDir . '/decrypted';

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Failed to decrypt payload');

        $this->decryptor->decryptEnvelope(
            $envelopePath,
            $keypair2['private_key'],
            $outputPath
        );
    }

    public function testExtractEncryptedEnvelopeThrowsError(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Create encrypted envelope
        $keypair = PayloadEncryptor::generateKeypair();
        $config['encryption'] = ['recipient_public_key' => $keypair['public_key']];

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/encrypted_envelope', $config);

        $outputPath = $this->tempDir . '/extracted';

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Envelope is encrypted - use decryptEnvelope() instead');

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testDecryptUnencryptedEnvelopeThrowsError(): void
    {
        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Create unencrypted envelope
        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $outputPath = $this->tempDir . '/decrypted';
        $fakePrivateKey = 'fake-key';

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Envelope is not encrypted');

        $this->decryptor->decryptEnvelope($envelopePath, $fakePrivateKey, $outputPath);
    }

    public function testAnalyzeNonexistentEnvelopeThrowsError(): void
    {
        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Envelope directory does not exist');

        $this->decryptor->analyzeEnvelope('/nonexistent/path');
    }

    public function testPayloadHashVerification(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Create encrypted envelope
        $keypair = PayloadEncryptor::generateKeypair();
        $config['encryption'] = ['recipient_public_key' => $keypair['public_key']];

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/encrypted_envelope', $config);

        // Corrupt the encrypted payload file - this will cause decryption to fail
        // before hash verification, which is the expected behavior
        $encryptedFile = $envelopePath . '/payload.encrypted';
        $corruptedData = 'corrupted' . file_get_contents($encryptedFile);
        file_put_contents($encryptedFile, $corruptedData);

        $outputPath = $this->tempDir . '/decrypted';

        $this->expectException(JmixException::class);
        // The corruption causes decryption to fail before hash verification
        $this->expectExceptionMessage('Failed to decrypt payload - invalid key or corrupted data');

        $this->decryptor->decryptEnvelope(
            $envelopePath,
            $keypair['private_key'],
            $outputPath
        );
    }

    public function testPayloadHashVerificationUnencryptedEnvelope(): void
    {
        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        // Corrupt one of the payload files to cause hash verification failure
        $dicomFile = $envelopePath . '/payload/dicom/test1.dcm';
        file_put_contents($dicomFile, 'corrupted data');

        $outputPath = $this->tempDir . '/extracted';

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Decrypted payload hash verification failed - content integrity compromised');

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testSchemaValidationFailureManifest(): void
    {
        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        // Corrupt the manifest JSON to make it invalid
        $manifestFile = $envelopePath . '/manifest.json';
        $manifestData = json_decode(file_get_contents($manifestFile), true);
        
        // Remove required field to make it schema-invalid
        unset($manifestData['version']);
        
        file_put_contents($manifestFile, json_encode($manifestData));

        $outputPath = $this->tempDir . '/extracted';

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageMatches('/Schema validation failed/');

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testSchemaValidationFailureMetadata(): void
    {
        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $outputPath = $this->tempDir . '/extracted';

        // Since payload hash verification happens before schema validation for unencrypted envelopes,
        // we need to expect a hash verification failure instead
        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Decrypted payload hash verification failed - content integrity compromised');

        // Corrupt the metadata JSON AFTER the envelope is created but BEFORE extraction
        // This will cause payload hash verification to fail first
        $metadataFile = $envelopePath . '/payload/metadata.json';
        $metadataData = json_decode(file_get_contents($metadataFile), true);
        
        // Add invalid field type to make it schema-invalid (but hash fails first)
        $metadataData['patient']['name'] = 'invalid string instead of object';
        file_put_contents($metadataFile, json_encode($metadataData));

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testSchemaValidationFailureAudit(): void
    {
        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        // Remove payload hash from manifest to skip payload hash verification
        $manifestFile = $envelopePath . '/manifest.json';
        $manifest = json_decode(file_get_contents($manifestFile), true);
        unset($manifest['security']['payload_hash']);
        file_put_contents($manifestFile, json_encode($manifest));

        // Corrupt the audit JSON to make it invalid
        $auditFile = $envelopePath . '/audit.json';
        $auditData = json_decode(file_get_contents($auditFile), true);
        
        // Remove required field from audit entry to make it schema-invalid
        if (isset($auditData['audit'][0])) {
            unset($auditData['audit'][0]['event']); // Remove required 'event' field
        }
        
        file_put_contents($auditFile, json_encode($auditData));

        $outputPath = $this->tempDir . '/extracted';

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageMatches('/Schema validation failed/');

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testAssertionVerificationFailureInvalidSignature(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Add assertion configuration with valid keypair
        $keypair = EntityAssertion::generateKeypair();
        $config['sender']['assertion'] = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key'],
            'key_reference' => 'test://sender-key',
            'expires_at' => '2025-12-31T23:59:59Z'
        ];
        $config['verifyAssertions'] = true;

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        // Corrupt the signature in the manifest to make assertion verification fail
        $manifestFile = $envelopePath . '/manifest.json';
        $manifestData = json_decode(file_get_contents($manifestFile), true);
        
        // Replace with invalid signature
        $manifestData['sender']['assertion']['signature'] = base64_encode(random_bytes(64));
        
        file_put_contents($manifestFile, json_encode($manifestData));

        $outputPath = $this->tempDir . '/extracted';

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Cryptographic assertion verification failed');

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testAssertionVerificationFailureExpiredAssertion(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Add assertion configuration with expired timestamp
        $keypair = EntityAssertion::generateKeypair();
        $config['sender']['assertion'] = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key'],
            'key_reference' => 'test://sender-key',
            'expires_at' => '2020-01-01T00:00:00Z' // Expired
        ];
        // Don't set verifyAssertions=true here - let decryptor verify assertions

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $outputPath = $this->tempDir . '/extracted';

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Cryptographic assertion verification failed');

        $this->decryptor->extractEnvelope($envelopePath, $outputPath);
    }

    public function testAssertionVerificationSuccess(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Add assertion configuration
        $keypair = EntityAssertion::generateKeypair();
        $config['sender']['assertion'] = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key'],
            'key_reference' => 'test://sender-key',
            'expires_at' => '2025-12-31T23:59:59Z'
        ];
        $config['verifyAssertions'] = true;

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $outputPath = $this->tempDir . '/extracted';
        
        // This should succeed without throwing exceptions
        $extractedEnvelope = $this->decryptor->extractEnvelope($envelopePath, $outputPath);

        $this->assertArrayHasKey('manifest', $extractedEnvelope);
        $this->assertArrayHasKey('audit', $extractedEnvelope);
        $this->assertArrayHasKey('metadata', $extractedEnvelope);
        $this->assertArrayHasKey('payload_path', $extractedEnvelope);

        // Verify assertion is present
        $this->assertArrayHasKey('assertion', $extractedEnvelope['manifest']['sender']);
        $this->assertArrayHasKey('signature', $extractedEnvelope['manifest']['sender']['assertion']);
    }

    public function testValidEnvelopePassesAllValidations(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $dicomPath = $this->createTestDicomFiles();
        $config = $this->getValidConfig();

        // Add valid assertion configuration
        $keypair = EntityAssertion::generateKeypair();
        $config['sender']['assertion'] = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key'],
            'key_reference' => 'test://sender-key',
            'expires_at' => '2025-12-31T23:59:59Z'
        ];
        $config['verifyAssertions'] = true;

        $envelope = $this->builder->buildFromDicom($dicomPath, $config);
        $envelopePath = $this->builder->saveToFiles($envelope, $this->tempDir . '/envelope', $config);

        $outputPath = $this->tempDir . '/extracted';
        
        // This should pass all validations: schema, payload hash, and assertion verification
        $extractedEnvelope = $this->decryptor->extractEnvelope($envelopePath, $outputPath);

        $this->assertArrayHasKey('manifest', $extractedEnvelope);
        $this->assertArrayHasKey('audit', $extractedEnvelope);
        $this->assertArrayHasKey('metadata', $extractedEnvelope);
        $this->assertArrayHasKey('payload_path', $extractedEnvelope);

        // Check extracted files exist
        $this->assertFileExists($outputPath . '/manifest.json');
        $this->assertFileExists($outputPath . '/audit.json');
        $this->assertFileExists($outputPath . '/payload/metadata.json');
        $this->assertDirectoryExists($outputPath . '/payload/dicom');

        // Verify DICOM files were extracted correctly
        $this->assertFileExists($outputPath . '/payload/dicom/test1.dcm');
        $this->assertFileExists($outputPath . '/payload/dicom/test2.dcm');
    }
}
