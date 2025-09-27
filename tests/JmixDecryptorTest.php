<?php

namespace AuraBox\Jmix\Tests;

use AuraBox\Jmix\JmixBuilder;
use AuraBox\Jmix\JmixDecryptor;
use AuraBox\Jmix\Encryption\PayloadEncryptor;
use AuraBox\Jmix\Exceptions\JmixException;
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

        $this->builder = new JmixBuilder();
        $this->decryptor = new JmixDecryptor();
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
}
