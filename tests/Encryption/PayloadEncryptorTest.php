<?php

namespace AuraBox\Jmix\Tests\Encryption;

use AuraBox\Jmix\Encryption\PayloadEncryptor;
use PHPUnit\Framework\TestCase;

class PayloadEncryptorTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/jmix_test_' . uniqid();
        if (!mkdir($this->tempDir, 0755, true)) {
            throw new \RuntimeException("Failed to create temp directory: {$this->tempDir}");
        }
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

    public function testGenerateKeypair(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $keypair = PayloadEncryptor::generateKeypair();

        $this->assertArrayHasKey('public_key', $keypair);
        $this->assertArrayHasKey('private_key', $keypair);

        // Keys should be base64-encoded
        $this->assertIsString($keypair['public_key']);
        $this->assertIsString($keypair['private_key']);
        $this->assertEquals(44, strlen($keypair['public_key'])); // 32 bytes base64 encoded
        $this->assertEquals(44, strlen($keypair['private_key'])); // 32 bytes base64 encoded

        // Should decode properly
        $this->assertNotFalse(base64_decode($keypair['public_key']));
        $this->assertNotFalse(base64_decode($keypair['private_key']));
    }

    public function testEncryptAndDecryptPayloadDirectory(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        // Create test payload directory with various files
        $payloadDir = $this->tempDir . '/payload';
        mkdir($payloadDir . '/dicom', 0755, true);
        mkdir($payloadDir . '/files', 0755, true);

        file_put_contents($payloadDir . '/metadata.json', '{"test": "metadata"}');
        file_put_contents($payloadDir . '/files.json', '{"files": []}');
        file_put_contents($payloadDir . '/dicom/test.dcm', str_repeat("\x00", 128) . 'DICM' . 'test data');
        file_put_contents($payloadDir . '/files/report.pdf', 'dummy pdf content');

        // Generate test keypair
        $keypair = PayloadEncryptor::generateKeypair();
        $encryptor = new PayloadEncryptor();

        // Encrypt the payload directory
        $encryptionResult = $encryptor->encryptPayload(
            $payloadDir,
            $keypair['public_key']
        );

        $this->assertArrayHasKey('encrypted_data', $encryptionResult);
        $this->assertEquals('AES-256-GCM', $encryptionResult['algorithm']);
        $this->assertArrayHasKey('ephemeral_public_key', $encryptionResult);
        $this->assertArrayHasKey('iv', $encryptionResult);
        $this->assertArrayHasKey('auth_tag', $encryptionResult);

        // Decrypt the payload
        $decryptedDir = $this->tempDir . '/decrypted';
        mkdir($decryptedDir, 0755, true);

        // Prepare encryption params for decryption (exclude encrypted_data)
        $params = $encryptionResult;
        unset($params['encrypted_data']);

        $encryptor->decryptPayload(
            $encryptionResult['encrypted_data'],
            $keypair['private_key'],
            $params,
            $decryptedDir
        );

        // Verify decrypted content
        $this->assertFileExists($decryptedDir . '/metadata.json');
        $this->assertFileExists($decryptedDir . '/files.json');
        $this->assertFileExists($decryptedDir . '/dicom/test.dcm');
        $this->assertFileExists($decryptedDir . '/files/report.pdf');

        $this->assertEquals('{"test": "metadata"}', file_get_contents($decryptedDir . '/metadata.json'));
        $this->assertEquals('{"files": []}', file_get_contents($decryptedDir . '/files.json'));
        $this->assertEquals('dummy pdf content', file_get_contents($decryptedDir . '/files/report.pdf'));
    }

    public function testEncryptEmptyDirectory(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        // Create empty payload directory
        $payloadDir = $this->tempDir . '/empty_payload';
        mkdir($payloadDir, 0755, true);

        $keypair = PayloadEncryptor::generateKeypair();
        $encryptor = new PayloadEncryptor();

        $encryptionResult = $encryptor->encryptPayload(
            $payloadDir,
            $keypair['public_key']
        );

        $this->assertArrayHasKey('encrypted_data', $encryptionResult);
        $this->assertArrayHasKey('algorithm', $encryptionResult);

        // Should be able to decrypt empty directory
        $decryptedDir = $this->tempDir . '/decrypted_empty';
        mkdir($decryptedDir, 0755, true);

        // Prepare encryption params for decryption (exclude encrypted_data)
        $params = $encryptionResult;
        unset($params['encrypted_data']);

        $encryptor->decryptPayload(
            $encryptionResult['encrypted_data'],
            $keypair['private_key'],
            $params,
            $decryptedDir
        );

        $this->assertDirectoryExists($decryptedDir);
        // Directory should be empty or only contain the placeholder file
        $files = array_diff(scandir($decryptedDir), ['.', '..']);
        // Either empty or only contains the .jmix-empty placeholder
        $this->assertTrue(
            empty($files) || (count($files) === 1 && $files[array_key_first($files)] === '.jmix-empty')
        );
    }

    public function testDecryptWithWrongKey(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $payloadDir = $this->tempDir . '/payload';
        mkdir($payloadDir, 0755, true);
        file_put_contents($payloadDir . '/test.txt', 'test content');

        // Generate two different keypairs
        $keypair1 = PayloadEncryptor::generateKeypair();
        $keypair2 = PayloadEncryptor::generateKeypair();

        $encryptor = new PayloadEncryptor();

        // Encrypt with first keypair
        $encryptionResult = $encryptor->encryptPayload(
            $payloadDir,
            $keypair1['public_key']
        );

        // Try to decrypt with second keypair (wrong key)
        $decryptedDir = $this->tempDir . '/decrypted_wrong';
        mkdir($decryptedDir, 0755, true);

        // Prepare encryption params for decryption (exclude encrypted_data)
        $params = $encryptionResult;
        unset($params['encrypted_data']);

        $this->expectException(\Exception::class);
        $encryptor->decryptPayload(
            $encryptionResult['encrypted_data'],
            $keypair2['private_key'],
            $params,
            $decryptedDir
        );
    }
}
