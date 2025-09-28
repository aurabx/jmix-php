<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Tests\Security;

use AuraBox\Jmix\Security\JwsHandler;
use AuraBox\Jmix\Exceptions\JmixException;
use PHPUnit\Framework\TestCase;

class JwsHandlerTest extends TestCase
{
    private JwsHandler $jwsHandler;
    private string $privateKey;
    private string $publicKey;

    protected function setUp(): void
    {
        $this->jwsHandler = new JwsHandler();
        
        // Generate test keypair
        $keypair = sodium_crypto_sign_keypair();
        $this->publicKey = base64_encode(sodium_crypto_sign_publickey($keypair));
        $this->privateKey = base64_encode(sodium_crypto_sign_secretkey($keypair));
        
        sodium_memzero($keypair);
    }

    public function testCreateJws(): void
    {
        $manifest = [
            'version' => '1.0',
            'id' => '123e4567-e89b-12d3-a456-426614174000',
            'timestamp' => '2025-01-01T00:00:00Z',
        ];

        $jws = $this->jwsHandler->createJws($manifest, $this->privateKey);

        // JWS should have 3 parts separated by dots
        $parts = explode('.', $jws);
        $this->assertCount(3, $parts);

        // Each part should be base64url encoded
        foreach ($parts as $part) {
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $part);
        }
    }

    public function testVerifyJws(): void
    {
        $manifest = [
            'version' => '1.0',
            'id' => '123e4567-e89b-12d3-a456-426614174000',
            'timestamp' => '2025-01-01T00:00:00Z',
        ];

        $jws = $this->jwsHandler->createJws($manifest, $this->privateKey);
        $verifiedPayload = $this->jwsHandler->verifyJws($jws, $this->publicKey);

        $this->assertEquals($manifest, $verifiedPayload);
    }

    public function testVerifyJwsWithInvalidSignature(): void
    {
        $manifest = [
            'version' => '1.0',
            'id' => '123e4567-e89b-12d3-a456-426614174000',
            'timestamp' => '2025-01-01T00:00:00Z',
        ];

        // Create JWS with one key
        $jws = $this->jwsHandler->createJws($manifest, $this->privateKey);

        // Try to verify with different key
        $wrongKeypair = sodium_crypto_sign_keypair();
        $wrongPublicKey = base64_encode(sodium_crypto_sign_publickey($wrongKeypair));

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('JWS signature verification failed');

        $this->jwsHandler->verifyJws($jws, $wrongPublicKey);
        
        sodium_memzero($wrongKeypair);
    }

    public function testExtractPayload(): void
    {
        $manifest = [
            'version' => '1.0',
            'id' => '123e4567-e89b-12d3-a456-426614174000',
            'timestamp' => '2025-01-01T00:00:00Z',
        ];

        $jws = $this->jwsHandler->createJws($manifest, $this->privateKey);
        $extractedPayload = $this->jwsHandler->extractPayload($jws);

        $this->assertEquals($manifest, $extractedPayload);
    }

    public function testInvalidJwsFormat(): void
    {
        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Invalid JWS format: expected 3 parts');

        $this->jwsHandler->verifyJws('invalid.jws', $this->publicKey);
    }

    public function testInvalidPublicKeyLength(): void
    {
        $manifest = ['test' => 'data'];
        $jws = $this->jwsHandler->createJws($manifest, $this->privateKey);

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Invalid public key length for Ed25519');

        $this->jwsHandler->verifyJws($jws, base64_encode('invalid_key'));
    }

    public function testInvalidPrivateKeyLength(): void
    {
        $manifest = ['test' => 'data'];

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('Invalid private key length for Ed25519');

        $this->jwsHandler->createJws($manifest, base64_encode('invalid_key'));
    }
}