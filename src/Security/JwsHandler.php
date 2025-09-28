<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Security;

use AuraBox\Jmix\Exceptions\JmixException;

/**
 * JSON Web Signature (JWS) handler for JMIX manifest signatures
 * 
 * Provides cryptographic verification of manifest.json integrity and authenticity
 * using the JSON Web Signature (RFC 7515) standard.
 */
class JwsHandler
{
    /**
     * Create a JWS signature for the manifest
     * 
     * @param array $manifest The manifest data to sign
     * @param string $privateKey Base64-encoded Ed25519 private key
     * @param string $algorithm Signature algorithm (Ed25519)
     * @return string Complete JWS in compact serialization format
     * @throws JmixException
     */
    public function createJws(array $manifest, string $privateKey, string $algorithm = 'EdDSA'): string
    {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for JWS signatures');
        }

        // Create JWS header
        $header = [
            'alg' => $algorithm,
            'typ' => 'JWT'
        ];

        // Encode header and payload
        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        // Create signing input
        $signingInput = $headerEncoded . '.' . $payloadEncoded;

        // Sign with Ed25519
        $privateKeyBinary = base64_decode($privateKey);
        if (strlen($privateKeyBinary) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new JmixException('Invalid private key length for Ed25519');
        }

        $signature = sodium_crypto_sign_detached($signingInput, $privateKeyBinary);
        $signatureEncoded = $this->base64UrlEncode($signature);

        // Clear sensitive data
        sodium_memzero($privateKeyBinary);

        // Return complete JWS
        return $signingInput . '.' . $signatureEncoded;
    }

    /**
     * Verify a JWS signature
     * 
     * @param string $jws Complete JWS in compact serialization format
     * @param string $publicKey Base64-encoded Ed25519 public key
     * @return array Decoded payload if verification succeeds
     * @throws JmixException
     */
    public function verifyJws(string $jws, string $publicKey): array
    {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for JWS verification');
        }

        $parts = explode('.', $jws);
        if (count($parts) !== 3) {
            throw new JmixException('Invalid JWS format: expected 3 parts');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        // Decode header and verify algorithm
        $header = json_decode($this->base64UrlDecode($headerEncoded), true);
        if (!$header || !isset($header['alg']) || $header['alg'] !== 'EdDSA') {
            throw new JmixException('Invalid or unsupported JWS algorithm');
        }

        // Verify signature
        $signingInput = $headerEncoded . '.' . $payloadEncoded;
        $signature = $this->base64UrlDecode($signatureEncoded);
        $publicKeyBinary = base64_decode($publicKey);

        if (strlen($publicKeyBinary) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new JmixException('Invalid public key length for Ed25519');
        }

        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new JmixException('Invalid signature length for Ed25519');
        }

        if (!sodium_crypto_sign_verify_detached($signature, $signingInput, $publicKeyBinary)) {
            throw new JmixException('JWS signature verification failed');
        }

        // Return decoded payload
        $payload = json_decode($this->base64UrlDecode($payloadEncoded), true);
        if (!$payload) {
            throw new JmixException('Failed to decode JWS payload');
        }

        return $payload;
    }

    /**
     * Extract payload from JWS without verification (for inspection)
     * 
     * @param string $jws Complete JWS in compact serialization format
     * @return array Decoded payload
     * @throws JmixException
     */
    public function extractPayload(string $jws): array
    {
        $parts = explode('.', $jws);
        if (count($parts) !== 3) {
            throw new JmixException('Invalid JWS format: expected 3 parts');
        }

        $payload = json_decode($this->base64UrlDecode($parts[1]), true);
        if (!$payload) {
            throw new JmixException('Failed to decode JWS payload');
        }

        return $payload;
    }

    /**
     * Base64URL encode (RFC 4648)
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL decode (RFC 4648)
     */
    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        
        return base64_decode(strtr($data, '-_', '+/'));
    }
}