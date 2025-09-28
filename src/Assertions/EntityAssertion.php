<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Assertions;

use AuraBox\Jmix\Exceptions\JmixException;

/**
 * Base class for JMIX entity assertions (sender, requester, receiver)
 * 
 * Provides cryptographic verification of entity identities using Ed25519 signatures
 * over canonicalized field values from the JMIX envelope.
 */
abstract class EntityAssertion
{
    protected string $algorithm = 'Ed25519';
    protected string $publicKey;
    protected string $privateKey;
    protected string $fingerprint;
    protected ?string $keyReference = null;
    protected array $signedFields = [];
    protected ?string $signature = null;
    protected ?string $expiresAt = null;
    protected ?array $directoryAttestation = null;

    /**
     * @param string $publicKey Base64-encoded Ed25519 public key
     * @param string $privateKey Base64-encoded Ed25519 private key
     * @param string|null $keyReference Optional URI for key discovery
     * @param array $signedFields List of field paths to include in signature
     * @param string|null $expiresAt Optional expiry timestamp (ISO 8601)
     * @throws JmixException
     */
    public function __construct(
        string $publicKey,
        string $privateKey,
        ?string $keyReference = null,
        array $signedFields = [],
        ?string $expiresAt = null
    ) {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for Ed25519 assertions');
        }

        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
        $this->keyReference = $keyReference;
        $this->signedFields = $signedFields ?: $this->getDefaultSignedFields();
        $this->expiresAt = $expiresAt;
        
        // Calculate fingerprint
        $this->fingerprint = $this->calculateFingerprint($publicKey);
    }

    /**
     * Generate an Ed25519 keypair for assertions
     * 
     * @return array ['public_key' => base64_string, 'private_key' => base64_string]
     * @throws JmixException
     */
    public static function generateKeypair(): array
    {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for key generation');
        }

        $keypair = sodium_crypto_sign_keypair();
        $publicKey = sodium_crypto_sign_publickey($keypair);
        $privateKey = sodium_crypto_sign_secretkey($keypair);

        $result = [
            'public_key' => base64_encode($publicKey),
            'private_key' => base64_encode($privateKey),
        ];

        // Clear keypair from memory
        sodium_memzero($keypair);

        return $result;
    }

    /**
     * Sign the specified fields from the envelope data
     * 
     * @param array $envelopeData Complete envelope data
     * @return string Base64-encoded signature
     * @throws JmixException
     */
    public function signFields(array $envelopeData): string
    {
        $fieldsToSign = $this->extractSignedFields($envelopeData);
        $canonicalData = $this->canonicalizeFields($fieldsToSign);
        
        $privateKeyBinary = base64_decode($this->privateKey);
        if (strlen($privateKeyBinary) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new JmixException('Invalid private key length for Ed25519');
        }

        $signature = sodium_crypto_sign_detached($canonicalData, $privateKeyBinary);
        $this->signature = base64_encode($signature);

        // Clear sensitive data
        sodium_memzero($privateKeyBinary);

        return $this->signature;
    }

    /**
     * Verify a signature against the envelope data
     * 
     * @param array $envelopeData Complete envelope data
     * @param string $signature Base64-encoded signature to verify
     * @return bool True if signature is valid
     * @throws JmixException
     */
    public function verifySignature(array $envelopeData, string $signature): bool
    {
        $fieldsToSign = $this->extractSignedFields($envelopeData);
        $canonicalData = $this->canonicalizeFields($fieldsToSign);
        
        $publicKeyBinary = base64_decode($this->publicKey);
        if (strlen($publicKeyBinary) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new JmixException('Invalid public key length for Ed25519');
        }

        $signatureBinary = base64_decode($signature);
        if (strlen($signatureBinary) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new JmixException('Invalid signature length for Ed25519');
        }

        return sodium_crypto_sign_verify_detached($signatureBinary, $canonicalData, $publicKeyBinary);
    }

    /**
     * Check if the assertion has expired
     */
    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        $expiryTime = strtotime($this->expiresAt);
        return $expiryTime !== false && $expiryTime < time();
    }

    /**
     * Set directory attestation
     */
    public function setDirectoryAttestation(array $attestation): void
    {
        $this->directoryAttestation = $attestation;
    }

    /**
     * Convert assertion to array format for JSON encoding
     */
    public function toArray(): array
    {
        $assertion = [
            'signing_key' => [
                'alg' => $this->algorithm,
                'public_key' => $this->publicKey,
                'fingerprint' => $this->fingerprint,
            ],
            'signed_fields' => $this->signedFields,
        ];

        if ($this->keyReference !== null) {
            $assertion['key_reference'] = $this->keyReference;
        }

        if ($this->signature !== null) {
            $assertion['signature'] = $this->signature;
        }

        if ($this->expiresAt !== null) {
            $assertion['expires_at'] = $this->expiresAt;
        }

        if ($this->directoryAttestation !== null) {
            $assertion['directory_attestation'] = $this->directoryAttestation;
        }

        return $assertion;
    }

    /**
     * Get default signed fields for this entity type
     */
    abstract protected function getDefaultSignedFields(): array;

    /**
     * Calculate SHA-256 fingerprint of public key
     */
    private function calculateFingerprint(string $publicKeyBase64): string
    {
        $publicKeyBinary = base64_decode($publicKeyBase64);
        $hash = hash('sha256', $publicKeyBinary);
        return 'SHA256:' . $hash;
    }

    /**
     * Extract the values of signed fields from envelope data
     */
    private function extractSignedFields(array $envelopeData): array
    {
        $fields = [];
        
        foreach ($this->signedFields as $fieldPath) {
            $value = $this->getNestedValue($envelopeData, $fieldPath);
            $fields[$fieldPath] = $value;
        }

        return $fields;
    }

    /**
     * Get nested value from array using dot notation
     */
    private function getNestedValue(array $data, string $path)
    {
        $keys = explode('.', $path);
        $value = $data;

        foreach ($keys as $key) {
            if (is_array($value) && isset($value[$key])) {
                $value = $value[$key];
            } else {
                return null;
            }
        }

        return $value;
    }

    /**
     * Canonicalize fields for signing using JSON Canonical Form
     */
    private function canonicalizeFields(array $fields): string
    {
        // Sort fields by key for deterministic ordering
        ksort($fields);
        
        // Convert to JSON with consistent formatting
        $json = json_encode($fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new JmixException('Failed to canonicalize fields for signing');
        }

        return $json;
    }
}