<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Assertions;

use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Exceptions\ValidationException;

/**
 * Builder and validator for JMIX entity assertions
 * 
 * Handles creation, validation, and verification of cryptographic assertions
 * for senders, requesters, and receivers in JMIX envelopes.
 */
class AssertionBuilder
{
    /**
     * Create a sender assertion from configuration
     * 
     * @param array $config Sender configuration with assertion details
     * @return SenderAssertion
     * @throws JmixException
     */
    public function createSenderAssertion(array $config): SenderAssertion
    {
        $this->validateAssertionConfig($config);

        return new SenderAssertion(
            $config['public_key'],
            $config['private_key'],
            $config['key_reference'] ?? null,
            $config['signed_fields'] ?? [],
            $config['expires_at'] ?? null
        );
    }

    /**
     * Create a requester assertion from configuration
     * 
     * @param array $config Requester configuration with assertion details
     * @return RequesterAssertion
     * @throws JmixException
     */
    public function createRequesterAssertion(array $config): RequesterAssertion
    {
        $this->validateAssertionConfig($config);

        return new RequesterAssertion(
            $config['public_key'],
            $config['private_key'],
            $config['key_reference'] ?? null,
            $config['signed_fields'] ?? [],
            $config['expires_at'] ?? null
        );
    }

    /**
     * Create a receiver assertion from configuration
     * 
     * @param array $config Receiver configuration with assertion details
     * @param int $receiverIndex Index of this receiver in the receivers array
     * @return ReceiverAssertion
     * @throws JmixException
     */
    public function createReceiverAssertion(array $config, int $receiverIndex): ReceiverAssertion
    {
        $this->validateAssertionConfig($config);

        return new ReceiverAssertion(
            $config['public_key'],
            $config['private_key'],
            $receiverIndex,
            $config['key_reference'] ?? null,
            $config['signed_fields'] ?? [],
            $config['expires_at'] ?? null
        );
    }

    /**
     * Verify all assertions in a JMIX envelope
     * 
     * @param array $envelope Complete envelope data
     * @param bool $checkExpiry Whether to check assertion expiry
     * @return array Validation results with details
     * @throws JmixException
     */
    public function verifyEnvelopeAssertions(array $envelope, bool $checkExpiry = true): array
    {
        $results = [
            'valid' => true,
            'sender' => null,
            'requester' => null,
            'receivers' => [],
            'errors' => []
        ];

        // Verify sender assertion
        if (isset($envelope['manifest']['sender']['assertion'])) {
            try {
                $results['sender'] = $this->verifySenderAssertion(
                    $envelope,
                    $envelope['manifest']['sender']['assertion'],
                    $checkExpiry
                );
                if (!$results['sender']['valid']) {
                    $results['valid'] = false;
                }
            } catch (JmixException $e) {
                $results['valid'] = false;
                $results['errors'][] = 'Sender assertion verification failed: ' . $e->getMessage();
            }
        }

        // Verify requester assertion
        if (isset($envelope['manifest']['requester']['assertion'])) {
            try {
                $results['requester'] = $this->verifyRequesterAssertion(
                    $envelope,
                    $envelope['manifest']['requester']['assertion'],
                    $checkExpiry
                );
                if (!$results['requester']['valid']) {
                    $results['valid'] = false;
                }
            } catch (JmixException $e) {
                $results['valid'] = false;
                $results['errors'][] = 'Requester assertion verification failed: ' . $e->getMessage();
            }
        }

        // Verify receiver assertions
        if (isset($envelope['manifest']['receiver'])) {
            foreach ($envelope['manifest']['receiver'] as $index => $receiver) {
                if (isset($receiver['assertion'])) {
                    try {
                        $results['receivers'][$index] = $this->verifyReceiverAssertion(
                            $envelope,
                            $receiver['assertion'],
                            $index,
                            $checkExpiry
                        );
                        if (!$results['receivers'][$index]['valid']) {
                            $results['valid'] = false;
                        }
                    } catch (JmixException $e) {
                        $results['valid'] = false;
                        $results['errors'][] = "Receiver[$index] assertion verification failed: " . $e->getMessage();
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Verify a sender assertion
     */
    private function verifySenderAssertion(array $envelope, array $assertionData, bool $checkExpiry): array
    {
        $this->validateAssertionData($assertionData);

        $assertion = new SenderAssertion(
            $assertionData['signing_key']['public_key'],
            '', // Don't need private key for verification
            $assertionData['key_reference'] ?? null,
            $assertionData['signed_fields'],
            $assertionData['expires_at'] ?? null
        );

        if ($checkExpiry && $assertion->isExpired()) {
            throw new JmixException('Sender assertion has expired');
        }

        $isValid = $assertion->verifySignature($envelope, $assertionData['signature']);

        return [
            'valid' => $isValid,
            'fingerprint' => $assertionData['signing_key']['fingerprint'],
            'expires_at' => $assertionData['expires_at'] ?? null,
            'expired' => $assertion->isExpired()
        ];
    }

    /**
     * Verify a requester assertion
     */
    private function verifyRequesterAssertion(array $envelope, array $assertionData, bool $checkExpiry): array
    {
        $this->validateAssertionData($assertionData);

        $assertion = new RequesterAssertion(
            $assertionData['signing_key']['public_key'],
            '', // Don't need private key for verification
            $assertionData['key_reference'] ?? null,
            $assertionData['signed_fields'],
            $assertionData['expires_at'] ?? null
        );

        if ($checkExpiry && $assertion->isExpired()) {
            throw new JmixException('Requester assertion has expired');
        }

        $isValid = $assertion->verifySignature($envelope, $assertionData['signature']);

        return [
            'valid' => $isValid,
            'fingerprint' => $assertionData['signing_key']['fingerprint'],
            'expires_at' => $assertionData['expires_at'] ?? null,
            'expired' => $assertion->isExpired()
        ];
    }

    /**
     * Verify a receiver assertion
     */
    private function verifyReceiverAssertion(array $envelope, array $assertionData, int $receiverIndex, bool $checkExpiry): array
    {
        $this->validateAssertionData($assertionData);

        $assertion = new ReceiverAssertion(
            $assertionData['signing_key']['public_key'],
            '', // Don't need private key for verification
            $receiverIndex,
            $assertionData['key_reference'] ?? null,
            $assertionData['signed_fields'],
            $assertionData['expires_at'] ?? null
        );

        if ($checkExpiry && $assertion->isExpired()) {
            throw new JmixException("Receiver[$receiverIndex] assertion has expired");
        }

        $isValid = $assertion->verifySignature($envelope, $assertionData['signature']);

        return [
            'valid' => $isValid,
            'fingerprint' => $assertionData['signing_key']['fingerprint'],
            'expires_at' => $assertionData['expires_at'] ?? null,
            'expired' => $assertion->isExpired()
        ];
    }

    /**
     * Validate assertion configuration before creating assertion
     */
    private function validateAssertionConfig(array $config): void
    {
        $required = ['public_key', 'private_key'];
        
        foreach ($required as $field) {
            if (!isset($config[$field]) || empty($config[$field])) {
                throw new ValidationException("Missing required assertion field: {$field}");
            }
        }

        // Validate base64 encoding
        if (base64_decode($config['public_key'], true) === false) {
            throw new ValidationException('Invalid base64 encoding for public_key');
        }

        if (base64_decode($config['private_key'], true) === false) {
            throw new ValidationException('Invalid base64 encoding for private_key');
        }

        // Validate expiry format if provided
        if (isset($config['expires_at']) && strtotime($config['expires_at']) === false) {
            throw new ValidationException('Invalid expires_at timestamp format');
        }
    }

    /**
     * Validate assertion data for verification
     */
    private function validateAssertionData(array $assertionData): void
    {
        $required = [
            'signing_key.alg',
            'signing_key.public_key', 
            'signing_key.fingerprint',
            'signed_fields',
            'signature'
        ];

        foreach ($required as $field) {
            if (!$this->hasNestedKey($assertionData, $field)) {
                throw new ValidationException("Missing required assertion field: {$field}");
            }
        }

        // Validate algorithm
        if ($assertionData['signing_key']['alg'] !== 'Ed25519') {
            throw new ValidationException('Unsupported signature algorithm: ' . $assertionData['signing_key']['alg']);
        }

        // Validate signed_fields is not empty
        if (empty($assertionData['signed_fields'])) {
            throw new ValidationException('signed_fields cannot be empty');
        }
    }

    /**
     * Check if nested key exists in array using dot notation
     */
    private function hasNestedKey(array $data, string $key): bool
    {
        $keys = explode('.', $key);
        $value = $data;

        foreach ($keys as $k) {
            if (!is_array($value) || !isset($value[$k])) {
                return false;
            }
            $value = $value[$k];
        }

        return true;
    }
}