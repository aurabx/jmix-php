<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Assertions;

/**
 * Receiver assertion for JMIX envelopes
 * 
 * Provides cryptographic verification of a receiver's identity. This can be used
 * to ensure that the receiver is authorized to receive the data and for audit purposes.
 */
class ReceiverAssertion extends EntityAssertion
{
    private int $receiverIndex;

    /**
     * @param string $publicKey Base64-encoded Ed25519 public key
     * @param string $privateKey Base64-encoded Ed25519 private key
     * @param int $receiverIndex Index of this receiver in the receivers array
     * @param string|null $keyReference Optional URI for key discovery
     * @param array $signedFields List of field paths to include in signature
     * @param string|null $expiresAt Optional expiry timestamp (ISO 8601)
     */
    public function __construct(
        string $publicKey,
        string $privateKey,
        int $receiverIndex,
        ?string $keyReference = null,
        array $signedFields = [],
        ?string $expiresAt = null
    ) {
        $this->receiverIndex = $receiverIndex;
        parent::__construct($publicKey, $privateKey, $keyReference, $signedFields, $expiresAt);
    }

    /**
     * Get default signed fields for receiver assertions
     * 
     * Default fields include receiver identity information for the specific receiver index.
     */
    protected function getDefaultSignedFields(): array
    {
        return [
            "receiver.{$this->receiverIndex}.id",
            "receiver.{$this->receiverIndex}.name",
            "receiver.{$this->receiverIndex}.contact",
            'id', // envelope ID
            'timestamp'
        ];
    }
}