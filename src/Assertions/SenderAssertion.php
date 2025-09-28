<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Assertions;

/**
 * Sender assertion for JMIX envelopes
 * 
 * Provides cryptographic verification of the sender's identity and ensures
 * the integrity of key sender-related fields in the envelope.
 */
class SenderAssertion extends EntityAssertion
{
    /**
     * Get default signed fields for sender assertions
     * 
     * Default fields include sender identity information and manifest hash
     * for strong integrity guarantees.
     */
    protected function getDefaultSignedFields(): array
    {
        return [
            'sender.id',
            'sender.name',
            'sender.contact',
            'manifest_hash',
            'id', // envelope ID
            'timestamp'
        ];
    }
}