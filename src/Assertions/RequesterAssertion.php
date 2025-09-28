<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Assertions;

/**
 * Requester assertion for JMIX envelopes
 * 
 * Provides cryptographic verification of the requester's identity, typically
 * used for the original requestor of the imaging transfer (e.g., referring physician).
 */
class RequesterAssertion extends EntityAssertion
{
    /**
     * Get default signed fields for requester assertions
     * 
     * Default fields include requester identity information and basic envelope metadata.
     */
    protected function getDefaultSignedFields(): array
    {
        return [
            'requester.id',
            'requester.name',
            'requester.contact',
            'id', // envelope ID
            'timestamp'
        ];
    }
}