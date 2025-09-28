<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Tests\Assertions;

use AuraBox\Jmix\Assertions\AssertionBuilder;
use AuraBox\Jmix\Assertions\EntityAssertion;
use AuraBox\Jmix\Exceptions\JmixException;
use AuraBox\Jmix\Exceptions\ValidationException;
use PHPUnit\Framework\TestCase;

class AssertionBuilderTest extends TestCase
{
    private AssertionBuilder $builder;

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is not available');
        }

        $this->builder = new AssertionBuilder();
    }

    public function testCreateSenderAssertion(): void
    {
        $keypair = EntityAssertion::generateKeypair();
        $config = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key'],
            'key_reference' => 'test://sender',
            'expires_at' => '2025-12-31T23:59:59Z'
        ];

        $assertion = $this->builder->createSenderAssertion($config);
        $assertionArray = $assertion->toArray();

        $this->assertEquals('Ed25519', $assertionArray['signing_key']['alg']);
        $this->assertEquals($keypair['public_key'], $assertionArray['signing_key']['public_key']);
        $this->assertStringStartsWith('SHA256:', $assertionArray['signing_key']['fingerprint']);
        $this->assertEquals('test://sender', $assertionArray['key_reference']);
        $this->assertEquals('2025-12-31T23:59:59Z', $assertionArray['expires_at']);
        $this->assertContains('sender.id', $assertionArray['signed_fields']);
        $this->assertContains('sender.name', $assertionArray['signed_fields']);
    }

    public function testCreateRequesterAssertion(): void
    {
        $keypair = EntityAssertion::generateKeypair();
        $config = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key']
        ];

        $assertion = $this->builder->createRequesterAssertion($config);
        $assertionArray = $assertion->toArray();

        $this->assertContains('requester.id', $assertionArray['signed_fields']);
        $this->assertContains('requester.name', $assertionArray['signed_fields']);
    }

    public function testCreateReceiverAssertion(): void
    {
        $keypair = EntityAssertion::generateKeypair();
        $config = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key']
        ];

        $assertion = $this->builder->createReceiverAssertion($config, 1);
        $assertionArray = $assertion->toArray();

        $this->assertContains('receiver.1.id', $assertionArray['signed_fields']);
        $this->assertContains('receiver.1.name', $assertionArray['signed_fields']);
    }

    public function testValidateAssertionConfigMissingFields(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Missing required assertion field: public_key');

        $config = [
            'private_key' => 'test'
        ];

        $this->builder->createSenderAssertion($config);
    }

    public function testValidateAssertionConfigInvalidBase64(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Invalid base64 encoding for public_key');

        $config = [
            'public_key' => 'not-base64!',
            'private_key' => 'dGVzdA=='
        ];

        $this->builder->createSenderAssertion($config);
    }

    public function testVerifyEnvelopeAssertionsWithValidSignature(): void
    {
        $keypair = EntityAssertion::generateKeypair();
        
        // Create envelope with sender assertion
        $envelope = [
            'manifest' => [
                'id' => 'test-envelope-id',
                'timestamp' => '2025-01-01T00:00:00Z',
                'sender' => [
                    'id' => 'org:test.sender',
                    'name' => 'Test Sender',
                    'contact' => 'sender@test.com',
                    'assertion' => [
                        'signing_key' => [
                            'alg' => 'Ed25519',
                            'public_key' => $keypair['public_key'],
                            'fingerprint' => 'SHA256:' . hash('sha256', base64_decode($keypair['public_key']))
                        ],
                        'signed_fields' => ['sender.id', 'sender.name', 'id', 'timestamp'],
                        'signature' => '' // Will be filled by signFields
                    ]
                ]
            ]
        ];

        // Sign the assertion
        $config = [
            'public_key' => $keypair['public_key'],
            'private_key' => $keypair['private_key'],
            'signed_fields' => ['sender.id', 'sender.name', 'id', 'timestamp']
        ];
        $assertion = $this->builder->createSenderAssertion($config);
        $signature = $assertion->signFields($envelope);
        $envelope['manifest']['sender']['assertion']['signature'] = $signature;

        // Verify the envelope assertions
        $results = $this->builder->verifyEnvelopeAssertions($envelope);

        $this->assertTrue($results['valid']);
        $this->assertNotNull($results['sender']);
        $this->assertTrue($results['sender']['valid']);
        $this->assertFalse($results['sender']['expired']);
        $this->assertEmpty($results['errors']);
    }

    public function testVerifyEnvelopeAssertionsWithInvalidSignature(): void
    {
        $keypair = EntityAssertion::generateKeypair();
        
        // Create envelope with sender assertion and invalid signature
        $envelope = [
            'manifest' => [
                'id' => 'test-envelope-id',
                'timestamp' => '2025-01-01T00:00:00Z',
                'sender' => [
                    'id' => 'org:test.sender',
                    'name' => 'Test Sender',
                    'contact' => 'sender@test.com',
                    'assertion' => [
                        'signing_key' => [
                            'alg' => 'Ed25519',
                            'public_key' => $keypair['public_key'],
                            'fingerprint' => 'SHA256:' . hash('sha256', base64_decode($keypair['public_key']))
                        ],
                        'signed_fields' => ['sender.id', 'sender.name', 'id', 'timestamp'],
                        'signature' => base64_encode(random_bytes(64)) // Invalid signature
                    ]
                ]
            ]
        ];

        // Verify the envelope assertions
        $results = $this->builder->verifyEnvelopeAssertions($envelope);
        
        // Should fail because signature is invalid
        $this->assertFalse($results['valid'], 'Expected envelope validation to fail with invalid signature');
        $this->assertNotNull($results['sender'], 'Expected sender assertion results');
        $this->assertFalse($results['sender']['valid'], 'Expected sender assertion to be invalid');
        $this->assertFalse($results['sender']['expired'], 'Sender assertion should not be expired');
        $this->assertStringStartsWith('SHA256:', $results['sender']['fingerprint']);
        $this->assertNull($results['sender']['expires_at']);
        $this->assertEmpty($results['errors'], 'No errors expected for invalid signature, just invalid status');
    }

    public function testGenerateKeypair(): void
    {
        $keypair = EntityAssertion::generateKeypair();

        $this->assertIsArray($keypair);
        $this->assertArrayHasKey('public_key', $keypair);
        $this->assertArrayHasKey('private_key', $keypair);

        // Check that keys are valid base64
        $this->assertNotFalse(base64_decode($keypair['public_key'], true));
        $this->assertNotFalse(base64_decode($keypair['private_key'], true));

        // Check key lengths for Ed25519
        $this->assertEquals(32, strlen(base64_decode($keypair['public_key'])));
        $this->assertEquals(64, strlen(base64_decode($keypair['private_key'])));
    }
}