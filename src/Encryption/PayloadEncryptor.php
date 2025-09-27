<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Encryption;

use AuraBox\Jmix\Exceptions\JmixException;
use Random\RandomException;

/**
 * Handles payload encryption for JMIX envelopes using AES-256-GCM
 * Implements ECDH key exchange with Curve25519 and HKDF key derivation
 */
class PayloadEncryptor
{
    /**
     * Encrypt a payload directory using recipient's public key
     *
     * @param  string  $payloadPath  Path to the payload directory
     * @param  string  $recipientPublicKey  Base64-encoded recipient's public key (Curve25519)
     * @return array Encryption parameters for manifest
     * @throws JmixException
     * @throws RandomException
     * @throws \SodiumException
     */
    public function encryptPayload(string $payloadPath, string $recipientPublicKey): array
    {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for encryption');
        }

        if (!is_dir($payloadPath)) {
            throw new JmixException("Payload directory does not exist: {$payloadPath}");
        }

        // Generate ephemeral keypair for this envelope (forward secrecy)
        $ephemeralKeyPair = sodium_crypto_box_keypair();
        $ephemeralPrivateKey = sodium_crypto_box_secretkey($ephemeralKeyPair);
        $ephemeralPublicKey = sodium_crypto_box_publickey($ephemeralKeyPair);

        // Decode recipient's public key
        $recipientKey = base64_decode($recipientPublicKey);
        if (strlen($recipientKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new JmixException('Invalid recipient public key length');
        }

        // Perform ECDH key exchange
        $sharedSecret = sodium_crypto_scalarmult($ephemeralPrivateKey, $recipientKey);

        // Derive AES-256 key using HKDF-SHA256
        $aesKey = hash_hkdf('sha256', $sharedSecret, 32, 'JMIX-payload-encryption', '');

        // Generate random 12-byte IV for AES-GCM
        $iv = random_bytes(12);

        // Create tar archive of payload directory
        $payloadData = $this->createPayloadArchive($payloadPath);

        // Encrypt using AES-256-GCM
        $tag = '';
        $ciphertext = openssl_encrypt(
            $payloadData,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            throw new JmixException('Failed to encrypt payload');
        }

        // Clear sensitive data
        sodium_memzero($ephemeralPrivateKey);
        sodium_memzero($sharedSecret);
        sodium_memzero($aesKey);

        return [
            'algorithm' => 'AES-256-GCM',
            'ephemeral_public_key' => base64_encode($ephemeralPublicKey),
            'iv' => base64_encode($iv),
            'auth_tag' => base64_encode($tag),
            'encrypted_data' => $ciphertext, // This will be written to a file, not included in manifest
        ];
    }

    /**
     * Decrypt a payload using recipient's private key and encryption parameters
     *
     * @param string $encryptedData The encrypted payload data
     * @param string $recipientPrivateKey Base64-encoded recipient's private key
     * @param array $encryptionParams Encryption parameters from manifest
     * @param string $outputPath Where to extract the decrypted payload
     * @throws JmixException|\SodiumException
     */
    public function decryptPayload(
        string $encryptedData,
        string $recipientPrivateKey,
        array $encryptionParams,
        string $outputPath
    ): void {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for decryption');
        }

        // Validate required parameters
        $required = ['algorithm', 'ephemeral_public_key', 'iv', 'auth_tag'];
        foreach ($required as $param) {
            if (!isset($encryptionParams[$param])) {
                throw new JmixException("Missing encryption parameter: {$param}");
            }
        }

        if ($encryptionParams['algorithm'] !== 'AES-256-GCM') {
            throw new JmixException('Unsupported encryption algorithm: ' . $encryptionParams['algorithm']);
        }

        // Decode parameters
        $ephemeralPublicKey = base64_decode($encryptionParams['ephemeral_public_key']);
        $iv = base64_decode($encryptionParams['iv']);
        $authTag = base64_decode($encryptionParams['auth_tag']);
        $recipientKey = base64_decode($recipientPrivateKey);

        // Perform ECDH key exchange
        $sharedSecret = sodium_crypto_scalarmult($recipientKey, $ephemeralPublicKey);

        // Derive AES-256 key using HKDF-SHA256
        $aesKey = hash_hkdf('sha256', $sharedSecret, 32, 'JMIX-payload-encryption', '');

        // Decrypt using AES-256-GCM
        $decryptedData = openssl_decrypt(
            $encryptedData,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $authTag
        );

        if ($decryptedData === false) {
            throw new JmixException('Failed to decrypt payload - invalid key or corrupted data');
        }

        // Extract tar archive to output directory
        $this->extractPayloadArchive($decryptedData, $outputPath);

        // Clear sensitive data
        sodium_memzero($sharedSecret);
        sodium_memzero($aesKey);
    }

    /**
     * Create a tar archive of the payload directory
     * @throws JmixException
     */
    private function createPayloadArchive(string $payloadPath): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'jmix_payload_');
        if ($tempFile === false) {
            throw new JmixException('Failed to create temporary file for payload archive');
        }

        try {
            $phar = new \PharData($tempFile . '.tar');

            // Check if directory has contents
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(
                    $payloadPath,
                    \FilesystemIterator::SKIP_DOTS
                )
            );

            $hasFiles = false;
            /** @noinspection PhpLoopNeverIteratesInspection */
            /** @noinspection LoopWhichDoesNotLoopInspection */
            foreach ($iterator as $file) {
                $hasFiles = true;
                break;
            }

            if ($hasFiles) {
                $phar->buildFromDirectory($payloadPath);
            } else {
                // For empty directory, create a minimal placeholder file
                $placeholderPath = $payloadPath . '/.jmix-empty';
                file_put_contents($placeholderPath, '');
                try {
                    $phar->buildFromDirectory($payloadPath);
                } finally {
                    @unlink($placeholderPath);
                }
            }

            $archiveData = file_get_contents($tempFile . '.tar');
            if ($archiveData === false) {
                throw new JmixException('Failed to read payload archive');
            }
        } finally {
            // Clean up temporary files
            @unlink($tempFile);
            @unlink($tempFile . '.tar');
        }

        return $archiveData;
    }

    /**
     * Extract a tar archive to the output directory
     * @throws JmixException
     */
    private function extractPayloadArchive(string $archiveData, string $outputPath): void
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'jmix_decrypt_');
        if ($tempFile === false) {
            throw new JmixException('Failed to create temporary file for extraction');
        }

        try {
            // Write archive data to temp file
            if (file_put_contents($tempFile . '.tar', $archiveData) === false) {
                throw new JmixException('Failed to write temporary archive file');
            }

            // Create output directory
            if (!is_dir($outputPath)) {
                if (!mkdir($outputPath, 0755, true) && !is_dir($outputPath)) {
                    throw new JmixException("Failed to create output directory: {$outputPath}");
                }
            }

            // Extract archive
            $phar = new \PharData($tempFile . '.tar');
            $phar->extractTo($outputPath);
        } finally {
            // Clean up temporary files
            @unlink($tempFile);
            @unlink($tempFile . '.tar');
        }
    }

    /**
     * Generate a Curve25519 keypair for testing/demo purposes
     *
     * @return array ['public_key' => base64_string, 'private_key' => base64_string]
     * @throws JmixException
     * @throws \SodiumException
     */
    public static function generateKeypair(): array
    {
        if (!extension_loaded('sodium')) {
            throw new JmixException('Sodium extension is required for key generation');
        }

        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $privateKey = sodium_crypto_box_secretkey($keyPair);

        $result = [
            'public_key' => base64_encode($publicKey),
            'private_key' => base64_encode($privateKey),
        ];

        // Clear the original keypair from memory
        sodium_memzero($keyPair);

        return $result;
    }
}
