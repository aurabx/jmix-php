# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-09-27

### Added
- New `EnvelopeWriter` class for managing JMIX envelope directory structure
- Support for copying DICOM files into `payload/dicom/` directory
- Support for copying report files and attachments into `payload/files/` directory  
- Automatic generation of `files.json` manifest when `payload/files/` directory exists
- Enhanced CLI output showing the complete envelope directory structure
- **Payload hash calculation**: Automatic SHA-256 hash computation of the entire payload directory structure
- Real-time payload integrity verification through `security.payload_hash` field
- **Payload encryption**: Full AES-256-GCM encryption with ECDH key exchange (Curve25519)
  - `PayloadEncryptor` class for encryption/decryption operations
  - Ephemeral keys for forward secrecy
  - HKDF-SHA256 key derivation for enhanced security
  - Compliant with JMIX security specification
  - Encrypted payload replaces directory structure with single `payload.encrypted` file
  - Key generation utilities for testing and development
  - Encryption configuration via `config.encryption.recipient_public_key`
- **Envelope decryption and extraction**: Complete toolset for processing JMIX envelopes
  - `JmixDecryptor` class for decrypting encrypted envelopes and extracting unencrypted ones
  - Payload hash verification for data integrity
  - Envelope analysis without extraction (metadata inspection)
  - Support for both encrypted (`payload.encrypted`) and unencrypted (`payload/`) envelope formats
  - `jmix-decrypt` CLI tool with analyze, extract, and decrypt commands
  - Automatic detection of envelope encryption status

### Changed
- **BREAKING**: `saveToFiles()` now creates JMIX envelope directories following the official specification format: `<output>/<envelope-id>.JMIX/`
- **BREAKING**: `saveToFiles()` now returns the path to the created envelope directory
- **BREAKING**: `saveToFiles()` now accepts an optional third parameter `$config` for handling file attachments
- **BREAKING**: Renamed `transmission.json` to `audit.json` to match JMIX specification
- **BREAKING**: Renamed `validateTransmission()` method to `validateAudit()` in `SchemaValidator`
- **BREAKING**: Changed envelope array structure from `$envelope['transmission']` to `$envelope['audit']`
- **BREAKING**: Renamed internal `buildTransmission()` method to `buildAudit()`
- Enhanced security: `payload_hash` field now contains a real SHA-256 hash of the entire payload directory instead of placeholder value
- Improved manifest validation: Schema validation now occurs after payload hash calculation to ensure compliance
- File structure now follows JMIX envelope specification:
  ```
  # Unencrypted envelope
  <envelope-id>.JMIX/
  ├── manifest.json              # Security & routing metadata (includes payload_hash)
  ├── audit.json                 # Audit trail (renamed from transmission.json)
  ├── payload/
  │   ├── metadata.json          # Medical data & patient info
  │   ├── dicom/                 # DICOM files (copied from source)
  │   ├── files/                 # Optional: report files and attachments
  │   └── files.json             # File manifest (when files/ present)
  
  # Encrypted envelope (when config.encryption.recipient_public_key is provided)
  <envelope-id>.JMIX/
  ├── manifest.json              # Includes encryption parameters in security.encryption
  ├── audit.json                 # Audit trail
  └── payload.encrypted          # AES-256-GCM encrypted tar archive of payload/
  ```
  
- The `manifest.json` now includes a real payload hash and optional encryption. 

  For an unencrypted envelope:
  ```json
  {
    "security": {
      "payload_hash": "sha256:0fc9c6433e90e7f8c1add4e56738418793f47f5e1f2f97b098973b53fd3c4a86"
    }
  }
  ```

  For an encrypted envelope:
  ```json
  {
    "security": {
      "payload_hash": "sha256:65aaa7d639c9773f0bb1c7af7d9eb851b2a1b444919e84dcb3be54ad7a5247b3",
      "encryption": {
        "algorithm": "AES-256-GCM",
        "ephemeral_public_key": "ReHLA0HZP9dYizZgKPwWHbkPxJkpxv88obmDHAI24w8=",
        "iv": "uTv8nI6Wi/a/O7wc",
        "auth_tag": "5c8VZzxSuWM3RMqA4fAPMw=="
      }
    }
  }
  ```

### Migration Guide

#### For Library Users:
```php
// Before v0.2.0
$jmixBuilder->saveToFiles($envelope, '/path/to/output');
// Files created: /path/to/output/{manifest.json, metadata.json, transmission.json}

// v2.0.0+ Unencrypted envelope
$envelopePath = $jmixBuilder->saveToFiles($envelope, '/path/to/output', $config);
// Envelope created: /path/to/output/<UUID>.JMIX/ (with proper directory structure)
echo "Envelope created at: {$envelopePath}";

// v2.0.0+ Encrypted envelope
$config['encryption'] = ['recipient_public_key' => $publicKey];
$envelopePath = $jmixBuilder->saveToFiles($envelope, '/path/to/output', $config);
// Creates: /path/to/output/<UUID>.JMIX/{manifest.json, audit.json, payload.encrypted}
```

#### For Testing Code:
```php
// Before v0.2.0
$this->assertFileExists($outputPath . '/transmission.json');

// v0.2.0+
$envelopePath = $jmixBuilder->saveToFiles($envelope, $outputPath, $config);
$this->assertFileExists($envelopePath . '/audit.json');
$this->assertFileExists($envelopePath . '/payload/metadata.json');
$this->assertDirectoryExists($envelopePath . '/payload/dicom');
```

#### Encryption Setup:
```php
// Generate keypair for testing/development
use AuraBox\Jmix\Encryption\PayloadEncryptor;

$keypair = PayloadEncryptor::generateKeypair();
$publicKey = $keypair['public_key'];   // For encryption config
$privateKey = $keypair['private_key']; // For decryption (keep secure!)

// Use in configuration
$config['encryption'] = [
    'recipient_public_key' => $publicKey
];
```

#### Decryption and Extraction:
```php
// Decrypt encrypted envelopes
use AuraBox\Jmix\JmixDecryptor;

$decryptor = new JmixDecryptor();

// Analyze envelope (without extracting)
$analysis = $decryptor->analyzeEnvelope('/path/to/envelope.JMIX');
echo $analysis['is_encrypted'] ? 'Encrypted' : 'Not encrypted';

// Decrypt encrypted envelope
if ($analysis['is_encrypted']) {
    $envelope = $decryptor->decryptEnvelope(
        '/path/to/encrypted.JMIX',
        $privateKey,
        '/path/to/output'
    );
} else {
    // Extract unencrypted envelope
    $envelope = $decryptor->extractEnvelope(
        '/path/to/unencrypted.JMIX',
        '/path/to/output'
    );
}

// Access extracted content
echo "Patient: " . $envelope['metadata']['patient']['name']['text'];
echo "DICOM files: " . $envelope['payload_path'] . '/dicom/';
```

#### CLI Tools:
```bash
# Analyze envelope
jmix-decrypt analyze /path/to/envelope.JMIX

# Extract unencrypted envelope
jmix-decrypt extract /path/to/envelope.JMIX /path/to/output

# Decrypt encrypted envelope
jmix-decrypt decrypt /path/to/encrypted.JMIX /path/to/output <private-key>
```

#### Schema Validation:
- Update any code calling `validateTransmission()` to use `validateAudit()`
- Ensure `audit.schema.json` is available in your schema directory

## [0.1.0] - 2024-XX-XX

### Added
- Initial release with basic JMIX envelope generation
- Support for DICOM metadata extraction  
- JSON schema validation
- CLI tool for envelope creation
- Basic cryptographic assertion placeholders