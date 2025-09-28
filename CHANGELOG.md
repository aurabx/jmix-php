# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-09-27

### Added
- **🔐 Entity Assertions**: Full cryptographic identity verification for JMIX envelopes
  - `EntityAssertion` base class with Ed25519 signature support
  - `SenderAssertion`, `RequesterAssertion`, and `ReceiverAssertion` specialized classes  
  - `AssertionBuilder` factory and validation service
  - Automatic signature generation over canonicalized envelope fields
  - Memory-safe private key handling with secure clearing
  - Support for key references and directory attestations
  - Optional assertion expiry validation
- **CLI Enhancements**:
  - **`jmix-keygen`**: New Ed25519 keypair generator with multiple output formats
    - JSON format for programmatic use
    - Config format for ready-to-use JMIX configuration snippets
    - Separate format for manual key handling
    - Support for generating multiple keypairs
    - Entity type hints (sender, requester, receiver)
  - **Enhanced `jmix-build`**: Assertion status reporting and configuration guidance
  - **Enhanced `jmix-decrypt`**: New `--verify-assertions` flag for cryptographic verification
- **Security Features**:
  - Ed25519 digital signatures for non-repudiation
  - Field-level signing with configurable signed fields
  - JSON canonicalization for deterministic signatures  
  - Forward-compatible directory attestation support
  - Integration with existing AES-256-GCM encryption
- **Files.json schema validation**: Added `validateFiles()` method to `SchemaValidator` class
- **Cross-platform dcmdump detection**: Enhanced `isDcmdumpAvailable()` to work on Windows, Linux, and macOS
- **Schema compliance improvements**: All generated envelopes now pass strict schema validation

### Changed
- **BREAKING**: Removed all dummy/placeholder data from envelope generation
  - Digital signatures only included when provided in configuration
  - Patient data fallback now uses config values instead of hardcoded "Jane Doe" etc.
  - Patient verification data only included when provided in configuration  
  - Consent information only included when provided in configuration
  - Study/series data only includes actual extracted data, no dummy fallbacks
- **Fixed schema compliance**:
  - `studies` field now returns proper object structure instead of array
  - `extensions` field now returns proper object structure instead of empty array
  - Files.json manifests are now validated against `files.schema.json` schema
- **Enhanced DicomProcessor**:
  - Config data is now used as fallback when dcmdump is unavailable
  - Removed unused variables and cleaned up code
  - Cross-platform compatibility for dcmdump detection using `PHP_OS_FAMILY`
- **Production-ready data generation**: Envelopes no longer contain any test/dummy data
- **Enhanced JmixBuilder**: 
  - Automatic detection and processing of assertion configurations
  - Optional signature verification via `verifyAssertions` config flag
  - Schema-compliant assertion embedding in manifest entities
- **Improved CLI Output**:
  - `jmix-build` now reports assertion count and verification status
  - `jmix-decrypt analyze` shows assertion presence and optional verification
  - Enhanced help text with assertion examples and keypair generation guidance

### Fixed
- Added the missing bin folder with jmix-build and jmix-decrypt scripts
- Schema validation errors resolved - all components now validate correctly
- Removed unused `$filename` variable in `DicomProcessor::findDicomFiles()`
- Cross-platform dcmdump detection now works on Windows (`where` command) and Unix-like systems (`which` command)

### Security
- **Non-repudiation**: Cryptographic proof of envelope sender identity
- **Tamper Evidence**: Any modification to signed fields invalidates signatures
- **Offline Verification**: Assertion validation works without directory dependencies
- **Memory Safety**: Private keys are securely cleared after use
- **Standards Compliance**: Ed25519 signatures follow RFC 8032 specification

### Removed
- **All dummy data**: No more hardcoded patient names, signatures, consent data, or study information
- **Placeholder values**: Removed fallback dummy data that was not schema-compliant
- **TODO comments**: Resolved all outstanding TODO items in the codebase

### Configuration

#### Entity Assertions Configuration
```json
{
  "sender": {
    "name": "Healthcare Provider A",
    "id": "org:healthcare.provider.a",
    "contact": "admin@provider-a.com",
    "assertion": {
      "public_key": "<base64-ed25519-public-key>",
      "private_key": "<base64-ed25519-private-key>",
      "key_reference": "aurabox://org/provider-a#key-ed25519",
      "signed_fields": ["sender.id", "sender.name", "id", "timestamp"],
      "expires_at": "2025-12-31T23:59:59Z"
    }
  },
  "verifyAssertions": true
}
```

#### CLI Usage Examples
```bash
# Generate keypairs for assertions
jmix-keygen --format config --entity sender

# Build envelope with assertions
jmix-build /dicom config-with-assertions.json /output

# Analyze and verify assertions
jmix-decrypt analyze envelope.JMIX --verify-assertions
```

### Testing
- **28 PHPUnit tests**: Comprehensive test coverage including assertion functionality
- **Error handling**: Tests for malformed configurations and invalid signatures
- **Integration tests**: JmixBuilder with assertions, encryption, and schema validation
- **CLI testing**: Verification of assertion generation and validation workflows

### Backward Compatibility
- **Zero breaking changes**: Existing JMIX envelopes continue working without modification
- **Optional feature**: Assertions only added when configured in entity objects
- **Schema compliance**: Works with existing `manifest.schema.json` assertion definitions
- **Encryption compatibility**: Seamlessly integrates with AES-256-GCM payload encryption

### Migration Guide for v0.3.0

#### Data Configuration
With dummy data removed, you must now provide actual data in your configuration:

```php
// Before v0.3.0: Dummy data was automatically included
$config = [
    'sender' => [...],
    'patient' => ['name' => 'John Smith'] // Minimal config worked
];

// v0.3.0+: Provide complete data or expect null values
$config = [
    'sender' => [...],
    'patient' => [
        'name' => 'John Smith',
        'dob' => '1980-01-01',
        'sex' => 'M',
        'identifiers' => [[
            'system' => 'http://example.org/patient-ids',
            'value' => 'PATIENT-12345'
        ]],
        'verification' => [
            'verified_by' => 'my-health-system.org',
            'verified_on' => '2025-09-27'
        ]
    ],
    'consent' => [
        'status' => 'granted',
        'scope' => ['treatment'],
        'method' => 'digital-signature',
        'signed_on' => '2025-09-27'
    ],
    'security' => [
        'signature' => [
            'alg' => 'RS256',
            'sig' => '<actual-signature>',
            'hash' => 'sha256:<actual-hash>'
        ]
    ]
];
```

#### Schema Validation
- Files.json manifests are now automatically validated
- All envelope components must be schema-compliant
- No more dummy data masking validation issues

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