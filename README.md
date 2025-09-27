# JMIX PHP Library

A PHP library for creating and processing JMIX (JSON Medical Interchange) envelopes from DICOM files. JMIX is a secure data format for exchanging medical/healthcare information with strong cryptographic features including AES-256-GCM encryption.

## Features

- **Convert DICOM folders to complete JMIX envelopes**
- **Automatic metadata extraction from DICOM files**
- **JSON Schema validation for all components**
- **Simple, array-based configuration**
- **AES-256-GCM payload encryption** with ECDH key exchange (Curve25519)
- **Payload decryption and envelope extraction**
- **SHA-256 payload hash verification** for data integrity
- **Built-in audit trail generation**
- **CLI tools** for building, analyzing, and decrypting envelopes
- **Ephemeral keys** for forward secrecy

## Installation

```bash
composer require aurabx/jmix
```

## Quick Start

```php
<?php
require_once 'vendor/autoload.php';

use AuraBox\Jmix\JmixBuilder;

// Configuration array
$config = [
    'sender' => [
        'name' => 'Radiology Clinic A',
        'id' => 'org:au.gov.health.123456',
        'contact' => 'imaging@clinica.org.au',
    ],
    'requester' => [
        'name' => 'Dr John Smith',
        'id' => 'org:au.gov.health.55555',
        'contact' => 'smith@clinicb.org.au',
    ],
    'receivers' => [[
        'name' => 'Radiology Clinic B',
        'id' => 'org:au.gov.health.987654',
        'contact' => ['system' => 'phone', 'value' => '+61049555555'],
    ]],
    'patient' => [
        'name' => 'Jane Doe',
        'dob' => '1975-02-14',
        'sex' => 'F',
        'ihi' => '8003608166690503',
    ],
];

// Build JMIX envelope
$jmixBuilder = new JmixBuilder();
$envelope = $jmixBuilder->buildFromDicom('/path/to/dicom/files', $config);

// Save to JMIX envelope directory
$envelopePath = $jmixBuilder->saveToFiles($envelope, '/path/to/output', $config);
echo "Envelope created at: {$envelopePath}\n";

// Example with encryption (optional)
// Generate keypair for encryption
use AuraBox\Jmix\Encryption\PayloadEncryptor;
$keypair = PayloadEncryptor::generateKeypair();

// Add encryption to config
$config['encryption'] = [
    'recipient_public_key' => $keypair['public_key']
];

// Build encrypted envelope
$encryptedEnvelope = $jmixBuilder->buildFromDicom('/path/to/dicom/files', $config);
$encryptedPath = $jmixBuilder->saveToFiles($encryptedEnvelope, '/path/to/output', $config);
echo "🔒 Encrypted envelope created at: {$encryptedPath}\n";
```

## JMIX Components

The library generates three main components:

### 1. Manifest (`manifest.json`)
Contains security and routing metadata:
- Digital signatures and cryptographic assertions
- Sender, requester, and receiver information
- Encryption parameters
- Security classification

### 2. Metadata (`metadata.json`) 
Contains medical/clinical data:
- Patient information with healthcare identifiers
- Medical imaging study details (extracted from DICOM)
- Consent management
- De-identification tracking
- File/report references

### 3. Audit (`audit.json`)
Contains audit trail:
- Event logging with timestamps
- Chain of custody tracking
- Cryptographic signatures for events

## Encryption and Decryption

The library supports enterprise-grade AES-256-GCM encryption with ECDH key exchange for secure medical data transmission.

### Generating Keys

```php
use AuraBox\Jmix\Encryption\PayloadEncryptor;

// Generate a keypair for testing/development
$keypair = PayloadEncryptor::generateKeypair();
$publicKey = $keypair['public_key'];   // For encryption (share with sender)
$privateKey = $keypair['private_key']; // For decryption (keep secure!)

echo "Public Key: " . $publicKey . "\n";
echo "Private Key: " . $privateKey . "\n";
```

### Creating Encrypted Envelopes

```php
use AuraBox\Jmix\JmixBuilder;
use AuraBox\Jmix\Encryption\PayloadEncryptor;

// Your regular configuration
$config = [
    'sender' => ['name' => 'Clinic A', 'id' => 'org:clinic.a', 'contact' => 'info@clinica.com'],
    'requester' => ['name' => 'Dr Smith', 'id' => 'doc:smith', 'contact' => 'smith@clinic.com'],
    'receivers' => [['name' => 'Clinic B', 'id' => 'org:clinic.b', 'contact' => 'info@clinicb.com']],
    'patient' => ['name' => 'Jane Doe', 'dob' => '1975-02-14', 'sex' => 'F'],
    // ... other config
];

// Add encryption
$config['encryption'] = [
    'recipient_public_key' => $recipientPublicKey  // Recipient's public key
];

// Build encrypted envelope
$jmixBuilder = new JmixBuilder();
$envelope = $jmixBuilder->buildFromDicom('/path/to/dicom', $config);
$envelopePath = $jmixBuilder->saveToFiles($envelope, '/path/to/output', $config);

echo "🔒 Encrypted envelope created at: {$envelopePath}\n";
```

### Analyzing and Decrypting Envelopes

```php
use AuraBox\Jmix\JmixDecryptor;

$decryptor = new JmixDecryptor();

// 1. Analyze envelope (without extracting)
$analysis = $decryptor->analyzeEnvelope('/path/to/envelope.JMIX');
echo "Envelope ID: " . $analysis['envelope_id'] . "\n";
echo "Encrypted: " . ($analysis['is_encrypted'] ? 'Yes' : 'No') . "\n";
echo "Patient: " . $analysis['sender']['name'] . "\n";

if ($analysis['is_encrypted']) {
    echo "Encryption: " . $analysis['encryption']['algorithm'] . "\n";
}

// 2. Decrypt encrypted envelope
if ($analysis['is_encrypted']) {
    $envelope = $decryptor->decryptEnvelope(
        '/path/to/encrypted.JMIX',
        $privateKey,           // Your private key
        '/path/to/output'
    );
    
    echo "🔓 Decrypted envelope contents:\n";
    echo "Patient: " . $envelope['metadata']['patient']['name']['text'] . "\n";
    echo "DICOM files: " . $envelope['payload_path'] . '/dicom/' . "\n";
}

// 3. Extract unencrypted envelope
else {
    $envelope = $decryptor->extractEnvelope(
        '/path/to/unencrypted.JMIX',
        '/path/to/output'
    );
    
    echo "Extracted envelope contents:\n";
    echo "Patient: " . $envelope['metadata']['patient']['name']['text'] . "\n";
    echo "DICOM files: " . $envelope['payload_path'] . '/dicom/' . "\n";
}
```

### CLI Tools

The library includes command-line tools for building and processing envelopes:

#### Building Envelopes

```bash
# Create unencrypted envelope
jmix-build /path/to/dicom config.json /path/to/output

# Create encrypted envelope (add encryption config to config.json)
jmix-build /path/to/dicom encrypted-config.json /path/to/output
```

#### Analyzing Envelopes

```bash
# Analyze any envelope (shows encryption status, metadata, etc.)
jmix-decrypt analyze /path/to/envelope.JMIX
```

Output:
```
Envelope Analysis
ID: a1b2c3d4-5678-90ab-cdef-123456789abc
Timestamp: 2025-09-27T06:32:05Z
Encrypted: 🔒 Yes
Has Payload Hash: ✓ Yes

Sender:
  Name: Test Healthcare Organization
  ID: org:test.health.123

Encryption Details:
  Algorithm: AES-256-GCM
  Ephemeral Public Key: Y12JovXD3Hjc/mMk...
```

#### Extracting Unencrypted Envelopes

```bash
# Extract unencrypted envelope
jmix-decrypt extract /path/to/envelope.JMIX /path/to/output
```

#### Decrypting Encrypted Envelopes

```bash
# Decrypt encrypted envelope
jmix-decrypt decrypt /path/to/encrypted.JMIX /path/to/output <private-key-base64>
```

Output:
```
✓ Envelope decrypted successfully!

🔓 Decrypted Envelope Contents:
  ID: a1b2c3d4-5678-90ab-cdef-123456789abc
  Patient: Jane Doe
  Study: CT Pulmonary Angiogram
  Payload Path: /path/to/output/payload

📁 Extracted Files:
  - DICOM files in: /path/to/output/payload/dicom/
  - Attachment files in: /path/to/output/payload/files/
```

### Security Features

- **AES-256-GCM Encryption**: Authenticated encryption providing both confidentiality and integrity
- **ECDH Key Exchange**: Uses Curve25519 elliptic curve for secure key agreement
- **Forward Secrecy**: Ephemeral keypairs generated per envelope
- **HKDF Key Derivation**: HKDF-SHA256 for secure key generation from shared secret
- **Payload Hash Verification**: SHA-256 hashing ensures data integrity during decryption
- **Memory Safety**: Sensitive data is securely cleared from memory after use

## Configuration

### Required Configuration

```php
$config = [
    'sender' => [
        'name' => 'Clinic Name',
        'id' => 'org:identifier',
        'contact' => 'email@clinic.com',
    ],
    'requester' => [
        'name' => 'Doctor Name', 
        'id' => 'org:doctor.id',
        'contact' => 'doctor@clinic.com',
    ],
    'receivers' => [
        [
            'name' => 'Receiving Clinic',
            'id' => 'org:receiver.id', 
            'contact' => 'receiver@clinic.com',
        ],
    ],
    'patient' => [
        'name' => 'Patient Name',
        'dob' => '1975-02-14',
        'sex' => 'F',
        'ihi' => '8003608166690503', // Australian Individual Healthcare Identifier
    ],
];
```

### Optional Configuration

```php
$config = [
    // ... required fields above
    
    'version' => '1.0',
    
    'custom_tags' => ['teaching', 'priority-review'],
    
    'security' => [
        'classification' => 'confidential', // or 'restricted', 'public'
    ],
    
    // Encryption (optional)
    'encryption' => [
        'recipient_public_key' => '<base64-encoded-public-key>', // Recipient's Curve25519 public key
    ],
    
    'report' => [
        'file' => 'files/report.pdf',
        'url' => 'https://example.com/report',
    ],
    
    'files' => [
        'file' => 'files/images.zip',
        'url' => 'https://example.com/images',
    ],
    
    'consent' => [
        'status' => 'granted',
        'scope' => ['treatment', 'research'],
        'method' => 'digital-signature',
    ],
    
    'deid_keys' => ['PatientName', 'PatientID', 'IssuerOfPatientID'],
    
    // Cryptographic assertions (for production use)
    'sender' => [
        // ... other fields
        'assertion' => [
            'alg' => 'Ed25519',
            'public_key' => '<base64_encoded_public_key>',
            'fingerprint' => 'SHA256:<hex_fingerprint>',
            'key_reference' => 'aurabox://org/clinic#key-ed25519',
            'signature' => '<base64_signature>',
            'expires_at' => '2025-12-31T23:59:59Z',
        ],
    ],
];
```

## DICOM Processing

The library automatically:

1. **Scans DICOM folders** recursively for `.dcm` files
2. **Detects DICOM files** by checking for the `DICM` magic number at offset 128
3. **Extracts metadata** including:
   - Patient information (name, ID, DOB, sex)
   - Study details (description, UID, modalities)
   - Series information (UIDs, body parts, instance counts)
4. **Merges data** from multiple DICOM files intelligently
5. **Validates output** against JSON schemas

### DICOM Parsing

In order to extract file information to build the files list, DCMTK is required.

Without this, the library will not extract DICOM data.

```bash
# Install DCMTK on macOS
brew install dcmtk

# Install DCMTK on Ubuntu
apt-get install dcmtk
```

The library will automatically use `dcmdump` if available.

## Output Structure

After processing, you'll have a JMIX envelope directory. The structure depends on whether encryption was used:

### Unencrypted Envelope

```
<envelope-id>.JMIX/
├── manifest.json              # Security & routing metadata (includes payload_hash)
├── audit.json                 # Audit trail
└── payload/
    ├── metadata.json          # Medical data & patient info
    ├── dicom/                 # DICOM files (copied from source)
    │   ├── series_1/
    │   │   ├── CT.1.1.dcm
    │   │   └── ...
    │   └── series_2/
    │       └── ...
    ├── files/                 # Optional: report files and attachments
    │   └── report.pdf
    └── files.json             # File manifest (when files/ present)
```

### Encrypted Envelope

```
<envelope-id>.JMIX/
├── manifest.json              # Security & routing metadata + encryption parameters
├── audit.json                 # Audit trail  
└── payload.encrypted          # AES-256-GCM encrypted TAR archive of payload/
```

The `manifest.json` in encrypted envelopes includes encryption details:

```json
{
  "security": {
    "payload_hash": "sha256:abc123...",
    "encryption": {
      "algorithm": "AES-256-GCM",
      "ephemeral_public_key": "Y12JovXD3Hjc...",
      "iv": "uTv8nI6Wi/a/O7wc",
      "auth_tag": "5c8VZzxSuWM3RMqA..."
    }
  }
}
```

Each file is validated against its respective JSON schema before being saved.

## Error Handling

The library provides specific exception types:

```php
use AuraBox\Jmix\Exceptions\{JmixException, ValidationException, CryptographyException};

try {
    $envelope = $jmixBuilder->buildFromDicom($dicomPath, $config);
} catch (ValidationException $e) {
    echo "Validation failed: " . $e->getMessage() . "\n";
    foreach ($e->getErrors() as $error) {
        echo "  - $error\n"; 
    }
} catch (JmixException $e) {
    echo "JMIX error: " . $e->getMessage() . "\n";
}
```

## Development

### Requirements
- PHP 8.1+
- ext-json
- ext-openssl
- ext-sodium (for encryption/decryption)
- Composer
- Optional: DCMTK's `dcmdump` for enhanced DICOM metadata extraction

### Setup
```bash
git clone https://github.com/aurabx/jmix-php
cd jmix-php/php-library
composer install
```

### Testing
```bash
# Run all tests
composer test

# Run specific test files
vendor/bin/phpunit tests/JmixBuilderTest.php
vendor/bin/phpunit tests/JmixDecryptorTest.php
vendor/bin/phpunit tests/Encryption/PayloadEncryptorTest.php

# Run tests with coverage (requires Xdebug)
XDEBUG_MODE=coverage vendor/bin/phpunit

# Test CLI tools
bin/jmix-build ./samples/study_1 ./examples/sample-config.json ./tmp/test-output
bin/jmix-decrypt analyze ./tmp/test-output/*.JMIX
```

### Code Quality
```bash
composer cs-check   # Check coding standards
composer cs-fix     # Fix coding standards
composer phpstan    # Static analysis
composer psalm      # Additional static analysis
```

## Security Considerations

### ✅ Production-Ready Security Features

This library includes **enterprise-grade encryption** that is production-ready:

- **AES-256-GCM encryption** with authenticated encryption
- **ECDH key exchange** using Curve25519 elliptic curve
- **HKDF key derivation** with SHA-256
- **Forward secrecy** through ephemeral keypairs
- **Payload integrity verification** with SHA-256 hashing
- **Memory safety** with secure key clearing

### ⚠️ Additional Production Considerations

For **production use**, you should also consider:

1. **Key Management**:
   - Use hardware security modules (HSMs) for key storage
   - Implement proper key rotation and expiration handling
   - Secure key distribution mechanisms

2. **Digital Signatures** (currently placeholders):
   - Integrate with `web-token/jwt-framework` for JWT/JWS signatures
   - Use `paragonie/constant_time_encoding` for secure encoding

3. **Certificate Authority Integration**:
   - Integrate with a certificate authority for directory attestations
   - Implement certificate validation and revocation checking

4. **Compliance**:
   - Ensure compliance with healthcare data regulations (HIPAA, GDPR, etc.)
   - Implement audit logging for all cryptographic operations
   - Regular security assessments and penetration testing

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [Full API Documentation](docs/)
- **Issues**: [GitHub Issues](https://github.com/aurabx/jmix-php/issues)
- **Email**: dev@aurabx.com

## Changelog

### v2.0.0
- **🔒 Full AES-256-GCM encryption** with ECDH key exchange (Curve25519)
- **🔓 Decryption and envelope extraction** capabilities
- **📋 CLI tools** for analyzing, extracting, and decrypting envelopes
- **🔐 Payload hash verification** for data integrity
- **📁 JMIX envelope directory structure** compliance
- **🧪 Forward secrecy** with ephemeral keypairs
- **🛡️ Memory safety** with secure key clearing
- **Breaking changes**: Updated envelope structure and API

### v1.0.0
- Initial release
- DICOM folder processing
- JMIX envelope generation
- JSON schema validation
- Basic cryptographic placeholders
