# JMIX PHP Library

A PHP library for creating JMIX (JSON Medical Interchange) envelopes from DICOM files. JMIX is a secure data format for exchanging medical/healthcare information with strong cryptographic features.

## Features

- Convert DICOM folders to complete JMIX envelopes
- Automatic metadata extraction from DICOM files
- JSON Schema validation for all components
- Simple, array-based configuration
- Cryptographic assertion support (placeholders for real implementations)
- Built-in audit trail generation

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

// Save to files
$jmixBuilder->saveToFiles($envelope, '/path/to/output');
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

### 3. Transmission (`transmission.json`)
Contains audit trail:
- Event logging with timestamps
- Chain of custody tracking
- Cryptographic signatures for events

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

### DICOM Integration Options

The library provides multiple ways to extract DICOM metadata:

#### Built-in Parser (Default)
Uses PHP's file reading capabilities with placeholder data. Suitable for testing and development.

#### DCMTK Integration (Optional)
If you have [DCMTK](https://dicom.offis.de/dcmtk.php.en) installed:

```bash
# Install DCMTK on macOS
brew install dcmtk

# Install DCMTK on Ubuntu
apt-get install dcmtk
```

The library will automatically use `dcmdump` if available.

## Output Structure

After processing, you'll have three JSON files:

```
output/
├── manifest.json     # Security & routing metadata
├── metadata.json     # Medical data & patient info  
└── transmission.json # Audit trail
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
- Composer

### Setup
```bash
git clone https://github.com/aurabx/jmix-php
cd jmix-php/php-library
composer install
```

### Testing
```bash
composer test
```

### Code Quality
```bash
composer cs-check   # Check coding standards
composer cs-fix     # Fix coding standards
composer phpstan    # Static analysis
composer psalm      # Additional static analysis
```

## Security Considerations

This library currently uses **placeholder cryptographic values** for:
- Digital signatures  
- Public keys
- Encryption parameters
- Directory attestations

For **production use**, you must:

1. **Implement real cryptographic operations** using libraries like:
   - `paragonie/halite` for encryption
   - `web-token/jwt-framework` for JWT/JWS signatures
   - `paragonie/constant_time_encoding` for secure encoding

2. **Integrate with a certificate authority** for directory attestations

3. **Use hardware security modules (HSMs)** for key management

4. **Implement proper key rotation** and expiration handling

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

### v1.0.0
- Initial release
- DICOM folder processing
- JMIX envelope generation
- JSON schema validation
- Basic cryptographic placeholders