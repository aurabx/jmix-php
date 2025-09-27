# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Repository: aurabx/jmix/jmix-php (PHP 8.1+)

What this library does
- Builds a JMIX (JSON Medical Interchange) envelope from a folder of DICOM files and a configuration array.
- Produces three validated JSON components: manifest.json (security/routing), metadata.json (clinical data), transmission.json (audit trail).

Prerequisites
- PHP 8.1+, ext-json, ext-openssl
- Composer
- Optional: DCMTK’s dcmdump available on PATH for richer DICOM extraction

Common commands
- Install dependencies
  - composer install
- Run all tests (PHPUnit 10)
  - composer test
  - or: vendor/bin/phpunit
- Run a single test file or method
  - Single file: vendor/bin/phpunit tests/JmixBuilderTest.php
  - Filter by test: vendor/bin/phpunit --filter 'JmixBuilderTest::testSaveToFiles'
- Generate coverage (requires Xdebug)
  - XDEBUG_MODE=coverage vendor/bin/phpunit
  - HTML report outputs to coverage/ per phpunit.xml
- Lint and formatting
  - Check: composer cs-check (phpcs)
  - Fix: composer cs-fix (phpcbf)
- Static analysis
  - composer phpstan
  - composer psalm
- CLI to build an envelope
  - bin/jmix-build <dicom-path> <config-json> <output-path>
  - Example: bin/jmix-build ./samples/study_1 ./examples/sample-config.json ./output

High-level architecture
- Namespaces and autoloading
  - PSR-4 root: AuraBox\Jmix\ → src/ (composer.json)
  - Tests: AuraBox\Jmix\Tests\ → tests/
- Primary orchestrator: src/JmixBuilder.php
  - Orchestrates the full build pipeline via buildFromDicom($dicomPath, $config): array
    - Generates transmission ID (ramsey/uuid) and timestamp
    - Extracts DICOM metadata via DicomProcessor
    - Builds components: manifest, metadata, transmission
    - Validates each component via SchemaValidator
    - Returns ['manifest' => ..., 'metadata' => ..., 'transmission' => ...]
  - saveToFiles($envelope, $outputPath): writes the three JSON files with pretty-printing
- DICOM processing: src/Dicom/DicomProcessor.php
  - Recursively scans a directory and detects DICOM files using the DICM magic number at byte offset 128
  - Produces merged metadata: patient details, study description/UID, modalities, series, instance_count
  - Contains a fallback hook to use dcmdump if available (extractWithDcmdump); otherwise returns placeholder metadata suitable for tests/dev
- JSON Schema validation: src/Validation/SchemaValidator.php
  - Uses justinrainbow/json-schema to validate each component
  - Looks for schema files by filename (e.g., manifest.schema.json, metadata.schema.json, transmission.schema.json)
  - Note: Ensure the schemas/ directory is present and accessible by the validator; adjust the constructor’s schema base path if schemas live elsewhere
- Exceptions: src/Exceptions/*
  - JmixException: base type
  - ValidationException: includes getErrors() for structured schema errors
  - CryptographyException: reserved for future crypto failures
- Command-line entrypoint: bin/jmix-build
  - Thin wrapper around JmixBuilder; loads a JSON config and prints a brief summary

Test Data
- Sample DICOM files: samples/
  - Contains study_1/ with 3 series of CT scans (5 files each, 15 total)
  - Structured as study_1/series_1/, study_1/series_2/, study_1/series_3/
  - Each series contains CT.{series}.{instance}.dcm files (e.g., CT.1.1.dcm through CT.1.5.dcm)
  - Used for testing and development without needing to generate dummy DICOM files

Tests
- Location: tests/JmixBuilderTest.php
- Strategy: can use either constructed dummy DICOM files with valid DICM headers or the sample data in samples/
- Sample data provides realistic multi-series DICOM structure for comprehensive testing

Notes pulled from README.md (key items only)
- Quick start uses AuraBox\Jmix\JmixBuilder to build from a DICOM folder, then save to files
- Optional DICOM extraction strategies: built-in placeholder parsing, DCMTK (dcmdump), or a third-party PHP DICOM library
- Development commands match the composer scripts listed above

Operational tips for Warp
- Prefer composer scripts where available (test, cs-check, cs-fix, phpstan, psalm)
- For focused debugging, run a single PHPUnit test or limit to a specific file
- Use samples/study_1 for testing with realistic DICOM structure (3 series, 15 files total)
- If schema validation fails, verify the schemas/ path used by SchemaValidator and that the schema files exist and are valid JSON

Schemas
- Canonical source: https://github.com/aurabx/jmix (see /schemas)
- Where the validator looks by default: src/Validation/SchemaValidator.php uses '../jmix/schemas' relative to the package root — i.e., it expects the jmix monorepo to be at ../jmix/ relative to this package.
- This works automatically in the monorepo structure where both jmix-php and jmix directories are siblings.
- For custom deployments, you can pass a custom schema path to the JmixBuilder constructor or CLI tool.
- Schema path can be overridden via CLI: bin/jmix-build <dicom> <config> <output> [schema-path]
