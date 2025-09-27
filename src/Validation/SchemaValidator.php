<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Validation;

use AuraBox\Jmix\Exceptions\ValidationException;
use JsonSchema\Validator;
use JsonSchema\Constraints\Constraint;

/**
 * Validates JMIX components against their JSON schemas
 */
class SchemaValidator
{
    private string $schemaPath;

    public function __construct(?string $schemaPath = null)
    {
        $this->schemaPath = $schemaPath ?? dirname(__DIR__, 2) . '/../jmix/schemas';
    }

    /**
     * Validate manifest against its schema
     */
    public function validateManifest(array $data): void
    {
        $this->validate($data, 'manifest.schema.json');
    }

    /**
     * Validate metadata against its schema
     */
    public function validateMetadata(array $data): void
    {
        $this->validate($data, 'metadata.schema.json');
    }

    /**
     * Validate audit against its schema
     */
    public function validateAudit(array $data): void
    {
        $this->validate($data, 'audit.schema.json');
    }

    /**
     * Validate files manifest against its schema
     */
    public function validateFiles(array $data): void
    {
        $this->validate($data, 'files.schema.json');
    }

    /**
     * Generic validation method
     */
    private function validate(array $data, string $schemaFile): void
    {
        $schemaPath = $this->schemaPath . '/' . $schemaFile;

        if (!file_exists($schemaPath)) {
            throw new ValidationException("Schema file not found: {$schemaPath}");
        }

        $schema = json_decode(file_get_contents($schemaPath));
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ValidationException("Invalid schema JSON in: {$schemaPath}");
        }

        $validator = new Validator();
        $dataObj = json_decode(json_encode($data)); // Convert array to object

        $validator->validate($dataObj, $schema, Constraint::CHECK_MODE_COERCE_TYPES);

        if (!$validator->isValid()) {
            $errors = [];
            foreach ($validator->getErrors() as $error) {
                $errors[] = sprintf('[%s] %s', $error['property'], $error['message']);
            }

            throw new ValidationException(
                'Schema validation failed for ' . $schemaFile,
                $errors
            );
        }
    }
}
