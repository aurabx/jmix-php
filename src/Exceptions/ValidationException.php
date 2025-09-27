<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Exceptions;

/**
 * Exception thrown when JSON schema validation fails
 */
class ValidationException extends JmixException
{
    private array $errors;

    public function __construct(string $message, array $errors = [])
    {
        parent::__construct($message);
        $this->errors = $errors;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }
}
