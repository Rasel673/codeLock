<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseInvalidException extends CodeLockException
{
    public function __construct(string $message = 'The license certificate is invalid or corrupted.', array $context = [])
    {
        parent::__construct($message, LicenseStatus::INVALID, 'License certificate validation failed.', $context);
    }
}

