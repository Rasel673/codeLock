<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class DomainMismatchException extends CodeLockException
{
    public function __construct(string $message = 'The current domain is not authorized for this license.', array $context = [])
    {
        parent::__construct(
            $message,
            LicenseStatus::INVALID,
            'Unauthorized domain usage detected.',
            $context
        );
    }
}

