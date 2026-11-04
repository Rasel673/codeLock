<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class TamperDetectedException extends CodeLockException
{
    public function __construct(string $message = 'License tampering or clock rollback detected.', ?string $reason = null, array $context = [])
    {
        parent::__construct(
            $message,
            LicenseStatus::INVALID,
            $reason ?? 'Tampering detected.',
            $context
        );
    }
}

