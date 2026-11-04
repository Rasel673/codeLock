<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseSuspendedException extends CodeLockException
{
    public function __construct(string $message = 'The license has been suspended by the administrator.', ?string $reason = null, array $context = [])
    {
        parent::__construct($message, LicenseStatus::SUSPENDED, $reason ?? 'License suspended.', $context);
    }
}

