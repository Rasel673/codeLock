<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseLockedException extends CodeLockException
{
    public function __construct(string $message = 'The installation has been locked remotely.', ?string $lockMessage = null, array $context = [])
    {
        parent::__construct(
            $message,
            LicenseStatus::LOCKED,
            $lockMessage ?? 'This software installation has been locked by the vendor.',
            $context
        );
    }
}

