<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseRevokedException extends CodeLockException
{
    public function __construct(string $message = 'This license agreement has been permanently revoked.', ?string $lockMessage = null, array $context = [])
    {
        parent::__construct(
            $message,
            LicenseStatus::REVOKED,
            $lockMessage ?? 'This software license has been revoked by the vendor.',
            $context
        );
    }
}

