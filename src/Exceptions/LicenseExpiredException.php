<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseExpiredException extends CodeLockException
{
    public function __construct(string $message = 'The commercial license subscription has expired.', array $context = [])
    {
        parent::__construct($message, LicenseStatus::EXPIRED, 'Subscription expired.', $context);
    }
}

