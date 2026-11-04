<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseNotFoundException extends CodeLockException
{
    public function __construct(string $message = 'No license file or key found.', array $context = [])
    {
        parent::__construct($message, LicenseStatus::UNLICENSED, 'Installation is not licensed.', $context);
    }
}

