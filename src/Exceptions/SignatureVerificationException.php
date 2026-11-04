<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class SignatureVerificationException extends CodeLockException
{
    public function __construct(string $message = 'Ed25519 cryptographic signature verification failed.', array $context = [])
    {
        parent::__construct(
            $message,
            LicenseStatus::INVALID,
            'Cryptographic signature is invalid or license certificate has been modified.',
            $context
        );
    }
}

