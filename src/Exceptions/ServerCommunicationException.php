<?php

namespace Rasel\CodeLock\Exceptions;

use Rasel\CodeLock\Enums\LicenseStatus;

class ServerCommunicationException extends CodeLockException
{
    public function __construct(string $message = 'Failed to communicate with license server.', array $context = [], ?\Throwable $previous = null)
    {
        parent::__construct(
            $message,
            LicenseStatus::INVALID,
            'License server unreachable.',
            $context,
            0,
            $previous
        );
    }
}

