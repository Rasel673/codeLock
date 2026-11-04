<?php

namespace Rasel\CodeLock\Exceptions;

use Exception;
use Rasel\CodeLock\Enums\LicenseStatus;

class CodeLockException extends Exception
{
    protected LicenseStatus $status = LicenseStatus::INVALID;
    protected ?string $lockReason = null;
    protected array $context = [];

    public function __construct(
        string $message = '',
        LicenseStatus $status = LicenseStatus::INVALID,
        ?string $lockReason = null,
        array $context = [],
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->status = $status;
        $this->lockReason = $lockReason;
        $this->context = $context;
    }

    public function getStatus(): LicenseStatus
    {
        return $this->status;
    }

    public function getLockReason(): ?string
    {
        return $this->lockReason;
    }

    public function getContext(): array
    {
        return $this->context;
    }
}

