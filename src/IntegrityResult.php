<?php

namespace Rasel\CodeLock;

use Illuminate\Contracts\Support\Arrayable;

class IntegrityResult implements Arrayable
{
    protected bool $valid;
    protected array $modifiedFiles;
    protected array $missingFiles;
    protected ?string $errorCode;
    protected ?string $reason;
    protected int $checkedCount;
    protected int $timestamp;
    protected bool $cached;

    public function __construct(
        bool $valid,
        array $modifiedFiles = [],
        array $missingFiles = [],
        ?string $errorCode = null,
        ?string $reason = null,
        int $checkedCount = 0,
        ?int $timestamp = null,
        bool $cached = false
    ) {
        $this->valid = $valid;
        $this->modifiedFiles = $modifiedFiles;
        $this->missingFiles = $missingFiles;
        $this->errorCode = $errorCode;
        $this->reason = $reason;
        $this->checkedCount = $checkedCount;
        $this->timestamp = $timestamp ?? time();
        $this->cached = $cached;
    }

    /**
     * Create a successful integrity verification result.
     */
    public static function success(int $checkedCount = 0, bool $cached = false): self
    {
        return new self(
            valid: true,
            modifiedFiles: [],
            missingFiles: [],
            errorCode: null,
            reason: null,
            checkedCount: $checkedCount,
            cached: $cached
        );
    }

    /**
     * Create a failed integrity verification result.
     */
    public static function failure(
        string $errorCode,
        string $reason,
        array $modifiedFiles = [],
        array $missingFiles = [],
        int $checkedCount = 0
    ): self {
        return new self(
            valid: false,
            modifiedFiles: $modifiedFiles,
            missingFiles: $missingFiles,
            errorCode: $errorCode,
            reason: $reason,
            checkedCount: $checkedCount,
            cached: false
        );
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function hasModifiedFiles(): bool
    {
        return !empty($this->modifiedFiles);
    }

    public function hasMissingFiles(): bool
    {
        return !empty($this->missingFiles);
    }

    public function getModifiedFiles(): array
    {
        return $this->modifiedFiles;
    }

    public function getMissingFiles(): array
    {
        return $this->missingFiles;
    }

    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }

    public function getCheckedCount(): int
    {
        return $this->checkedCount;
    }

    public function getTimestamp(): int
    {
        return $this->timestamp;
    }

    public function isCached(): bool
    {
        return $this->cached;
    }

    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'checked_count' => $this->checkedCount,
            'modified_files' => $this->modifiedFiles,
            'missing_files' => $this->missingFiles,
            'error_code' => $this->errorCode,
            'reason' => $this->reason,
            'timestamp' => $this->timestamp,
            'cached' => $this->cached,
        ];
    }
}

