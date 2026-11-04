<?php

namespace Rasel\CodeLock;

use ArrayAccess;
use JsonSerializable;

/**
 * Structured outcome of a license heartbeat execution.
 */
class HeartbeatResult implements ArrayAccess, JsonSerializable
{
    public function __construct(
        protected bool $success,
        protected ?RemoteLicenseStatus $status = null,
        protected bool $offline = false,
        protected bool $graceActive = false,
        protected bool $graceExpired = false,
        protected int $remainingGraceSeconds = 0,
        protected string $message = '',
        protected ?string $errorCode = null,
        protected array $raw = []
    ) {}

    public static function success(RemoteLicenseStatus $status, string $message = 'Heartbeat synchronized successfully.'): static
    {
        return new static(
            success: true,
            status: $status,
            offline: false,
            graceActive: false,
            graceExpired: false,
            remainingGraceSeconds: $status->getRemainingGraceSeconds(),
            message: $message,
            raw: $status->toArray()
        );
    }

    public static function grace(int $remainingSeconds, string $message = 'Operating in offline grace period.', ?RemoteLicenseStatus $cachedStatus = null): static
    {
        return new static(
            success: false,
            status: $cachedStatus,
            offline: true,
            graceActive: true,
            graceExpired: false,
            remainingGraceSeconds: $remainingSeconds,
            message: $message,
            errorCode: 'E_GRACE_ACTIVE'
        );
    }

    public static function graceExpired(string $message = 'Offline grace period has elapsed. Server connection required.'): static
    {
        return new static(
            success: false,
            status: null,
            offline: true,
            graceActive: false,
            graceExpired: true,
            remainingGraceSeconds: 0,
            message: $message,
            errorCode: 'E_GRACE_EXCEEDED'
        );
    }

    public static function failure(string $message, ?string $errorCode = null, array $raw = []): static
    {
        return new static(
            success: false,
            status: null,
            offline: false,
            graceActive: false,
            graceExpired: false,
            remainingGraceSeconds: 0,
            message: $message,
            errorCode: $errorCode,
            raw: $raw
        );
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function isOffline(): bool
    {
        return $this->offline;
    }

    public function isGraceActive(): bool
    {
        return $this->graceActive;
    }

    public function isGraceExpired(): bool
    {
        return $this->graceExpired;
    }

    public function getRemainingGraceSeconds(): int
    {
        return $this->remainingGraceSeconds;
    }

    public function getStatus(): ?RemoteLicenseStatus
    {
        return $this->status;
    }

    public function getMessage(): string
    {
        return $this->message;
    }

    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }

    public function toArray(): array
    {
        return [
            'success' => $this->success,
            'offline' => $this->offline,
            'grace_active' => $this->graceActive,
            'grace_expired' => $this->graceExpired,
            'remaining_grace_seconds' => $this->remainingGraceSeconds,
            'status' => $this->status?->toArray(),
            'message' => $this->message,
            'error_code' => $this->errorCode,
            'raw' => $this->raw,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    // ArrayAccess for backwards compatibility with code expecting array
    public function offsetExists(mixed $offset): bool
    {
        return array_key_exists($offset, $this->toArray())
            || ($this->status !== null && isset($this->status[$offset]));
    }

    public function offsetGet(mixed $offset): mixed
    {
        $arr = $this->toArray();
        if (array_key_exists($offset, $arr)) {
            return $arr[$offset];
        }
        if ($this->status !== null && isset($this->status[$offset])) {
            return $this->status[$offset];
        }
        return null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new \BadMethodCallException('HeartbeatResult is immutable.');
    }

    public function offsetUnset(mixed $offset): void
    {
        throw new \BadMethodCallException('HeartbeatResult is immutable.');
    }
}

