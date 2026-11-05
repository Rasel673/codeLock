<?php

namespace Rasel\CodeLock;

use ArrayAccess;
use Illuminate\Contracts\Support\Arrayable;
use Rasel\CodeLock\Enums\LicenseStatus;

class LicenseVerificationResult implements ArrayAccess, Arrayable
{
    protected bool $valid;
    protected LicenseStatus $status;
    protected ?string $reason;
    protected ?string $errorCode;
    protected ?LicenseDocument $document;
    protected array $context;

    public function __construct(
        bool $valid,
        LicenseStatus $status,
        ?string $reason = null,
        ?string $errorCode = null,
        ?LicenseDocument $document = null,
        array $context = []
    ) {
        $this->valid = $valid;
        $this->status = $status;
        $this->reason = $reason;
        $this->errorCode = $errorCode;
        $this->document = $document;
        $this->context = $context;
    }

    /**
     * Create a successful verification result.
     */
    public static function success(LicenseDocument $document, array $context = []): self
    {
        return new self(
            valid: true,
            status: LicenseStatus::ACTIVE,
            reason: null,
            errorCode: null,
            document: $document,
            context: $context
        );
    }

    /**
     * Create a failed verification result.
     */
    public static function failure(
        LicenseStatus $status,
        string $reason,
        string $errorCode,
        ?LicenseDocument $document = null,
        array $context = []
    ): self {
        return new self(
            valid: false,
            status: $status,
            reason: $reason,
            errorCode: $errorCode,
            document: $document,
            context: $context
        );
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function getStatus(): LicenseStatus
    {
        return $this->status;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }

    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }

    public function getDocument(): ?LicenseDocument
    {
        return $this->document;
    }

    public function getPayload(): ?array
    {
        return $this->document?->getPayload();
    }

    public function getContext(): array
    {
        return $this->context;
    }

    public function getDomain(): ?string
    {
        return $this->context['domain'] ?? null;
    }

    /**
     * Check if a specific signed feature entitlement is granted.
     */
    public function can(string $ability): bool
    {
        if (!$this->isValid() || $this->document === null) {
            return false;
        }

        return $this->document->hasFeature($ability);
    }

    /**
     * Alias for can()
     */
    public function hasFeature(string $feature): bool
    {
        return $this->can($feature);
    }

    /**
     * Query a numeric quota or entitlement limit.
     */
    public function quota(string $key, mixed $default = null): mixed
    {
        if (!$this->isValid() || $this->document === null) {
            return $default;
        }

        return $this->document->getQuota($key, $default);
    }

    /**
     * Get the subscription tier string.
     */
    public function tier(): ?string
    {
        return $this->document?->getTier();
    }

    /**
     * Export to array representation.
     */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'status' => $this->status,
            'reason' => $this->reason,
            'error_code' => $this->errorCode,
            'payload' => $this->getPayload(),
            'domain' => $this->context['domain'] ?? null,
            'document' => $this->document?->toArray(),
        ];
    }

    // ArrayAccess Implementation for backwards compatibility

    public function offsetExists(mixed $offset): bool
    {
        return array_key_exists($offset, $this->toArray());
    }

    public function offsetGet(mixed $offset): mixed
    {
        $arr = $this->toArray();
        return $arr[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        if ($offset === 'domain') {
            $this->context['domain'] = $value;
        }
    }

    public function offsetUnset(mixed $offset): void
    {
        // Immutable
    }
}

