<?php

namespace Rasel\CodeLock;

use ArrayAccess;
use JsonSerializable;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;

/**
 * Immutable representation of a cryptographically signed remote status document from the license server.
 */
class RemoteLicenseStatus implements ArrayAccess, JsonSerializable
{
    protected array $header;
    protected array $payload;
    protected string $signature;

    public function __construct(array $header, array $payload, string $signature)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->signature = $signature;
    }

    /**
     * Reconstruct an instance from an untrusted associative array envelope.
     *
     * @param array $data
     * @return static
     * @throws LicenseInvalidException
     */
    public static function fromArray(array $data): static
    {
        if (!isset($data['payload'], $data['signature']) || !is_array($data['payload']) || !is_string($data['signature'])) {
            throw new LicenseInvalidException('Invalid remote license status envelope: missing payload or signature.');
        }

        $header = isset($data['header']) && is_array($data['header'])
            ? $data['header']
            : ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'];

        return new static($header, $data['payload'], $data['signature']);
    }

    /**
     * Convert to standard envelope array.
     */
    public function toArray(): array
    {
        return [
            'header' => $this->header,
            'payload' => $this->payload,
            'signature' => $this->signature,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    public function getHeader(): array
    {
        return $this->header;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getStatus(): LicenseStatus
    {
        $statusStr = strtoupper((string) ($this->payload['sta'] ?? 'ACTIVE'));
        return LicenseStatus::tryFrom($statusStr) ?? LicenseStatus::INVALID;
    }

    public function getLicenseKey(): ?string
    {
        return $this->payload['lic'] ?? null;
    }

    public function getDeadline(): ?int
    {
        return isset($this->payload['deadline']) ? (int) $this->payload['deadline'] : null;
    }

    public function getTimestamp(): int
    {
        return (int) ($this->payload['timestamp'] ?? 0);
    }

    public function getNonce(): ?string
    {
        return $this->payload['nonce'] ?? null;
    }

    public function getLockMessage(): ?string
    {
        return $this->payload['lock_message'] ?? null;
    }

    public function getReasonCode(): ?string
    {
        return $this->payload['reason_code'] ?? null;
    }

    public function isActive(): bool
    {
        return $this->getStatus() === LicenseStatus::ACTIVE;
    }

    public function isLocked(): bool
    {
        return $this->getStatus() === LicenseStatus::LOCKED;
    }

    public function isSuspended(): bool
    {
        return $this->getStatus() === LicenseStatus::SUSPENDED;
    }

    public function isExpired(): bool
    {
        return $this->getStatus() === LicenseStatus::EXPIRED;
    }

    public function isRevoked(): bool
    {
        return $this->getStatus() === LicenseStatus::REVOKED;
    }

    public function getActionUrl(): ?string
    {
        return $this->payload['action_url'] ?? null;
    }

    /**
     * Determine if the remote grace period deadline has elapsed.
     */
    public function isGraceExpired(?int $now = null): bool
    {
        $now = $now ?? time();
        $deadline = $this->getDeadline();

        if ($deadline === null || $deadline <= 0) {
            return false;
        }

        return $now > $deadline;
    }

    /**
     * Calculate remaining grace duration in seconds.
     */
    public function getRemainingGraceSeconds(?int $now = null): int
    {
        $now = $now ?? time();
        $deadline = $this->getDeadline();

        if ($deadline === null || $deadline <= 0) {
            return 0;
        }

        return max(0, $deadline - $now);
    }

    /**
     * Check if this response carries a renewed license certificate.
     */
    public function hasRenewedCertificate(): bool
    {
        return !empty($this->payload['renew_license'])
            && !empty($this->payload['certificate'])
            && is_array($this->payload['certificate']);
    }

    /**
     * Retrieve the renewed certificate data if present.
     */
    public function getRenewedCertificate(): ?array
    {
        return $this->hasRenewedCertificate() ? $this->payload['certificate'] : null;
    }

    /**
     * Verify the Ed25519 signature of the payload against the provided public key(s).
     *
     * @param string|array<string, string> $publicKey Base64 public key or key rotation map [kid => key]
     * @return bool
     */
    public function verifySignature(string|array $publicKey): bool
    {
        $resolvedKey = null;

        if (is_array($publicKey)) {
            $kid = $this->header['kid'] ?? null;
            if ($kid !== null && isset($publicKey[$kid])) {
                $resolvedKey = $publicKey[$kid];
            } elseif ($kid === null && !empty($publicKey)) {
                $resolvedKey = reset($publicKey);
            }
        } elseif (is_string($publicKey) && !empty($publicKey)) {
            $resolvedKey = $publicKey;
        }

        if (empty($resolvedKey)) {
            return false;
        }

        $canonicalPayload = CanonicalJson::encode($this->payload);
        return Ed25519Verifier::verify($this->signature, $canonicalPayload, $resolvedKey);
    }

    // --- ArrayAccess Implementation for backwards compatibility ---

    public function offsetExists(mixed $offset): bool
    {
        return in_array($offset, ['header', 'payload', 'signature'], true)
            || array_key_exists($offset, $this->payload);
    }

    public function offsetGet(mixed $offset): mixed
    {
        if ($offset === 'header') {
            return $this->header;
        }
        if ($offset === 'payload') {
            return $this->payload;
        }
        if ($offset === 'signature') {
            return $this->signature;
        }

        return $this->payload[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new \BadMethodCallException('RemoteLicenseStatus is immutable.');
    }

    public function offsetUnset(mixed $offset): void
    {
        throw new \BadMethodCallException('RemoteLicenseStatus is immutable.');
    }
}

