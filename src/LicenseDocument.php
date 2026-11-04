<?php

namespace Rasel\CodeLock;

use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\Support\CanonicalJson;

class LicenseDocument
{
    protected array $header;
    protected array $payload;
    protected string $signature;
    protected ?string $rawJson;

    public function __construct(array $header, array $payload, string $signature, ?string $rawJson = null)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->signature = $signature;
        $this->rawJson = $rawJson;
    }

    /**
     * Create a LicenseDocument instance from an associative array.
     *
     * @param array $data
     * @return self
     * @throws LicenseInvalidException
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['payload']) || !is_array($data['payload'])) {
            throw new LicenseInvalidException('License document missing payload object.');
        }

        if (!isset($data['signature']) || !is_string($data['signature'])) {
            throw new LicenseInvalidException('License document missing signature.');
        }

        $header = isset($data['header']) && is_array($data['header'])
            ? $data['header']
            : ['alg' => 'Ed25519', 'typ' => 'CODELOCK-LIC', 'ver' => '1.0'];

        return new self($header, $data['payload'], $data['signature']);
    }

    /**
     * Create a LicenseDocument from a raw JSON string.
     *
     * @param string $json
     * @return self
     * @throws LicenseInvalidException
     */
    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);

        if (!is_array($data)) {
            throw new LicenseInvalidException('Malformed JSON document: ' . json_last_error_msg());
        }

        $doc = self::fromArray($data);
        $doc->rawJson = $json;

        return $doc;
    }

    /**
     * Get the envelope header.
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Get the cryptographic algorithm declared in the header.
     */
    public function getAlgorithm(): string
    {
        return $this->header['alg'] ?? 'Ed25519';
    }

    /**
     * Get the Key Identifier (kid) declared in the header.
     */
    public function getKeyId(): ?string
    {
        return $this->header['kid'] ?? null;
    }

    /**
     * Get the document payload claims dictionary.
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Generate the deterministic RFC 8785 canonical JSON representation of the payload.
     */
    public function getCanonicalPayload(): string
    {
        return CanonicalJson::encode($this->payload);
    }

    /**
     * Get the Base64-encoded Ed25519 detached signature.
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * Get the canonical license key.
     */
    public function getLicenseKey(): string
    {
        return (string) ($this->payload['lic'] ?? '');
    }

    /**
     * Get the product identifier.
     */
    public function getProductId(): string
    {
        return (string) ($this->payload['prd'] ?? '');
    }

    /**
     * Get the bound installation/instance fingerprint, if any.
     */
    public function getInstallationId(): ?string
    {
        return isset($this->payload['ins']) && !empty($this->payload['ins'])
            ? (string) $this->payload['ins']
            : null;
    }

    /**
     * Get the list of authorized domains.
     *
     * @return array<string>
     */
    public function getAllowedDomains(): array
    {
        $domains = $this->payload['dom'] ?? [];
        return is_array($domains) ? $domains : [(string) $domains];
    }

    /**
     * Get the baseline license status claim.
     */
    public function getStatus(): LicenseStatus
    {
        $sta = strtoupper((string) ($this->payload['sta'] ?? 'ACTIVE'));

        return LicenseStatus::tryFrom($sta) ?? LicenseStatus::INVALID;
    }

    /**
     * Get the Issued At (iat) Unix timestamp.
     */
    public function getIssuedAt(): int
    {
        return (int) ($this->payload['iat'] ?? 0);
    }

    /**
     * Get the Not Before (nbf) Unix timestamp.
     */
    public function getNotBefore(): int
    {
        return (int) ($this->payload['nbf'] ?? 0);
    }

    /**
     * Get the Expiration (exp) Unix timestamp (0 or null indicates lifetime).
     */
    public function getExpiresAt(): ?int
    {
        if (!isset($this->payload['exp']) || $this->payload['exp'] === null) {
            return null;
        }

        $exp = (int) $this->payload['exp'];
        return $exp > 0 ? $exp : null;
    }

    /**
     * Determine if this is a lifetime / non-expiring license.
     */
    public function isLifetime(): bool
    {
        return $this->getExpiresAt() === null;
    }

    /**
     * Get offline grace period in days.
     */
    public function getGracePeriodDays(): int
    {
        return (int) ($this->payload['grc'] ?? config('codelock.offline_grace_period', 7));
    }

    /**
     * Get heartbeat interval in hours.
     */
    public function getHeartbeatIntervalHours(): int
    {
        return (int) ($this->payload['hbi'] ?? config('codelock.heartbeat_interval', 24));
    }

    /**
     * Get the signed feature entitlements dictionary.
     */
    public function getEntitlements(): array
    {
        $ent = $this->payload['ent'] ?? [];
        return is_array($ent) ? $ent : [];
    }

    /**
     * Check if a specific feature entitlement is enabled.
     */
    public function hasFeature(string $feature): bool
    {
        $ent = $this->getEntitlements();

        // Check boolean flag: ent[feature] === true
        if (isset($ent[$feature]) && is_bool($ent[$feature])) {
            return $ent[$feature];
        }

        // Check features list: ent['features'] contains feature
        if (isset($ent['features']) && is_array($ent['features'])) {
            return in_array($feature, $ent['features'], true);
        }

        return false;
    }

    /**
     * Get a numeric quota or limit value from entitlements.
     */
    public function getQuota(string $key, mixed $default = null): mixed
    {
        $ent = $this->getEntitlements();
        return $ent[$key] ?? $default;
    }

    /**
     * Get the subscription tier string if declared.
     */
    public function getTier(): ?string
    {
        $ent = $this->getEntitlements();
        return isset($ent['tier']) ? (string) $ent['tier'] : null;
    }

    /**
     * Get the licensing policy options.
     */
    public function getPolicies(): array
    {
        $pol = $this->payload['pol'] ?? [];
        return is_array($pol) ? $pol : [];
    }

    /**
     * Check if instance binding is strictly enforced by license policy.
     */
    public function isInstanceStrict(): bool
    {
        $pol = $this->getPolicies();
        return (bool) ($pol['strict_instance'] ?? false);
    }

    /**
     * Get document cryptographic nonce.
     */
    public function getNonce(): string
    {
        return (string) ($this->payload['nonce'] ?? '');
    }

    /**
     * Export complete document envelope as an array.
     */
    public function toArray(): array
    {
        return [
            'header' => $this->header,
            'payload' => $this->payload,
            'signature' => $this->signature,
        ];
    }

    /**
     * Export as clean JSON.
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

