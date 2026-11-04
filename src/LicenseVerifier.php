<?php

namespace Rasel\CodeLock;

use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Exceptions\CodeLockException;
use Rasel\CodeLock\Exceptions\DomainMismatchException;
use Rasel\CodeLock\Exceptions\LicenseExpiredException;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\Exceptions\LicenseLockedException;
use Rasel\CodeLock\Exceptions\LicenseNotFoundException;
use Rasel\CodeLock\Exceptions\LicenseRevokedException;
use Rasel\CodeLock\Exceptions\LicenseSuspendedException;
use Rasel\CodeLock\Exceptions\SignatureVerificationException;
use Rasel\CodeLock\Exceptions\TamperDetectedException;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Support\MachineFingerprint;

class LicenseVerifier
{
    protected LicenseStorage $storage;
    /** @var string|array<string, string> */
    protected string|array $publicKeys;
    protected ?string $productId;
    protected bool $allowLocal;

    public function __construct(
        ?LicenseStorage $storage = null,
        string|array|null $publicKeys = null,
        ?string $productId = null,
        ?bool $allowLocal = null
    ) {
        $this->storage = $storage ?? new LicenseStorage();
        $this->publicKeys = $publicKeys ?? config('codelock.public_keys', config('codelock.public_key', ''));
        $this->productId = $productId ?? config('codelock.product_id');
        $this->allowLocal = $allowLocal ?? (bool) config('codelock.allow_local', false);
    }

    /**
     * Perform full verification of certificate, domain, validity, clock, and remote status.
     *
     * @param ?string $domain Current host/domain to verify (defaults to current request host)
     * @param LicenseDocument|array|null $certificate Explicit certificate or null to load from storage
     * @param bool $throw Whether to throw exceptions on failure
     * @return LicenseVerificationResult
     */
    public function verify(?string $domain = null, LicenseDocument|array|null $certificate = null, bool $throw = false): LicenseVerificationResult
    {
        $domain = $this->resolveDomain($domain);

        // 1. Load Certificate Document
        $document = null;
        if ($certificate instanceof LicenseDocument) {
            $document = $certificate;
        } elseif (is_array($certificate)) {
            try {
                $document = LicenseDocument::fromArray($certificate);
            } catch (\Throwable $e) {
                return $this->fail(
                    new LicenseInvalidException('Malformed license document structure: ' . $e->getMessage()),
                    LicenseStatus::INVALID,
                    'License certificate structure is corrupted.',
                    'E_STRUCTURE_MALFORMED',
                    null,
                    ['domain' => $domain],
                    $throw
                );
            }
        } else {
            $loaded = $this->storage->loadCertificate();
            if ($loaded === null) {
                return $this->fail(
                    new LicenseNotFoundException('No license certificate found.'),
                    LicenseStatus::UNLICENSED,
                    'Installation is not licensed.',
                    'E_LICENSE_NOT_FOUND',
                    null,
                    ['domain' => $domain],
                    $throw
                );
            }

            try {
                $document = LicenseDocument::fromArray($loaded);
            } catch (\Throwable $e) {
                return $this->fail(
                    new LicenseInvalidException('Stored license document is malformed: ' . $e->getMessage()),
                    LicenseStatus::INVALID,
                    'Stored license document is corrupted.',
                    'E_STRUCTURE_MALFORMED',
                    null,
                    ['domain' => $domain],
                    $throw
                );
            }
        }

        // 2. Algorithm & Header Assertion
        $alg = $document->getAlgorithm();
        if ($alg !== 'Ed25519') {
            return $this->fail(
                new SignatureVerificationException("Unsupported algorithm '{$alg}'. Only Ed25519 is accepted."),
                LicenseStatus::INVALID,
                "Unsupported cryptographic algorithm '{$alg}'.",
                'E_ALGORITHM_UNSUPPORTED',
                $document,
                ['domain' => $domain],
                $throw
            );
        }

        // 3. Resolve Public Verification Key
        $publicKey = $this->resolvePublicKey($document->getKeyId());
        if (empty($publicKey)) {
            return $this->fail(
                new SignatureVerificationException('Public key not found for key ID: ' . ($document->getKeyId() ?? 'default')),
                LicenseStatus::INVALID,
                'Public verification key is missing or unrecognized.',
                'E_KEY_UNKNOWN',
                $document,
                ['domain' => $domain],
                $throw
            );
        }

        // 4. Ed25519 Cryptographic Signature Verification
        $canonicalPayload = $document->getCanonicalPayload();
        $signature = $document->getSignature();

        if (!Ed25519Verifier::verify($signature, $canonicalPayload, $publicKey)) {
            return $this->fail(
                new SignatureVerificationException('Cryptographic signature verification failed. Certificate modified.'),
                LicenseStatus::INVALID,
                'Cryptographic signature does not match payload.',
                'E_SIGNATURE_MISMATCH',
                $document,
                ['domain' => $domain],
                $throw
            );
        }

        // 5. Product Identity Verification
        if (!empty($this->productId)) {
            $docProduct = $document->getProductId();
            if ($docProduct !== $this->productId) {
                $reason = "Product mismatch: expected '{$this->productId}', license is for '{$docProduct}'.";
                return $this->fail(
                    new LicenseInvalidException($reason),
                    LicenseStatus::INVALID,
                    $reason,
                    'E_PRODUCT_MISMATCH',
                    $document,
                    ['domain' => $domain],
                    $throw
                );
            }
        }

        // 6. Installation Identity (Machine Fingerprint) Binding Check
        $docInstance = $document->getInstallationId();
        if (!empty($docInstance) && $document->isInstanceStrict()) {
            $currentInstance = MachineFingerprint::get();
            if ($docInstance !== $currentInstance) {
                $reason = "License is bound to another server installation ({$docInstance}).";
                return $this->fail(
                    new LicenseInvalidException($reason),
                    LicenseStatus::INVALID,
                    $reason,
                    'E_INSTANCE_MISMATCH',
                    $document,
                    ['domain' => $domain, 'expected' => $docInstance, 'actual' => $currentInstance],
                    $throw
                );
            }
        }

        // 7. Domain Legitimacy Verification
        if (!$this->isDomainAllowed($domain, $document)) {
            return $this->fail(
                new DomainMismatchException("Domain '{$domain}' is not authorized for this license."),
                LicenseStatus::INVALID,
                "Domain '{$domain}' is not authorized.",
                'E_DOMAIN_UNAUTHORIZED',
                $document,
                ['domain' => $domain, 'allowed_domains' => $document->getAllowedDomains()],
                $throw
            );
        }

        // 8. Temporal Validity & Clock Integrity
        $now = time();
        $lastVerified = $this->storage->getLastVerificationTimestamp();
        $fallbackFloor = max((int) $document->getIssuedAt(), $this->storage->getLastSyncTimestamp());
        $effectiveFloor = max($lastVerified, $fallbackFloor);

        // Clock Rollback Detection (1 hour NTP jitter tolerance)
        if ($effectiveFloor > 0 && ($now < $effectiveFloor - 3600)) {
            return $this->fail(
                new TamperDetectedException('System clock rollback detected.'),
                LicenseStatus::INVALID,
                'System clock tampering detected. Time was set backwards.',
                'E_CLOCK_ROLLBACK_DETECTED',
                $document,
                ['domain' => $domain, 'now' => $now, 'last_verified' => $effectiveFloor],
                $throw
            );
        }

        // Issue Date Floor Check (system clock cannot be earlier than certificate issuance)
        $iat = $document->getIssuedAt();
        if ($iat > 0 && ($now + 300) < $iat) {
            return $this->fail(
                new TamperDetectedException('System clock is earlier than license certificate issuance date.'),
                LicenseStatus::INVALID,
                'System clock tampering detected. Time was set prior to license creation.',
                'E_CLOCK_ROLLBACK_DETECTED',
                $document,
                ['domain' => $domain, 'now' => $now, 'issued_at' => $iat],
                $throw
            );
        }

        // Record verification timestamp
        $this->storage->recordVerificationTimestamp($now);

        // Not Before (nbf) Check (5-minute drift allowance)
        $nbf = $document->getNotBefore();
        if ($nbf > 0 && ($now + 300) < $nbf) {
            return $this->fail(
                new LicenseInvalidException('License is not yet active (nbf in future).'),
                LicenseStatus::INVALID,
                'License certificate not yet active.',
                'E_TEMPORAL_NOT_YET_VALID',
                $document,
                ['domain' => $domain, 'nbf' => $nbf, 'now' => $now],
                $throw
            );
        }

        // Expiration Check
        $exp = $document->getExpiresAt();
        if ($exp !== null && $now > $exp) {
            return $this->fail(
                new LicenseExpiredException('License subscription expired on ' . date('Y-m-d H:i:s', $exp)),
                LicenseStatus::EXPIRED,
                'License subscription has expired.',
                'E_TEMPORAL_EXPIRED',
                $document,
                ['domain' => $domain, 'exp' => $exp, 'now' => $now],
                $throw
            );
        }

        // 9. Status Claim Check
        $claimedStatus = $document->getStatus();
        if ($claimedStatus === LicenseStatus::SUSPENDED) {
            return $this->fail(
                new LicenseSuspendedException('License certificate is marked as suspended.'),
                LicenseStatus::SUSPENDED,
                'This license subscription is suspended.',
                'E_STATUS_SUSPENDED',
                $document,
                ['domain' => $domain],
                $throw
            );
        }

        if ($claimedStatus === LicenseStatus::LOCKED) {
            return $this->fail(
                new LicenseLockedException('License certificate is marked as locked.'),
                LicenseStatus::LOCKED,
                'This software installation is locked.',
                'E_STATUS_LOCKED',
                $document,
                ['domain' => $domain],
                $throw
            );
        }

        // 10. Remote Status Cache Check (Signed Remote Override)
        $remoteStatus = $this->storage->loadRemoteStatus();
        if ($remoteStatus === null) {
            // Defense against status cache deletion: verify persistent lock state (SEC-02)
            $lastLockState = $this->storage->getLastLockState();
            if ($lastLockState !== null && ($lastLockState['status'] ?? '') === LicenseStatus::LOCKED->value) {
                $installedCert = $this->storage->loadCertificate();
                if ($installedCert !== null && ($installedCert['payload']['lic'] ?? '') === $document->getLicenseKey()) {
                    $lockMsg = $lastLockState['reason'] ?? 'This installation remains locked pending server synchronization.';
                    return $this->fail(
                        new LicenseLockedException($lockMsg, $lockMsg),
                        LicenseStatus::LOCKED,
                        $lockMsg,
                        'E_STATUS_LOCKED',
                        $document,
                        ['domain' => $domain, 'cached_lock' => true],
                        $throw
                    );
                }
            }
        } else {
            if (!isset($remoteStatus['payload'], $remoteStatus['signature']) || !is_array($remoteStatus['payload']) || !is_string($remoteStatus['signature'])) {
                return $this->fail(
                    new SignatureVerificationException('Remote status cache is malformed or corrupted.'),
                    LicenseStatus::INVALID,
                    'Remote status cache structure is corrupted.',
                    'E_STRUCTURE_MALFORMED',
                    $document,
                    ['domain' => $domain, 'remote' => true],
                    $throw
                );
            }

            $remotePayload = $remoteStatus['payload'];
            $canonicalRemote = CanonicalJson::encode($remotePayload);

            // Verify remote status signature using active public key
            if (!Ed25519Verifier::verify($remoteStatus['signature'], $canonicalRemote, $publicKey)) {
                return $this->fail(
                    new SignatureVerificationException('Remote status signature is invalid or forged.'),
                    LicenseStatus::INVALID,
                    'Remote status signature verification failed. Untrusted status file.',
                    'E_REMOTE_STATUS_FORGED',
                    $document,
                    ['domain' => $domain, 'remote' => true],
                    $throw
                );
            }

            // Cross-Tenant Status Binding Checks
            if (isset($remotePayload['lic']) && $remotePayload['lic'] !== $document->getLicenseKey()) {
                return $this->fail(
                    new LicenseInvalidException('Remote status license key does not match installed license certificate.'),
                    LicenseStatus::INVALID,
                    'Remote status license key mismatch.',
                    'E_IDENTITY_MISMATCH',
                    $document,
                    ['domain' => $domain, 'remote' => true],
                    $throw
                );
            }

            if (isset($remotePayload['prd']) && $remotePayload['prd'] !== $document->getProductId()) {
                return $this->fail(
                    new LicenseInvalidException('Remote status product ID does not match installed license certificate.'),
                    LicenseStatus::INVALID,
                    'Remote status product mismatch.',
                    'E_PRODUCT_MISMATCH',
                    $document,
                    ['domain' => $domain, 'remote' => true],
                    $throw
                );
            }

            $statusStr = strtoupper($remotePayload['sta'] ?? '');

            if ($statusStr === LicenseStatus::LOCKED->value) {
                $lockMsg = $remotePayload['lock_message'] ?? 'This installation has been locked remotely.';
                return $this->fail(
                    new LicenseLockedException($lockMsg, $lockMsg),
                    LicenseStatus::LOCKED,
                    $lockMsg,
                    'E_STATUS_LOCKED',
                    $document,
                    [
                        'domain' => $domain,
                        'remote' => true,
                        'reason_code' => $remotePayload['reason_code'] ?? null,
                        'action_url' => $remotePayload['action_url'] ?? null,
                    ],
                    $throw
                );
            }

            if ($statusStr === LicenseStatus::SUSPENDED->value) {
                $suspMsg = $remotePayload['lock_message'] ?? 'This license is temporarily suspended.';
                return $this->fail(
                    new LicenseSuspendedException($suspMsg, $suspMsg),
                    LicenseStatus::SUSPENDED,
                    $suspMsg,
                    'E_STATUS_SUSPENDED',
                    $document,
                    [
                        'domain' => $domain,
                        'remote' => true,
                        'reason_code' => $remotePayload['reason_code'] ?? null,
                        'action_url' => $remotePayload['action_url'] ?? null,
                    ],
                    $throw
                );
            }

            if ($statusStr === LicenseStatus::REVOKED->value) {
                $revMsg = $remotePayload['lock_message'] ?? 'This license agreement has been permanently revoked.';
                return $this->fail(
                    new LicenseRevokedException($revMsg, $revMsg),
                    LicenseStatus::REVOKED,
                    $revMsg,
                    'E_STATUS_REVOKED',
                    $document,
                    [
                        'domain' => $domain,
                        'remote' => true,
                        'reason_code' => $remotePayload['reason_code'] ?? null,
                        'action_url' => $remotePayload['action_url'] ?? null,
                    ],
                    $throw
                );
            }

            if ($statusStr === LicenseStatus::ACTIVE->value) {
                $this->storage->recordLockState(LicenseStatus::ACTIVE->value, null, time());
            }

            // Check Grace Period Deadline
            if (isset($remotePayload['deadline'])) {
                $deadline = (int) $remotePayload['deadline'];
                if ($deadline > 0 && $now > $deadline) {
                    return $this->fail(
                        new LicenseExpiredException('Heartbeat grace period elapsed. Server connection required.'),
                        LicenseStatus::EXPIRED,
                        'Heartbeat grace period elapsed. Please connect to the license server.',
                        'E_GRACE_EXCEEDED',
                        $document,
                        ['domain' => $domain],
                        $throw
                    );
                }
            }
        }

        // 11. Offline Grace Period Enforcement (Direct Request Validation - SEC-04)
        $lastSync = $this->storage->getLastSyncTimestamp();
        $graceDays = (int) config('codelock.offline_grace_period', 7);
        if ($graceDays > 0 && $lastSync > 0) {
            $maxGraceSeconds = $graceDays * 86400;
            if (($now - $lastSync) > $maxGraceSeconds) {
                $reason = "Offline grace period of {$graceDays} days has elapsed. Server connection required.";
                return $this->fail(
                    new LicenseExpiredException($reason),
                    LicenseStatus::EXPIRED,
                    $reason,
                    'E_GRACE_EXCEEDED',
                    $document,
                    ['domain' => $domain, 'last_sync' => $lastSync, 'now' => $now],
                    $throw
                );
            }
        }

        // Record successful local active state
        $this->storage->recordLockState(LicenseStatus::ACTIVE->value, null, $now);

        // All 11 verification stages passed successfully!
        return LicenseVerificationResult::success($document, ['domain' => $domain]);
    }

    /**
     * Resolve public key given a key identifier.
     */
    public function resolvePublicKey(?string $kid = null): ?string
    {
        if (is_array($this->publicKeys)) {
            if (!empty($kid)) {
                return $this->publicKeys[$kid] ?? null;
            }

            if (isset($this->publicKeys['default'])) {
                return $this->publicKeys['default'];
            }

            // Return first key if present and no kid was specified
            $first = reset($this->publicKeys);
            return $first ?: null;
        }

        if (is_string($this->publicKeys) && !empty($this->publicKeys)) {
            return $this->publicKeys;
        }

        return null;
    }

    /**
     * Check if a domain matches allowed domains list or rules.
     */
    public function isDomainAllowed(string $domain, LicenseDocument $document): bool
    {
        $domain = $this->normalizeDomain($domain);

        // Local development bypass
        if ($this->allowLocal && $this->isLocalDomain($domain)) {
            return true;
        }

        $allowedDomains = $document->getAllowedDomains();

        foreach ($allowedDomains as $allowed) {
            $allowed = $this->normalizeDomain((string) $allowed);

            // Exact match
            if ($domain === $allowed) {
                return true;
            }

            // Wildcard match (e.g. *.example.com)
            if (str_starts_with($allowed, '*.')) {
                $base = substr($allowed, 2);
                if ($domain === $base || str_ends_with($domain, '.' . $base)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Normalize a domain string safely (lowercase, strip port, protocol, IPv6 brackets, trailing dots).
     */
    public function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain));

        // Strip protocol if present
        if (str_starts_with($domain, 'http://') || str_starts_with($domain, 'https://')) {
            $parts = parse_url($domain);
            $domain = $parts['host'] ?? $domain;
        }

        // Handle IPv6 brackets [::1] -> ::1
        if (str_starts_with($domain, '[') && str_contains($domain, ']')) {
            $domain = substr($domain, 1, strpos($domain, ']') - 1);
        } elseif (str_contains($domain, ':')) {
            // Strip port (e.g. app.example.com:8080 -> app.example.com)
            $domain = explode(':', $domain)[0];
        }

        // Strip trailing dots (e.g. example.com. -> example.com)
        return rtrim($domain, '.');
    }

    /**
     * Check if domain is a local development domain.
     * Enforces production safety: never allows bypass when application environment is production.
     */
    public function isLocalDomain(string $domain): bool
    {
        // Critical safety invariant: Production environments NEVER allow local dev bypass
        if (app()->bound('env')) {
            $isProd = app()->isProduction() || app()['env'] === 'production' || config('app.env') === 'production';
            if ($isProd) {
                return false;
            }
        }

        $normalized = $this->normalizeDomain($domain);

        if (in_array($normalized, ['localhost', '127.0.0.1', '::1'], true)) {
            return true;
        }

        foreach (['.test', '.local', '.localhost', '.invalid', '.example'] as $suffix) {
            if (str_ends_with($normalized, $suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve the current domain from request or environment.
     */
    public function resolveDomain(?string $explicit = null): string
    {
        if (!empty($explicit)) {
            return $this->normalizeDomain($explicit);
        }

        if (app()->bound('request')) {
            $request = request();
            $host = $request->getHost();
            if (!empty($host)) {
                return $this->normalizeDomain($host);
            }
        }

        $appUrl = config('app.url');
        if (!empty($appUrl)) {
            $parsed = parse_url($appUrl, PHP_URL_HOST);
            if (!empty($parsed)) {
                return $this->normalizeDomain($parsed);
            }
        }

        return 'localhost';
    }

    /**
     * Helper to return failure result or throw exception.
     */
    protected function fail(
        \Throwable $exception,
        LicenseStatus $status,
        string $reason,
        string $errorCode,
        ?LicenseDocument $document,
        array $context,
        bool $throw
    ): LicenseVerificationResult {
        $this->storage->recordLockState($status->value, $reason, time());

        if ($throw) {
            throw $exception;
        }

        return LicenseVerificationResult::failure(
            status: $status,
            reason: $reason,
            errorCode: $errorCode,
            document: $document,
            context: $context
        );
    }
}
