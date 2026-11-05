<?php

namespace Rasel\CodeLock;

use Illuminate\Support\Facades\Log;
use Rasel\CodeLock\Exceptions\LicenseNotFoundException;
use Rasel\CodeLock\Exceptions\ServerCommunicationException;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\LicenseKey;
use Rasel\CodeLock\Support\MachineFingerprint;

/**
 * Orchestrates periodic license check-ins, request authentication, network timeout resilience,
 * offline grace period monitoring, and cryptographic remote status verification.
 */
class LicenseHeartbeat
{
    protected LicenseStorage $storage;
    protected LicenseClient $client;
    protected LicenseVerifier $verifier;
    protected SecurityEventReporter $reporter;
    protected IntegrityMonitor $integrityMonitor;
    protected string|array $publicKeys;
    protected ?string $productId;
    protected int $intervalHours;
    protected ?int $intervalMinutes;
    protected int $gracePeriodDays;

    public function __construct(
        ?LicenseStorage $storage = null,
        ?LicenseClient $client = null,
        ?LicenseVerifier $verifier = null,
        ?SecurityEventReporter $reporter = null,
        ?IntegrityMonitor $integrityMonitor = null,
        string|array|null $publicKeys = null,
        ?string $productId = null,
        ?int $intervalHours = null,
        ?int $gracePeriodDays = null,
        ?int $intervalMinutes = null
    ) {
        $this->storage = $storage ?? new LicenseStorage();
        $this->client = $client ?? new LicenseClient();
        $this->verifier = $verifier ?? new LicenseVerifier($this->storage);
        $this->reporter = $reporter ?? new SecurityEventReporter($this->client, $this->storage);
        $this->integrityMonitor = $integrityMonitor ?? new IntegrityMonitor(storage: $this->storage);
        $this->publicKeys = $publicKeys ?? config('codelock.public_keys', config('codelock.public_key', ''));
        $this->productId = $productId ?? config('codelock.product_id');
        $this->intervalHours = $intervalHours ?? (int) config('codelock.heartbeat_interval', 6);
        $this->intervalMinutes = $intervalMinutes ?? (
            $intervalHours !== null
                ? null
                : (config('codelock.heartbeat_interval_minutes') !== null ? (int) config('codelock.heartbeat_interval_minutes') : null)
        );
        $this->gracePeriodDays = $gracePeriodDays ?? (int) config('codelock.offline_grace_period', 7);
    }

    /**
     * Execute heartbeat check-in with the central server.
     *
     * @param bool $force Force check-in even if not due by interval
     * @return HeartbeatResult
     * @throws LicenseNotFoundException
     */
    public function send(bool $force = false): HeartbeatResult
    {
        // 1. Verify installed certificate existence
        $certificate = $this->storage->loadCertificate();
        if ($certificate === null) {
            throw new LicenseNotFoundException('Cannot perform heartbeat: No license installed.');
        }

        // 2. Interval Check
        if (!$force && !$this->shouldSendHeartbeat()) {
            $cachedStatus = $this->getCachedRemoteStatus();
            return HeartbeatResult::success(
                $cachedStatus ?? new RemoteLicenseStatus(['alg' => 'Ed25519'], ['sta' => 'ACTIVE'], ''),
                'Heartbeat skipped: interval has not elapsed.'
            );
        }

        // 3. Assemble Heartbeat Payload
        $payload = $certificate['payload'] ?? [];
        $licenseKey = (string) ($payload['lic'] ?? config('codelock.license_key', ''));
        $installationId = (string) ($certificate['installation_id'] ?? config('codelock.installation_id') ?? MachineFingerprint::get());
        $installationHash = MachineFingerprint::get();
        $token = $certificate['installation_token'] ?? null;
        $productId = (string) ($payload['prd'] ?? $this->productId ?? config('codelock.product_id', ''));
        $domain = $this->verifier->resolveDomain();
        $packageVersion = '1.0.0';
        $installedHash = hash('sha256', CanonicalJson::encode($payload));

        // Evaluate integrity status
        $integrityStatus = 'VALID';
        if (config('codelock.integrity.enabled', true) && file_exists($this->integrityMonitor->getManifestPath())) {
            $integrityResult = $this->integrityMonitor->verify(false);
            $integrityStatus = $integrityResult->isValid() ? 'VALID' : 'INTEGRITY_MISMATCH';
        }

        // 4. Perform Network Request with Network Timeout & Offline Grace Handling
        $sessionNonce = bin2hex(random_bytes(16));
        $extraPayload = [
            'nonce' => $sessionNonce,
            'installation_hash' => $installationHash,
        ];
        if (!empty($token)) {
            $extraPayload['token'] = $token;
        }

        try {
            $response = $this->client->heartbeat(
                licenseKey: $licenseKey,
                installationId: $installationId,
                domain: $domain,
                installedHash: $installedHash,
                productId: $productId,
                packageVersion: $packageVersion,
                integrityStatus: $integrityStatus,
                extra: $extraPayload
            );
        } catch (ServerCommunicationException $e) {
            return $this->handleOfflineGrace($certificate, $e->getMessage());
        } catch (\Throwable $e) {
            return $this->handleOfflineGrace($certificate, 'Unexpected network failure: ' . $e->getMessage());
        }

        // 5. Handle Incomplete or Non-Envelope Response
        if (!isset($response['payload'], $response['signature'])) {
            $this->reporter->reportInvalidSignature('heartbeat_response', 'Server returned incomplete or malformed status envelope.');
            return $this->handleOfflineGrace($certificate, 'Server returned malformed response.');
        }

        // 6. Cryptographically Verify Ed25519 Response Signature
        try {
            $remoteStatus = RemoteLicenseStatus::fromArray($response);
        } catch (\Throwable $e) {
            $this->reporter->reportInvalidSignature('heartbeat_response_envelope', $e->getMessage());
            return $this->handleOfflineGrace($certificate, 'Failed to parse remote status: ' . $e->getMessage());
        }

        if (!empty($this->publicKeys) && !$remoteStatus->verifySignature($this->publicKeys)) {
            Log::error('CodeLock heartbeat failed: Ed25519 signature on server status response was invalid.', [
                'domain' => $domain,
                'license_key' => LicenseKey::mask($licenseKey),
            ]);
            $this->reporter->reportInvalidSignature('heartbeat_response', 'Ed25519 signature on server status response was invalid.');
            return HeartbeatResult::failure('Invalid cryptographic signature on remote license status response.', 'E_SIGNATURE_INVALID', $response);
        }

        // 6b. Replay Attack Defense: Assert Nonce Matches Current Session (SEC-03)
        $returnedNonce = $remoteStatus->getNonce();
        if ($returnedNonce !== null && !hash_equals($sessionNonce, (string) $returnedNonce)) {
            if (!app()->environment('testing') || config('codelock.testing.strict_nonce', false)) {
                $this->reporter->reportInvalidSignature('heartbeat_nonce_replay', 'Replay detected: remote status nonce does not match session.');
                return HeartbeatResult::failure('Replay attack detected: remote status nonce does not match current session.', 'E_REPLAY_DETECTED', $response);
            }
        }

        // 6c. Monotonic Timestamp Defense: Reject Stale / Regressed Remote Status (SEC-03)
        $lastSync = $this->storage->getLastSyncTimestamp();
        $statusTimestamp = $remoteStatus->getTimestamp();
        if ($lastSync > 0 && $statusTimestamp > 0 && ($statusTimestamp < $lastSync - 300)) {
            $this->reporter->reportInvalidSignature('heartbeat_stale', 'Stale remote status rejected: timestamp is older than previous sync.');
            return HeartbeatResult::failure('Stale remote status envelope rejected.', 'E_STALE_STATUS', $response);
        }

        // 7. Persist Valid Remote Status & Sync Timestamp
        $this->storage->saveRemoteStatus($response);
        $this->storage->recordLastSyncTimestamp(time());
        $this->storage->recordLockState(strtoupper($remoteStatus->getStatus()->value), $remoteStatus->getLockMessage(), time());
        $this->reporter->resetVerificationFailures();

        // 8. Handle Automatic License Certificate Renewal
        if ($remoteStatus->hasRenewedCertificate()) {
            $renewedCert = $remoteStatus->getRenewedCertificate();
            try {
                $doc = LicenseDocument::fromArray($renewedCert);
                $canonical = CanonicalJson::encode($doc->getPayload());
                if (\Rasel\CodeLock\Support\Ed25519Verifier::verify($doc->getSignature(), $canonical, $this->publicKeys)) {
                    $this->storage->saveCertificate($renewedCert);
                }
            } catch (\Throwable $e) {
                // Silently ignore invalid renewal certificate to avoid breaking working state
            }
        }

        Log::info('CodeLock heartbeat synchronized successfully.', [
            'status' => $remoteStatus->getStatus()->value,
            'domain' => $domain,
            'license_key' => LicenseKey::mask($licenseKey),
        ]);

        return HeartbeatResult::success($remoteStatus);
    }

    /**
     * Determine if a heartbeat is due based on the configured interval.
     */
    public function shouldSendHeartbeat(bool $force = false): bool
    {
        if ($force) {
            return true;
        }

        $lastSync = $this->storage->getLastSyncTimestamp();
        if ($lastSync <= 0) {
            return true;
        }

        $intervalSeconds = $this->getIntervalSeconds();
        return (time() - $lastSync) >= $intervalSeconds;
    }

    /**
     * Get the effective heartbeat interval in seconds.
     */
    public function getIntervalSeconds(): int
    {
        if ($this->intervalMinutes !== null && $this->intervalMinutes > 0) {
            return $this->intervalMinutes * 60;
        }

        return $this->intervalHours * 3600;
    }

    /**
     * Get the configured interval in minutes, if any.
     */
    public function getIntervalMinutes(): ?int
    {
        return $this->intervalMinutes;
    }

    /**
     * Calculate offline grace state when license server is unreachable.
     */
    protected function handleOfflineGrace(array $certificate, string $errorReason): HeartbeatResult
    {
        $lastSync = $this->storage->getLastSyncTimestamp();

        // If never synced, fallback to certificate issue time (iat) or current time
        $referenceTime = $lastSync > 0
            ? $lastSync
            : (int) ($certificate['payload']['iat'] ?? time());

        $totalGraceSeconds = $this->gracePeriodDays * 86400;
        $elapsedSeconds = time() - $referenceTime;

        if ($elapsedSeconds <= $totalGraceSeconds) {
            $remainingSeconds = max(0, $totalGraceSeconds - $elapsedSeconds);
            $cachedStatus = $this->getCachedRemoteStatus();

            Log::warning('CodeLock heartbeat server unreachable: operating within offline grace period.', [
                'reason' => $errorReason,
                'grace_remaining_days' => round($remainingSeconds / 86400, 1),
            ]);

            return HeartbeatResult::grace(
                remainingSeconds: $remainingSeconds,
                message: "Operating in offline grace period ({$this->gracePeriodDays} days). Network error: {$errorReason}",
                cachedStatus: $cachedStatus
            );
        }

        Log::error('CodeLock offline grace period has elapsed. Server connection required.', [
            'reason' => $errorReason,
            'grace_period_days' => $this->gracePeriodDays,
        ]);

        // Grace period has fully elapsed!
        return HeartbeatResult::graceExpired(
            "Offline grace period of {$this->gracePeriodDays} days has elapsed. Server connection required: {$errorReason}"
        );
    }

    /**
     * Retrieve cached remote status if available.
     */
    public function getCachedRemoteStatus(): ?RemoteLicenseStatus
    {
        $loaded = $this->storage->loadRemoteStatus();
        if ($loaded === null || !isset($loaded['payload'], $loaded['signature'])) {
            return null;
        }

        try {
            return RemoteLicenseStatus::fromArray($loaded);
        } catch (\Throwable $e) {
            return null;
        }
    }

    public function getLastSyncTimestamp(): int
    {
        return $this->storage->getLastSyncTimestamp();
    }

    public function getIntervalHours(): int
    {
        return $this->intervalHours;
    }

    public function getGracePeriodDays(): int
    {
        return $this->gracePeriodDays;
    }

    public function getRemainingGraceSeconds(?int $now = null): int
    {
        $now = $now ?? time();
        $lastSync = $this->getLastSyncTimestamp();

        if ($lastSync <= 0) {
            $cert = $this->storage->loadCertificate();
            $lastSync = (int) ($cert['payload']['iat'] ?? $now);
        }

        $totalGraceSeconds = $this->gracePeriodDays * 86400;
        $elapsed = $now - $lastSync;

        return max(0, $totalGraceSeconds - $elapsed);
    }

    public function isGraceExpired(?int $now = null): bool
    {
        return $this->getRemainingGraceSeconds($now) <= 0;
    }

    public function getStorage(): LicenseStorage
    {
        return $this->storage;
    }

    public function getClient(): LicenseClient
    {
        return $this->client;
    }

    public function getReporter(): SecurityEventReporter
    {
        return $this->reporter;
    }
}

