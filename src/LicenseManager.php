<?php

namespace Rasel\CodeLock;

use Illuminate\Http\Response;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Enums\SecurityEventCode;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\Exceptions\LicenseNotFoundException;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\MachineFingerprint;

class LicenseManager
{
    protected LicenseStorage $storage;
    protected LicenseVerifier $verifier;
    protected LicenseClient $client;
    protected IntegrityMonitor $integrityMonitor;
    protected SecurityEventReporter $securityReporter;
    protected LicenseHeartbeat $heartbeat;
    protected ?LicenseVerificationResult $cachedVerificationResult = null;

    public function __construct(
        ?LicenseStorage $storage = null,
        ?LicenseVerifier $verifier = null,
        ?LicenseClient $client = null,
        ?IntegrityMonitor $integrityMonitor = null,
        ?SecurityEventReporter $securityReporter = null,
        ?LicenseHeartbeat $heartbeat = null
    ) {
        $this->storage = $storage ?? new LicenseStorage();
        $this->verifier = $verifier ?? new LicenseVerifier($this->storage);
        $this->client = $client ?? new LicenseClient();
        $this->integrityMonitor = $integrityMonitor ?? new IntegrityMonitor(storage: $this->storage);
        $this->securityReporter = $securityReporter ?? new SecurityEventReporter($this->client, $this->storage);
        $this->heartbeat = $heartbeat ?? new LicenseHeartbeat(
            $this->storage,
            $this->client,
            $this->verifier,
            $this->securityReporter,
            $this->integrityMonitor
        );
    }

    /**
     * Check if CodeLock enforcement is globally enabled in config.
     */
    public function isEnabled(): bool
    {
        return (bool) config('codelock.enabled', true);
    }

    /**
     * Verify license legitimacy for the given domain.
     * Caches result in memory for the duration of the current request.
     *
     * @param ?string $domain
     * @param bool $throw
     * @return LicenseVerificationResult
     */
    public function verify(?string $domain = null, bool $throw = false): LicenseVerificationResult
    {
        if (!$this->isEnabled()) {
            return LicenseVerificationResult::success(
                new LicenseDocument(
                    ['alg' => 'Ed25519', 'typ' => 'CODELOCK-LIC'],
                    ['lic' => 'BYPASS-LOCAL', 'prd' => (string) config('codelock.product_id'), 'sta' => 'ACTIVE'],
                    'bypass_signature'
                ),
                ['domain' => $domain ?? 'localhost', 'bypassed' => true]
            );
        }

        $resolvedDomain = $this->verifier->resolveDomain($domain);

        // Check request-scoped memoization if running inside an HTTP request
        if (app()->bound('request')) {
            $request = request();
            $memoized = $request->attributes->get('_codelock_result');
            if ($memoized instanceof LicenseVerificationResult &&
                ($memoized['domain'] ?? '') === $resolvedDomain) {
                if ($throw && !$memoized->isValid()) {
                    $this->verifier->verify($resolvedDomain, null, true);
                }
                return $memoized;
            }
        } elseif ($this->cachedVerificationResult !== null &&
            ($this->cachedVerificationResult['domain'] ?? '') === $resolvedDomain) {
            if ($throw && !$this->cachedVerificationResult->isValid()) {
                $this->verifier->verify($resolvedDomain, null, true);
            }
            return $this->cachedVerificationResult;
        }

        // Never trust unverified documents: Run full cryptographic verification pipeline
        $result = $this->verifier->verify($resolvedDomain, null, $throw);
        $result['domain'] = $resolvedDomain;

        // Cryptographic Package Integrity Tripwire Check
        if ($result->isValid() && config('codelock.integrity.enabled', true) && file_exists($this->integrityMonitor->getManifestPath())) {
            $integrity = $this->integrityMonitor->verify(false);
            if (!$integrity->isValid()) {
                $tamperResult = LicenseVerificationResult::failure(
                    LicenseStatus::INVALID,
                    $integrity->getReason() ?? 'Package integrity violation detected.',
                    $integrity->getErrorCode() ?? 'E_INTEGRITY_MISMATCH',
                    $result->getDocument(),
                    ['domain' => $resolvedDomain, 'integrity' => $integrity->toArray()]
                );
                $tamperResult['domain'] = $resolvedDomain;

                // Dispatch telemetry to central server
                $this->securityReporter->reportIntegrityMismatch(
                    $integrity->getModifiedFiles(),
                    $integrity->getReason()
                );

                if ($throw) {
                    throw new \Rasel\CodeLock\Exceptions\TamperDetectedException(
                        $integrity->getReason() ?? 'Package integrity violation.',
                        $integrity->getReason()
                    );
                }

                return $tamperResult;
            }
        }

        if (app()->bound('request')) {
            request()->attributes->set('_codelock_result', $result);
        } else {
            $this->cachedVerificationResult = $result;
        }

        // Auto-report domain mismatch or tamper attempts
        if (!$result->isValid()) {
            $this->securityReporter->recordVerificationFailure($resolvedDomain, $result->getReason());

            if ($result->getStatus() === LicenseStatus::INVALID) {
                $allowed = $result->getDocument()?->getAllowedDomains() ?? [];
                $this->securityReporter->reportDomainMismatch($resolvedDomain, $allowed);
            }
        } else {
            $this->securityReporter->resetVerificationFailures();
        }

        return $result;
    }

    /**
     * Shorthand check returning boolean.
     */
    public function check(?string $domain = null): bool
    {
        return $this->verify($domain, false)->isValid();
    }

    /**
     * Get the active verified LicenseDocument if valid.
     */
    public function getDocument(?string $domain = null): ?LicenseDocument
    {
        $res = $this->verify($domain, false);
        return $res->isValid() ? $res->getDocument() : null;
    }

    /**
     * Check if a specific signed feature entitlement is granted.
     */
    public function can(string $ability): bool
    {
        return $this->verify()->can($ability);
    }

    /**
     * Check if a specific feature entitlement is enabled.
     */
    public function hasFeature(string $feature): bool
    {
        return $this->verify()->hasFeature($feature);
    }

    /**
     * Query a signed numeric quota or limit value.
     */
    public function quota(string $key, mixed $default = null): mixed
    {
        return $this->verify()->quota($key, $default);
    }

    /**
     * Get the active subscription tier string.
     */
    public function tier(): ?string
    {
        return $this->verify()->tier();
    }

    /**
     * Get all signed entitlements.
     */
    public function entitlements(): array
    {
        return $this->getDocument()?->getEntitlements() ?? [];
    }

    /**
     * Activate a license key by calling the central server and saving the signed certificate.
     */
    public function activate(string $licenseKey, ?string $domain = null): array
    {
        $domain = $this->verifier->resolveDomain($domain);
        $certificate = $this->client->activate($licenseKey, $domain);

        if (!isset($certificate['payload'], $certificate['signature'])) {
            throw new LicenseInvalidException('License server returned an invalid or incomplete certificate.');
        }

        // Convert to LicenseDocument
        $doc = LicenseDocument::fromArray($certificate);

        // Immediately verify cryptographic validity before persisting
        $verification = $this->verifier->verify($domain, $doc, true);

        // Save locally
        $this->storage->saveCertificate($certificate);
        $this->storage->recordLastSyncTimestamp(time());
        $this->storage->recordLockState(LicenseStatus::ACTIVE->value, null, time());
        $this->clearCache();

        return [
            'success' => true,
            'status' => $verification->getStatus(),
            'payload' => $doc->getPayload(),
            'document' => $doc,
        ];
    }

    /**
     * Perform a heartbeat synchronization with the license server.
     */
    public function heartbeat(bool $force = true): HeartbeatResult
    {
        $result = $this->heartbeat->send($force);
        $this->clearCache();
        return $result;
    }

    /**
     * Force refresh the local license status from remote server.
     */
    public function refresh(): HeartbeatResult
    {
        return $this->heartbeat(true);
    }

    /**
     * Deactivate the license on remote server and delete local certificate.
     */
    public function deactivate(?string $domain = null): bool
    {
        $domain = $this->verifier->resolveDomain($domain);
        $certificate = $this->storage->loadCertificate();

        if ($certificate !== null) {
            $licenseKey = $certificate['payload']['lic'] ?? config('codelock.license_key');
            $instanceId = $certificate['installation_id'] ?? MachineFingerprint::get();
            $installationToken = $certificate['installation_token'] ?? null;

            try {
                $this->client->deactivate($licenseKey, $instanceId, $domain, $installationToken);
            } catch (\Throwable $e) {
                // Log deactivation failure but continue local deletion
                if (function_exists('logger')) {
                    logger()?->warning('CodeLock remote deactivation warning: ' . $e->getMessage());
                }
            }
        }

        $this->clearCache();
        return $this->storage->deleteCertificate();
    }

    /**
     * Get a comprehensive status report for CLI or dashboard inspection.
     */
    public function status(?string $domain = null): array
    {
        $domain = $this->verifier->resolveDomain($domain);
        $certificate = $this->storage->loadCertificate();
        $remoteStatus = $this->storage->loadRemoteStatus();
        $verification = $this->verifier->verify($domain, $certificate, false);

        $payload = $certificate['payload'] ?? [];
        $remotePayload = $remoteStatus['payload'] ?? [];

        return [
            'enabled' => $this->isEnabled(),
            'valid' => $verification->isValid(),
            'status' => $verification->getStatus()->value,
            'status_label' => $verification->getStatus()->label(),
            'reason' => $verification->getReason(),
            'error_code' => $verification->getErrorCode(),
            'domain' => $domain,
            'instance_id' => MachineFingerprint::get(),
            'product_id' => $payload['prd'] ?? config('codelock.product_id', 'N/A'),
            'license_key' => $payload['lic'] ?? config('codelock.license_key', 'N/A'),
            'allowed_domains' => $payload['dom'] ?? [],
            'entitlements' => $payload['ent'] ?? [],
            'tier' => $payload['ent']['tier'] ?? 'Standard',
            'issued_at' => isset($payload['iat']) ? date('Y-m-d H:i:s', $payload['iat']) : null,
            'expires_at' => isset($payload['exp']) && $payload['exp'] > 0 ? date('Y-m-d H:i:s', $payload['exp']) : 'Lifetime / Never',
            'last_verified_at' => date('Y-m-d H:i:s', $this->storage->getLastVerificationTimestamp()),
            'last_sync_at' => $this->heartbeat->getLastSyncTimestamp() > 0 ? date('Y-m-d H:i:s', $this->heartbeat->getLastSyncTimestamp()) : 'Never',
            'grace_remaining_seconds' => $this->heartbeat->getRemainingGraceSeconds(),
            'grace_expired' => $this->heartbeat->isGraceExpired(),
            'heartbeat_interval_hours' => $this->heartbeat->getIntervalHours(),
            'remote_status' => $remotePayload['sta'] ?? 'NOT_SYNCED',
            'lock_message' => $remotePayload['lock_message'] ?? null,
            'reason_code' => $remotePayload['reason_code'] ?? null,
            'action_url' => $this->sanitizeUrl($remotePayload['action_url'] ?? null),
            'grace_period_days' => config('codelock.offline_grace_period', 7),
            'contact_email' => config('codelock.contact_email'),
            'contact_url' => $this->sanitizeUrl(config('codelock.contact_url')),
        ];
    }

    /**
     * Render the professional lock screen response.
     */
    public function renderLockResponse(?string $reason = null, int $statusCode = 403, ?string $domain = null): Response
    {
        $statusInfo = $this->status($domain);
        $reason = $reason ?? $statusInfo['reason'] ?? 'This installation is currently locked or unlicensed.';
        $viewName = config('codelock.lock_view', 'codelock::locked');

        if (!view()->exists($viewName)) {
            $appName = e(config('app.name', 'Software Application'));
            $contactEmail = e(filter_var($statusInfo['contact_email'] ?? 'licensing@example.com', FILTER_VALIDATE_EMAIL) ? $statusInfo['contact_email'] : 'licensing@example.com');

            // SEC-14: Validate URL scheme to prevent javascript: pseudo-protocol execution
            $rawContactUrl = (string) ($statusInfo['contact_url'] ?? '#');
            $parsedUrl = parse_url($rawContactUrl);
            $scheme = strtolower($parsedUrl['scheme'] ?? '');
            $contactUrl = (in_array($scheme, ['http', 'https'], true)) ? e($rawContactUrl) : '#';

            $reasonSafe = e($reason);
            $instanceId = $statusInfo['instance_id'] ?? 'N/A';
            $customerRef = !empty($instanceId) && $instanceId !== 'N/A'
                ? 'REF-' . strtoupper(substr(hash('crc32b', $instanceId), 0, 8)) . '-' . strtoupper(substr($instanceId, -8))
                : 'REF-GENERAL';
            $statusLabel = e($statusInfo['status_label'] ?? 'License Restricted');
            $reasonCode = !empty($statusInfo['reason_code']) ? '<span style="font-family: monospace; font-size: 10px; color: #c084fc; display: block; margin-top: 4px;">Reason Code: ' . e($statusInfo['reason_code']) . '</span>' : '';

            // SEC-08: Add CSRF token for web recovery submissions
            $csrfToken = function_exists('csrf_token') ? csrf_token() : '';
            $csrfField = !empty($csrfToken) ? '<input type="hidden" name="_token" value="' . e($csrfToken) . '">' : '';

            $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software License Restricted &bull; Access Restricted | {$appName}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #020617; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1.5rem; }
        .card { background: rgba(15, 23, 42, 0.9); border: 1px solid #1e293b; border-radius: 1rem; max-width: 32rem; width: 100%; padding: 2rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); position: relative; }
        .icon { width: 3rem; height: 3rem; border-radius: 1rem; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.2); color: #c084fc; display: flex; align-items: center; justify-content: center; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .brand { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #c084fc; font-family: monospace; }
        .badge { display: inline-block; padding: 0.125rem 0.625rem; border-radius: 9999px; font-size: 10px; font-weight: 600; background: rgba(59, 7, 100, 0.8); color: #d8b4fe; border: 1px solid rgba(107, 33, 168, 0.6); text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0.25rem; }
        h1 { font-size: 1.5rem; font-weight: 700; color: #ffffff; margin: 0 0 0.75rem 0; }
        p.lead { color: #cbd5e1; font-size: 0.875rem; line-height: 1.5; margin: 0 0 0.5rem 0; }
        p.sub { color: #94a3b8; font-size: 0.8125rem; line-height: 1.5; margin: 0 0 1.5rem 0; }
        .notice { background: rgba(59, 7, 100, 0.3); border: 1px solid rgba(107, 33, 168, 0.4); color: #d8b4fe; border-radius: 0.75rem; padding: 0.75rem; font-size: 0.75rem; margin-bottom: 1.5rem; }
        .ref-box { background: rgba(2, 6, 23, 0.8); border: 1px solid rgba(30, 41, 59, 0.8); border-radius: 0.75rem; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.75rem; }
        .ref-row { display: flex; justify-content: space-between; align-items: center; color: #94a3b8; }
        .ref-val { font-family: monospace; color: #d8b4fe; font-weight: 600; }
        .btn-primary { display: block; width: 100%; box-sizing: border-box; text-align: center; background: #9333ea; color: #ffffff; font-weight: 500; padding: 0.75rem 1.25rem; border-radius: 0.75rem; text-decoration: none; border: none; cursor: pointer; font-size: 0.875rem; }
        .btn-primary:hover { background: #a855f7; }
        .links { display: flex; gap: 0.75rem; margin-top: 0.75rem; }
        .btn-sec { flex: 1; text-align: center; border: 1px solid #334155; color: #e2e8f0; font-size: 0.75rem; padding: 0.625rem; border-radius: 0.75rem; text-decoration: none; }
        .btn-sec:hover { border-color: rgba(168, 85, 247, 0.5); background: rgba(30, 41, 59, 0.6); }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="icon">
                <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
            </div>
            <div style="text-align: right;">
                <div class="brand">{$appName} &bull; Access Restricted</div>
                <div class="badge">{$statusLabel}</div>
            </div>
        </div>
        <h1>Software License Restricted</h1>
        <p class="lead">This application is currently unavailable because its software license requires attention.</p>
        <p class="sub">Please contact your software provider to restore access.</p>
        <div class="notice">
            <strong>Notice:</strong> {$reasonSafe}
            {$reasonCode}
        </div>
        <div class="ref-box">
            <div class="ref-row">
                <span>Customer Reference:</span>
                <span class="ref-val">{$customerRef}</span>
            </div>
        </div>
        <form method="POST" action="/codelock/recover">
            {$csrfField}
            <button type="submit" class="btn-primary">Verify &amp; Restore Access</button>
        </form>
        <div class="links">
            <a href="mailto:{$contactEmail}" class="btn-sec">Contact Support</a>
            <a href="{$contactUrl}" target="_blank" rel="noopener noreferrer" class="btn-sec">Support Website</a>
        </div>
    </div>
</body>
</html>
HTML;
            return new Response($html, $statusCode, ['Content-Type' => 'text/html']);
        }

        return new Response(view($viewName, [
            'statusInfo' => $statusInfo,
            'reason' => $reason,
        ])->render(), $statusCode, ['Content-Type' => 'text/html']);
    }

    /**
     * Clear all cached verification state.
     */
    public function clearCache(): void
    {
        $this->cachedVerificationResult = null;
        if (app()->bound('request')) {
            request()->attributes->remove('_codelock_result');
        }
        $this->integrityMonitor->clearCache();
        $this->storage->clearMemoryCache();
    }

    /**
     * Execute package file integrity verification.
     */
    public function checkIntegrity(bool $force = false): IntegrityResult
    {
        return $this->integrityMonitor->verify($force);
    }

    public function getIntegrityMonitor(): IntegrityMonitor
    {
        return $this->integrityMonitor;
    }

    public function getCertificate(): ?array
    {
        return $this->storage->loadCertificate();
    }

    public function getLicenseKey(): ?string
    {
        $cert = $this->getCertificate();
        return $cert['payload']['lic'] ?? config('codelock.license_key');
    }

    public function getStorage(): LicenseStorage
    {
        return $this->storage;
    }

    public function getVerifier(): LicenseVerifier
    {
        return $this->verifier;
    }

    public function getClient(): LicenseClient
    {
        return $this->client;
    }

    public function getHeartbeat(): LicenseHeartbeat
    {
        return $this->heartbeat;
    }

    public function getSecurityReporter(): SecurityEventReporter
    {
        return $this->securityReporter;
    }

    /**
     * Neutralize dangerous URL schemes (preventing javascript:, data:, etc.)
     */
    public function sanitizeUrl(?string $url): ?string
    {
        if (empty($url)) {
            return null;
        }
        $parsed = parse_url($url);
        $scheme = strtolower($parsed['scheme'] ?? '');
        return in_array($scheme, ['http', 'https'], true) ? $url : '#';
    }
}
