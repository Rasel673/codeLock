<?php

namespace Rasel\CodeLock;

use Rasel\CodeLock\Enums\SecurityEventCode;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\LicenseKey;
use Rasel\CodeLock\Support\MachineFingerprint;

/**
 * Dispatches rate-limited, sanitized, untrusted client security telemetry to the license server.
 *
 * In accordance with commercial security guidelines:
 * - Telemetry is fire-and-forget: failure to report never halts the customer application.
 * - Client reports are classified as untrusted evidence: they never directly lock licenses.
 * - Customer database contents, passwords, API tokens, and payment data are strictly redacted.
 * - Client-side rate limiting prevents runaway reporting loops.
 */
class SecurityEventReporter
{
    protected LicenseClient $client;
    protected ?LicenseStorage $storage;
    protected int $maxReportsPerHour;
    protected int $repeatedFailureThreshold;
    protected array $inMemoryRateLimits = [];
    protected int $consecutiveVerificationFailures = 0;
    protected array $recentFailureContexts = [];

    /**
     * Regex patterns for sensitive keys that MUST be redacted.
     */
    protected const SENSITIVE_KEY_PATTERN = '/^(?:.*_)?(?:password|passwd|secret|token|api_key|apikey|auth|jwt|bearer|card|cvv|credit|database|db_password|session|cookie|private_key|pin|ssn)(?:_.*)?$/i';

    public function __construct(
        ?LicenseClient $client = null,
        ?LicenseStorage $storage = null,
        int $maxReportsPerHour = 5,
        int $repeatedFailureThreshold = 5
    ) {
        $this->client = $client ?? new LicenseClient();
        $this->storage = $storage;
        $this->maxReportsPerHour = $maxReportsPerHour;
        $this->repeatedFailureThreshold = $repeatedFailureThreshold;
    }

    /**
     * Report an integrity mismatch event (e.g. modified files).
     */
    public function reportIntegrityMismatch(
        array $modifiedFiles,
        ?string $reason = null,
        SecurityEventCode|string $eventCode = SecurityEventCode::TAMPER_DETECTED
    ): array {
        return $this->report(
            $eventCode,
            'CRITICAL',
            [
                'reason' => $reason ?? 'Protected package files have been modified.',
                'modified_files' => array_values($modifiedFiles),
            ]
        );
    }

    /**
     * Report missing protected files.
     */
    public function reportMissingProtectedFile(array $missingFiles, ?string $reason = null): array
    {
        return $this->report(
            SecurityEventCode::MISSING_PROTECTED_FILE,
            'CRITICAL',
            [
                'reason' => $reason ?? 'Required package enforcement files are missing.',
                'missing_files' => array_values($missingFiles),
            ]
        );
    }

    /**
     * Report an invalid cryptographic signature.
     */
    public function reportInvalidSignature(string $context, ?string $reason = null): array
    {
        return $this->report(
            SecurityEventCode::INVALID_SIGNATURE,
            'CRITICAL',
            [
                'reason' => $reason ?? 'Ed25519 signature verification failed.',
                'context' => $context,
            ]
        );
    }

    /**
     * Report an unauthorized domain access attempt.
     */
    public function reportDomainMismatch(string $attemptedDomain, array $allowedDomains = []): array
    {
        return $this->report(
            SecurityEventCode::DOMAIN_MISMATCH,
            'WARNING',
            [
                'reason' => "Host [{$attemptedDomain}] is not authorized.",
                'attempted_domain' => $attemptedDomain,
                'allowed_domains' => $allowedDomains,
            ],
            domain: $attemptedDomain
        );
    }

    /**
     * Report suspicious configuration modifications.
     */
    public function reportSuspiciousConfig(array $suspiciousChanges): array
    {
        return $this->report(
            SecurityEventCode::SUSPICIOUS_CONFIG,
            'HIGH',
            [
                'reason' => 'Suspicious runtime configuration alterations detected.',
                'changes' => $suspiciousChanges,
            ]
        );
    }

    /**
     * Report repeated verification failures (e.g. brute force or tampering attempt).
     */
    public function reportRepeatedVerificationFailures(int $failureCount, string $context, array $recentErrors = []): array
    {
        return $this->report(
            SecurityEventCode::REPEATED_VERIFICATION_FAILURES,
            'CRITICAL',
            [
                'reason' => "Repeated license verification failures detected ({$failureCount} consecutive failures).",
                'failure_count' => $failureCount,
                'context' => $context,
                'recent_errors' => $recentErrors,
            ]
        );
    }

    /**
     * Track a verification failure and automatically report if threshold is reached.
     */
    public function recordVerificationFailure(string $context, ?string $reason = null): void
    {
        $this->consecutiveVerificationFailures++;
        $this->recentFailureContexts[] = [
            'time' => time(),
            'context' => $context,
            'reason' => $reason ?? 'Verification failure',
        ];

        // Keep only the last 10 error records in memory
        if (count($this->recentFailureContexts) > 10) {
            array_shift($this->recentFailureContexts);
        }

        if ($this->consecutiveVerificationFailures >= $this->repeatedFailureThreshold) {
            $count = $this->consecutiveVerificationFailures;
            $errors = array_map(fn($item) => $item['reason'], $this->recentFailureContexts);
            $this->reportRepeatedVerificationFailures($count, $context, $errors);
            // Reset counter after reporting to avoid redundant repeated triggers
            $this->consecutiveVerificationFailures = 0;
        }
    }

    /**
     * Reset verification failure counter (invoked on successful license verification).
     */
    public function resetVerificationFailures(): void
    {
        $this->consecutiveVerificationFailures = 0;
        $this->recentFailureContexts = [];
    }

    public function getConsecutiveFailures(): int
    {
        return $this->consecutiveVerificationFailures;
    }

    /**
     * Dispatch a sanitized, rate-limited security report to the license server.
     *
     * @param SecurityEventCode|string $event
     * @param string $severity INFO|WARNING|HIGH|CRITICAL|ALERT
     * @param array $details
     * @param ?string $licenseKey
     * @param ?string $domain
     * @return array Telemetry dispatch outcome
     */
    public function report(
        SecurityEventCode|string $event,
        string $severity,
        array $details,
        ?string $licenseKey = null,
        ?string $domain = null
    ): array {
        $eventCode = $event instanceof SecurityEventCode ? $event->value : (string) $event;

        // 1. Client-Side Rate Limiting Check
        if ($this->isRateLimited($eventCode)) {
            return [
                'reported' => false,
                'rate_limited' => true,
                'event_code' => $eventCode,
                'reason' => "Rate limit of {$this->maxReportsPerHour} reports/hour reached for event [{$eventCode}].",
            ];
        }

        // 2. Strict Data Sanitization & Secret Redaction
        $sanitizedDetails = $this->sanitizeDetails($details);

        // 3. Resolve Identity Safely
        $key = $licenseKey ?? (string) config('codelock.license_key', '');
        $cleanKey = !empty($key) ? LicenseKey::normalize($key) : 'UNSPECIFIED';
        $instanceId = (string) (config('codelock.installation_id') ?? MachineFingerprint::get());

        // 4. Record Rate Limit Hit Before Network Attempt
        $this->recordRateLimitHit($eventCode);

        // 5. Build Safe Untrusted Telemetry Envelope
        $payload = [
            'telemetry_type' => 'UNTRUSTED_CLIENT_TELEMETRY',
            'event_code' => $eventCode,
            'severity' => strtoupper($severity),
            'license_key' => $cleanKey,
            'instance_id' => $instanceId,
            'domain' => $domain ?? (string) (config('app.url') ? parse_url(config('app.url'), PHP_URL_HOST) : 'unknown'),
            'details' => $sanitizedDetails,
            'client_timestamp' => time(),
        ];

        // 6. Safe Fire-and-Forget Dispatch
        try {
            $response = $this->client->reportSecurityEvent(
                $eventCode,
                $severity,
                $sanitizedDetails,
                $cleanKey,
                $domain
            );

            $wasReported = !isset($response['status']) || $response['status'] !== 'failed_to_report';

            return [
                'reported' => $wasReported,
                'rate_limited' => false,
                'event_code' => $eventCode,
                'response' => $response,
            ];
        } catch (\Throwable $e) {
            // Under no circumstances should security telemetry failure crash the client application
            return [
                'reported' => false,
                'rate_limited' => false,
                'event_code' => $eventCode,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Recursively sanitize all context data to guarantee zero leaks of passwords, database dumps, or secrets.
     */
    public function sanitizeDetails(array $data, int $depth = 0): array
    {
        if ($depth > 5) {
            return ['[TRUNCATED_DEPTH]'];
        }

        $sanitized = [];

        foreach ($data as $key => $value) {
            $keyStr = (string) $key;

            // Check if key matches sensitive patterns
            if (preg_match(self::SENSITIVE_KEY_PATTERN, $keyStr)) {
                $sanitized[$keyStr] = '[REDACTED]';
                continue;
            }

            if (is_array($value)) {
                $sanitized[$keyStr] = $this->sanitizeDetails($value, $depth + 1);
            } elseif (is_string($value)) {
                $sanitized[$keyStr] = $this->sanitizeString($value);
            } elseif (is_scalar($value) || $value === null) {
                $sanitized[$keyStr] = $value;
            } else {
                $sanitized[$keyStr] = '[OBJECT:' . get_class($value) . ']';
            }
        }

        return $sanitized;
    }

    /**
     * Clean strings of raw database queries, credit card numbers, or excessive lengths.
     */
    protected function sanitizeString(string $val): string
    {
        // 1. Redact potential SQL statements
        if (preg_match('/\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM)\b/i', $val)) {
            return '[SQL_QUERY_REDACTED]';
        }

        // 2. Redact potential credit card numbers (Luhn-like 13-16 digits)
        $val = preg_replace('/\b(?:\d[ -]*?){13,16}\b/', '[CARD_REDACTED]', $val);

        // 3. Limit string length to 1000 characters to prevent accidental file dumps
        if (strlen($val) > 1000) {
            $val = substr($val, 0, 1000) . '...[TRUNCATED]';
        }

        return $val;
    }

    /**
     * Determine if an event is currently rate limited.
     */
    public function isRateLimited(string $eventCode): bool
    {
        $now = time();
        $window = 3600; // 1 hour

        // Purge expired hits from memory
        $hits = $this->inMemoryRateLimits[$eventCode] ?? [];
        $validHits = array_filter($hits, fn($timestamp) => ($now - $timestamp) < $window);
        $this->inMemoryRateLimits[$eventCode] = $validHits;

        return count($validHits) >= $this->maxReportsPerHour;
    }

    /**
     * Record a rate limit hit for an event.
     */
    protected function recordRateLimitHit(string $eventCode): void
    {
        $this->inMemoryRateLimits[$eventCode][] = time();
    }

    /**
     * Reset rate limits (primarily for testing).
     */
    public function resetRateLimits(): void
    {
        $this->inMemoryRateLimits = [];
    }
}

