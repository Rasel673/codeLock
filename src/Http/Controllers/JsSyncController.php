<?php

namespace Rasel\CodeLock\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response as HttpResponse;
use Illuminate\Routing\Controller;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Support\JsGuardBuilder;
use Symfony\Component\HttpFoundation\Response;

/**
 * Handles background 5-minute JS synchronization requests and serves the
 * fallback encrypted runtime script when the static asset has not yet been published.
 */
class JsSyncController extends Controller
{
    protected LicenseManager $manager;
    protected JsGuardBuilder $builder;

    /** @var array<string, array<int, int>> */
    protected static array $rateLimits = [];

    protected int $maxAttempts = 30;
    protected int $decaySeconds = 60;

    public function __construct(LicenseManager $manager, ?JsGuardBuilder $builder = null)
    {
        $this->manager = $manager;
        $this->builder = $builder ?? new JsGuardBuilder();
    }

    /**
     * Serve the encrypted JavaScript guard dynamically if static publishing hasn't been executed.
     */
    public function script(): Response
    {
        if (!$this->manager->isEnabled() || !config('codelock.js_guard.enabled', true)) {
            return new HttpResponse('/* CodeLock JS Guard Disabled */', 200, [
                'Content-Type' => 'application/javascript; charset=utf-8',
                'Cache-Control' => 'no-store, no-cache, must-revalidate',
            ]);
        }

        $script = $this->builder->build();

        return new HttpResponse($script, 200, [
            'Content-Type' => 'application/javascript; charset=utf-8',
            'Cache-Control' => 'public, max-age=300',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    /**
     * Verify current license validity and trigger background heartbeat sync if due.
     */
    public function sync(Request $request): Response
    {
        $ip = $request->ip() ?? '127.0.0.1';
        $intervalSeconds = max(60, (int) config('codelock.js_guard.interval_minutes', 5) * 60);

        if (!$this->manager->isEnabled()) {
            return new JsonResponse([
                'verified' => true,
                'valid' => true,
                'status' => 'DISABLED',
                'next_sync_in' => $intervalSeconds,
                'synced_at' => time(),
            ], 200);
        }

        if ($this->isRateLimited($ip)) {
            return new JsonResponse([
                'verified' => false,
                'valid' => true,
                'error' => 'rate_limited',
                'message' => 'Too many sync checks. Retry later.',
                'next_sync_in' => $intervalSeconds,
            ], 429);
        }

        $this->recordAttempt($ip);

        $host = $request->getHost();
        $storage = $this->manager->getStorage();
        $heartbeat = $this->manager->getHeartbeat();

        // Trigger remote heartbeat synchronization if due and certificate exists
        if ($storage->hasCertificate() && config('codelock.heartbeat_enabled', true) && $heartbeat->shouldSendHeartbeat()) {
            $lock = $storage->acquireSyncLock(120);
            if ($lock) {
                try {
                    $heartbeat->send(true);
                    $this->manager->clearCache();
                } catch (\Throwable $e) {
                    // Fail safely under offline grace handling without disrupting client visitors
                } finally {
                    $storage->releaseSyncLock($lock);
                }
            }
        }

        $verification = $this->manager->verify($host, false);

        if ($verification->isValid()) {
            return new JsonResponse([
                'verified' => true,
                'valid' => true,
                'status' => $verification->getStatus()->value,
                'next_sync_in' => $intervalSeconds,
                'synced_at' => time(),
            ], 200);
        }

        $statusCode = $verification->getStatus() === LicenseStatus::LOCKED ? 423 : 403;

        return new JsonResponse([
            'verified' => true,
            'valid' => false,
            'status' => $verification->getStatus()->value,
            'code' => $verification->getErrorCode() ?? 'E_LICENSE_RESTRICTION',
            'message' => $verification->getReason() ?? 'This application requires an active software license.',
            'contact_email' => config('codelock.contact_email'),
            'contact_url' => $this->manager->sanitizeUrl(config('codelock.contact_url')),
            'next_sync_in' => $intervalSeconds,
        ], $statusCode);
    }

    /**
     * Rate limiter helper.
     */
    protected function isRateLimited(string $ip): bool
    {
        $now = time();
        $attempts = static::$rateLimits[$ip] ?? [];

        $validAttempts = array_filter($attempts, fn($t) => ($now - $t) < $this->decaySeconds);
        static::$rateLimits[$ip] = array_values($validAttempts);

        return count(static::$rateLimits[$ip]) >= $this->maxAttempts;
    }

    /**
     * Record sync attempt timestamp.
     */
    protected function recordAttempt(string $ip): void
    {
        static::$rateLimits[$ip][] = time();
    }

    /**
     * Clear static rate limits for test isolation.
     */
    public static function resetRateLimits(): void
    {
        static::$rateLimits = [];
    }
}

