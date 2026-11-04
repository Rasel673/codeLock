<?php

namespace Rasel\CodeLock\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Rasel\CodeLock\LicenseManager;
use Symfony\Component\HttpFoundation\Response;

class RecoveryController extends Controller
{
    protected LicenseManager $manager;

    /** @var array<string, array<int, int>> */
    protected static array $rateLimits = [];

    protected int $maxAttempts = 3;
    protected int $decaySeconds = 60;

    public function __construct(LicenseManager $manager)
    {
        $this->manager = $manager;
    }

    /**
     * Handle manual or self-service license recovery request.
     */
    public function recover(Request $request): Response
    {
        $ip = $request->ip() ?? '127.0.0.1';

        // 1. Rate Limiting Check
        if ($this->isRateLimited($ip)) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return new JsonResponse([
                    'success' => false,
                    'error' => 'rate_limited',
                    'message' => "Too many recovery attempts. Please wait {$this->decaySeconds} seconds before retrying.",
                ], 429);
            }

            return redirect()->back()->with(
                'codelock_error',
                "Too many recovery attempts. Please wait {$this->decaySeconds} seconds before retrying."
            );
        }

        $this->recordAttempt($ip);

        // 2. Trigger Outbound Heartbeat / Remote Status Refresh
        try {
            $this->manager->refresh();
        } catch (\Throwable $e) {
            // Heartbeat resilience handles offline grace internally
        }

        // 3. Evaluate Verification Result
        $host = $request->getHost();
        $this->manager->clearCache();
        $verification = $this->manager->verify($host, false);

        if ($verification->isValid()) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return new JsonResponse([
                    'success' => true,
                    'message' => 'License verification succeeded. Application access restored.',
                    'status' => $verification->getStatus()->value,
                ], 200);
            }

            $targetUrl = config('app.url', '/');
            return redirect()->to($targetUrl)->with(
                'codelock_success',
                'License verification succeeded! Application access has been restored.'
            );
        }

        // Still locked or restricted
        $reason = $verification->getReason() ?? 'License verification did not succeed. Application remains restricted.';

        if ($request->expectsJson() || $request->is('api/*')) {
            return new JsonResponse([
                'success' => false,
                'status' => $verification->getStatus()->value,
                'code' => $verification->getErrorCode() ?? 'E_LICENSE_RESTRICTION',
                'message' => $reason,
            ], 423);
        }

        return redirect()->back()->with('codelock_error', $reason);
    }

    /**
     * Rate limiter helper.
     */
    protected function isRateLimited(string $ip): bool
    {
        $now = time();
        $attempts = static::$rateLimits[$ip] ?? [];

        // Purge attempts older than decay window
        $validAttempts = array_filter($attempts, fn($t) => ($now - $t) < $this->decaySeconds);
        static::$rateLimits[$ip] = array_values($validAttempts);

        return count(static::$rateLimits[$ip]) >= $this->maxAttempts;
    }

    /**
     * Record a recovery request timestamp.
     */
    protected function recordAttempt(string $ip): void
    {
        static::$rateLimits[$ip][] = time();
    }

    /**
     * Reset rate limits (for test isolation).
     */
    public static function resetRateLimits(): void
    {
        static::$rateLimits = [];
    }
}

