<?php

namespace Rasel\CodeLock\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Support\MachineFingerprint;
use Symfony\Component\HttpFoundation\Response;

class EnsureLicensed
{
    protected LicenseManager $manager;

    public function __construct(LicenseManager $manager)
    {
        $this->manager = $manager;
    }

    /**
     * Handle an incoming request and enforce domain and license validity.
     *
     * @param Request $request
     * @param Closure $next
     * @return Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Check if CodeLock enforcement is globally active
        if (!$this->manager->isEnabled()) {
            return $next($request);
        }

        // 2. Check excluded route paths (e.g. /up, /health, /codelock/*)
        if ($this->isExcludedRoute($request)) {
            return $next($request);
        }

        // 3. Normalize hostname safely
        $hostname = $this->resolveNormalizedHostname($request);

        // 4. Verify signed license, domain, expiration, status, and product identity
        $result = $this->manager->verify($hostname, false);

        if ($result->isValid()) {
            return $next($request);
        }

        // 5. Determine HTTP Status Code
        $statusCode = match ($result->getStatus()) {
            LicenseStatus::LOCKED => 423, // 423 Locked
            default => 403,              // 403 Forbidden
        };

        // 6. Return structured JSON for API requests
        if ($this->wantsJsonResponse($request)) {
            $context = $result->getContext();
            $instanceId = MachineFingerprint::get();
            $customerRef = !empty($instanceId) && $instanceId !== 'N/A'
                ? 'REF-' . strtoupper(substr(hash('crc32b', $instanceId), 0, 8)) . '-' . strtoupper(substr($instanceId, -8))
                : 'REF-GENERAL';

            return new JsonResponse([
                'error' => 'license_restriction',
                'code' => $result->getErrorCode() ?? 'E_LICENSE_RESTRICTION',
                'status' => $result->getStatus()->value,
                'message' => $result->getReason() ?? 'This application is currently unavailable because its software license requires attention.',
                'instruction' => 'Please contact your software provider to restore access.',
                'software_name' => config('app.name', 'Software Application'),
                'customer_reference' => $customerRef,
                'reason_code' => $context['reason_code'] ?? null,
                'action_url' => $context['action_url'] ?? null,
                'domain' => $hostname,
                'contact_email' => config('codelock.contact_email'),
                'contact_url' => config('codelock.contact_url'),
            ], $statusCode);
        }

        // 7. Return professional restriction page for browser requests
        return $this->manager->renderLockResponse($result->getReason(), $statusCode, $hostname);
    }

    /**
     * Resolve and safely normalize the target hostname from the request.
     */
    public function resolveNormalizedHostname(Request $request): string
    {
        // Rely exclusively on Laravel's getHost(), which strictly enforces configured trusted proxies.
        // Direct inspection of X-Forwarded-Host without proxy validation allows arbitrary header injection.
        $rawHost = $request->getHost();

        return $this->normalizeHostname($rawHost);
    }

    /**
     * Sanitize and normalize hostname (lowercase, port stripping, IPv6 clean, dot stripping).
     */
    public function normalizeHostname(string $host): string
    {
        $host = strtolower(trim($host));

        // If multiple comma-separated hosts in proxy header (e.g. host1, host2), take the first one
        if (str_contains($host, ',')) {
            $parts = explode(',', $host);
            $host = trim($parts[0]);
        }

        // Strip http:// or https:// if provided
        if (str_starts_with($host, 'http://') || str_starts_with($host, 'https://')) {
            $parsed = parse_url($host, PHP_URL_HOST);
            $host = $parsed ?: $host;
        }

        // Handle IPv6 brackets [::1] -> ::1
        if (str_starts_with($host, '[') && str_contains($host, ']')) {
            $host = substr($host, 1, strpos($host, ']') - 1);
        } elseif (str_contains($host, ':')) {
            // Strip port number (e.g. app.example.com:8080 -> app.example.com)
            $host = explode(':', $host)[0];
        }

        // Strip trailing dots (e.g. app.example.com. -> app.example.com)
        return rtrim($host, '.');
    }

    /**
     * Determine if request matches an excluded URI pattern.
     */
    protected function isExcludedRoute(Request $request): bool
    {
        $excluded = config('codelock.excluded_paths', []);

        foreach ($excluded as $path) {
            if ($path !== '/') {
                $path = trim($path, '/');
            }

            if ($request->is($path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the request expects or desires a JSON response.
     */
    protected function wantsJsonResponse(Request $request): bool
    {
        return $request->expectsJson()
            || $request->is('api/*')
            || str_contains((string) $request->header('Accept'), 'application/json');
    }

    /**
     * Perform post-response actions, including automatic request-triggered heartbeat synchronization without cron.
     *
     * @param Request $request
     * @param Response $response
     * @return void
     */
    public function terminate(Request $request, Response $response): void
    {
        // 1. Check if CodeLock and automatic synchronization are enabled
        if (!$this->manager->isEnabled()) {
            return;
        }

        if (!config('codelock.automatic_sync', true) || !config('codelock.heartbeat_enabled', true)) {
            return;
        }

        // 2. Check if a local license certificate is installed
        $storage = $this->manager->getStorage();
        if (!$storage->hasCertificate()) {
            return;
        }

        // 3. Skip excluded routes (health probes, webhook callbacks, etc.)
        if ($this->isExcludedRoute($request)) {
            return;
        }

        // 4. Verify local certificate is currently recognized
        $hostname = $this->resolveNormalizedHostname($request);
        $result = $this->manager->verify($hostname, false);
        if (!$result->isValid() && $result->getStatus() === LicenseStatus::UNLICENSED) {
            return;
        }

        // 5. Check if heartbeat is due by interval
        $heartbeat = $this->manager->getHeartbeat();
        if (!$heartbeat->shouldSendHeartbeat()) {
            return;
        }

        // 6. Complete HTTP client response immediately where FastCGI is supported
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }

        // 7. Acquire non-blocking concurrency lock to prevent duplicate concurrent heartbeats
        $lock = $storage->acquireSyncLock(120);
        if (!$lock) {
            return;
        }

        // 8. Dispatch heartbeat check-in safely
        try {
            $heartbeat->send(true);
        } catch (\Throwable $e) {
            Log::warning('CodeLock automatic request-triggered heartbeat synchronization failed: ' . $e->getMessage());
        } finally {
            $storage->releaseSyncLock($lock);
        }
    }
}
