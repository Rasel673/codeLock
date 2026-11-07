<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware as GuzzleMiddleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Http\Response as LaravelResponse;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseHeartbeat;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Middleware\EnsureLicensed;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class AutomaticHeartbeatTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);
    }

    protected function createMockHttpClient(array $responses, array &$container = []): GuzzleClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        $handlerStack->push(GuzzleMiddleware::history($container));

        return new GuzzleClient(['handler' => $handlerStack]);
    }

    protected function createValidActiveCertificate(): array
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-AUTO-HB',
            'prd' => 'PROD-TEST',
            'dom' => ['localhost'],
            'iat' => time() - 3600,
        ]);
        $cert['installation_id'] = 'inst_auto_hb_123';
        $this->storage->saveCertificate($cert);

        return $cert;
    }

    protected function createMockSignedResponse(): array
    {
        $payload = [
            'lic' => 'CLK-2026-AUTO-HB',
            'sta' => 'ACTIVE',
            'deadline' => time() + (86400 * 7),
            'timestamp' => time(),
            'nonce' => 'nonce_auto_test',
        ];
        $canonical = CanonicalJson::encode($payload);
        $sig = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        return [
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => $payload,
            'signature' => $sig,
            'status' => 'healthy',
            'directive' => 'continue',
            'is_locked' => false,
        ];
    }

    public function test_middleware_terminate_triggers_automatic_heartbeat_when_due(): void
    {
        $this->createValidActiveCertificate();

        // Simulate last sync was 10 minutes ago
        $tenMinutesAgo = time() - 600;
        $this->storage->recordLastSyncTimestamp($tenMinutesAgo);

        $container = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($this->createMockSignedResponse())),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );
        $this->app->instance(LicenseClient::class, $client);

        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            productId: 'PROD-TEST',
            intervalMinutes: 5
        );
        $this->app->instance(LicenseHeartbeat::class, $heartbeat);

        $manager = new LicenseManager(
            storage: $this->storage,
            client: $client,
            heartbeat: $heartbeat
        );
        $this->app->instance(LicenseManager::class, $manager);

        $middleware = new EnsureLicensed($manager);
        $request = Request::create('http://localhost/', 'GET');
        $response = new LaravelResponse('OK', 200);

        // Run post-response termination
        $middleware->terminate($request, $response);

        // Assert network request was dispatched to licensing server
        $this->assertNotEmpty($container, 'Automatic heartbeat network request should have been dispatched.');
        $req = $container[0]['request'];
        $this->assertSame('/api/v1/license/heartbeat', $req->getUri()->getPath());

        // Assert local sync timestamp updated
        $this->assertGreaterThan($tenMinutesAgo, $this->storage->getLastSyncTimestamp());
    }

    public function test_middleware_terminate_skips_heartbeat_when_interval_has_not_elapsed(): void
    {
        $this->createValidActiveCertificate();

        // Simulate last sync was 1 minute ago (interval is 5 minutes)
        $oneMinuteAgo = time() - 60;
        $this->storage->recordLastSyncTimestamp($oneMinuteAgo);

        $container = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($this->createMockSignedResponse())),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );
        $this->app->instance(LicenseClient::class, $client);

        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            intervalMinutes: 5
        );
        $this->app->instance(LicenseHeartbeat::class, $heartbeat);

        $manager = new LicenseManager(
            storage: $this->storage,
            client: $client,
            heartbeat: $heartbeat
        );

        $middleware = new EnsureLicensed($manager);
        $request = Request::create('http://localhost/', 'GET');
        $response = new LaravelResponse('OK', 200);

        $middleware->terminate($request, $response);

        // No network request dispatched
        $this->assertEmpty($container, 'Heartbeat must not be dispatched when interval has not elapsed.');
    }

    public function test_middleware_terminate_skips_when_automatic_sync_disabled(): void
    {
        $this->createValidActiveCertificate();
        $this->storage->recordLastSyncTimestamp(time() - 3600); // 1 hour ago (due)

        config(['codelock.automatic_sync' => false]);

        $container = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($this->createMockSignedResponse())),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            intervalMinutes: 5
        );

        $manager = new LicenseManager(
            storage: $this->storage,
            client: $client,
            heartbeat: $heartbeat
        );

        $middleware = new EnsureLicensed($manager);
        $request = Request::create('http://localhost/', 'GET');
        $response = new LaravelResponse('OK', 200);

        $middleware->terminate($request, $response);

        $this->assertEmpty($container, 'Heartbeat must not be dispatched when automatic_sync is false.');
    }

    public function test_middleware_terminate_skips_on_excluded_route(): void
    {
        $this->createValidActiveCertificate();
        $this->storage->recordLastSyncTimestamp(time() - 3600);

        $container = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($this->createMockSignedResponse())),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            intervalMinutes: 5
        );

        $manager = new LicenseManager(
            storage: $this->storage,
            client: $client,
            heartbeat: $heartbeat
        );

        $middleware = new EnsureLicensed($manager);
        // Excluded route /up (healthcheck)
        $request = Request::create('http://localhost/up', 'GET');
        $response = new LaravelResponse('OK', 200);

        $middleware->terminate($request, $response);

        $this->assertEmpty($container, 'Heartbeat must not run on excluded health routes.');
    }

    public function test_middleware_terminate_skips_when_concurrency_lock_is_held(): void
    {
        $this->createValidActiveCertificate();
        $this->storage->recordLastSyncTimestamp(time() - 3600);

        // Pre-acquire lock by another process
        $heldLock = $this->storage->acquireSyncLock(120);
        $this->assertNotFalse($heldLock, 'First lock acquisition should succeed.');

        $container = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($this->createMockSignedResponse())),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            intervalMinutes: 5
        );

        $manager = new LicenseManager(
            storage: $this->storage,
            client: $client,
            heartbeat: $heartbeat
        );

        $middleware = new EnsureLicensed($manager);
        $request = Request::create('http://localhost/', 'GET');
        $response = new LaravelResponse('OK', 200);

        // Terminate while lock is busy
        $middleware->terminate($request, $response);

        // Heartbeat should have skipped safely without blocking or error
        $this->assertEmpty($container, 'Heartbeat must not dispatch when another process holds the sync lock.');

        // Cleanup lock
        $this->storage->releaseSyncLock($heldLock);
    }

    public function test_sync_lock_lifecycle_acquires_and_releases(): void
    {
        $lock1 = $this->storage->acquireSyncLock(120);
        $this->assertNotFalse($lock1);

        // Attempting to acquire again on the same path fails non-blockingly
        $lock2 = $this->storage->acquireSyncLock(120);
        $this->assertFalse($lock2);

        // Release first lock
        $this->storage->releaseSyncLock($lock1);

        // Now can acquire again
        $lock3 = $this->storage->acquireSyncLock(120);
        $this->assertNotFalse($lock3);
        $this->storage->releaseSyncLock($lock3);
    }

    public function test_verification_timestamp_throttling_skips_disk_writes_within_60_seconds(): void
    {
        $timeFile = dirname($this->storage->getStoragePath()) . '/.codelock.time';

        $now = time();
        $this->storage->recordVerificationTimestamp($now);
        $this->assertTrue(file_exists($timeFile));

        $mtimeBefore = filemtime($timeFile);

        // Record again 10 seconds later
        $this->storage->recordVerificationTimestamp($now + 10);
        clearstatcache();
        $mtimeAfter = filemtime($timeFile);

        // Mtime should remain unchanged because disk write was throttled
        $this->assertSame($mtimeBefore, $mtimeAfter, 'Disk write should be skipped when timestamp has not advanced by >= 60 seconds.');

        // Record with force flag
        $this->storage->recordVerificationTimestamp($now + 10, true);
        clearstatcache();
        $this->assertTrue(file_exists($timeFile));
    }

    public function test_lock_state_throttling_skips_disk_writes_when_state_unchanged(): void
    {
        $lockStateFile = dirname($this->storage->getStoragePath()) . '/.codelock.lock_state';

        $this->storage->recordLockState('ACTIVE', null, time());
        $this->assertTrue(file_exists($lockStateFile));

        $mtimeBefore = filemtime($lockStateFile);

        // Record same status again
        $this->storage->recordLockState('ACTIVE', null, time() + 5);
        clearstatcache();
        $mtimeAfter = filemtime($lockStateFile);

        $this->assertSame($mtimeBefore, $mtimeAfter, 'Disk write should be skipped when lock state is identical.');
    }
}

