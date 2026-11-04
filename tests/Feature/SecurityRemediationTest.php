<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseHeartbeat;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class SecurityRemediationTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);

        Route::middleware('codelock')->get('/app/secure-area', function () {
            return response()->json(['status' => 'authenticated_access']);
        });
    }

    /**
     * [SEC-01] Domain Spoofing Defense: X-Forwarded-Host header must not bypass domain authorization.
     */
    public function test_sec01_domain_spoofing_via_x_forwarded_host_is_ignored(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.example.com'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // Attacker accesses via unauthorized host, attempting to spoof authorized domain via X-Forwarded-Host
        $response = $this->withHeaders([
            'X-Forwarded-Host' => 'licensed.example.com',
        ])->getJson('http://unauthorized.attacker.io/app/secure-area');

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_DOMAIN_UNAUTHORIZED',
            ]);
    }

    /**
     * [SEC-02] Remote Lock Evasion Defense: Deleting .codelock.status must not unlock an installation.
     */
    public function test_sec02_status_cache_deletion_does_not_evade_remote_lock(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.example.com'],
            'lic' => 'CLK-SEC02-TEST',
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // Record persistent lock state
        $this->storage->recordLockState(LicenseStatus::LOCKED->value, 'Administrative kill order active.', time());

        // Ensure remote status file does not exist (attacker deleted it)
        $this->storage->deleteRemoteStatus();
        $this->assertNull($this->storage->loadRemoteStatus());

        // Middleware check must still block and return E_STATUS_LOCKED
        $response = $this->getJson('http://licensed.example.com/app/secure-area');

        $response->assertStatus(423)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_STATUS_LOCKED',
                'message' => 'Administrative kill order active.',
            ]);
    }

    /**
     * [SEC-03] Replay Attack Defense: Heartbeat response with mismatched nonce must be rejected.
     */
    public function test_sec03_heartbeat_replay_attack_rejected_on_nonce_mismatch(): void
    {
        config(['codelock.testing.strict_nonce' => true]);

        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.example.com'],
            'lic' => 'CLK-REPLAY-TEST',
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // Captured status response with an old/replayed nonce
        $replayedStatus = $this->createSignedRemoteStatus([
            'lic' => 'CLK-REPLAY-TEST',
            'sta' => 'ACTIVE',
            'nonce' => 'captured_old_nonce_from_yesterday',
            'timestamp' => time(),
        ]);

        $mock = new MockHandler([
            new Response(200, [], json_encode($replayedStatus)),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mock)]));
        $heartbeat = new LicenseHeartbeat(storage: $this->storage, client: $client, publicKeys: $this->testPublicKey);

        $result = $heartbeat->send(true);

        $this->assertFalse($result->isSuccess());
        $this->assertSame('E_REPLAY_DETECTED', $result->getErrorCode());
    }

    /**
     * [SEC-03] Monotonic Timestamp Defense: Stale/regressed remote status timestamp must be rejected.
     */
    public function test_sec03_stale_monotonic_timestamp_rejected(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.example.com'],
            'lic' => 'CLK-STALE-TEST',
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // Previous sync was recorded 10 minutes ago
        $this->storage->recordLastSyncTimestamp(time() - 600);

        // Attacker replays envelope with timestamp 20 minutes ago (stale)
        $staleStatus = $this->createSignedRemoteStatus([
            'lic' => 'CLK-STALE-TEST',
            'sta' => 'ACTIVE',
            'timestamp' => time() - 1200,
        ]);

        $mock = new MockHandler([
            new Response(200, [], json_encode($staleStatus)),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mock)]));
        $heartbeat = new LicenseHeartbeat(storage: $this->storage, client: $client, publicKeys: $this->testPublicKey);

        $result = $heartbeat->send(true);

        $this->assertFalse($result->isSuccess());
        $this->assertSame('E_STALE_STATUS', $result->getErrorCode());
    }

    /**
     * [SEC-04] Direct Request Grace Enforcement: Expired offline grace window blocks web requests.
     */
    public function test_sec04_offline_grace_period_enforced_directly_on_middleware_requests(): void
    {
        config(['codelock.offline_grace_period' => 7]); // 7 days grace

        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.example.com'],
            'lic' => 'CLK-GRACE-TEST',
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // Last sync recorded 10 days ago (elapsed exceeds 7 days)
        $tenDaysAgo = time() - (10 * 86400);
        $this->storage->recordLastSyncTimestamp($tenDaysAgo);

        $response = $this->getJson('http://licensed.example.com/app/secure-area');

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_GRACE_EXCEEDED',
                'status' => 'EXPIRED',
            ]);
    }

    /**
     * [SEC-08] CSRF Defense on Recovery: GET requests to /codelock/recover must be rejected.
     */
    public function test_sec08_recovery_route_rejects_get_requests(): void
    {
        $response = $this->get('http://licensed.example.com/codelock/recover');
        $response->assertStatus(405); // Method Not Allowed
    }

    /**
     * [SEC-14] URI Scheme Validation: javascript: URIs in contact URL must be neutralized.
     */
    public function test_sec14_lock_page_sanitizes_javascript_uri_in_contact_url(): void
    {
        config(['codelock.contact_url' => 'javascript:alert(document.cookie)']);

        /** @var LicenseManager $manager */
        $manager = app(LicenseManager::class);
        $response = $manager->renderLockResponse('Testing XSS neutralization');

        $content = $response->getContent();
        $this->assertStringNotContainsString('href="javascript:', $content);
        $this->assertStringContainsString('href="#"', $content);
    }
}
