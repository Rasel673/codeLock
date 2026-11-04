<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Http\Controllers\RecoveryController;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseHeartbeat;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class RemoteLockAndRecoveryTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        RecoveryController::resetRateLimits();
        \Illuminate\Support\Facades\Artisan::call('view:clear');

        // Register protected routes for test
        Route::middleware('codelock')->get('/app/dashboard', function () {
            return response()->json(['message' => 'Protected Dashboard Accessed']);
        });

        Route::middleware('codelock')->get('/app/invoices', function () {
            return 'Web Invoices View';
        });
    }

    public function test_remote_suspension_returns_http_403_for_web_and_api(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['crm.example.com']]));

        // Server sets SUSPENDED status
        $signedSuspended = $this->createSignedRemoteStatus([
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'SUSPENDED',
            'lock_message' => 'Invoice #1049 overdue. Please settle balance.',
            'reason_code' => 'BILLING_OVERDUE',
            'action_url' => 'https://billing.example.com/inv/1049',
        ]);
        $storage->saveRemoteStatus($signedSuspended);

        // 1. API Request (JSON)
        $apiResponse = $this->getJson('http://crm.example.com/app/dashboard');
        $apiResponse->assertStatus(403)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_STATUS_SUSPENDED',
                'status' => 'SUSPENDED',
                'message' => 'Invoice #1049 overdue. Please settle balance.',
                'reason_code' => 'BILLING_OVERDUE',
                'action_url' => 'https://billing.example.com/inv/1049',
            ]);

        // 2. Browser Request (HTML)
        $webResponse = $this->get('http://crm.example.com/app/invoices');
        $webResponse->assertStatus(403)
            ->assertSee('Subscription Suspended')
            ->assertSee('Invoice #1049 overdue. Please settle balance.')
            ->assertSee('https://billing.example.com/inv/1049')
            ->assertSee('Verify &amp; Restore Access', false);
    }

    public function test_remote_lock_returns_http_423_for_web_and_api(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['app.example.com']]));

        // Server sets LOCKED status
        $signedLocked = $this->createSignedRemoteStatus([
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'LOCKED',
            'lock_message' => 'Security compliance lock. Unauthorized redistribution suspected.',
            'reason_code' => 'COMPLIANCE_LOCK',
        ]);
        $storage->saveRemoteStatus($signedLocked);

        // 1. API Request
        $apiResponse = $this->getJson('http://app.example.com/app/dashboard');
        $apiResponse->assertStatus(423)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_STATUS_LOCKED',
                'status' => 'LOCKED',
                'message' => 'Security compliance lock. Unauthorized redistribution suspected.',
            ]);

        // 2. Web Request
        $webResponse = $this->get('http://app.example.com/app/invoices');
        $webResponse->assertStatus(423)
            ->assertSee('Access Restricted')
            ->assertSee('Security compliance lock. Unauthorized redistribution suspected.')
            ->assertSee('COMPLIANCE_LOCK');
    }

    public function test_permanent_revocation_returns_http_403(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['revoked.example.com']]));

        // Server sets REVOKED status
        $signedRevoked = $this->createSignedRemoteStatus([
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'REVOKED',
            'lock_message' => 'Contract terminated. Software usage permanently prohibited.',
            'reason_code' => 'CONTRACT_TERMINATED',
        ]);
        $storage->saveRemoteStatus($signedRevoked);

        // API request
        $apiResponse = $this->getJson('http://revoked.example.com/app/dashboard');
        $apiResponse->assertStatus(403)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_STATUS_REVOKED',
                'status' => 'REVOKED',
                'message' => 'Contract terminated. Software usage permanently prohibited.',
            ]);

        // Web request
        $webResponse = $this->get('http://revoked.example.com/app/invoices');
        $webResponse->assertStatus(403)
            ->assertSee('License Revoked')
            ->assertSee('Contract terminated. Software usage permanently prohibited.');
    }

    public function test_self_service_recovery_restores_access_after_admin_unlocks(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['app.example.com']]));

        // Initially LOCKED
        $signedLocked = $this->createSignedRemoteStatus([
            'sta' => 'LOCKED',
            'lock_message' => 'Temporarily locked pending verification.',
        ]);
        $storage->saveRemoteStatus($signedLocked);

        // Assert locked initially
        $this->getJson('http://app.example.com/app/dashboard')->assertStatus(423);

        // Vendor admin unlocks customer: Next heartbeat returns ACTIVE
        $signedActive = $this->createSignedRemoteStatus([
            'sta' => 'ACTIVE',
            'deadline' => time() + (86400 * 7),
        ]);

        $mock = new MockHandler([
            new Response(200, [], json_encode($signedActive)),
        ]);
        $handlerStack = HandlerStack::create($mock);
        $http = new GuzzleClient(['handler' => $handlerStack]);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            publicKeys: $this->testPublicKey
        );
        $manager = new LicenseManager(
            storage: $storage,
            client: $client,
            heartbeat: $heartbeat
        );
        $this->app->instance(LicenseManager::class, $manager);
        $this->app->alias(LicenseManager::class, 'codelock');

        // Customer triggers recovery via web endpoint
        $recoverResponse = $this->postJson('http://app.example.com/codelock/recover');
        $recoverResponse->assertStatus(200)
            ->assertJson([
                'success' => true,
                'status' => 'ACTIVE',
            ]);

        // Access to protected route is immediately restored!
        $dashboardResponse = $this->getJson('http://app.example.com/app/dashboard');
        $dashboardResponse->assertStatus(200)
            ->assertJson(['message' => 'Protected Dashboard Accessed']);
    }

    public function test_recovery_endpoint_is_rate_limited_to_prevent_dos(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['app.example.com']]));
        $storage->saveRemoteStatus($this->createSignedRemoteStatus(['sta' => 'LOCKED']));

        $mock = new MockHandler([
            new Response(200, [], json_encode($this->createSignedRemoteStatus(['sta' => 'LOCKED']))),
            new Response(200, [], json_encode($this->createSignedRemoteStatus(['sta' => 'LOCKED']))),
            new Response(200, [], json_encode($this->createSignedRemoteStatus(['sta' => 'LOCKED']))),
        ]);
        $http = new GuzzleClient(['handler' => HandlerStack::create($mock)]);
        $client = new LicenseClient(http: $http);
        $manager = new LicenseManager(
            storage: $storage,
            client: $client,
            heartbeat: new LicenseHeartbeat(storage: $storage, client: $client, publicKeys: $this->testPublicKey)
        );
        $this->app->instance(LicenseManager::class, $manager);
        $this->app->alias(LicenseManager::class, 'codelock');

        // 3 allowed attempts
        $this->postJson('http://app.example.com/codelock/recover')->assertStatus(423);
        $this->postJson('http://app.example.com/codelock/recover')->assertStatus(423);
        $this->postJson('http://app.example.com/codelock/recover')->assertStatus(423);

        // 4th attempt trips rate limiter
        $rateLimited = $this->postJson('http://app.example.com/codelock/recover');
        $rateLimited->assertStatus(429)
            ->assertJson([
                'success' => false,
                'error' => 'rate_limited',
            ]);
    }

    public function test_expired_deadline_locks_application_even_without_network(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['offline.example.com']]));

        // Status is marked ACTIVE, but monotonic deadline expired 1 hour ago
        $expiredDeadlineStatus = $this->createSignedRemoteStatus([
            'sta' => 'ACTIVE',
            'deadline' => time() - 3600,
        ]);
        $storage->saveRemoteStatus($expiredDeadlineStatus);

        $response = $this->getJson('http://offline.example.com/app/dashboard');
        $response->assertStatus(403)
            ->assertJson([
                'error' => 'license_restriction',
                'code' => 'E_GRACE_EXCEEDED',
                'status' => 'EXPIRED',
            ]);
    }

    public function test_tampered_status_cache_is_rejected_due_to_signature_mismatch(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate(['dom' => ['tamper.example.com']]));

        $signedLocked = $this->createSignedRemoteStatus(['sta' => 'LOCKED']);
        
        // Attacker modifies "sta" to "ACTIVE" in storage without knowing private key
        $tamperedPayload = $signedLocked['payload'];
        $tamperedPayload['sta'] = 'ACTIVE';

        $tamperedStatus = [
            'header' => $signedLocked['header'],
            'payload' => $tamperedPayload,
            'signature' => $signedLocked['signature'], // Old signature!
        ];

        $storage->saveRemoteStatus($tamperedStatus);

        $manager = app(LicenseManager::class);
        $manager->clearCache();

        // Verification must strictly reject tampered status signature!
        $result = $manager->verify('tamper.example.com');
        $this->assertFalse($result->isValid());
        $this->assertSame('E_REMOTE_STATUS_FORGED', $result->getErrorCode());

        // Verify local lock state was recorded
        $lockState = $storage->getLastLockState();
        $this->assertNotNull($lockState);
        $this->assertSame('INVALID', $lockState['status']);
    }

    public function test_rejects_cross_tenant_status_injection(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate([
            'dom' => ['tenant-a.com'],
            'lic' => 'CLK-TENANT-A',
        ]));

        // Status signed for TENANT-B injected into TENANT-A
        $rogueStatus = $this->createSignedRemoteStatus([
            'lic' => 'CLK-TENANT-B',
            'sta' => 'LOCKED',
        ]);
        $storage->saveRemoteStatus($rogueStatus);

        $manager = app(LicenseManager::class);
        $manager->clearCache();

        $result = $manager->verify('tenant-a.com');
        $this->assertFalse($result->isValid());
        $this->assertSame('E_IDENTITY_MISMATCH', $result->getErrorCode());
    }

    public function test_rejects_system_clock_prior_to_license_issue_date(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $futureCert = $this->createSignedCertificate([
            'dom' => ['app.example.com'],
            'iat' => time() + 3600, // issued in future relative to system clock
        ]);
        $storage->saveCertificate($futureCert);

        $manager = app(LicenseManager::class);
        $manager->clearCache();

        $result = $manager->verify('app.example.com');
        $this->assertFalse($result->isValid());
        $this->assertSame('E_CLOCK_ROLLBACK_DETECTED', $result->getErrorCode());
    }
}

