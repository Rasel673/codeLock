<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\LicenseVerifier;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class LicenseManagerTest extends TestCase
{
    protected LicenseStorage $storage;
    protected LicenseVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->verifier = new LicenseVerifier($this->storage, $this->testPublicKey, 'PROD-TEST', false);
    }

    public function test_full_activation_and_verification_lifecycle(): void
    {
        // 1. Prepare server mock response with signed certificate
        $serverCert = $this->createSignedCertificate([
            'dom' => ['app.example.com'],
            'lic' => 'CLK-ACTIVATE-TEST',
        ]);

        $mockHandler = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($serverCert)),
        ]);
        $httpClient = new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]);
        $licenseClient = new LicenseClient('https://license.test', 'PROD-TEST', 5, $httpClient);

        $manager = new LicenseManager($this->storage, $this->verifier, $licenseClient);

        // 2. Perform Activation
        $activationResult = $manager->activate('CLK-ACTIVATE-TEST', 'app.example.com');
        $this->assertTrue($activationResult['success']);
        $this->assertSame(LicenseStatus::ACTIVE, $activationResult['status']);

        // 3. Verify Local Persistence
        $this->assertTrue($this->storage->hasCertificate());
        $this->assertTrue($manager->check('app.example.com'));

        // 4. Inspect Status Dictionary
        $status = $manager->status('app.example.com');
        $this->assertTrue($status['valid']);
        $this->assertSame('ACTIVE', $status['status']);
        $this->assertSame('CLK-ACTIVATE-TEST', $status['license_key']);

        // 5. Deactivate
        $deactivateMock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['status' => 'deactivated'])),
        ]);
        $licenseClientWithDeact = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($deactivateMock)]));
        $managerWithDeact = new LicenseManager($this->storage, $this->verifier, $licenseClientWithDeact);

        $this->assertTrue($managerWithDeact->deactivate('app.example.com'));
        $this->assertFalse($this->storage->hasCertificate());
        $this->assertFalse($managerWithDeact->check('app.example.com'));
    }

    public function test_heartbeat_sync_updates_remote_lock_status(): void
    {
        // Setup initial active certificate
        $cert = $this->createSignedCertificate(['dom' => ['app.example.com']]);
        $this->storage->saveCertificate($cert);

        // Create remote status payload signed by server
        $remotePayload = [
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'ins' => 'inst_test',
            'sta' => 'LOCKED',
            'lock_message' => 'Subscription cancelled by administrator.',
            'deadline' => time() + 86400,
            'timestamp' => time(),
            'nonce' => 'nonce_123',
        ];
        $canonical = CanonicalJson::encode($remotePayload);
        $remoteSig = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        $signedRemoteStatus = [
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => $remotePayload,
            'signature' => $remoteSig,
        ];

        $mockHandler = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($signedRemoteStatus)),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]));
        $manager = new LicenseManager($this->storage, $this->verifier, $client);

        // Run Heartbeat
        $result = $manager->heartbeat();
        $this->assertSame('LOCKED', $result['payload']['sta']);

        // Verification must now fail due to remote lock
        $verification = $manager->verify('app.example.com', false);
        $this->assertFalse($verification['valid']);
        $this->assertSame(LicenseStatus::LOCKED, $verification['status']);
        $this->assertSame('Subscription cancelled by administrator.', $verification['reason']);
    }
}

