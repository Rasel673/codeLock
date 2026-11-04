<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Exceptions\LicenseNotFoundException;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseHeartbeat;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\RemoteLicenseStatus;
use Rasel\CodeLock\SecurityEventReporter;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class HeartbeatTest extends TestCase
{
    protected function createMockHttpClient(array $responses, array &$container = []): GuzzleClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        $handlerStack->push(Middleware::history($container));

        return new GuzzleClient(['handler' => $handlerStack]);
    }

    public function test_heartbeat_fails_when_no_license_installed(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $heartbeat = new LicenseHeartbeat(storage: $storage);

        $this->expectException(LicenseNotFoundException::class);
        $heartbeat->send();
    }

    public function test_successful_heartbeat_sends_required_fields_and_authenticates_requests(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-HB-TEST',
            'prd' => 'PROD-TEST',
            'dom' => ['example.com'],
        ]);
        $storage->saveCertificate($cert);

        $signedRemoteStatus = $this->createSignedRemoteStatus([
            'lic' => 'CLK-2026-HB-TEST',
            'sta' => 'ACTIVE',
            'deadline' => time() + (86400 * 7),
        ]);

        $container = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($signedRemoteStatus)),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            productId: 'PROD-TEST'
        );

        $result = $heartbeat->send(true);

        $this->assertTrue($result->isSuccess());
        $this->assertFalse($result->isOffline());
        $this->assertInstanceOf(RemoteLicenseStatus::class, $result->getStatus());
        $this->assertSame(LicenseStatus::ACTIVE, $result->getStatus()->getStatus());

        // Verify request payload transmitted to server
        $this->assertNotEmpty($container);
        $req = $container[0]['request'];
        $this->assertSame('/api/v1/license/heartbeat', $req->getUri()->getPath());

        $body = json_decode((string) $req->getBody(), true);
        $this->assertArrayHasKey('installation_id', $body);
        $this->assertArrayHasKey('product_id', $body);
        $this->assertSame('PROD-TEST', $body['product_id']);
        $this->assertArrayHasKey('license_id', $body);
        $this->assertSame('CLK-2026-HB-TEST', $body['license_id']);
        $this->assertArrayHasKey('authorized_domain', $body);
        $this->assertArrayHasKey('package_version', $body);
        $this->assertArrayHasKey('integrity_status', $body);
        $this->assertArrayHasKey('timestamp', $body);
        $this->assertArrayHasKey('nonce', $body);

        // Verify request authentication headers
        $this->assertTrue($req->hasHeader('X-CodeLock-Signature'));
        $this->assertTrue($req->hasHeader('X-CodeLock-Timestamp'));
        $this->assertTrue($req->hasHeader('X-CodeLock-Nonce'));
        $this->assertTrue($req->hasHeader('X-CodeLock-Key'));
        $this->assertTrue($req->hasHeader('X-CodeLock-Instance'));

        // Verify HMAC signature validity
        $computedHmac = hash_hmac('sha256', CanonicalJson::encode($body), 'CLK-2026-HB-TEST');
        $this->assertSame($computedHmac, $req->getHeaderLine('X-CodeLock-Signature'));

        // Verify status was persisted locally
        $savedStatus = $storage->loadRemoteStatus();
        $this->assertNotNull($savedStatus);
        $this->assertSame('ACTIVE', $savedStatus['payload']['sta']);
        $this->assertGreaterThan(0, $storage->getLastSyncTimestamp());
    }

    public function test_network_failure_enters_offline_grace_period_without_crashing(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-OFFLINE-GRACE',
            'iat' => time() - 3600, // issued 1 hour ago
        ]);
        $storage->saveCertificate($cert);

        $container = [];
        $http = $this->createMockHttpClient([
            new ConnectException('Connection refused by license server', new Request('POST', '/api/v1/license/heartbeat')),
        ], $container);

        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            gracePeriodDays: 7
        );

        // Send heartbeat during network outage
        $result = $heartbeat->send(true);

        $this->assertFalse($result->isSuccess());
        $this->assertTrue($result->isOffline());
        $this->assertTrue($result->isGraceActive());
        $this->assertFalse($result->isGraceExpired());
        $this->assertGreaterThan(0, $result->getRemainingGraceSeconds());
        $this->assertStringContainsString('Operating in offline grace period', $result->getMessage());
    }

    public function test_offline_grace_period_expires_when_elapsed_time_exceeds_threshold(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $cert = $this->createSignedCertificate(['lic' => 'CLK-EXPIRED-GRACE']);
        $storage->saveCertificate($cert);

        // Simulate last sync was 10 days ago
        $tenDaysAgo = time() - (86400 * 10);
        $storage->recordLastSyncTimestamp($tenDaysAgo);

        $http = $this->createMockHttpClient([
            new ConnectException('Network down', new Request('POST', '/api/v1/license/heartbeat')),
        ]);

        $client = new LicenseClient(http: $http);

        // Grace period is 7 days
        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            gracePeriodDays: 7
        );

        $result = $heartbeat->send(true);

        $this->assertFalse($result->isSuccess());
        $this->assertTrue($result->isOffline());
        $this->assertFalse($result->isGraceActive());
        $this->assertTrue($result->isGraceExpired());
        $this->assertSame('E_GRACE_EXCEEDED', $result->getErrorCode());
        $this->assertStringContainsString('Offline grace period of 7 days has elapsed', $result->getMessage());
    }

    public function test_rejects_server_response_with_invalid_cryptographic_signature(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate());

        // Create remote status signed with an unknown key
        $rogueKeyPair = Ed25519Verifier::generateKeyPair();
        $roguePayload = [
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'LOCKED',
            'deadline' => time() + 86400,
            'timestamp' => time(),
            'nonce' => 'rogue_nonce',
        ];
        $rogueSignature = Ed25519Verifier::sign(CanonicalJson::encode($roguePayload), $rogueKeyPair['secret_key']);

        $spoofedResponse = [
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => $roguePayload,
            'signature' => $rogueSignature,
        ];

        $reporterHistory = [];
        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($spoofedResponse)),
            new Response(200, [], json_encode(['status' => 'logged'])), // for security event reporter
        ], $reporterHistory);

        $client = new LicenseClient(http: $http);
        $reporter = new SecurityEventReporter($client, $storage);

        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            reporter: $reporter,
            publicKeys: $this->testPublicKey // Real public key
        );

        $result = $heartbeat->send(true);

        // Must reject invalid signature
        $this->assertFalse($result->isSuccess());
        $this->assertSame('E_SIGNATURE_INVALID', $result->getErrorCode());

        // Must NOT overwrite local status with unverified response
        $this->assertNull($storage->loadRemoteStatus());
    }

    public function test_skips_heartbeat_when_interval_has_not_elapsed(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate());

        // Record sync was performed 1 hour ago
        $storage->recordLastSyncTimestamp(time() - 3600);

        $container = [];
        // No HTTP responses queued, so if a network request is attempted Guzzle will throw an OutOfBoundsException
        $http = $this->createMockHttpClient([], $container);

        $client = new LicenseClient(http: $http);
        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            intervalHours: 24 // 24 hour interval
        );

        $this->assertFalse($heartbeat->shouldSendHeartbeat(false));

        // When force is false, network request should be skipped
        $result = $heartbeat->send(force: false);
        $this->assertTrue($result->isSuccess());
        $this->assertEmpty($container);
        $this->assertStringContainsString('skipped', $result->getMessage());
    }

    public function test_automatic_license_certificate_renewal_during_heartbeat(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $oldCert = $this->createSignedCertificate([
            'lic' => 'CLK-RENEW-TEST',
            'exp' => time() + 3600, // expiring in 1 hour
        ]);
        $storage->saveCertificate($oldCert);

        // New renewed certificate valid for 1 year
        $newCert = $this->createSignedCertificate([
            'lic' => 'CLK-RENEW-TEST',
            'exp' => time() + (86400 * 365),
        ]);

        $signedRemoteStatus = $this->createSignedRemoteStatus([
            'lic' => 'CLK-RENEW-TEST',
            'sta' => 'ACTIVE',
            'renew_license' => true,
            'certificate' => $newCert,
        ]);

        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($signedRemoteStatus)),
        ]);

        $client = new LicenseClient(http: $http);
        $heartbeat = new LicenseHeartbeat(
            storage: $storage,
            client: $client,
            publicKeys: $this->testPublicKey
        );

        $result = $heartbeat->send(true);
        $this->assertTrue($result->isSuccess());

        // Verify stored certificate was atomically updated to new certificate
        $loadedCert = $storage->loadCertificate();
        $this->assertSame($newCert['payload']['exp'], $loadedCert['payload']['exp']);
    }

    public function test_license_manager_refresh_facade_integration(): void
    {
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $storage->saveCertificate($this->createSignedCertificate());

        $signedRemoteStatus = $this->createSignedRemoteStatus([
            'sta' => 'LOCKED',
            'lock_message' => 'Remote lockout active.',
        ]);

        $http = $this->createMockHttpClient([
            new Response(200, [], json_encode($signedRemoteStatus)),
        ]);

        $client = new LicenseClient(http: $http);
        $manager = new LicenseManager(
            storage: $storage,
            client: $client
        );

        $refreshResult = $manager->refresh();
        $this->assertTrue($refreshResult->isSuccess());
        $this->assertSame('LOCKED', $refreshResult['payload']['sta']);
        $this->assertSame('Remote lockout active.', $refreshResult['payload']['lock_message']);

        // Next verification should reflect the locked status
        $verifyResult = $manager->verify('example.com');
        $this->assertFalse($verifyResult->isValid());
        $this->assertSame(LicenseStatus::LOCKED, $verifyResult->getStatus());
    }
}

