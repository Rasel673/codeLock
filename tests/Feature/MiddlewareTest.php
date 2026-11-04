<?php

namespace Rasel\CodeLock\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\Http\Middleware\EnsureLicenseValid;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class MiddlewareTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);

        // Define test routes
        Route::middleware(EnsureLicenseValid::class)->group(function () {
            Route::get('/dashboard', function () {
                return 'ACCESS_GRANTED';
            });
            Route::get('/api/data', function () {
                return response()->json(['data' => 'secure_payload']);
            });
        });

        Route::middleware(EnsureLicenseValid::class)->get('/up', function () {
            return 'UP_AND_RUNNING';
        });
    }

    public function test_allows_request_when_license_is_valid(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['localhost', '127.0.0.1']]);
        $this->storage->saveCertificate($cert);

        $response = $this->get('/dashboard');

        $response->assertStatus(200);
        $this->assertSame('ACCESS_GRANTED', $response->getContent());
    }

    public function test_blocks_request_and_renders_lock_screen_when_unlicensed(): void
    {
        $response = $this->get('/dashboard');

        $response->assertStatus(403);
        $response->assertSee('Access Restricted');
        $response->assertSee('Contact Licensing Support');
    }

    public function test_returns_423_when_license_is_remotely_locked(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['localhost']]);
        $this->storage->saveCertificate($cert);

        // Inject signed remote lock status
        $remotePayload = [
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'LOCKED',
            'lock_message' => 'Remote admin lock applied.',
            'timestamp' => time(),
        ];
        $canonical = CanonicalJson::encode($remotePayload);
        $sig = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        $this->storage->saveRemoteStatus([
            'header' => ['alg' => 'Ed25519'],
            'payload' => $remotePayload,
            'signature' => $sig,
        ]);

        $response = $this->get('/dashboard');

        $response->assertStatus(423);
        $response->assertSee('Remote admin lock applied.');
    }

    public function test_returns_json_error_for_api_requests(): void
    {
        $response = $this->getJson('/api/data');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'license_restriction',
            'status' => 'UNLICENSED',
        ]);
    }

    public function test_bypasses_excluded_routes(): void
    {
        // No license installed, but /up is excluded
        $response = $this->get('/up');

        $response->assertStatus(200);
        $this->assertSame('UP_AND_RUNNING', $response->getContent());
    }
}

