<?php

namespace Rasel\CodeLock\Tests\Feature;

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\Middleware\EnsureLicensed;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class GlobalMiddlewareTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);

        // Define raw unannotated routes without any route middleware
        Route::get('/unannotated-page', function () {
            return 'PROTECTED_GLOBAL_CONTENT';
        });

        Route::get('/api/unannotated-data', function () {
            return response()->json(['secret' => 'global_secret_data']);
        });

        Route::get('/up', function () {
            return 'SYSTEM_HEALTHY';
        });
    }

    public function test_global_middleware_is_registered_on_http_kernel(): void
    {
        $kernel = $this->app->make(HttpKernel::class);

        $this->assertTrue(
            $kernel->hasMiddleware(EnsureLicensed::class),
            'EnsureLicensed middleware must be registered on the global HTTP Kernel.'
        );
    }

    public function test_global_middleware_protects_unannotated_web_route_when_unlicensed(): void
    {
        // No certificate installed
        $response = $this->get('/unannotated-page');

        $response->assertStatus(403);
        $response->assertSee('Access Restricted');
    }

    public function test_global_middleware_protects_unannotated_api_route_when_unlicensed(): void
    {
        $response = $this->getJson('/api/unannotated-data');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'license_restriction',
            'status' => 'UNLICENSED',
        ]);
    }

    public function test_global_middleware_allows_unannotated_routes_when_license_is_valid(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['localhost', '127.0.0.1']]);
        $this->storage->saveCertificate($cert);

        $response = $this->get('/unannotated-page');
        $response->assertStatus(200);
        $this->assertSame('PROTECTED_GLOBAL_CONTENT', $response->getContent());

        $apiResponse = $this->getJson('/api/unannotated-data');
        $apiResponse->assertStatus(200);
        $apiResponse->assertJson(['secret' => 'global_secret_data']);
    }

    public function test_global_middleware_bypasses_excluded_paths_when_unlicensed(): void
    {
        // /up is excluded by default in config
        $response = $this->get('/up');

        $response->assertStatus(200);
        $this->assertSame('SYSTEM_HEALTHY', $response->getContent());
    }
}
