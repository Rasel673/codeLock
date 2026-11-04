<?php

namespace Rasel\CodeLock\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class DomainProtectionTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);

        // Define routes using the 'codelock' middleware alias
        Route::middleware('codelock')->group(function () {
            Route::get('/app/dashboard', function () {
                return 'DASHBOARD_ACCESS_GRANTED';
            });

            Route::get('/api/v1/users', function () {
                return response()->json(['users' => ['Alice', 'Bob']]);
            });
        });

        // Excluded routes
        Route::middleware('codelock')->get('/health', function () {
            return 'SYSTEM_HEALTH_OK';
        });

        Route::middleware('codelock')->get('/up', function () {
            return 'SYSTEM_UP';
        });
    }

    /**
     * Requirement: Exact domain matching on authorized domain.
     */
    public function test_allows_access_on_exact_authorized_domain(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        $response = $this->get('http://crm.example.com/app/dashboard');

        $response->assertStatus(200);
        $this->assertSame('DASHBOARD_ACCESS_GRANTED', $response->getContent());
    }

    /**
     * Requirement: Explicitly authorized subdomains (e.g. wildcards).
     */
    public function test_allows_access_on_authorized_wildcard_subdomain(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['*.saascorp.io'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        $response1 = $this->get('http://tenant-a.saascorp.io/app/dashboard');
        $response1->assertStatus(200);

        $response2 = $this->get('http://tenant-b.saascorp.io/app/dashboard');
        $response2->assertStatus(200);
    }

    /**
     * Requirement: Reject unauthorized domains.
     */
    public function test_rejects_unauthorized_domain_with_browser_lock_page(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.com'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        $response = $this->get('http://pirate-site.com/app/dashboard');

        $response->assertStatus(403);
        $response->assertSee('Access Restricted');
        $response->assertSee('Contact Licensing Support');
        $response->assertSee('pirate-site.com');
    }

    /**
     * Requirement: Reject unauthorized domain with API JSON response.
     */
    public function test_rejects_unauthorized_domain_with_json_response(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.com'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        $response = $this->getJson('http://pirate-site.com/api/v1/users');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'license_restriction',
            'code' => 'E_DOMAIN_UNAUTHORIZED',
            'status' => 'INVALID',
            'domain' => 'pirate-site.com',
        ]);
    }

    /**
     * Requirement: Reject expired licenses.
     */
    public function test_rejects_expired_license(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'prd' => 'PROD-TEST',
            'exp' => time() - 3600, // Expired 1 hour ago
        ]);
        $this->storage->saveCertificate($cert);

        $response = $this->getJson('http://crm.example.com/api/v1/users');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'license_restriction',
            'code' => 'E_TEMPORAL_EXPIRED',
            'status' => 'EXPIRED',
        ]);
    }

    /**
     * Requirement: Reject suspended licenses.
     */
    public function test_rejects_suspended_license(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'prd' => 'PROD-TEST',
            'sta' => 'SUSPENDED',
        ]);
        $this->storage->saveCertificate($cert);

        $response = $this->getJson('http://crm.example.com/api/v1/users');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'license_restriction',
            'code' => 'E_STATUS_SUSPENDED',
            'status' => 'SUSPENDED',
        ]);
    }

    /**
     * Requirement: Reject wrong product identity.
     */
    public function test_rejects_wrong_product(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'prd' => 'INCORRECT-PRODUCT-SKU',
        ]);
        $this->storage->saveCertificate($cert);

        $response = $this->getJson('http://crm.example.com/api/v1/users');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'license_restriction',
            'code' => 'E_PRODUCT_MISMATCH',
        ]);
    }

    /**
     * Requirement: Support excluded routes.
     */
    public function test_supports_excluded_routes_without_valid_license(): void
    {
        // No license installed, yet excluded paths must respond 200 OK
        $response1 = $this->get('/health');
        $response1->assertStatus(200);
        $this->assertSame('SYSTEM_HEALTH_OK', $response1->getContent());

        $response2 = $this->get('/up');
        $response2->assertStatus(200);
        $this->assertSame('SYSTEM_UP', $response2->getContent());
    }

    /**
     * Requirement: Normalize hostname safely (port stripping, trailing dots, reverse proxies).
     */
    public function test_normalizes_hostnames_safely(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // 1. Port stripping: crm.example.com:8443
        $respPort = $this->get('http://crm.example.com:8443/app/dashboard');
        $respPort->assertStatus(200);

        // 2. Trailing dot: crm.example.com.
        $respDot = $this->get('http://crm.example.com./app/dashboard');
        $respDot->assertStatus(200);

        // 3. Reverse proxy header: X-Forwarded-Host
        $respProxy = $this->get('/app/dashboard', [
            'X-Forwarded-Host' => 'crm.example.com',
        ]);
        $respProxy->assertStatus(200);
    }

    /**
     * Requirement: Support development environments without production bypass.
     */
    public function test_development_environments_without_production_bypass(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['production-domain.com'],
            'prd' => 'PROD-TEST',
        ]);
        $this->storage->saveCertificate($cert);

        // In test/local environment with allow_local=true, localhost passes
        config(['codelock.allow_local' => true]);
        $this->app['env'] = 'local';
        config(['app.env' => 'local']);

        $respLocal = $this->get('http://localhost/app/dashboard');
        $respLocal->assertStatus(200);

        // Critical Test: In PRODUCTION environment, localhost MUST BE REJECTED even if allow_local is true!
        $this->app['env'] = 'production';
        config(['app.env' => 'production']);

        $respProd = $this->get('http://localhost/app/dashboard');
        $respProd->assertStatus(403);
    }
}
