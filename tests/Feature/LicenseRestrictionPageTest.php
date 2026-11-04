<?php

namespace Rasel\CodeLock\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class LicenseRestrictionPageTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        \Illuminate\Support\Facades\Artisan::call('view:clear');

        // Configure deterministic integrity monitoring
        config(['codelock.integrity.stochastic_rate' => 0]);
        config(['app.name' => 'Acme Enterprise CRM']);
        config(['codelock.contact_email' => 'licensing@acme.example.com']);
        config(['codelock.contact_url' => 'https://acme.example.com/support']);

        // Define test routes
        Route::middleware('codelock')->get('/app/dashboard', function () {
            return response()->json(['message' => 'Dashboard Access Granted']);
        });

        Route::middleware('codelock')->get('/app/settings', function () {
            return 'Settings Page';
        });

        Route::middleware('codelock')->get('/up', function () {
            return 'OK';
        });
    }

    public function test_renders_professional_purple_restriction_page_for_browser_requests(): void
    {
        // Unlicensed browser request
        $response = $this->get('http://crm.example.com/app/settings');

        $response->assertStatus(403);

        // Required Exact Messaging
        $response->assertSee('Software License Restricted');
        $response->assertSee('This application is currently unavailable because its software license requires attention.');
        $response->assertSee('Please contact your software provider to restore access.');

        // Purple Accent & Visual Design Tokens
        $response->assertSee('bg-slate-950');
        $response->assertSee('bg-purple-600');
        $response->assertSee('text-purple-400');
        $response->assertSee('border-purple-500/20');
        $response->assertSee('selection:bg-purple-500');

        // Lock Icon SVG Path
        $response->assertSee('M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z');

        // Software Branding
        $response->assertSee('Acme Enterprise CRM');

        // Customer Support Reference Token
        $response->assertSee('Customer Reference:');
        $response->assertSee('REF-');

        // Support Links
        $response->assertSee('licensing@acme.example.com');
        $response->assertSee('https://acme.example.com/support');
        $response->assertSee('Contact Licensing Support');
        $response->assertSee('Support Website');

        // Self-Service Recovery Button
        $response->assertSee('Verify &amp; Restore Access', false);
    }

    public function test_restriction_page_strictly_avoids_data_leakage(): void
    {
        $rawLicenseKey = 'CLK-ULTRA-SECRET-KEY-9999-XXXX';
        $storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $cert = $this->createSignedCertificate([
            'dom' => ['licensed.example.com'],
            'lic' => $rawLicenseKey,
            'prd' => 'PROD-SECRET',
        ]);
        $storage->saveCertificate($cert);

        config(['codelock.license_key' => $rawLicenseKey]);
        config(['codelock.server_url' => 'https://internal-licensing-vault.private.corp/api']);

        // Request from unauthorized domain
        $response = $this->get('http://rogue.example.com/app/settings');

        $response->assertStatus(403);

        // Zero-Leakage Assurances
        $response->assertDontSee($rawLicenseKey);
        $response->assertDontSee('https://internal-licensing-vault.private.corp');
        $response->assertDontSee('Stack trace:');
        $response->assertDontSee('Fatal error');
        $response->assertDontSee('vendor/orchestra');
        $response->assertDontSee('database');
    }

    public function test_api_requests_receive_structured_sanitized_json(): void
    {
        $response = $this->getJson('http://crm.example.com/app/dashboard');

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'license_restriction',
                'status' => 'UNLICENSED',
                'instruction' => 'Please contact your software provider to restore access.',
                'software_name' => 'Acme Enterprise CRM',
                'contact_email' => 'licensing@acme.example.com',
                'contact_url' => 'https://acme.example.com/support',
            ]);

        $json = $response->json();
        $this->assertNotEmpty($json['customer_reference']);
        $this->assertStringStartsWith('REF-', $json['customer_reference']);
    }

    public function test_permitted_routes_and_zero_redirect_loops(): void
    {
        // 1. Health check route /up is excluded and returns HTTP 200
        $healthResponse = $this->get('http://crm.example.com/up');
        $healthResponse->assertStatus(200);
        $healthResponse->assertSee('OK');

        // 2. Lock page returns inline HTTP 403 rather than a 302 redirect loop
        $lockResponse = $this->get('http://crm.example.com/app/settings');
        $this->assertSame(403, $lockResponse->getStatusCode());
        $this->assertFalse($lockResponse->isRedirection());
    }

    public function test_inline_fallback_template_when_blade_view_missing(): void
    {
        config(['codelock.lock_view' => 'codelock::nonexistent_view_file']);

        /** @var LicenseManager $manager */
        $manager = app(LicenseManager::class);
        $response = $manager->renderLockResponse('Custom outage message', 403, 'crm.example.com');

        $this->assertSame(403, $response->getStatusCode());
        $content = $response->getContent();

        $this->assertStringContainsString('Software License Restricted', $content);
        $this->assertStringContainsString('This application is currently unavailable because its software license requires attention.', $content);
        $this->assertStringContainsString('Please contact your software provider to restore access.', $content);
        $this->assertStringContainsString('Acme Enterprise CRM', $content);
        $this->assertStringContainsString('REF-', $content);
        $this->assertStringContainsString('Custom outage message', $content);
        $this->assertStringContainsString('licensing@acme.example.com', $content);
    }
}

