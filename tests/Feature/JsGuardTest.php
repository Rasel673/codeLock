<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware as GuzzleMiddleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Rasel\CodeLock\Http\Controllers\JsSyncController;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseHeartbeat;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\LicenseVerifier;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Support\JsGuardBuilder;
use Rasel\CodeLock\Tests\TestCase;

class JsGuardTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        JsSyncController::resetRateLimits();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);
    }

    protected function tearDown(): void
    {
        JsSyncController::resetRateLimits();
        parent::tearDown();
    }

    public function test_builder_encrypts_payload_without_leaking_secrets_or_plaintext_urls(): void
    {
        config([
            'codelock.license_key' => 'CLK-SECRET-KEY-9999-DO-NOT-EXPOSE',
            'codelock.public_key' => $this->testPublicKey,
        ]);

        $overrides = [
            'server_url' => 'https://license.example.test',
            'product_id' => 'PROD-JS-TEST',
            'interval_minutes' => 5,
            'contact_email' => 'licensing@example.test',
            'contact_url' => 'https://support.example.test',
        ];

        $builder = new JsGuardBuilder();
        $plain = $builder->buildPlainSource($overrides);
        $encrypted = $builder->build($overrides);

        $this->assertStringStartsWith('/* CodeLock Runtime Protection Guard */', $encrypted);

        // Plaintext URLs, routes, and UI copy must not appear in encrypted ciphertext
        $this->assertStringNotContainsString('https://license.example.test', $encrypted);
        $this->assertStringNotContainsString('/codelock/js-sync', $encrypted);
        $this->assertStringNotContainsString('Software License Restricted', $encrypted);
        $this->assertStringNotContainsString('PROD-JS-TEST', $encrypted);

        // Secrets must never appear in either ciphertext or decrypted browser script
        foreach ([$encrypted, $plain] as $content) {
            $this->assertStringNotContainsString('CLK-SECRET-KEY-9999-DO-NOT-EXPOSE', $content);
            $this->assertStringNotContainsString($this->testPublicKey, $content);
            $this->assertStringNotContainsString($this->testSecretKey, $content);
            $this->assertStringNotContainsString('installation_token', $content);
        }

        // Verify RC4 round-trip matches buildPlainSource()
        $matched = preg_match('/\}\)\("([^"]+)","([^"]+)"\);/', $encrypted, $matches);
        $this->assertSame(1, $matched, 'Expected encrypted wrapper to embed key and base64 payload.');

        $decoded = $builder->rc4($matches[1], base64_decode($matches[2], true));
        $this->assertSame($plain, $decoded);
        $this->assertStringContainsString('"iv":300000', $decoded);
        $this->assertStringContainsString('/codelock/js-sync', $decoded);
        $this->assertStringContainsString('https://license.example.test/api/v1/public/domain-verify', $decoded);
    }

    public function test_builder_sanitizes_javascript_urls_and_ignores_placeholder_server(): void
    {
        $builder = new JsGuardBuilder();
        $plain = $builder->buildPlainSource([
            'server_url' => 'https://license.yourdomain.com',
            'contact_url' => 'javascript:alert(1)',
        ]);

        $this->assertStringContainsString('"fu":""', $plain);
        $this->assertStringContainsString('"cu":""', $plain);
        $this->assertStringNotContainsString('javascript:alert', $plain);
    }

    public function test_guard_script_route_serves_encrypted_javascript(): void
    {
        $response = $this->get('/codelock/guard.js');

        $response->assertStatus(200);
        $this->assertStringContainsString('application/javascript', (string) $response->headers->get('Content-Type'));
        $body = (string) $response->getContent();
        $this->assertStringStartsWith('/* CodeLock Runtime Protection Guard */', $body);
        $this->assertStringNotContainsString('/codelock/js-sync', $body);
    }

    public function test_guard_script_route_returns_disabled_stub_when_disabled(): void
    {
        config(['codelock.js_guard.enabled' => false]);

        $response = $this->get('/codelock/guard.js');

        $response->assertStatus(200);
        $this->assertStringContainsString('CodeLock JS Guard Disabled', (string) $response->getContent());
    }

    public function test_js_sync_endpoint_returns_valid_when_licensed_and_when_disabled(): void
    {
        config(['codelock.enabled' => false]);
        $disabledResp = $this->postJson('/codelock/js-sync', ['domain' => 'localhost']);
        $disabledResp->assertStatus(200)->assertJson([
            'verified' => true,
            'valid' => true,
            'status' => 'DISABLED',
            'next_sync_in' => 300,
        ]);

        config(['codelock.enabled' => true]);
        $cert = $this->createSignedCertificate(['dom' => ['localhost', '127.0.0.1']]);
        $this->storage->saveCertificate($cert);

        $validResp = $this->postJson('/codelock/js-sync', ['domain' => 'localhost']);
        $validResp->assertStatus(200)->assertJson([
            'verified' => true,
            'valid' => true,
            'status' => 'ACTIVE',
            'next_sync_in' => 300,
        ]);
    }

    public function test_js_sync_endpoint_returns_verified_denial_when_unlicensed_or_locked(): void
    {
        // Unlicensed
        $unlicensed = $this->postJson('/codelock/js-sync');
        $unlicensed->assertStatus(403)->assertJson([
            'verified' => true,
            'valid' => false,
            'status' => 'UNLICENSED',
        ]);

        // Locked remotely
        $cert = $this->createSignedCertificate(['dom' => ['localhost']]);
        $this->storage->saveCertificate($cert);

        $remoteStatus = $this->createSignedRemoteStatus([
            'sta' => 'LOCKED',
            'lock_message' => 'Subscription paused by vendor.',
        ]);
        $this->storage->saveRemoteStatus($remoteStatus);

        $locked = $this->postJson('/codelock/js-sync');
        $locked->assertStatus(423)->assertJson([
            'verified' => true,
            'valid' => false,
            'status' => 'LOCKED',
            'message' => 'Subscription paused by vendor.',
        ]);
    }

    public function test_js_sync_endpoint_triggers_due_heartbeat_and_enforces_signed_server_lock(): void
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'dom' => ['localhost'],
        ]);
        $cert['installation_id'] = 'inst_js_sync_test';
        $this->storage->saveCertificate($cert);
        $this->storage->recordLastSyncTimestamp(time() - 600);

        $lockedPayload = [
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'LOCKED',
            'deadline' => time() + (86400 * 7),
            'timestamp' => time(),
            'nonce' => 'nonce_js_sync_lock',
            'lock_message' => 'Locked during JS background sync.',
        ];
        $sig = Ed25519Verifier::sign(CanonicalJson::encode($lockedPayload), $this->testSecretKey);
        $body = json_encode([
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => $lockedPayload,
            'signature' => $sig,
        ]);

        $container = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], $body)]));
        $stack->push(GuzzleMiddleware::history($container));
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => $stack]));

        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            productId: 'PROD-TEST',
            intervalMinutes: 5
        );
        $manager = new LicenseManager(storage: $this->storage, client: $client, heartbeat: $heartbeat);
        $this->app->instance(LicenseManager::class, $manager);

        $resp = $this->postJson('/codelock/js-sync');

        $this->assertNotEmpty($container);
        $this->assertSame('/api/v1/license/heartbeat', $container[0]['request']->getUri()->getPath());
        $resp->assertStatus(423)->assertJson([
            'verified' => true,
            'valid' => false,
            'status' => 'LOCKED',
            'message' => 'Locked during JS background sync.',
        ]);
    }

    public function test_js_sync_endpoint_enforces_ip_rate_limit(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['localhost']]);
        $this->storage->saveCertificate($cert);

        for ($i = 0; $i < 30; $i++) {
            $this->postJson('/codelock/js-sync')->assertStatus(200);
        }

        $this->postJson('/codelock/js-sync')->assertStatus(429)->assertJson([
            'verified' => false,
            'valid' => true,
            'error' => 'rate_limited',
        ]);
    }

    public function test_middleware_injects_script_before_body_closing_tag_on_html_responses(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['localhost', '127.0.0.1']]);
        $this->storage->saveCertificate($cert);

        Route::get('/html-page', function () {
            return '<!doctype html><html><body><h1>Welcome</h1></body></html>';
        });

        Route::get('/html-already-injected', function () {
            return '<html><body><h1>Ok</h1><script src="/vendor/codelock/codelock-guard.js" defer></script></body></html>';
        });

        // 1. Dynamic fallback route before static publish
        $respDynamic = $this->get('/html-page');
        $respDynamic->assertStatus(200);
        $this->assertSame(
            '<!doctype html><html><body><h1>Welcome</h1><script src="/codelock/guard.js" defer></script></body></html>',
            $respDynamic->getContent()
        );

        // 2. Uses published static path once file exists in public/
        (new JsGuardBuilder())->writeToPublicPath();
        $respStatic = $this->get('/html-page');
        $respStatic->assertStatus(200);
        $this->assertSame(
            '<!doctype html><html><body><h1>Welcome</h1><script src="/vendor/codelock/codelock-guard.js" defer></script></body></html>',
            $respStatic->getContent()
        );

        // 3. Does not duplicate script if already present in template
        $respExisting = $this->get('/html-already-injected');
        $this->assertSame(1, substr_count((string) $respExisting->getContent(), 'codelock-guard.js'));
    }

    public function test_middleware_skips_injection_on_non_html_ajax_redirects_or_when_disabled(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['localhost', '127.0.0.1']]);
        $this->storage->saveCertificate($cert);

        Route::get('/html-skip-test', function () {
            return '<html><body><h1>Page</h1></body></html>';
        });
        Route::get('/plain-with-tag', function () {
            return response('Raw </body> text', 200, ['Content-Type' => 'text/plain']);
        });
        Route::get('/json-with-tag', function () {
            return response()->json(['html' => '<b></body></b>']);
        });
        Route::get('/redirect-page', function () {
            return redirect('/html-skip-test');
        });

        $this->get('/plain-with-tag')->assertContent('Raw </body> text');
        $this->getJson('/json-with-tag')->assertExactJson(['html' => '<b></body></b>']);
        $this->get('/redirect-page')->assertStatus(302);

        $ajax = $this->get('/html-skip-test', ['X-Requested-With' => 'XMLHttpRequest']);
        $this->assertStringNotContainsString('guard.js', (string) $ajax->getContent());

        $inertia = $this->get('/html-skip-test', ['X-Inertia' => 'true']);
        $this->assertStringNotContainsString('guard.js', (string) $inertia->getContent());

        config(['codelock.js_guard.auto_inject' => false]);
        $disabledAuto = $this->get('/html-skip-test');
        $this->assertSame('<html><body><h1>Page</h1></body></html>', $disabledAuto->getContent());
    }

    public function test_install_command_publishes_persistent_encrypted_js_guard(): void
    {
        $publicGuard = public_path('vendor/codelock/codelock-guard.js');
        if (file_exists($publicGuard)) {
            @unlink($publicGuard);
        }

        $this->artisan('codelock:install')
            ->expectsOutputToContain('Browser JS Guard Asset:')
            ->expectsOutputToContain('Every 5 Minutes')
            ->assertExitCode(0);

        $this->assertFileExists($publicGuard);
        $content = (string) file_get_contents($publicGuard);
        $this->assertStringStartsWith('/* CodeLock Runtime Protection Guard */', $content);
        $this->assertStringNotContainsString('/codelock/js-sync', $content);
    }

    public function test_blade_directive_codelock_script_renders_appropriate_tag(): void
    {
        $dynamicRendered = trim(Blade::render('@codelockScript'));
        $this->assertSame('<script src="/codelock/guard.js" defer></script>', $dynamicRendered);

        (new JsGuardBuilder())->writeToPublicPath();
        $staticRendered = trim(Blade::render('@codelockScript'));
        $this->assertSame('<script src="/vendor/codelock/codelock-guard.js" defer></script>', $staticRendered);
    }

    public function test_activate_command_refreshes_persistent_public_js_guard(): void
    {
        $publicGuard = public_path('vendor/codelock/codelock-guard.js');
        if (file_exists($publicGuard)) {
            @unlink($publicGuard);
        }

        config([
            'codelock.server_url' => 'https://licensing.activated.test',
            'codelock.product_id' => 'PROD-TEST',
        ]);

        $signedCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'lic' => 'CLK-ACTIVATE-JS-GUARD-2026',
            'prd' => 'PROD-TEST',
        ]);

        $client = new LicenseClient(
            'https://licensing.activated.test',
            'PROD-TEST',
            5,
            new GuzzleClient(['handler' => HandlerStack::create(new MockHandler([
                new Response(200, ['Content-Type' => 'application/json'], json_encode($signedCert)),
            ]))])
        );

        $verifier = new LicenseVerifier($this->storage, $this->testPublicKey, 'PROD-TEST', false);
        $manager = new LicenseManager($this->storage, $verifier, $client);
        $this->app->instance(LicenseManager::class, $manager);

        $this->artisan('codelock:activate', [
            'key' => 'CLK-ACTIVATE-JS-GUARD-2026',
            '--domain' => 'example.com',
        ])
            ->expectsOutputToContain('Browser JS Guard Synchronized:')
            ->assertExitCode(0);

        $this->assertFileExists($publicGuard);
        $content = (string) file_get_contents($publicGuard);
        $this->assertStringNotContainsString('https://licensing.activated.test', $content);

        preg_match('/\}\)\("([^"]+)","([^"]+)"\);/', $content, $m);
        $decoded = (new JsGuardBuilder())->rc4($m[1], base64_decode($m[2], true));
        $this->assertStringContainsString('https://licensing.activated.test/api/v1/public/domain-verify', $decoded);
        $this->assertStringNotContainsString('CLK-ACTIVATE-JS-GUARD-2026', $decoded);
    }
}
