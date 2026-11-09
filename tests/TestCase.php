<?php

namespace Rasel\CodeLock\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Rasel\CodeLock\CodeLockServiceProvider;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;

abstract class TestCase extends OrchestraTestCase
{
    protected string $testPublicKey;
    protected string $testSecretKey;
    protected string $tempStoragePath;
    protected string $tempStatusPath;

    protected function setUp(): void
    {
        // Deterministic Ed25519 keypair for testing
        // Generated valid keypair
        $keyPair = Ed25519Verifier::generateKeyPair();
        $this->testPublicKey = $keyPair['public_key'];
        $this->testSecretKey = $keyPair['secret_key'];

        $this->tempStoragePath = sys_get_temp_dir() . '/.codelock_test_' . uniqid() . '.lic';
        $this->tempStatusPath = sys_get_temp_dir() . '/.codelock_status_' . uniqid() . '.status';

        $lockFile = dirname($this->tempStoragePath) . '/.codelock.lock_state';
        if (file_exists($lockFile)) {
            @unlink($lockFile);
        }

        parent::setUp();
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempStoragePath)) {
            @unlink($this->tempStoragePath);
        }
        if (file_exists($this->tempStatusPath)) {
            @unlink($this->tempStatusPath);
        }

        $timeFile = dirname($this->tempStoragePath) . '/.codelock.time';
        if (file_exists($timeFile)) {
            @unlink($timeFile);
        }

        $syncFile = dirname($this->tempStoragePath) . '/.codelock.sync';
        if (file_exists($syncFile)) {
            @unlink($syncFile);
        }

        $lockFile = dirname($this->tempStoragePath) . '/.codelock.lock_state';
        if (file_exists($lockFile)) {
            @unlink($lockFile);
        }

        $publishedView = resource_path('views/vendor/codelock/locked.blade.php');
        if (file_exists($publishedView)) {
            @unlink($publishedView);
        }

        $publishedConfig = config_path('codelock.php');
        if (file_exists($publishedConfig)) {
            @unlink($publishedConfig);
        }

        $publishedJsGuard = public_path('vendor/codelock/codelock-guard.js');
        if (file_exists($publishedJsGuard)) {
            @unlink($publishedJsGuard);
        }

        parent::tearDown();
    }

    protected function getPackageProviders($app)
    {
        return [
            CodeLockServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app)
    {
        $app['config']->set('app.key', 'base64:6vN0k6l+j/3wZ3QY7+yB7HnN+pZ9xXw8YV8K5+x9o9U=');
        $app['config']->set('codelock.enabled', true);
        $app['config']->set('codelock.product_id', 'PROD-TEST');
        $app['config']->set('codelock.public_key', $this->testPublicKey);
        $app['config']->set('codelock.storage_path', $this->tempStoragePath);
        $app['config']->set('codelock.status_cache_path', $this->tempStatusPath);
        $app['config']->set('codelock.contact_email', 'licensing@example.com');
        $app['config']->set('codelock.contact_url', 'https://example.com/support');
    }

    /**
     * Helper to create a signed certificate dictionary for testing.
     */
    protected function createSignedCertificate(array $customPayload = []): array
    {
        $payload = array_merge([
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'prd' => 'PROD-TEST',
            'ins' => 'inst_test_fingerprint',
            'dom' => ['example.com', 'test.app'],
            'sta' => 'ACTIVE',
            'iat' => time() - 3600,
            'nbf' => time() - 3600,
            'exp' => time() + (86400 * 365),
            'grc' => 7,
            'hbi' => 24,
            'nonce' => 'test_nonce_123',
        ], $customPayload);

        $canonical = CanonicalJson::encode($payload);
        $signature = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        return [
            'header' => [
                'alg' => 'Ed25519',
                'typ' => 'CODELOCK-LIC',
            ],
            'payload' => $payload,
            'signature' => $signature,
        ];
    }

    /**
     * Helper to create a signed remote status dictionary for testing.
     */
    protected function createSignedRemoteStatus(array $customPayload = []): array
    {
        $payload = array_merge([
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'sta' => 'ACTIVE',
            'deadline' => time() + (86400 * 7),
            'timestamp' => time(),
            'nonce' => bin2hex(random_bytes(16)),
            'lock_message' => null,
            'reason_code' => null,
            'renew_license' => false,
            'certificate' => null,
        ], $customPayload);

        $canonical = CanonicalJson::encode($payload);
        $signature = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        return [
            'header' => [
                'alg' => 'Ed25519',
                'typ' => 'CODELOCK-STATUS',
            ],
            'payload' => $payload,
            'signature' => $signature,
        ];
    }
}

