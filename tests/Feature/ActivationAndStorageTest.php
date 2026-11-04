<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\LicenseVerifier;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\LicenseKey;
use Rasel\CodeLock\Tests\TestCase;

class ActivationAndStorageTest extends TestCase
{
    protected LicenseStorage $storage;
    protected LicenseVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->verifier = new LicenseVerifier($this->storage, $this->testPublicKey, 'PROD-TEST', false);
        $this->app->instance(LicenseStorage::class, $this->storage);
        $this->app->instance(LicenseVerifier::class, $this->verifier);
    }

    /**
     * Requirement: Secure activation request, verify server signature, atomic write.
     */
    public function test_successful_activation_and_atomic_storage(): void
    {
        $signedCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'lic' => 'CLK-2026-ALPHA-9821-BETA',
            'prd' => 'PROD-TEST',
        ]);

        $mockHandler = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($signedCert)),
        ]);
        $httpClient = new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, $httpClient);
        $manager = new LicenseManager($this->storage, $this->verifier, $client);
        $this->app->instance(LicenseManager::class, $manager);

        $this->artisan('codelock:activate', [
            'key' => 'CLK-2026-ALPHA-9821-BETA',
            '--domain' => 'example.com',
        ])
            ->expectsOutputToContain('License activated and cryptographically verified successfully!')
            ->expectsOutputToContain(LicenseKey::mask('CLK-2026-ALPHA-9821-BETA'))
            ->assertExitCode(0);

        // Assert file exists and was written atomically
        $this->assertTrue($this->storage->hasCertificate());
        $this->assertFileExists($this->tempStoragePath);

        // Assert file content on disk is encrypted (not plaintext JSON)
        $rawDisk = file_get_contents($this->tempStoragePath);
        $this->assertFalse(str_contains($rawDisk, 'CLK-2026-ALPHA-9821-BETA'));
    }

    /**
     * Requirement: Validate license key format before network transmission.
     */
    public function test_rejects_invalid_license_key_format_early(): void
    {
        $this->artisan('codelock:activate', ['key' => 'short'])
            ->expectsOutputToContain('Invalid license key format')
            ->assertExitCode(1);

        $this->artisan('codelock:activate', ['key' => 'invalid$$$characters!!!'])
            ->expectsOutputToContain('Invalid license key format')
            ->assertExitCode(1);

        $this->assertFalse($this->storage->hasCertificate());
    }

    /**
     * Requirement: Verify server signature before saving certificate.
     */
    public function test_rejects_certificate_with_invalid_signature_and_does_not_save(): void
    {
        $signedCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'lic' => 'CLK-TAMPERED-KEY',
        ]);

        // Tamper with signature
        $signedCert['signature'] = base64_encode(str_repeat('X', 64));

        $mockHandler = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($signedCert)),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]));
        $manager = new LicenseManager($this->storage, $this->verifier, $client);
        $this->app->instance(LicenseManager::class, $manager);

        $this->artisan('codelock:activate', [
            'key' => 'CLK-TAMPERED-KEY',
            '--domain' => 'example.com',
        ])
            ->expectsOutputToContain('Activation Failed')
            ->assertExitCode(1);

        // Certificate MUST NOT be persisted to disk
        $this->assertFalse($this->storage->hasCertificate());
    }

    /**
     * Requirement: Handle network errors (timeouts, DNS failures, connection refused).
     */
    public function test_handles_network_connection_errors_gracefully(): void
    {
        $mockHandler = new MockHandler([
            new ConnectException('Connection timed out after 5000ms', new Request('POST', 'https://license.test/api/v1/license/activate')),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]));
        $manager = new LicenseManager($this->storage, $this->verifier, $client);
        $this->app->instance(LicenseClient::class, $client);
        $this->app->instance(LicenseManager::class, $manager);
        $this->app->instance('codelock', $manager);

        // Direct manager call asserts ServerCommunicationException
        try {
            $manager->activate('CLK-VALID-KEY-FORMAT', 'example.com');
            $this->fail('Expected ServerCommunicationException was not thrown.');
        } catch (\Rasel\CodeLock\Exceptions\ServerCommunicationException $e) {
            $this->assertStringContainsString('Unable to connect to license server', $e->getMessage());
        }

        // Artisan command catches exception and exits with failure
        $this->artisan('codelock:activate', [
            'key' => 'CLK-VALID-KEY-FORMAT',
            '--domain' => 'example.com',
        ])
            ->assertExitCode(1);
    }

    /**
     * Requirement: Handle invalid/non-JSON server responses (e.g. 502 Bad Gateway HTML).
     */
    public function test_handles_invalid_html_server_responses(): void
    {
        $mockHandler = new MockHandler([
            new Response(502, ['Content-Type' => 'text/html'], '<html><body>502 Bad Gateway</body></html>'),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]));
        $manager = new LicenseManager($this->storage, $this->verifier, $client);
        $this->app->instance(LicenseClient::class, $client);
        $this->app->instance(LicenseManager::class, $manager);
        $this->app->instance('codelock', $manager);

        try {
            $manager->activate('CLK-VALID-KEY-FORMAT', 'example.com');
            $this->fail('Expected ServerCommunicationException was not thrown.');
        } catch (\Rasel\CodeLock\Exceptions\ServerCommunicationException $e) {
            $this->assertStringContainsString('non-JSON response', $e->getMessage());
        }

        $this->artisan('codelock:activate', [
            'key' => 'CLK-VALID-KEY-FORMAT',
            '--domain' => 'example.com',
        ])
            ->assertExitCode(1);
    }

    /**
     * Requirement: Handle server 4xx rejection (e.g. activation limit exceeded).
     */
    public function test_handles_server_rejection_error(): void
    {
        $mockHandler = new MockHandler([
            new Response(403, ['Content-Type' => 'application/json'], json_encode([
                'error' => 'max_activations_exceeded',
                'message' => 'License activation limit exceeded for this key.',
            ])),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]));
        $manager = new LicenseManager($this->storage, $this->verifier, $client);
        $this->app->instance(LicenseManager::class, $manager);

        $this->artisan('codelock:activate', [
            'key' => 'CLK-VALID-KEY-FORMAT',
            '--domain' => 'example.com',
        ])
            ->expectsOutputToContain('License activation limit exceeded')
            ->assertExitCode(1);
    }

    /**
     * Requirement: Support deactivation.
     */
    public function test_deactivation_cleans_up_local_storage(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);
        $this->storage->saveRemoteStatus(['payload' => ['sta' => 'ACTIVE'], 'signature' => 'sig']);

        $this->assertTrue($this->storage->hasCertificate());
        $this->assertFileExists($this->tempStatusPath);

        $mockHandler = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['status' => 'deactivated'])),
        ]);
        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, new GuzzleClient(['handler' => HandlerStack::create($mockHandler)]));
        $manager = new LicenseManager($this->storage, $this->verifier, $client);
        $this->app->instance(LicenseManager::class, $manager);

        $this->artisan('codelock:deactivate', ['--force' => true, '--domain' => 'example.com'])
            ->expectsOutputToContain('License deactivated and local certificate removed')
            ->assertExitCode(0);

        $this->assertFalse($this->storage->hasCertificate());
        $this->assertFileDoesNotExist($this->tempStatusPath);
    }

    /**
     * Requirement: Avoid logging full license keys / mask in status output.
     */
    public function test_masks_license_keys_in_status_output(): void
    {
        $rawKey = 'CLK-2026-ALPHA-9821-BETA';
        $cert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'lic' => $rawKey,
        ]);
        $this->storage->saveCertificate($cert);

        // Default: key must be masked
        $this->artisan('codelock:status', ['--domain' => 'example.com'])
            ->expectsOutputToContain(LicenseKey::mask($rawKey))
            ->doesntExpectOutputToContain($rawKey)
            ->assertExitCode(0);

        // With --show-key flag: raw key is shown
        $this->artisan('codelock:status', ['--domain' => 'example.com', '--show-key' => true])
            ->expectsOutputToContain($rawKey)
            ->assertExitCode(0);
    }

    /**
     * Requirement: Never store private signing keys in client applications.
     */
    public function test_stored_certificate_never_contains_private_keys(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);

        $loaded = $this->storage->loadCertificate();

        $this->assertArrayNotHasKey('private_key', $loaded);
        $this->assertArrayNotHasKey('secret_key', $loaded);
        $this->assertArrayNotHasKey('sec', $loaded['payload'] ?? []);
        $this->assertArrayNotHasKey('private_key', $loaded['payload'] ?? []);
    }
}
