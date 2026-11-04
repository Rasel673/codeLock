<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Rasel\CodeLock\IntegrityMonitor;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\LicenseVerifier;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class IntegrityVerificationTest extends TestCase
{
    protected string $tempPackageRoot;
    protected string $tempManifestPath;
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempPackageRoot = sys_get_temp_dir() . '/codelock_feature_pkg_' . uniqid();
        @mkdir($this->tempPackageRoot . '/src', 0755, true);
        @mkdir($this->tempPackageRoot . '/resources', 0755, true);

        file_put_contents($this->tempPackageRoot . '/src/LicenseVerifier.php', "<?php\n// Original Verifier Code\n");

        $this->tempManifestPath = $this->tempPackageRoot . '/resources/integrity.json';
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
    }

    protected function tearDown(): void
    {
        $this->deleteDirectory($this->tempPackageRoot);
        parent::tearDown();
    }

    protected function deleteDirectory(string $dir): void
    {
        if (!file_exists($dir)) {
            return;
        }
        foreach (scandir($dir) as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->deleteDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    public function test_tampered_package_blocks_license_and_triggers_telemetry(): void
    {
        $monitor = new IntegrityMonitor(
            packageRoot: $this->tempPackageRoot,
            manifestPath: $this->tempManifestPath,
            publicKeys: ['test_key' => $this->testPublicKey],
            storage: $this->storage
        );

        // Generate clean manifest
        $manifest = $monitor->generateManifest(['src/LicenseVerifier.php'], $this->testSecretKey, 'test_key');
        file_put_contents($this->tempManifestPath, json_encode($manifest));

        // Save a valid signed license
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);

        // Spy on outgoing telemetry HTTP requests
        $container = [];
        $history = Middleware::history($container);
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['status' => 'recorded'])),
        ]);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $httpClient = new GuzzleClient(['handler' => $stack]);

        $client = new LicenseClient('https://license.test', 'PROD-TEST', 5, $httpClient);
        $verifier = new LicenseVerifier($this->storage, $this->testPublicKey, 'PROD-TEST', false);
        $manager = new LicenseManager($this->storage, $verifier, $client, $monitor);

        // Intact package passes verification
        $resClean = $manager->verify('example.com');
        $this->assertTrue($resClean->isValid());

        // Tamper with the protected file
        file_put_contents($this->tempPackageRoot . '/src/LicenseVerifier.php', "<?php\n// Maliciously altered\n");
        $manager->clearCache();

        // Subsequent verification must fail and block access
        $resTampered = $manager->verify('example.com');
        $this->assertFalse($resTampered->isValid());
        $this->assertSame('E_INTEGRITY_MISMATCH', $resTampered->getErrorCode());

        // Assert telemetry event was transmitted
        $this->assertNotEmpty($container);
        $request = $container[0]['request'];
        $this->assertStringContainsString('/api/v1/license/security-event', (string) $request->getUri());

        $body = json_decode((string) $request->getBody(), true);
        $this->assertSame('TAMPER_DETECTED', $body['event_code']);
        $this->assertSame('CRITICAL', $body['severity']);
    }

    public function test_artisan_integrity_manifest_command_executes_successfully(): void
    {
        $outPath = $this->tempPackageRoot . '/resources/generated_manifest.json';

        $this->artisan('codelock:integrity-manifest', [
            '--key' => $this->testSecretKey,
            '--out' => $outPath,
        ])
            ->expectsOutputToContain('Integrity manifest generated and cryptographically signed successfully!')
            ->assertExitCode(0);

        $this->assertFileExists($outPath);
        $decoded = json_decode((string) file_get_contents($outPath), true);

        $this->assertIsArray($decoded);
        $this->assertSame('Ed25519', $decoded['header']['alg']);
        $this->assertNotEmpty($decoded['signature']);
        $this->assertNotEmpty($decoded['payload']['files']);
    }
}

