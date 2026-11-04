<?php

namespace Rasel\CodeLock\Tests\Unit;

use Rasel\CodeLock\IntegrityMonitor;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class IntegrityMonitorTest extends TestCase
{
    protected string $tempPackageRoot;
    protected string $tempManifestPath;
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();

        // Create temporary isolated package root for testing file modifications
        $this->tempPackageRoot = sys_get_temp_dir() . '/codelock_pkg_' . uniqid();
        @mkdir($this->tempPackageRoot . '/src', 0755, true);
        @mkdir($this->tempPackageRoot . '/resources', 0755, true);

        // Create sample protected files
        file_put_contents($this->tempPackageRoot . '/src/LicenseVerifier.php', "<?php\n// Original Verifier\n");
        file_put_contents($this->tempPackageRoot . '/src/LicenseManager.php', "<?php\n// Original Manager\n");

        $this->tempManifestPath = $this->tempPackageRoot . '/resources/integrity.json';
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
    }

    protected function tearDown(): void
    {
        // Cleanup temp files
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

    protected function createMonitor(): IntegrityMonitor
    {
        return new IntegrityMonitor(
            packageRoot: $this->tempPackageRoot,
            manifestPath: $this->tempManifestPath,
            publicKeys: ['test_key' => $this->testPublicKey],
            storage: $this->storage
        );
    }

    public function test_verifies_intact_designated_files_successfully(): void
    {
        $monitor = $this->createMonitor();

        // Generate manifest
        $manifest = $monitor->generateManifest(
            ['src/LicenseVerifier.php', 'src/LicenseManager.php'],
            $this->testSecretKey,
            'test_key'
        );
        file_put_contents($this->tempManifestPath, json_encode($manifest));

        $result = $monitor->verify(true);

        $this->assertTrue($result->isValid());
        $this->assertSame(2, $result->getCheckedCount());
        $this->assertFalse($result->hasModifiedFiles());
        $this->assertFalse($result->hasMissingFiles());
    }

    public function test_detects_modified_protected_file(): void
    {
        $monitor = $this->createMonitor();

        $manifest = $monitor->generateManifest(
            ['src/LicenseVerifier.php', 'src/LicenseManager.php'],
            $this->testSecretKey,
            'test_key'
        );
        file_put_contents($this->tempManifestPath, json_encode($manifest));

        // Malicious modification to LicenseVerifier.php
        file_put_contents($this->tempPackageRoot . '/src/LicenseVerifier.php', "<?php\n// Tampered return true;\n");

        $result = $monitor->verify(true);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_INTEGRITY_MISMATCH', $result->getErrorCode());
        $this->assertTrue($result->hasModifiedFiles());
        $this->assertCount(1, $result->getModifiedFiles());
        $this->assertSame('src/LicenseVerifier.php', $result->getModifiedFiles()[0]['path']);
    }

    public function test_detects_missing_protected_file(): void
    {
        $monitor = $this->createMonitor();

        $manifest = $monitor->generateManifest(
            ['src/LicenseVerifier.php', 'src/LicenseManager.php'],
            $this->testSecretKey,
            'test_key'
        );
        file_put_contents($this->tempManifestPath, json_encode($manifest));

        // Malicious deletion of LicenseManager.php
        @unlink($this->tempPackageRoot . '/src/LicenseManager.php');

        $result = $monitor->verify(true);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_INTEGRITY_MISMATCH', $result->getErrorCode());
        $this->assertTrue($result->hasMissingFiles());
        $this->assertSame(['src/LicenseManager.php'], $result->getMissingFiles());
    }

    public function test_rejects_altered_manifest_signature(): void
    {
        $monitor = $this->createMonitor();

        $manifest = $monitor->generateManifest(
            ['src/LicenseVerifier.php'],
            $this->testSecretKey,
            'test_key'
        );

        // Corrupt signature
        $manifest['signature'] = base64_encode(str_repeat('F', 64));
        file_put_contents($this->tempManifestPath, json_encode($manifest));

        $result = $monitor->verify(true);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_MANIFEST_INVALID_SIGNATURE', $result->getErrorCode());
    }

    public function test_rejects_missing_manifest_file(): void
    {
        $monitor = $this->createMonitor();

        $result = $monitor->verify(true);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_MANIFEST_NOT_FOUND', $result->getErrorCode());
    }

    public function test_normalization_prevents_false_positives_from_line_endings(): void
    {
        $monitor = $this->createMonitor();

        $unixContent = "class CodeLock {\n    public function check() {\n        return true;\n    }\n}\n";
        $windowsContent = "class CodeLock {\r\n    public function check() {\r\n        return true;\r\n    }\r\n}\r\n";

        $normUnix = $monitor->normalizeContent($unixContent);
        $normWin = $monitor->normalizeContent($windowsContent);

        $this->assertSame($normUnix, $normWin);
        $this->assertSame(hash('sha256', $normUnix), hash('sha256', $normWin));
    }

    public function test_cache_avoids_repeated_disk_reads(): void
    {
        config(['codelock.integrity.stochastic_rate' => 0]);
        $monitor = $this->createMonitor();

        $manifest = $monitor->generateManifest(
            ['src/LicenseVerifier.php'],
            $this->testSecretKey,
            'test_key'
        );
        file_put_contents($this->tempManifestPath, json_encode($manifest));

        // First verification computes hashes and caches clean state
        $res1 = $monitor->verify(false);
        $this->assertTrue($res1->isValid());
        $this->assertFalse($res1->isCached());

        // Second verification hits cache without re-reading
        $res2 = $monitor->verify(false);
        $this->assertTrue($res2->isValid());
        $this->assertTrue($res2->isCached());

        // Forcing bypasses cache
        $res3 = $monitor->verify(true);
        $this->assertTrue($res3->isValid());
        $this->assertFalse($res3->isCached());
    }
}

