<?php

namespace Rasel\CodeLock\Tests\Unit;

use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseVerifier;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class LicenseVerifierTest extends TestCase
{
    protected LicenseStorage $storage;
    protected LicenseVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->verifier = new LicenseVerifier($this->storage, $this->testPublicKey, 'PROD-TEST', false);
    }

    public function test_verifies_valid_signed_certificate_successfully(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['app.example.com']]);
        $this->storage->saveCertificate($cert);

        $result = $this->verifier->verify('app.example.com');

        $this->assertTrue($result['valid']);
        $this->assertSame(LicenseStatus::ACTIVE, $result['status']);
        $this->assertSame('CLK-TEST-1234-5678-ABCD', $result['payload']['lic']);
    }

    public function test_rejects_unauthorized_domain(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['allowed.com']]);
        $this->storage->saveCertificate($cert);

        $result = $this->verifier->verify('stolen-domain.com');

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('not authorized', $result['reason']);
    }

    public function test_supports_wildcard_domains(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['*.saas.io']]);
        $this->storage->saveCertificate($cert);

        $result1 = $this->verifier->verify('tenant1.saas.io');
        $result2 = $this->verifier->verify('tenant2.saas.io');
        $result3 = $this->verifier->verify('unrelated.com');

        $this->assertTrue($result1['valid']);
        $this->assertTrue($result2['valid']);
        $this->assertFalse($result3['valid']);
    }

    public function test_rejects_expired_license(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['app.example.com'],
            'exp' => time() - 3600, // expired 1 hour ago
        ]);
        $this->storage->saveCertificate($cert);

        $result = $this->verifier->verify('app.example.com');

        $this->assertFalse($result['valid']);
        $this->assertSame(LicenseStatus::EXPIRED, $result['status']);
        $this->assertStringContainsString('expired', $result['reason']);
    }

    public function test_rejects_product_mismatch(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['app.example.com'],
            'prd' => 'OTHER-PRODUCT',
        ]);
        $this->storage->saveCertificate($cert);

        $result = $this->verifier->verify('app.example.com');

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('Product mismatch', $result['reason']);
    }

    public function test_returns_unlicensed_when_no_certificate_exists(): void
    {
        $result = $this->verifier->verify('app.example.com');

        $this->assertFalse($result['valid']);
        $this->assertSame(LicenseStatus::UNLICENSED, $result['status']);
    }

    public function test_detects_clock_rollback(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['app.example.com']]);
        $this->storage->saveCertificate($cert);

        // Record a future verification timestamp
        $this->storage->recordVerificationTimestamp(time() + 100000);

        $result = $this->verifier->verify('app.example.com');

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('clock', strtolower($result['reason']));
    }
}

