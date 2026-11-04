<?php

namespace Rasel\CodeLock\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\LicenseDocument;

class LicenseDocumentTest extends TestCase
{
    protected function getSamplePayload(): array
    {
        return [
            'lic' => 'CLK-TEST-1234-5678-ABCD',
            'prd' => 'PROD-ERP-CORE',
            'ins' => 'inst_7bf82e43c5e88d12e848',
            'dom' => ['crm.example.com', '*.clientcorp.io'],
            'sta' => 'ACTIVE',
            'iat' => 1767225600,
            'nbf' => 1767225600,
            'exp' => 1798761600,
            'grc' => 7,
            'hbi' => 24,
            'ent' => [
                'api_access' => true,
                'max_users' => 50,
                'features' => ['billing', 'audit_trail', 'multi_warehouse'],
                'tier' => 'enterprise',
            ],
            'pol' => [
                'allow_local' => false,
                'allow_subdomains' => true,
                'strict_instance' => true,
            ],
            'nonce' => 'd8e37f90b9b32a188f6c4d',
        ];
    }

    public function test_creates_document_from_array_and_exposes_getters(): void
    {
        $payload = $this->getSamplePayload();
        $header = ['alg' => 'Ed25519', 'kid' => 'key_2026_01', 'typ' => 'CODELOCK-LIC', 'ver' => '1.0'];
        $signature = 'dummy_sig_base64';

        $doc = LicenseDocument::fromArray([
            'header' => $header,
            'payload' => $payload,
            'signature' => $signature,
        ]);

        $this->assertSame('Ed25519', $doc->getAlgorithm());
        $this->assertSame('key_2026_01', $doc->getKeyId());
        $this->assertSame('CLK-TEST-1234-5678-ABCD', $doc->getLicenseKey());
        $this->assertSame('PROD-ERP-CORE', $doc->getProductId());
        $this->assertSame('inst_7bf82e43c5e88d12e848', $doc->getInstallationId());
        $this->assertSame(['crm.example.com', '*.clientcorp.io'], $doc->getAllowedDomains());
        $this->assertSame(LicenseStatus::ACTIVE, $doc->getStatus());
        $this->assertSame(1767225600, $doc->getIssuedAt());
        $this->assertSame(1767225600, $doc->getNotBefore());
        $this->assertSame(1798761600, $doc->getExpiresAt());
        $this->assertFalse($doc->isLifetime());
        $this->assertSame(7, $doc->getGracePeriodDays());
        $this->assertSame(24, $doc->getHeartbeatIntervalHours());
        $this->assertTrue($doc->isInstanceStrict());
        $this->assertSame('d8e37f90b9b32a188f6c4d', $doc->getNonce());
    }

    public function test_parses_signed_entitlements_correctly(): void
    {
        $doc = LicenseDocument::fromArray([
            'payload' => $this->getSamplePayload(),
            'signature' => 'sig',
        ]);

        // Boolean feature flags
        $this->assertTrue($doc->hasFeature('api_access'));
        $this->assertFalse($doc->hasFeature('sso_login'));

        // Feature array membership
        $this->assertTrue($doc->hasFeature('billing'));
        $this->assertTrue($doc->hasFeature('audit_trail'));
        $this->assertFalse($doc->hasFeature('unknown_module'));

        // Numeric quotas
        $this->assertSame(50, $doc->getQuota('max_users'));
        $this->assertSame(10, $doc->getQuota('missing_quota', 10));

        // Tier
        $this->assertSame('enterprise', $doc->getTier());
    }

    public function test_json_roundtrip_preserves_structure(): void
    {
        $payload = $this->getSamplePayload();
        $doc = LicenseDocument::fromArray([
            'header' => ['alg' => 'Ed25519', 'kid' => 'k1'],
            'payload' => $payload,
            'signature' => 'sig_test',
        ]);

        $json = $doc->toJson();
        $restored = LicenseDocument::fromJson($json);

        $this->assertSame($doc->getLicenseKey(), $restored->getLicenseKey());
        $this->assertSame($doc->getAlgorithm(), $restored->getAlgorithm());
        $this->assertSame($doc->getCanonicalPayload(), $restored->getCanonicalPayload());
    }

    public function test_throws_exception_on_malformed_document(): void
    {
        $this->expectException(LicenseInvalidException::class);
        LicenseDocument::fromArray(['invalid' => 'structure']);
    }

    public function test_throws_exception_on_corrupted_json(): void
    {
        $this->expectException(LicenseInvalidException::class);
        LicenseDocument::fromJson('{"corrupted": json...');
    }
}

