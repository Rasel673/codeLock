<?php

namespace Rasel\CodeLock\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseDocument;
use Rasel\CodeLock\LicenseVerificationResult;

class LicenseVerificationResultTest extends TestCase
{
    protected function makeDocument(): LicenseDocument
    {
        return LicenseDocument::fromArray([
            'payload' => [
                'lic' => 'CLK-RESULT-TEST',
                'prd' => 'PROD-1',
                'dom' => ['example.com'],
                'sta' => 'ACTIVE',
                'ent' => [
                    'billing' => true,
                    'max_seats' => 25,
                    'tier' => 'pro',
                ],
            ],
            'signature' => 'dummy_signature',
        ]);
    }

    public function test_success_result_delegates_to_document(): void
    {
        $doc = $this->makeDocument();
        $result = LicenseVerificationResult::success($doc, ['domain' => 'example.com']);

        $this->assertTrue($result->isValid());
        $this->assertSame(LicenseStatus::ACTIVE, $result->getStatus());
        $this->assertNull($result->getReason());
        $this->assertNull($result->getErrorCode());
        $this->assertSame($doc, $result->getDocument());

        // Entitlement helpers
        $this->assertTrue($result->can('billing'));
        $this->assertFalse($result->can('reports'));
        $this->assertSame(25, $result->quota('max_seats'));
        $this->assertSame('pro', $result->tier());
    }

    public function test_failure_result_denies_all_entitlements(): void
    {
        $doc = $this->makeDocument();
        $result = LicenseVerificationResult::failure(
            LicenseStatus::EXPIRED,
            'License expired.',
            'E_TEMPORAL_EXPIRED',
            $doc
        );

        $this->assertFalse($result->isValid());
        $this->assertSame(LicenseStatus::EXPIRED, $result->getStatus());
        $this->assertSame('License expired.', $result->getReason());
        $this->assertSame('E_TEMPORAL_EXPIRED', $result->getErrorCode());

        // Must deny entitlements on invalid/expired status
        $this->assertFalse($result->can('billing'));
        $this->assertNull($result->quota('max_seats'));
    }

    public function test_array_access_backwards_compatibility(): void
    {
        $doc = $this->makeDocument();
        $result = LicenseVerificationResult::success($doc, ['domain' => 'example.com']);

        $this->assertTrue($result['valid']);
        $this->assertSame(LicenseStatus::ACTIVE, $result['status']);
        $this->assertNull($result['reason']);
        $this->assertSame('CLK-RESULT-TEST', $result['payload']['lic']);
        $this->assertSame('example.com', $result['domain']);
    }
}

