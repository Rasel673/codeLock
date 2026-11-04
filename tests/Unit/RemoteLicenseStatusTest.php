<?php

namespace Rasel\CodeLock\Tests\Unit;

use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\RemoteLicenseStatus;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class RemoteLicenseStatusTest extends TestCase
{
    public function test_can_instantiate_and_read_remote_status_claims(): void
    {
        $signed = $this->createSignedRemoteStatus([
            'lic' => 'CLK-2026-TEST-KEY',
            'sta' => 'ACTIVE',
            'deadline' => time() + 7200,
            'reason_code' => 'OK_ACTIVE',
        ]);

        $status = RemoteLicenseStatus::fromArray($signed);

        $this->assertSame(LicenseStatus::ACTIVE, $status->getStatus());
        $this->assertTrue($status->isActive());
        $this->assertFalse($status->isLocked());
        $this->assertFalse($status->isSuspended());
        $this->assertFalse($status->isExpired());
        $this->assertSame('CLK-2026-TEST-KEY', $status->getLicenseKey());
        $this->assertSame('OK_ACTIVE', $status->getReasonCode());
        $this->assertGreaterThan(0, $status->getDeadline());
        $this->assertGreaterThan(0, $status->getTimestamp());
        $this->assertNotEmpty($status->getNonce());
    }

    public function test_from_array_rejects_missing_payload_or_signature(): void
    {
        $this->expectException(LicenseInvalidException::class);
        RemoteLicenseStatus::fromArray(['header' => ['alg' => 'Ed25519']]);
    }

    public function test_evaluates_locked_and_suspended_states(): void
    {
        $lockedSigned = $this->createSignedRemoteStatus([
            'sta' => 'LOCKED',
            'lock_message' => 'Your account has been suspended due to overdue invoice.',
        ]);
        $lockedStatus = RemoteLicenseStatus::fromArray($lockedSigned);

        $this->assertTrue($lockedStatus->isLocked());
        $this->assertFalse($lockedStatus->isActive());
        $this->assertSame('Your account has been suspended due to overdue invoice.', $lockedStatus->getLockMessage());

        $suspendedSigned = $this->createSignedRemoteStatus([
            'sta' => 'SUSPENDED',
            'lock_message' => 'License temporarily paused.',
        ]);
        $suspendedStatus = RemoteLicenseStatus::fromArray($suspendedSigned);

        $this->assertTrue($suspendedStatus->isSuspended());
        $this->assertFalse($suspendedStatus->isActive());
    }

    public function test_grace_period_calculations(): void
    {
        $now = 1740000000;
        $activeDeadline = $now + 3600; // 1 hour in the future

        $status = RemoteLicenseStatus::fromArray($this->createSignedRemoteStatus([
            'deadline' => $activeDeadline,
        ]));

        $this->assertFalse($status->isGraceExpired($now));
        $this->assertSame(3600, $status->getRemainingGraceSeconds($now));

        // When deadline has passed
        $pastDeadline = $now - 60;
        $expiredStatus = RemoteLicenseStatus::fromArray($this->createSignedRemoteStatus([
            'deadline' => $pastDeadline,
        ]));

        $this->assertTrue($expiredStatus->isGraceExpired($now));
        $this->assertSame(0, $expiredStatus->getRemainingGraceSeconds($now));
    }

    public function test_renewed_certificate_parsing(): void
    {
        $signedCert = $this->createSignedCertificate();

        $status = RemoteLicenseStatus::fromArray($this->createSignedRemoteStatus([
            'renew_license' => true,
            'certificate' => $signedCert,
        ]));

        $this->assertTrue($status->hasRenewedCertificate());
        $this->assertSame($signedCert, $status->getRenewedCertificate());

        // Without renewal
        $normalStatus = RemoteLicenseStatus::fromArray($this->createSignedRemoteStatus([
            'renew_license' => false,
        ]));
        $this->assertFalse($normalStatus->hasRenewedCertificate());
        $this->assertNull($normalStatus->getRenewedCertificate());
    }

    public function test_cryptographic_signature_verification(): void
    {
        $signed = $this->createSignedRemoteStatus();
        $status = RemoteLicenseStatus::fromArray($signed);

        // Valid public key
        $this->assertTrue($status->verifySignature($this->testPublicKey));

        // Wrong public key
        $otherPair = Ed25519Verifier::generateKeyPair();
        $this->assertFalse($status->verifySignature($otherPair['public_key']));

        // Key rotation dictionary
        $keyMap = [
            'key-default' => $this->testPublicKey,
            'key-other' => $otherPair['public_key'],
        ];
        $this->assertTrue($status->verifySignature($keyMap));

        // Altered payload fails verification
        $tamperedData = $signed;
        $tamperedData['payload']['sta'] = 'TAMPERED';
        $tamperedStatus = RemoteLicenseStatus::fromArray($tamperedData);
        $this->assertFalse($tamperedStatus->verifySignature($this->testPublicKey));
    }

    public function test_array_access_and_json_serialization(): void
    {
        $signed = $this->createSignedRemoteStatus([
            'lic' => 'CLK-ARRAY-ACCESS',
            'sta' => 'ACTIVE',
        ]);
        $status = RemoteLicenseStatus::fromArray($signed);

        $this->assertSame('CLK-ARRAY-ACCESS', $status['lic']);
        $this->assertSame('ACTIVE', $status['sta']);
        $this->assertIsArray($status['payload']);
        $this->assertIsString($status['signature']);

        $json = json_encode($status);
        $decoded = json_decode($json, true);
        $this->assertSame('CLK-ARRAY-ACCESS', $decoded['payload']['lic']);

        $this->expectException(\BadMethodCallException::class);
        $status['sta'] = 'MUTATED';
    }
}

