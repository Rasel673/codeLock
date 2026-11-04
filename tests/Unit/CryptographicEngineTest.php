<?php

namespace Rasel\CodeLock\Tests\Unit;

use Rasel\CodeLock\Enums\LicenseStatus;
use Rasel\CodeLock\LicenseDocument;
use Rasel\CodeLock\LicenseVerifier;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Support\MachineFingerprint;
use Rasel\CodeLock\Tests\TestCase;

class CryptographicEngineTest extends TestCase
{
    protected LicenseStorage $storage;
    protected LicenseVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->verifier = new LicenseVerifier($this->storage, $this->testPublicKey, 'PROD-TEST', false);
    }

    /**
     * Requirement 1: Verify Ed25519 signatures with the exact test vector from the approved specification.
     */
    public function test_verifies_official_spec_test_vector(): void
    {
        $specPublicKey = 'jCQ1kxMGyjvpG6fMutklm6Wa3TYmEb3lF7RA3Ut81bo=';
        $specSignature = 'B5DR/l+rcrOGk+Jzh9CEF2vbRcCpayNqD3F2Mm7EmK46Qq852AwMa70ZRSOvOASvRoWBxkti1twVE3nG+MSKBA==';

        $specDocArray = [
            'header' => [
                'alg' => 'Ed25519',
                'kid' => 'key_2026_vector',
                'typ' => 'CODELOCK-LIC',
                'ver' => '1.0',
            ],
            'payload' => [
                'lic' => 'CLK-2026-ALPHA-9821-BETA',
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
                ],
                'pol' => [
                    'allow_local' => false,
                    'allow_subdomains' => true,
                ],
                'nonce' => 'd8e37f90b9b32a188f6c4d',
            ],
            'signature' => $specSignature,
        ];

        $doc = LicenseDocument::fromArray($specDocArray);
        $verifier = new LicenseVerifier($this->storage, $specPublicKey, 'PROD-ERP-CORE', false);

        // Verify apex/subdomain from test vector
        $result1 = $verifier->verify('crm.example.com', $doc);
        $this->assertTrue($result1->isValid());
        $this->assertSame(LicenseStatus::ACTIVE, $result1->getStatus());

        // Verify wildcard domain from test vector
        $result2 = $verifier->verify('billing.clientcorp.io', $doc);
        $this->assertTrue($result2->isValid());

        // Verify entitlements from test vector
        $this->assertTrue($result1->can('api_access'));
        $this->assertTrue($result1->can('billing'));
        $this->assertSame(50, $result1->quota('max_users'));
    }

    /**
     * Requirement 2: Reject malformed payloads.
     */
    public function test_rejects_malformed_payloads(): void
    {
        $malformedDoc = [
            'header' => ['alg' => 'Ed25519'],
            // Missing payload and signature
        ];

        $result = $this->verifier->verify('example.com', $malformedDoc);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_STRUCTURE_MALFORMED', $result->getErrorCode());
    }

    /**
     * Requirement 3: Reject altered payloads (tampering even 1 byte).
     */
    public function test_rejects_altered_payload_data(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'ent' => ['max_users' => 10],
        ]);

        // Maliciously tamper with quota: 10 -> 1000
        $cert['payload']['ent']['max_users'] = 1000;

        $result = $this->verifier->verify('crm.example.com', $cert);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_SIGNATURE_MISMATCH', $result->getErrorCode());
    }

    /**
     * Requirement 3b: Reject altered signature.
     */
    public function test_rejects_altered_cryptographic_signature(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['crm.example.com']]);

        // Corrupt signature by flipping first char
        $cert['signature'] = ($cert['signature'][0] === 'A' ? 'B' : 'A') . substr($cert['signature'], 1);

        $result = $this->verifier->verify('crm.example.com', $cert);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_SIGNATURE_MISMATCH', $result->getErrorCode());
    }

    /**
     * Requirement 4: Verify product identity.
     */
    public function test_rejects_mismatched_product_id(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['crm.example.com'],
            'prd' => 'DIFFERENT-PRODUCT-ID',
        ]);

        $result = $this->verifier->verify('crm.example.com', $cert);

        $this->assertFalse($result->isValid());
        $this->assertSame('E_PRODUCT_MISMATCH', $result->getErrorCode());
        $this->assertStringContainsString('Product mismatch', $result->getReason());
    }

    /**
     * Requirement 5: Verify authorized domains (including wildcards and ports).
     */
    public function test_domain_verification_rules(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['app.example.com', '*.clientcorp.io'],
        ]);

        // Matching exact domain
        $this->assertTrue($this->verifier->verify('app.example.com', $cert)->isValid());

        // Stripping port
        $this->assertTrue($this->verifier->verify('app.example.com:8443', $cert)->isValid());

        // Matching wildcard
        $this->assertTrue($this->verifier->verify('tenant1.clientcorp.io', $cert)->isValid());
        $this->assertTrue($this->verifier->verify('deep.sub.clientcorp.io', $cert)->isValid());

        // Unauthorized domain
        $failed = $this->verifier->verify('pirate-domain.com', $cert);
        $this->assertFalse($failed->isValid());
        $this->assertSame('E_DOMAIN_UNAUTHORIZED', $failed->getErrorCode());
    }

    /**
     * Requirement 6: Verify expiration and temporal validity.
     */
    public function test_rejects_expired_and_future_licenses(): void
    {
        // Expired
        $expiredCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'exp' => time() - 3600,
        ]);
        $expiredResult = $this->verifier->verify('example.com', $expiredCert);
        $this->assertFalse($expiredResult->isValid());
        $this->assertSame(LicenseStatus::EXPIRED, $expiredResult->getStatus());
        $this->assertSame('E_TEMPORAL_EXPIRED', $expiredResult->getErrorCode());

        // Future not-before
        $futureCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'nbf' => time() + 86400,
        ]);
        $futureResult = $this->verifier->verify('example.com', $futureCert);
        $this->assertFalse($futureResult->isValid());
        $this->assertSame('E_TEMPORAL_NOT_YET_VALID', $futureResult->getErrorCode());
    }

    /**
     * Requirement 7: Verify license status claim.
     */
    public function test_verifies_license_status_claim(): void
    {
        $suspendedCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'sta' => 'SUSPENDED',
        ]);
        $suspendedResult = $this->verifier->verify('example.com', $suspendedCert);
        $this->assertFalse($suspendedResult->isValid());
        $this->assertSame(LicenseStatus::SUSPENDED, $suspendedResult->getStatus());
        $this->assertSame('E_STATUS_SUSPENDED', $suspendedResult->getErrorCode());

        $lockedCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'sta' => 'LOCKED',
        ]);
        $lockedResult = $this->verifier->verify('example.com', $lockedCert);
        $this->assertFalse($lockedResult->isValid());
        $this->assertSame(LicenseStatus::LOCKED, $lockedResult->getStatus());
        $this->assertSame('E_STATUS_LOCKED', $lockedResult->getErrorCode());
    }

    /**
     * Requirement 8: Verify installation identity where applicable.
     */
    public function test_installation_identity_binding_when_strict(): void
    {
        $currentFingerprint = MachineFingerprint::get();

        // 1. Matching strict fingerprint
        $matchingCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'ins' => $currentFingerprint,
            'pol' => ['strict_instance' => true],
        ]);
        $this->assertTrue($this->verifier->verify('example.com', $matchingCert)->isValid());

        // 2. Mismatched strict fingerprint (e.g. copied from another server)
        $alienCert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'ins' => 'inst_stolen_alien_fingerprint',
            'pol' => ['strict_instance' => true],
        ]);
        $alienResult = $this->verifier->verify('example.com', $alienCert);
        $this->assertFalse($alienResult->isValid());
        $this->assertSame('E_INSTANCE_MISMATCH', $alienResult->getErrorCode());
        $this->assertStringContainsString('bound to another server', $alienResult->getReason());
    }

    /**
     * Requirement 9: Support signed license features and quotas.
     */
    public function test_supports_signed_feature_entitlements(): void
    {
        $cert = $this->createSignedCertificate([
            'dom' => ['example.com'],
            'ent' => [
                'dark_mode' => true,
                'beta_tester' => false,
                'features' => ['analytics', 'exports'],
                'max_projects' => 100,
                'tier' => 'Platinum',
            ],
        ]);

        $result = $this->verifier->verify('example.com', $cert);
        $this->assertTrue($result->isValid());

        $this->assertTrue($result->can('dark_mode'));
        $this->assertFalse($result->can('beta_tester'));
        $this->assertTrue($result->can('analytics'));
        $this->assertTrue($result->can('exports'));
        $this->assertFalse($result->can('missing_module'));
        $this->assertSame(100, $result->quota('max_projects'));
        $this->assertSame('Platinum', $result->tier());
    }

    /**
     * Requirement 10: Never trust unsigned or modified stored license documents.
     */
    public function test_never_trusts_unsigned_or_tampered_stored_documents(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);

        // Verify clean document passes
        $this->assertTrue($this->verifier->verify('example.com')->isValid());

        // Tamper with stored file content directly on disk
        $raw = file_get_contents($this->tempStoragePath);
        // Replace with raw unverified JSON without valid signature
        $tampered = json_encode([
            'header' => ['alg' => 'Ed25519'],
            'payload' => ['dom' => ['example.com'], 'sta' => 'ACTIVE', 'lic' => 'FORGED'],
            'signature' => base64_encode(str_repeat('X', 64)),
        ]);
        file_put_contents($this->tempStoragePath, $tampered);

        // Immediate subsequent verification must fail signature check
        $tamperedResult = $this->verifier->verify('example.com');
        $this->assertFalse($tamperedResult->isValid());
        $this->assertSame('E_SIGNATURE_MISMATCH', $tamperedResult->getErrorCode());
    }

    /**
     * Key Rotation: Multi-key resolution by kid.
     */
    public function test_resolves_keys_by_key_identifier_for_rotation(): void
    {
        $kp1 = Ed25519Verifier::generateKeyPair();
        $kp2 = Ed25519Verifier::generateKeyPair();

        $keysMap = [
            'key_2026_q1' => $kp1['public_key'],
            'key_2026_q2' => $kp2['public_key'],
        ];

        $rotVerifier = new LicenseVerifier($this->storage, $keysMap, 'PROD-TEST', false);

        // Sign with key 2
        $payload = [
            'lic' => 'CLK-ROTATION',
            'prd' => 'PROD-TEST',
            'dom' => ['example.com'],
            'sta' => 'ACTIVE',
            'iat' => time() - 100,
            'nbf' => time() - 100,
            'exp' => time() + 100000,
        ];
        $canonical = CanonicalJson::encode($payload);
        $sig2 = Ed25519Verifier::sign($canonical, $kp2['secret_key']);

        $doc2 = [
            'header' => ['alg' => 'Ed25519', 'kid' => 'key_2026_q2'],
            'payload' => $payload,
            'signature' => $sig2,
        ];

        $this->assertTrue($rotVerifier->verify('example.com', $doc2)->isValid());

        // Unknown key ID must fail with E_KEY_UNKNOWN
        $doc2['header']['kid'] = 'non_existent_key_id';
        $res = $rotVerifier->verify('example.com', $doc2);
        $this->assertFalse($res->isValid());
        $this->assertSame('E_KEY_UNKNOWN', $res->getErrorCode());
    }
}

