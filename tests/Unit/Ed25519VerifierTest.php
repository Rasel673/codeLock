<?php

namespace Rasel\CodeLock\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rasel\CodeLock\Support\Ed25519Verifier;

class Ed25519VerifierTest extends TestCase
{
    public function test_keypair_generation_and_signature_verification(): void
    {
        $keyPair = Ed25519Verifier::generateKeyPair();
        $this->assertNotEmpty($keyPair['public_key']);
        $this->assertNotEmpty($keyPair['secret_key']);

        $message = '{"domain":"crm.example.com","license":"CLK-999"}';
        $signature = Ed25519Verifier::sign($message, $keyPair['secret_key']);

        $this->assertNotEmpty($signature);

        $isValid = Ed25519Verifier::verify($signature, $message, $keyPair['public_key']);
        $this->assertTrue($isValid);
    }

    public function test_fails_verification_when_message_is_tampered(): void
    {
        $keyPair = Ed25519Verifier::generateKeyPair();
        $message = '{"amount":100}';
        $signature = Ed25519Verifier::sign($message, $keyPair['secret_key']);

        $tampered = '{"amount":101}';
        $isValid = Ed25519Verifier::verify($signature, $tampered, $keyPair['public_key']);

        $this->assertFalse($isValid);
    }

    public function test_fails_verification_with_wrong_public_key(): void
    {
        $keyPair1 = Ed25519Verifier::generateKeyPair();
        $keyPair2 = Ed25519Verifier::generateKeyPair();

        $message = 'SecretPayload';
        $signature = Ed25519Verifier::sign($message, $keyPair1['secret_key']);

        $isValid = Ed25519Verifier::verify($signature, $message, $keyPair2['public_key']);
        $this->assertFalse($isValid);
    }

    public function test_fails_gracefully_with_corrupted_key_or_signature(): void
    {
        $isValid = Ed25519Verifier::verify('not-a-valid-sig', 'message', 'not-a-valid-key');
        $this->assertFalse($isValid);
    }
}

