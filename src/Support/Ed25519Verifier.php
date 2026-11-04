<?php

namespace Rasel\CodeLock\Support;

use Rasel\CodeLock\Exceptions\SignatureVerificationException;

class Ed25519Verifier
{
    /**
     * Verify a detached Ed25519 signature against a message and public key.
     *
     * @param string $signature Base64-encoded or raw 64-byte signature
     * @param string $message The exact plaintext canonical message that was signed
     * @param string $publicKey Base64-encoded or raw 32-byte public key
     * @return bool True if signature is valid, false otherwise
     */
    public static function verify(string $signature, string $message, string $publicKey): bool
    {
        $rawSig = self::decodeKeyOrSig($signature, 64);
        $rawPub = self::decodeKeyOrSig($publicKey, 32);

        if ($rawSig === null || $rawPub === null) {
            return false;
        }

        try {
            if (function_exists('sodium_crypto_sign_verify_detached')) {
                return sodium_crypto_sign_verify_detached($rawSig, $message, $rawPub);
            }

            if (class_exists(\ParagonIE_Sodium_Compat::class)) {
                return \ParagonIE_Sodium_Compat::crypto_sign_verify_detached($rawSig, $message, $rawPub);
            }

            throw new SignatureVerificationException(
                'Neither ext-sodium nor paragonie/sodium_compat is available for Ed25519 verification.'
            );
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Create a detached Ed25519 signature (useful for tests and server signing).
     *
     * @param string $message
     * @param string $secretKey Base64-encoded or raw 64-byte secret key
     * @return string Base64-encoded detached signature
     */
    public static function sign(string $message, string $secretKey): string
    {
        $rawSec = self::decodeKeyOrSig($secretKey, 64);

        if ($rawSec === null) {
            throw new \InvalidArgumentException('Secret key must be a valid 64-byte key (raw or Base64).');
        }

        if (function_exists('sodium_crypto_sign_detached')) {
            $sig = sodium_crypto_sign_detached($message, $rawSec);
        } elseif (class_exists(\ParagonIE_Sodium_Compat::class)) {
            $sig = \ParagonIE_Sodium_Compat::crypto_sign_detached($message, $rawSec);
        } else {
            throw new \RuntimeException('Sodium support missing.');
        }

        return base64_encode($sig);
    }

    /**
     * Generate a new Ed25519 keypair for testing or key generation.
     *
     * @return array{public_key: string, secret_key: string} Base64 encoded keys
     */
    public static function generateKeyPair(): array
    {
        if (function_exists('sodium_crypto_sign_keypair')) {
            $kp = sodium_crypto_sign_keypair();
            $sec = sodium_crypto_sign_secretkey($kp);
            $pub = sodium_crypto_sign_publickey($kp);
        } elseif (class_exists(\ParagonIE_Sodium_Compat::class)) {
            $kp = \ParagonIE_Sodium_Compat::crypto_sign_keypair();
            $sec = \ParagonIE_Sodium_Compat::crypto_sign_secretkey($kp);
            $pub = \ParagonIE_Sodium_Compat::crypto_sign_publickey($kp);
        } else {
            throw new \RuntimeException('Sodium support missing.');
        }

        return [
            'public_key' => base64_encode($pub),
            'secret_key' => base64_encode($sec),
        ];
    }

    /**
     * Decode a key or signature from Base64 or Hex if not already raw binary of expected length.
     */
    protected static function decodeKeyOrSig(string $input, int $expectedLength): ?string
    {
        if (strlen($input) === $expectedLength) {
            return $input;
        }

        // Try Base64
        $decoded = base64_decode($input, true);
        if ($decoded !== false && strlen($decoded) === $expectedLength) {
            return $decoded;
        }

        // Try Hex
        if (ctype_xdigit($input) && strlen($input) === ($expectedLength * 2)) {
            $hexDecoded = hex2bin($input);
            if ($hexDecoded !== false && strlen($hexDecoded) === $expectedLength) {
                return $hexDecoded;
            }
        }

        return null;
    }
}

