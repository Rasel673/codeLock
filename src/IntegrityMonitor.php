<?php

namespace Rasel\CodeLock;

use Rasel\CodeLock\Exceptions\SignatureVerificationException;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;

class IntegrityMonitor
{
    protected string $packageRoot;
    protected string $manifestPath;
    /** @var string|array<string, string> */
    protected string|array $publicKeys;
    protected LicenseStorage $storage;
    protected string $cacheFilePath;

    public function __construct(
        ?string $packageRoot = null,
        ?string $manifestPath = null,
        string|array|null $publicKeys = null,
        ?LicenseStorage $storage = null
    ) {
        $this->packageRoot = rtrim($packageRoot ?? realpath(__DIR__ . '/..') ?: dirname(__DIR__), '/\\');
        $configuredManifest = config('codelock.integrity.manifest_path');
        $this->manifestPath = $manifestPath ?: (!empty($configuredManifest) ? $configuredManifest : $this->packageRoot . '/resources/integrity.json');
        $this->publicKeys = $publicKeys ?? config('codelock.public_keys', config('codelock.public_key', ''));
        $this->storage = $storage ?? new LicenseStorage();
        $this->cacheFilePath = dirname($this->storage->getStoragePath()) . '/.codelock.integrity';
    }

    /**
     * Default protected package enforcement files relative to package root.
     *
     * @return array<string>
     */
    public static function getDefaultProtectedFiles(): array
    {
        return [
            'src/LicenseVerifier.php',
            'src/LicenseManager.php',
            'src/LicenseDocument.php',
            'src/LicenseVerificationResult.php',
            'src/Middleware/EnsureLicensed.php',
            'src/Storage/LicenseStorage.php',
            'src/Support/Ed25519Verifier.php',
            'src/Support/CanonicalJson.php',
            'src/Support/MachineFingerprint.php',
            'src/Support/LicenseKey.php',
            'src/IntegrityMonitor.php',
            'src/IntegrityResult.php',
        ];
    }

    /**
     * Perform full integrity verification against signed manifest.
     *
     * @param bool $force Bypass memory/file cache and force hash calculation
     * @return IntegrityResult
     */
    public function verify(bool $force = false): IntegrityResult
    {
        // 1. Check if integrity monitoring is globally enabled
        if (!config('codelock.integrity.enabled', true)) {
            return IntegrityResult::success(0, true);
        }

        // 2. Check cached verification status (unless forced or hit by stochastic tripwire)
        if (!$force && $this->isCacheValid() && !$this->shouldRunStochasticCheck()) {
            return IntegrityResult::success($this->getCachedCheckedCount(), true);
        }

        // 3. Load Manifest File
        if (!file_exists($this->manifestPath) || filesize($this->manifestPath) === 0) {
            $this->clearCache();
            return IntegrityResult::failure(
                'E_MANIFEST_NOT_FOUND',
                "Integrity manifest not found at [{$this->manifestPath}].",
                [],
                [],
                0
            );
        }

        $rawJson = @file_get_contents($this->manifestPath);
        $manifest = json_decode((string) $rawJson, true);

        if (!is_array($manifest) || !isset($manifest['payload'], $manifest['signature'])) {
            $this->clearCache();
            return IntegrityResult::failure(
                'E_MANIFEST_MALFORMED',
                'Integrity manifest document is corrupted or missing cryptographic envelope.',
                [],
                [],
                0
            );
        }

        // 4. Cryptographically Verify Manifest Signature
        $header = $manifest['header'] ?? [];
        $payload = $manifest['payload'];
        $signature = $manifest['signature'];
        $keyId = $header['kid'] ?? null;

        $publicKey = $this->resolvePublicKey($keyId);
        if (empty($publicKey)) {
            $this->clearCache();
            return IntegrityResult::failure(
                'E_KEY_UNKNOWN',
                'Public key not found for manifest key ID: ' . ($keyId ?? 'default'),
                [],
                [],
                0
            );
        }

        $canonicalPayload = CanonicalJson::encode($payload);
        if (!Ed25519Verifier::verify($signature, $canonicalPayload, $publicKey)) {
            $this->clearCache();
            return IntegrityResult::failure(
                'E_MANIFEST_INVALID_SIGNATURE',
                'Integrity manifest signature verification failed. Manifest has been altered.',
                [],
                [],
                0
            );
        }

        // 5. Inspect Designated Protected Files
        $manifestFiles = $payload['files'] ?? [];
        if (!is_array($manifestFiles) || empty($manifestFiles)) {
            $this->clearCache();
            return IntegrityResult::failure(
                'E_MANIFEST_EMPTY',
                'Integrity manifest contains no protected files.',
                [],
                [],
                0
            );
        }

        $modified = [];
        $missing = [];
        $checkedCount = 0;

        foreach ($manifestFiles as $relativePath => $expectedHash) {
            // Path traversal guard
            if (str_contains($relativePath, '..') || str_starts_with($relativePath, '/') || str_starts_with($relativePath, '\\')) {
                continue;
            }

            $absolutePath = $this->packageRoot . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relativePath);
            $checkedCount++;

            // Detect missing files
            if (!file_exists($absolutePath)) {
                $missing[] = $relativePath;
                continue;
            }

            // Detect symlink replacements
            if (is_link($absolutePath)) {
                $modified[] = [
                    'path' => $relativePath,
                    'expected' => $expectedHash,
                    'actual' => 'SYMLINK_REPLACEMENT',
                ];
                continue;
            }

            // Compute normalized file hash
            $actualHash = $this->hashFile($absolutePath);
            if ($actualHash === null || !hash_equals((string) $expectedHash, $actualHash)) {
                $modified[] = [
                    'path' => $relativePath,
                    'expected' => $expectedHash,
                    'actual' => $actualHash ?? 'UNREADABLE',
                ];
            }
        }

        // 6. Handle Tampering / Missing Files
        if (!empty($modified) || !empty($missing)) {
            $this->clearCache();
            $reason = 'Integrity violation detected: ';
            if (!empty($modified)) {
                $reason .= count($modified) . ' file(s) modified. ';
            }
            if (!empty($missing)) {
                $reason .= count($missing) . ' file(s) missing.';
            }

            return IntegrityResult::failure(
                'E_INTEGRITY_MISMATCH',
                trim($reason),
                $modified,
                $missing,
                $checkedCount
            );
        }

        // 7. Verification Success: Cache Clean State
        $this->saveCache($checkedCount);

        return IntegrityResult::success($checkedCount, false);
    }

    /**
     * Compute deterministic SHA-256 hash of a file after normalizing line endings to LF.
     */
    public function hashFile(string $absolutePath): ?string
    {
        if (!file_exists($absolutePath) || !is_readable($absolutePath)) {
            return null;
        }

        $content = @file_get_contents($absolutePath);
        if ($content === false) {
            return null;
        }

        $normalized = $this->normalizeContent($content);

        return hash('sha256', $normalized);
    }

    /**
     * Normalize content line endings to LF to prevent false positives across git/Windows/cPanel deployments.
     */
    public function normalizeContent(string $content): string
    {
        // Standardize all linebreaks (CRLF -> LF, CR -> LF)
        return str_replace(["\r\n", "\r"], "\n", $content);
    }

    /**
     * Build and cryptographically sign an integrity manifest dictionary (for build script & tests).
     *
     * @param array<string> $files Relative paths to protect
     * @param string $secretKey Ed25519 Secret Key (Base64)
     * @param ?string $keyId Key identifier
     * @param string $version Package version
     * @return array Complete signed manifest envelope
     */
    public function generateManifest(
        array $files,
        string $secretKey,
        ?string $keyId = 'key_2026_vector',
        string $version = '1.0.0'
    ): array {
        $fileHashes = [];

        foreach ($files as $relPath) {
            $absPath = $this->packageRoot . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relPath);
            $hash = $this->hashFile($absPath);
            if ($hash !== null) {
                $fileHashes[$relPath] = $hash;
            }
        }

        // Sort keys lexicographically
        ksort($fileHashes, SORT_STRING);

        $payload = [
            'version' => $version,
            'algorithm' => 'SHA-256',
            'normalized' => 'LF',
            'timestamp' => time(),
            'files' => $fileHashes,
        ];

        $canonical = CanonicalJson::encode($payload);
        $signature = Ed25519Verifier::sign($canonical, $secretKey);

        return [
            'header' => [
                'alg' => 'Ed25519',
                'kid' => $keyId,
                'typ' => 'CODELOCK-INTEGRITY',
                'ver' => $version,
            ],
            'payload' => $payload,
            'signature' => $signature,
        ];
    }

    /**
     * Check if clean integrity cache marker is valid and within TTL.
     */
    protected function isCacheValid(): bool
    {
        if (!file_exists($this->cacheFilePath)) {
            return false;
        }

        $raw = @file_get_contents($this->cacheFilePath);
        if ($raw === false) {
            return false;
        }

        $decrypted = $this->storage->decrypt($raw);
        if ($decrypted === null) {
            return false;
        }

        $data = json_decode($decrypted, true);
        if (!is_array($data) || !isset($data['timestamp'], $data['valid']) || !$data['valid']) {
            return false;
        }

        $ttl = (int) config('codelock.integrity.cache_ttl', 3600);
        return (time() - (int) $data['timestamp']) < $ttl;
    }

    /**
     * Get the number of files checked in the cached state.
     */
    protected function getCachedCheckedCount(): int
    {
        if (!file_exists($this->cacheFilePath)) {
            return 0;
        }

        $raw = @file_get_contents($this->cacheFilePath);
        $decrypted = $raw ? $this->storage->decrypt($raw) : null;
        $data = $decrypted ? json_decode($decrypted, true) : null;

        return (int) ($data['checked_count'] ?? 0);
    }

    /**
     * Save clean encrypted cache marker.
     */
    protected function saveCache(int $checkedCount): void
    {
        $data = [
            'valid' => true,
            'timestamp' => time(),
            'checked_count' => $checkedCount,
        ];

        $encrypted = $this->storage->encrypt(json_encode($data));
        $this->storage->atomicWrite($this->cacheFilePath, $encrypted, 0600);
    }

    /**
     * Delete clean integrity cache.
     */
    public function clearCache(): void
    {
        if (file_exists($this->cacheFilePath)) {
            @unlink($this->cacheFilePath);
        }
    }

    /**
     * Determine if stochastic tripwire check should run on this execution.
     */
    protected function shouldRunStochasticCheck(): bool
    {
        $rate = (int) config('codelock.integrity.stochastic_rate', 5);
        if ($rate <= 0) {
            return false;
        }

        try {
            return random_int(1, 100) <= $rate;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Resolve public key given a key identifier.
     */
    protected function resolvePublicKey(?string $kid = null): ?string
    {
        if (is_array($this->publicKeys)) {
            if (!empty($kid)) {
                return $this->publicKeys[$kid] ?? null;
            }

            if (isset($this->publicKeys['default'])) {
                return $this->publicKeys['default'];
            }

            $first = reset($this->publicKeys);
            return $first ?: null;
        }

        if (is_string($this->publicKeys) && !empty($this->publicKeys)) {
            return $this->publicKeys;
        }

        return null;
    }

    public function getPackageRoot(): string
    {
        return $this->packageRoot;
    }

    public function getManifestPath(): string
    {
        return $this->manifestPath;
    }
}
