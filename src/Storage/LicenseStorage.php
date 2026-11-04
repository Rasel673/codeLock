<?php

namespace Rasel\CodeLock\Storage;

use Rasel\CodeLock\Exceptions\LicenseInvalidException;

class LicenseStorage
{
    protected string $storagePath;
    protected string $statusPath;
    protected string $timePath;
    protected string $syncPath;
    protected string $lockStatePath;

    public function __construct(?string $storagePath = null, ?string $statusPath = null)
    {
        $this->storagePath = $storagePath ?? config('codelock.storage_path', storage_path('app/.codelock.lic'));
        $this->statusPath = $statusPath ?? config('codelock.status_cache_path', storage_path('app/.codelock.status'));
        $storageDir = dirname($this->storagePath);
        $this->timePath = $storageDir . '/.codelock.time';
        $this->syncPath = $storageDir . '/.codelock.sync';
        $this->lockStatePath = $storageDir . '/.codelock.lock_state';

        // Assert storage paths are kept strictly outside public directory
        $this->assertOutsidePublicDirectory($this->storagePath);
        $this->assertOutsidePublicDirectory($this->statusPath);
    }

    /**
     * Save the signed license certificate securely using atomic file write.
     */
    public function saveCertificate(array $certificate): void
    {
        $json = json_encode($certificate, JSON_UNESCAPED_SLASHES);
        $encrypted = $this->encrypt($json);

        $this->atomicWrite($this->storagePath, $encrypted, 0600);
    }

    /**
     * Load and decrypt the stored license certificate.
     */
    public function loadCertificate(): ?array
    {
        if (!file_exists($this->storagePath)) {
            return null;
        }

        $raw = @file_get_contents($this->storagePath);
        if ($raw === false || empty($raw)) {
            return null;
        }

        $decrypted = $this->decrypt($raw);
        if ($decrypted === null) {
            // Check if stored as plain JSON fallback
            $decoded = json_decode($raw, true);
            if (is_array($decoded) && isset($decoded['payload'], $decoded['signature'])) {
                return $decoded;
            }
            return null;
        }

        $decoded = json_decode($decrypted, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Determine if a certificate file exists.
     */
    public function hasCertificate(): bool
    {
        return file_exists($this->storagePath) && filesize($this->storagePath) > 0;
    }

    /**
     * Delete the license certificate and its associated status caches cleanly.
     */
    public function deleteCertificate(): bool
    {
        $deleted = true;
        if (file_exists($this->storagePath)) {
            $deleted = @unlink($this->storagePath);
        }
        $this->deleteRemoteStatus();
        if (file_exists($this->syncPath)) {
            @unlink($this->syncPath);
        }
        if (file_exists($this->lockStatePath)) {
            @unlink($this->lockStatePath);
        }
        return $deleted;
    }

    /**
     * Save cached remote heartbeat status atomically.
     */
    public function saveRemoteStatus(array $status): void
    {
        $json = json_encode($status, JSON_UNESCAPED_SLASHES);
        $encrypted = $this->encrypt($json);

        $this->atomicWrite($this->statusPath, $encrypted, 0600);
    }

    /**
     * Load cached remote heartbeat status.
     */
    public function loadRemoteStatus(): ?array
    {
        if (!file_exists($this->statusPath)) {
            return null;
        }

        $raw = @file_get_contents($this->statusPath);
        if ($raw === false || empty($raw)) {
            return null;
        }

        $decrypted = $this->decrypt($raw);
        if ($decrypted === null) {
            $decoded = json_decode($raw, true);
            return is_array($decoded) ? $decoded : null;
        }

        $decoded = json_decode($decrypted, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Delete remote status cache.
     */
    public function deleteRemoteStatus(): bool
    {
        if (file_exists($this->statusPath)) {
            return @unlink($this->statusPath);
        }
        return true;
    }

    /**
     * Record monotonic verification timestamp atomically to detect clock rollbacks.
     */
    public function recordVerificationTimestamp(int $timestamp): void
    {
        $encrypted = $this->encrypt((string) $timestamp);
        $this->atomicWrite($this->timePath, $encrypted, 0600);
    }

    /**
     * Get the last recorded verification timestamp.
     */
    public function getLastVerificationTimestamp(): int
    {
        if (!file_exists($this->timePath)) {
            return 0;
        }

        $raw = @file_get_contents($this->timePath);
        if ($raw === false || empty($raw)) {
            return 0;
        }

        $decrypted = $this->decrypt($raw);
        return $decrypted !== null ? (int) $decrypted : 0;
    }

    /**
     * Record the timestamp of the last successful remote heartbeat synchronization.
     */
    public function recordLastSyncTimestamp(int $timestamp): void
    {
        $encrypted = $this->encrypt((string) $timestamp);
        $this->atomicWrite($this->syncPath, $encrypted, 0600);
    }

    /**
     * Retrieve the timestamp of the last successful remote heartbeat synchronization.
     */
    public function getLastSyncTimestamp(): int
    {
        if (!file_exists($this->syncPath)) {
            return 0;
        }

        $raw = @file_get_contents($this->syncPath);
        if ($raw === false || empty($raw)) {
            return 0;
        }

        $decrypted = $this->decrypt($raw);
        return $decrypted !== null ? (int) $decrypted : 0;
    }

    /**
     * Record local lock state and timestamp securely.
     */
    public function recordLockState(string $status, ?string $reason = null, ?int $timestamp = null): void
    {
        $data = [
            'status' => $status,
            'reason' => $reason,
            'timestamp' => $timestamp ?? time(),
        ];
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        $encrypted = $this->encrypt($json);
        $this->atomicWrite($this->lockStatePath, $encrypted, 0600);
    }

    /**
     * Retrieve the last recorded local lock state.
     */
    public function getLastLockState(): ?array
    {
        if (!file_exists($this->lockStatePath)) {
            return null;
        }

        $raw = @file_get_contents($this->lockStatePath);
        if ($raw === false || empty($raw)) {
            return null;
        }

        $decrypted = $this->decrypt($raw);
        if ($decrypted === null) {
            $decoded = json_decode($raw, true);
            return is_array($decoded) ? $decoded : null;
        }

        $decoded = json_decode($decrypted, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Perform atomic file write (write to temporary file with exclusive lock, set permissions, then atomic rename).
     */
    public function atomicWrite(string $destinationPath, string $content, int $mode = 0600): void
    {
        $dir = dirname($destinationPath);
        $this->ensureDirectoryExists($dir);

        // Create unique temporary file in the same directory to guarantee same filesystem for atomic rename
        $tempPath = $destinationPath . '.' . bin2hex(random_bytes(8)) . '.tmp';

        $written = @file_put_contents($tempPath, $content, LOCK_EX);
        if ($written === false) {
            throw new LicenseInvalidException("Failed to write temporary license file at [{$tempPath}]. Check directory permissions.");
        }

        // Restrict file permissions
        @chmod($tempPath, $mode);

        // Atomic rename replacing destination
        if (!@rename($tempPath, $destinationPath)) {
            // Windows fallback if destination is open: unlink then rename
            @unlink($destinationPath);
            if (!@rename($tempPath, $destinationPath)) {
                @unlink($tempPath);
                throw new LicenseInvalidException("Atomic swap failed when moving [{$tempPath}] to [{$destinationPath}].");
            }
        }

        @chmod($destinationPath, $mode);
    }

    /**
     * Assert that a storage path is located strictly outside the public web root.
     */
    public function assertOutsidePublicDirectory(string $path): void
    {
        if (!function_exists('public_path')) {
            return;
        }

        $publicDir = realpath(public_path());
        $targetDir = realpath(dirname($path)) ?: dirname($path);

        if ($publicDir !== false && str_starts_with($targetDir, $publicDir)) {
            throw new \InvalidArgumentException(
                "Security violation: CodeLock license storage path [{$path}] must NOT be placed inside the public directory [{$publicDir}]."
            );
        }
    }

    /**
     * Encrypt a string using authenticated AES-256-CBC with HMAC-SHA256.
     */
    public function encrypt(string $plainText): string
    {
        $key = $this->getEncryptionKey();
        $iv = random_bytes(16);
        $cipherText = openssl_encrypt($plainText, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $iv . $cipherText, $key, true);

        return base64_encode($iv . $hmac . $cipherText);
    }

    /**
     * Decrypt an authenticated AES-256-CBC ciphertext string.
     */
    public function decrypt(string $cipherText): ?string
    {
        $raw = base64_decode($cipherText, true);
        if ($raw === false || strlen($raw) < 48) { // 16 bytes IV + 32 bytes HMAC
            return null;
        }

        $key = $this->getEncryptionKey();
        $iv = substr($raw, 0, 16);
        $hmac = substr($raw, 16, 32);
        $cipher = substr($raw, 48);

        // Authenticated timing-safe HMAC check
        $calculatedHmac = hash_hmac('sha256', $iv . $cipher, $key, true);
        if (!hash_equals($hmac, $calculatedHmac)) {
            return null;
        }

        $decrypted = openssl_decrypt($cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return $decrypted !== false ? $decrypted : null;
    }

    /**
     * Derive a 32-byte encryption key from app key and salt.
     */
    protected function getEncryptionKey(): string
    {
        $appKey = config('app.key', 'codelock_default_app_key');
        if (str_starts_with($appKey, 'base64:')) {
            $appKey = base64_decode(substr($appKey, 7)) ?: $appKey;
        }

        return hash('sha256', $appKey . 'codelock_salt_v1', true);
    }

    /**
     * Ensure storage directory exists with restrictive permissions.
     */
    protected function ensureDirectoryExists(string $dir): void
    {
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }

    public function getStoragePath(): string
    {
        return $this->storagePath;
    }

    public function getStatusPath(): string
    {
        return $this->statusPath;
    }
}
