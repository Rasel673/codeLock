<?php

namespace Rasel\CodeLock\Support;

class LicenseKey
{
    /**
     * Validate whether a license key matches acceptable commercial format.
     */
    public static function isValidFormat(string $key): bool
    {
        $key = trim($key);

        if (empty($key) || strlen($key) < 10) {
            return false;
        }

        // Allow alphanumeric characters and dashes (e.g. CLK-XXXX-XXXX-XXXX-XXXX)
        return (bool) preg_match('/^[A-Za-z0-9\-_]{10,80}$/', $key);
    }

    /**
     * Normalize license key (trim and uppercase).
     */
    public static function normalize(string $key): string
    {
        return strtoupper(trim($key));
    }

    /**
     * Mask a license key for safe display and audit logging without leaking credentials.
     * e.g., "CLK-2026-ALPHA-9821-BETA" becomes "CLK-2026-****-****-BETA".
     */
    public static function mask(string $key): string
    {
        $normalized = self::normalize($key);
        $len = strlen($normalized);

        if ($len <= 8) {
            return str_repeat('*', $len);
        }

        // If formatted with dashes (e.g. CLK-AAAA-BBBB-CCCC)
        if (str_contains($normalized, '-')) {
            $parts = explode('-', $normalized);
            $count = count($parts);

            if ($count >= 3) {
                for ($i = 1; $i < $count - 1; $i++) {
                    $parts[$i] = str_repeat('*', strlen($parts[$i]));
                }
                return implode('-', $parts);
            }
        }

        // Fallback: show first 4 and last 4 characters
        $start = substr($normalized, 0, 4);
        $end = substr($normalized, -4);
        $middle = str_repeat('*', max(4, $len - 8));

        return $start . '-' . $middle . '-' . $end;
    }
}

