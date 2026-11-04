<?php

namespace Rasel\CodeLock\Support;

class MachineFingerprint
{
    /**
     * Get or compute the unique, stable installation identifier.
     */
    public static function get(): string
    {
        $explicit = config('codelock.installation_id');

        if (!empty($explicit) && is_string($explicit)) {
            return trim($explicit);
        }

        return self::generate();
    }

    /**
     * Generate a deterministic installation identifier.
     */
    public static function generate(): string
    {
        $components = [
            'app_key' => config('app.key', 'default_codelock_key'),
            'base_path' => function_exists('base_path') ? base_path() : __DIR__,
            'hostname' => gethostname() ?: php_uname('n'),
            'os' => PHP_OS_FAMILY,
        ];

        $hash = hash('sha256', implode('|', $components));

        return 'inst_' . substr($hash, 0, 24);
    }

    /**
     * Gather system and runtime environment metadata for telemetry.
     */
    public static function getSystemMetadata(): array
    {
        return [
            'instance_id' => self::get(),
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'os_family' => PHP_OS_FAMILY,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI',
            'installed_at' => date('c'),
        ];
    }
}

