<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\Support\MachineFingerprint;

class InstallCommand extends Command
{
    protected $signature = 'codelock:install
                            {--force : Overwrite existing published files}';

    protected $description = 'Install and publish CodeLock licensing configuration and assets';

    public function handle(): int
    {
        $this->info('Initializing CodeLock Licensing Engine...');

        // 1. Publish Configuration
        $this->call('vendor:publish', [
            '--tag' => 'codelock-config',
            '--force' => $this->option('force'),
        ]);

        // 2. Publish Views
        $this->call('vendor:publish', [
            '--tag' => 'codelock-views',
            '--force' => $this->option('force'),
        ]);

        // 3. System Environment Inspection
        $this->newLine();
        $this->info('Checking Environment Capabilities:');

        $hasNativeSodium = extension_loaded('sodium');
        $hasCompat = class_exists(\ParagonIE_Sodium_Compat::class);
        $hasCurl = extension_loaded('curl');
        $hasOpenssl = extension_loaded('openssl');

        $this->table(
            ['Component', 'Status', 'Driver'],
            [
                ['PHP Version', PHP_VERSION, PHP_VERSION_ID >= 80200 ? '<info>OK (8.2+)</info>' : '<error>Unsupported</error>'],
                ['Ed25519 Cryptography', ($hasNativeSodium || $hasCompat) ? '<info>Available</info>' : '<error>Missing</error>', $hasNativeSodium ? 'ext-sodium (Hardware Accelerated)' : 'paragonie/sodium_compat'],
                ['HTTPS / cURL', $hasCurl ? '<info>Available</info>' : '<error>Missing</error>', 'ext-curl'],
                ['AES-256 / OpenSSL', $hasOpenssl ? '<info>Available</info>' : '<error>Missing</error>', 'ext-openssl'],
            ]
        );

        // 4. Display Machine Fingerprint & Package Status
        $fingerprint = MachineFingerprint::get();
        $this->newLine();
        $this->line("Installation Fingerprint: <comment>{$fingerprint}</comment>");
        $this->line('Global Enforcement Middleware: <info>Active (EnsureLicensed)</info>');
        $heartbeatMins = config('codelock.heartbeat_interval_minutes');
        if (!empty($heartbeatMins) && (int) $heartbeatMins > 0) {
            $this->line("Automated Heartbeat Scheduler: <info>Active (Every {$heartbeatMins} Minutes - Testing Mode)</info>");
        } else {
            $heartbeatHours = (int) config('codelock.heartbeat_interval', 6);
            $this->line("Automated Heartbeat Scheduler: <info>Active (Every {$heartbeatHours} Hours)</info>");
        }
        $this->info('CodeLock package installed successfully.');
        $this->line('To activate your license, run: <comment>php artisan codelock:activate</comment>');

        return Command::SUCCESS;
    }
}

