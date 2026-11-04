<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\IntegrityMonitor;
use Rasel\CodeLock\Support\Ed25519Verifier;

class GenerateIntegrityManifestCommand extends Command
{
    protected $signature = 'codelock:integrity-manifest
                            {--key= : The Ed25519 Secret Signing Key (Base64)}
                            {--key-id=key_2026_vector : Key Identifier matching public key}
                            {--out= : Destination path for integrity.json}';

    protected $description = 'Generate and cryptographically sign the package integrity manifest';

    public function handle(IntegrityMonitor $monitor): int
    {
        $this->info('Scanning designated CodeLock protected enforcement files...');

        $files = IntegrityMonitor::getDefaultProtectedFiles();
        $secretKey = $this->option('key');

        if (empty($secretKey)) {
            // Check if test key generation is desired or prompt
            $this->warn('No secret key supplied. A temporary keypair will be generated for local manifest signing.');
            $kp = Ed25519Verifier::generateKeyPair();
            $secretKey = $kp['secret_key'];
            $this->line("Generated Public Key: <comment>{$kp['public_key']}</comment>");
        }

        $keyId = $this->option('key-id') ?: 'key_2026_vector';
        $destination = $this->option('out') ?: $monitor->getManifestPath();

        $manifest = $monitor->generateManifest($files, $secretKey, $keyId);

        $dir = dirname($destination);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        file_put_contents($destination, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $this->info("Integrity manifest generated and cryptographically signed successfully!");
        $this->line("Manifest Location: <comment>{$destination}</comment>");
        $this->line("Protected Files: <comment>" . count($manifest['payload']['files']) . "</comment>");

        return Command::SUCCESS;
    }
}

