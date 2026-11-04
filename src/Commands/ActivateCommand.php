<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\Exceptions\CodeLockException;
use Rasel\CodeLock\Exceptions\ServerCommunicationException;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Support\LicenseKey;

class ActivateCommand extends Command
{
    protected $signature = 'codelock:activate
                            {key? : The commercial license key}
                            {--domain= : Explicit domain name to register}
                            {--show-key : Display raw unmasked license key in output}';

    protected $description = 'Activate a commercial license key for this installation domain';

    public function handle(LicenseManager $manager): int
    {
        $rawKey = $this->argument('key');

        if (empty($rawKey)) {
            $rawKey = config('codelock.license_key');
        }

        if (empty($rawKey)) {
            $rawKey = $this->ask('Please enter your CodeLock License Key');
        }

        if (empty($rawKey)) {
            $this->error('A license key is required for activation.');
            return Command::FAILURE;
        }

        $rawKey = trim($rawKey);

        // Validate Key Format Before Network Calls
        if (!LicenseKey::isValidFormat($rawKey)) {
            $this->error("Invalid license key format [{$rawKey}]. Key must be an alphanumeric token (e.g. CLK-XXXX-XXXX-XXXX).");
            return Command::FAILURE;
        }

        $domain = $this->option('domain');
        $maskedKey = LicenseKey::mask($rawKey);
        $displayKey = $this->option('show-key') ? $rawKey : $maskedKey;

        $this->info("Contacting license server to activate [{$displayKey}]...");

        try {
            $result = $manager->activate($rawKey, $domain);

            $this->newLine();
            $this->info('License activated and cryptographically verified successfully!');
            $this->table(
                ['Property', 'Value'],
                [
                    ['Status', '<info>' . $result['status']->value . '</info>'],
                    ['License Key', $displayKey],
                    ['Product', $result['payload']['prd'] ?? 'N/A'],
                    ['Authorized Domains', implode(', ', (array) ($result['payload']['dom'] ?? []))],
                    ['Expires At', isset($result['payload']['exp']) && $result['payload']['exp'] > 0 ? date('Y-m-d H:i:s', $result['payload']['exp']) : 'Lifetime / Never'],
                ]
            );

            return Command::SUCCESS;
        } catch (ServerCommunicationException $e) {
            $this->newLine();
            $this->error('Server Communication Error: ' . $e->getMessage());
            return Command::FAILURE;
        } catch (CodeLockException $e) {
            $this->newLine();
            $this->error('Activation Failed: ' . $e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            $this->newLine();
            $this->error('Unexpected error: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
