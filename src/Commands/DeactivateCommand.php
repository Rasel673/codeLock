<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\LicenseManager;

class DeactivateCommand extends Command
{
    protected $signature = 'codelock:deactivate
                            {--force : Bypass confirmation prompt}
                            {--domain= : Explicit domain to release}';

    protected $description = 'Deactivate the commercial license on this installation and remove local certificate';

    public function handle(LicenseManager $manager): int
    {
        if (!$this->option('force') && !$this->confirm('Are you sure you want to deactivate and remove this license?')) {
            $this->line('Deactivation aborted.');
            return Command::SUCCESS;
        }

        $domain = $this->option('domain');
        $this->info('Deactivating installation and wiping local certificate...');

        $success = $manager->deactivate($domain);

        if ($success) {
            $this->info('License deactivated and local certificate removed successfully.');
            return Command::SUCCESS;
        }

        $this->warn('Local license certificate could not be completely removed or was already missing.');
        return Command::FAILURE;
    }
}

