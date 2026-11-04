<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\LicenseManager;

class CheckCommand extends Command
{
    protected $signature = 'codelock:check
                            {--domain= : Evaluate against an explicit domain}
                            {--silent : Suppress all console output}';

    protected $description = 'Verify license validity and return exit code 0 on success or 1 on failure';

    public function handle(LicenseManager $manager): int
    {
        $domain = $this->option('domain');
        $result = $manager->verify($domain, false);
        $isSilent = $this->option('silent') || $this->output->isQuiet();

        if ($result['valid']) {
            if (!$isSilent) {
                $this->info("License OK: Active and valid for domain [{$result['domain']}].");
            }
            return Command::SUCCESS;
        }

        if (!$isSilent) {
            $this->error("License Check Failed: {$result['reason']}");
        }

        return Command::FAILURE;
    }
}
