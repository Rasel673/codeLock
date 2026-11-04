<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Support\LicenseKey;

class StatusCommand extends Command
{
    protected $signature = 'codelock:status
                            {--domain= : Evaluate status against an explicit domain}
                            {--show-key : Display raw unmasked license key in output}';

    protected $description = 'Display comprehensive CodeLock license verification and deployment status';

    public function handle(LicenseManager $manager): int
    {
        $domain = $this->option('domain');
        $status = $manager->status($domain);

        $this->newLine();
        $this->line('<options=bold>CodeLock Licensing Engine: System Status</>');
        $this->newLine();

        $validTag = $status['valid']
            ? '<fg=green;options=bold>VALID</>'
            : '<fg=red;options=bold>INVALID / RESTRICTED</>';

        $rawKey = (string) $status['license_key'];
        $displayedKey = ($this->option('show-key') || $rawKey === 'N/A')
            ? $rawKey
            : LicenseKey::mask($rawKey);

        $rows = [
            ['Enforcement Enabled', $status['enabled'] ? '<info>Yes</info>' : '<comment>Disabled</comment>'],
            ['Overall Health', $validTag],
            ['License Status', $status['status_label']],
            ['Target Domain', $status['domain']],
            ['Instance Fingerprint', $status['instance_id']],
            ['Product Identifier', $status['product_id']],
            ['License Key', $displayedKey],
            ['Authorized Domains', implode(', ', (array) $status['allowed_domains'])],
            ['Subscription Tier', $status['tier'] ?? 'Standard'],
            ['Issued At', $status['issued_at'] ?? 'N/A'],
            ['Expires At', $status['expires_at']],
            ['Last Local Verification', $status['last_verified_at']],
            ['Last Remote Sync', $status['last_sync_at'] ?? 'Never'],
            ['Remote Sync Status', $status['remote_status']],
            ['Offline Grace Remaining', isset($status['grace_remaining_seconds']) ? round($status['grace_remaining_seconds'] / 86400, 1) . ' days' : 'N/A'],
        ];

        if (!empty($status['lock_message'])) {
            $rows[] = ['Lock Message', '<fg=red>' . $status['lock_message'] . '</>'];
        }

        if (!$status['valid'] && !empty($status['reason'])) {
            $rows[] = ['Restriction Reason', '<fg=yellow>' . $status['reason'] . '</>'];
        }

        $this->table(['Setting', 'Value'], $rows);

        return $status['valid'] ? Command::SUCCESS : Command::FAILURE;
    }
}
