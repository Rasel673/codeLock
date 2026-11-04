<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Rasel\CodeLock\Exceptions\CodeLockException;
use Rasel\CodeLock\Exceptions\ServerCommunicationException;
use Rasel\CodeLock\LicenseManager;

class RefreshCommand extends Command
{
    protected $signature = 'codelock:refresh
                            {--heartbeat : Run standard automated heartbeat}';

    protected $description = 'Synchronize license status and remote lock instructions with the central server';

    public function handle(LicenseManager $manager): int
    {
        $this->info('Synchronizing status with CodeLock license server...');

        try {
            $response = $manager->refresh();

            if (method_exists($response, 'isGraceExpired') && $response->isGraceExpired()) {
                $this->error('Offline grace period has elapsed. Server connection required.');
                return Command::FAILURE;
            }

            if (method_exists($response, 'isGraceActive') && $response->isGraceActive()) {
                $days = round($response->getRemainingGraceSeconds() / 86400, 1);
                $this->warn('Server unreachable. Operating within offline grace period (' . $days . ' days remaining).');
                return Command::SUCCESS;
            }

            $status = $response['payload']['sta'] ?? 'OK';
            $this->info("Heartbeat synchronized successfully. Remote Status: [{$status}]");

            if ($status === 'LOCKED') {
                $this->error('Warning: Server has marked this installation as LOCKED.');
                if (!empty($response['payload']['lock_message'])) {
                    $this->line("Lock Message: {$response['payload']['lock_message']}");
                }
            }

            return Command::SUCCESS;
        } catch (ServerCommunicationException $e) {
            $this->warn("Server unreachable: " . $e->getMessage());
            $this->line("Operating within offline grace period (" . config('codelock.offline_grace_period', 7) . " days).");
            return Command::SUCCESS; // Return success so scheduled cron does not fail noisily during transient network outages
        } catch (CodeLockException $e) {
            $this->error('Failed to synchronize status: ' . $e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            $this->error('Unexpected error: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
