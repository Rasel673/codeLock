<?php

namespace Rasel\CodeLock\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Rasel\CodeLock\Exceptions\CodeLockException;
use Rasel\CodeLock\Exceptions\ServerCommunicationException;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\LicenseKey;
use Rasel\CodeLock\Support\MachineFingerprint;

class HeartbeatCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'codelock:heartbeat
                            {--force : Force check-in even if configured heartbeat interval has not elapsed}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Send authenticated heartbeat check-in to CodeLock licensing server to synchronize status and remote locks';

    /**
     * Execute the console command.
     */
    public function handle(LicenseManager $manager, LicenseStorage $storage): int
    {
        // 1. Verify CodeLock is globally enabled
        if (!$manager->isEnabled()) {
            $this->info('CodeLock is currently disabled. Skipping heartbeat check-in.');
            Log::info('CodeLock: Heartbeat skipped because CodeLock enforcement is disabled.');
            return Command::SUCCESS;
        }

        // 2. Verify that an activated license certificate exists
        if (!$storage->hasCertificate()) {
            $this->error('Cannot perform heartbeat: No license installed.');
            Log::warning('CodeLock: Heartbeat skipped because no license certificate is installed.');
            return Command::FAILURE;
        }

        // 3. Verify local license validity before sending request (Do not send if license is invalid or tampered)
        $verification = $manager->verify(throw: false);
        if (!$verification->isValid()) {
            $reason = $verification->getReason() ?? 'License verification failed.';
            $this->error("Cannot perform heartbeat: License is invalid or compromised: {$reason}");
            Log::error('CodeLock: Heartbeat skipped because local license verification failed.', [
                'reason' => $reason,
                'error_code' => $verification->getErrorCode(),
            ]);
            return Command::FAILURE;
        }

        $force = (bool) $this->option('force');
        $this->info('Sending heartbeat check-in to CodeLock license server...');

        try {
            $result = $manager->heartbeat($force);

            // Handle offline grace expiration
            if ($result->isGraceExpired()) {
                $this->error('Offline grace period has elapsed. Server connection required.');
                Log::error('CodeLock: Heartbeat offline grace period has expired.');
                return Command::FAILURE;
            }

            // Handle active offline grace period (transient network failure)
            if ($result->isGraceActive()) {
                $days = round($result->getRemainingGraceSeconds() / 86400, 1);
                $this->warn("License server unreachable. Operating within offline grace period ({$days} days remaining).");
                $this->line("Operating within offline grace period ({$days} days remaining).");
                return Command::SUCCESS;
            }

            // Handle signature verification failure
            if ($result->getErrorCode() === 'E_SIGNATURE_INVALID') {
                $this->error('Cryptographic verification failed: Server response signature is invalid.');
                Log::error('CodeLock: Heartbeat server response signature verification failed.');
                return Command::FAILURE;
            }

            // Handle replay attack or stale status
            if (in_array($result->getErrorCode(), ['E_REPLAY_DETECTED', 'E_STALE_STATUS'], true)) {
                $this->error('Security verification failed: ' . $result->getMessage());
                Log::error('CodeLock: Heartbeat security check failed: ' . $result->getMessage());
                return Command::FAILURE;
            }

            // Check if heartbeat succeeded
            if ($result->isSuccess()) {
                if (str_starts_with($result->getMessage(), 'Heartbeat skipped:')) {
                    $this->info($result->getMessage());
                    return Command::SUCCESS;
                }

                $remoteStatus = $result->getStatus();
                $statusVal = $remoteStatus?->getStatus()->value ?? 'ACTIVE';

                $cert = $storage->loadCertificate() ?? [];
                $payload = $cert['payload'] ?? [];
                $rawKey = (string) ($payload['lic'] ?? config('codelock.license_key', 'N/A'));
                $displayKey = LicenseKey::mask($rawKey);
                $productId = (string) ($payload['prd'] ?? config('codelock.product_id', 'N/A'));
                $domain = $verification->getDomain() ?? config('app.url', 'localhost');

                $this->info("Heartbeat check-in successful. Remote status: [{$statusVal}]");

                if ($statusVal === 'LOCKED') {
                    $this->error('Warning: Server has marked this installation as LOCKED.');
                    $lockMessage = $remoteStatus?->getLockMessage();
                    if (!empty($lockMessage)) {
                        $this->line("Lock Message: {$lockMessage}");
                    }
                }

                $this->table(
                    ['Property', 'Value'],
                    [
                        ['Remote Status', $statusVal === 'ACTIVE' ? "<info>{$statusVal}</info>" : "<error>{$statusVal}</error>"],
                        ['License Key', $displayKey],
                        ['Product Code', $productId],
                        ['Target Domain', $domain],
                        ['Installation ID', (string) ($cert['installation_id'] ?? config('codelock.installation_id') ?? MachineFingerprint::get())],
                        ['Last Check-in', date('Y-m-d H:i:s', $storage->getLastSyncTimestamp())],
                    ]
                );

                return Command::SUCCESS;
            }

            $this->error('Heartbeat check-in failed: ' . $result->getMessage());
            return Command::FAILURE;
        } catch (ServerCommunicationException $e) {
            $days = config('codelock.offline_grace_period', 7);
            $this->warn("License server unreachable: " . $e->getMessage());
            $this->line("Operating within offline grace period ({$days} days).");
            Log::warning('CodeLock: Heartbeat server unreachable, operating in grace period: ' . $e->getMessage());
            return Command::SUCCESS;
        } catch (CodeLockException $e) {
            $this->error('Heartbeat check-in error: ' . $e->getMessage());
            Log::error('CodeLock: Heartbeat exception: ' . $e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            $this->error('Unexpected error during heartbeat check-in: ' . $e->getMessage());
            Log::error('CodeLock: Unexpected heartbeat exception: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
