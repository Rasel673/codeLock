<?php

namespace Rasel\CodeLock\Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Console\Scheduling\Schedule;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\LicenseHeartbeat;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\Ed25519Verifier;
use Rasel\CodeLock\Tests\TestCase;

class HeartbeatCommandTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);
    }

    protected function createMockHttpClient(array $responses, array &$container = []): GuzzleClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        $handlerStack->push(Middleware::history($container));

        return new GuzzleClient(['handler' => $handlerStack]);
    }

    protected function bindMockClient(array $responses, array &$container = []): LicenseClient
    {
        $http = $this->createMockHttpClient($responses, $container);
        $client = new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            http: $http
        );

        $this->app->instance(LicenseClient::class, $client);

        // Rebind heartbeater and manager with mock client
        $heartbeat = new LicenseHeartbeat(
            storage: $this->storage,
            client: $client,
            publicKeys: $this->testPublicKey,
            productId: 'PROD-TEST'
        );
        $this->app->instance(LicenseHeartbeat::class, $heartbeat);

        $manager = new LicenseManager(
            storage: $this->storage,
            client: $client,
            heartbeat: $heartbeat
        );
        $this->app->instance(LicenseManager::class, $manager);

        return $client;
    }

    public function test_heartbeat_command_fails_when_no_license_installed(): void
    {
        $this->artisan('codelock:heartbeat')
            ->expectsOutputToContain('Cannot perform heartbeat: No license installed.')
            ->assertExitCode(1);
    }

    public function test_heartbeat_command_skips_when_codelock_disabled(): void
    {
        config(['codelock.enabled' => false]);

        $this->artisan('codelock:heartbeat')
            ->expectsOutputToContain('CodeLock is currently disabled. Skipping heartbeat check-in.')
            ->assertExitCode(0);
    }

    public function test_heartbeat_command_aborts_without_request_when_license_is_invalid(): void
    {
        // Save certificate with a tampered cryptographic signature
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-TAMPERED',
            'dom' => ['localhost'],
        ]);
        $cert['signature'] = base64_encode(str_repeat('X', 64));
        $this->storage->saveCertificate($cert);

        $container = [];
        $this->bindMockClient([
            new Response(200, [], json_encode(['sta' => 'ACTIVE'])),
        ], $container);

        $this->artisan('codelock:heartbeat')
            ->expectsOutputToContain('Cannot perform heartbeat: License is invalid or compromised')
            ->assertExitCode(1);

        // Ensure no heartbeat request was sent
        $heartbeatRequests = array_filter($container, function ($item) {
            return str_contains($item['request']->getUri()->getPath(), 'heartbeat');
        });
        $this->assertEmpty($heartbeatRequests, 'Heartbeat network request must not be dispatched when local license is invalid.');
    }

    public function test_manual_heartbeat_command_executes_successfully(): void
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-HB-CMD-TEST',
            'prd' => 'PROD-TEST',
            'dom' => ['localhost'],
            'iat' => time() - 3600,
        ]);
        $cert['installation_id'] = 'inst_uuid_12345';
        $cert['installation_token'] = 'cl_inst_tok_abc123';
        $this->storage->saveCertificate($cert);

        $remotePayload = [
            'lic' => 'CLK-2026-HB-CMD-TEST',
            'sta' => 'ACTIVE',
            'deadline' => time() + (86400 * 7),
            'timestamp' => time(),
            'nonce' => 'session_nonce_probe',
        ];
        $canonical = CanonicalJson::encode($remotePayload);
        $signature = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        $signedResponse = [
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => $remotePayload,
            'signature' => $signature,
            'status' => 'healthy',
            'directive' => 'continue',
            'is_locked' => false,
        ];

        $container = [];
        $this->bindMockClient([
            new Response(200, [], json_encode($signedResponse)),
        ], $container);

        $this->artisan('codelock:heartbeat', ['--force' => true])
            ->expectsOutputToContain('Sending heartbeat check-in to CodeLock license server...')
            ->expectsOutputToContain('Heartbeat check-in successful. Remote status: [ACTIVE]')
            ->expectsOutputToContain('CLK-****-**-***-TEST')
            ->expectsOutputToContain('PROD-TEST')
            ->expectsOutputToContain('inst_uuid_12345')
            ->assertExitCode(0);

        // Verify request payload transmitted to server
        $this->assertNotEmpty($container);
        $req = $container[0]['request'];
        $this->assertSame('/api/v1/license/heartbeat', $req->getUri()->getPath());

        $body = json_decode((string) $req->getBody(), true);
        $this->assertSame('CLK-2026-HB-CMD-TEST', $body['license_key']);
        $this->assertSame('inst_uuid_12345', $body['installation_id']);
        $this->assertSame('PROD-TEST', $body['product_id']);
        $this->assertArrayHasKey('installation_hash', $body);
        $this->assertSame('cl_inst_tok_abc123', $body['token']);

        // Verify Bearer authorization header
        $this->assertTrue($req->hasHeader('Authorization'));
        $this->assertSame('Bearer cl_inst_tok_abc123', $req->getHeaderLine('Authorization'));

        // Verify local sync timestamp was updated
        $this->assertGreaterThan(0, $this->storage->getLastSyncTimestamp());
    }

    public function test_heartbeat_command_reports_when_check_in_is_skipped_by_interval(): void
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-HB-SKIPPED',
            'dom' => ['localhost'],
        ]);
        $this->storage->saveCertificate($cert);
        $this->storage->recordLastSyncTimestamp(time());

        $this->artisan('codelock:heartbeat')
            ->expectsOutputToContain('Heartbeat skipped: interval has not elapsed.')
            ->doesntExpectOutputToContain('Heartbeat check-in successful.')
            ->assertExitCode(0);
    }

    public function test_heartbeat_command_handles_network_failure_with_offline_grace(): void
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-NET-FAIL',
            'dom' => ['localhost'],
            'iat' => time() - 3600,
        ]);
        $this->storage->saveCertificate($cert);

        $container = [];
        $this->bindMockClient([
            new ConnectException('Connection refused by license authority', new Request('POST', '/api/v1/license/heartbeat')),
        ], $container);

        $this->artisan('codelock:heartbeat', ['--force' => true])
            ->expectsOutputToContain('Operating within offline grace period')
            ->assertExitCode(0);
    }

    public function test_heartbeat_command_detects_invalid_server_signature(): void
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-SIG-FAIL',
            'dom' => ['localhost'],
            'iat' => time() - 3600,
        ]);
        $this->storage->saveCertificate($cert);

        // Build response with forged signature
        $forgedResponse = [
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => [
                'lic' => 'CLK-2026-SIG-FAIL',
                'sta' => 'ACTIVE',
                'timestamp' => time(),
            ],
            'signature' => base64_encode(str_repeat('X', 64)), // Invalid fake signature
        ];

        $container = [];
        $this->bindMockClient([
            new Response(200, [], json_encode($forgedResponse)),
        ], $container);

        $this->artisan('codelock:heartbeat', ['--force' => true])
            ->expectsOutputToContain('Cryptographic verification failed: Server response signature is invalid.')
            ->assertExitCode(1);
    }

    public function test_heartbeat_command_displays_warning_when_server_marks_locked(): void
    {
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-2026-LOCKED',
            'dom' => ['localhost'],
            'iat' => time() - 3600,
        ]);
        $this->storage->saveCertificate($cert);

        $remotePayload = [
            'lic' => 'CLK-2026-LOCKED',
            'sta' => 'LOCKED',
            'lock_message' => 'Account suspended due to non-payment.',
            'timestamp' => time(),
        ];
        $canonical = CanonicalJson::encode($remotePayload);
        $signature = Ed25519Verifier::sign($canonical, $this->testSecretKey);

        $signedResponse = [
            'header' => ['alg' => 'Ed25519', 'typ' => 'CODELOCK-STATUS'],
            'payload' => $remotePayload,
            'signature' => $signature,
            'status' => 'locked',
            'directive' => 'lock',
            'is_locked' => true,
        ];

        $container = [];
        $this->bindMockClient([
            new Response(200, [], json_encode($signedResponse)),
        ], $container);

        $this->artisan('codelock:heartbeat', ['--force' => true])
            ->expectsOutputToContain('Heartbeat check-in successful. Remote status: [LOCKED]')
            ->expectsOutputToContain('Warning: Server has marked this installation as LOCKED.')
            ->expectsOutputToContain('Account suspended due to non-payment.')
            ->assertExitCode(0);
    }

    public function test_automatic_schedule_registration_in_scheduler(): void
    {
        $schedule = $this->app->make(Schedule::class);
        $events = $schedule->events();

        $heartbeatEvents = array_filter($events, function ($event) {
            return is_string($event->command) && str_contains($event->command, 'codelock:heartbeat');
        });

        $this->assertNotEmpty($heartbeatEvents, 'codelock:heartbeat must be registered in the application scheduler.');

        $event = reset($heartbeatEvents);
        // Configured for 5 minutes for testing: cron "*/5 * * * *"
        $this->assertSame('*/5 * * * *', $event->expression);

        // Verify withoutOverlapping is active
        $this->assertTrue($event->withoutOverlapping, 'Heartbeat schedule event must have withoutOverlapping enabled.');
    }

    public function test_automatic_schedule_registration_with_hourly_interval(): void
    {
        $schedule = new Schedule();
        $this->app->instance(Schedule::class, $schedule);
        config([
            'codelock.heartbeat_interval_minutes' => null,
            'codelock.heartbeat_interval' => 6,
        ]);

        $provider = $this->app->getProvider(\Rasel\CodeLock\CodeLockServiceProvider::class);
        $ref = new \ReflectionMethod($provider, 'registerSchedule');
        $ref->invoke($provider);

        $events = $schedule->events();
        $heartbeatEvents = array_filter($events, function ($event) {
            return is_string($event->command) && str_contains($event->command, 'codelock:heartbeat');
        });

        $event = reset($heartbeatEvents);
        $this->assertSame('0 */6 * * *', $event->expression);
    }

    public function test_scheduler_prevents_duplicate_tasks(): void
    {
        $schedule = $this->app->make(Schedule::class);

        // Call the service provider boot or schedule registration again
        $provider = $this->app->getProvider(\Rasel\CodeLock\CodeLockServiceProvider::class);
        $ref = new \ReflectionMethod($provider, 'registerSchedule');
        $ref->invoke($provider);

        $events = $schedule->events();
        $heartbeatEvents = array_filter($events, function ($event) {
            return is_string($event->command) && str_contains($event->command, 'codelock:heartbeat');
        });

        $this->assertCount(1, $heartbeatEvents, 'Scheduler must not contain duplicate codelock:heartbeat events.');
    }

    public function test_server_database_persistence_contract_simulation(): void
    {
        // Validate that client heartbeat request payload satisfies all server expectations
        $cert = $this->createSignedCertificate([
            'lic' => 'CLK-SERVER-PERSIST-TEST',
            'dom' => ['localhost'],
        ]);
        $cert['installation_id'] = '6b110bc7-a2f0-466d-8e42-706f97b5e40e';
        $this->storage->saveCertificate($cert);

        $container = [];
        $signedResponse = $this->createSignedRemoteStatus([
            'lic' => 'CLK-SERVER-PERSIST-TEST',
            'sta' => 'ACTIVE',
            'timestamp' => time(),
        ]);

        $this->bindMockClient([
            new Response(200, [], json_encode($signedResponse)),
        ], $container);

        $this->artisan('codelock:heartbeat', ['--force' => true])->assertExitCode(0);

        $this->assertNotEmpty($container);
        $body = json_decode((string) $container[0]['request']->getBody(), true);

        // Server HeartbeatController/HeartbeatService required contract fields
        $this->assertArrayHasKey('installation_id', $body);
        $this->assertArrayHasKey('instance_id', $body);
        $this->assertArrayHasKey('installation_hash', $body);
        $this->assertArrayHasKey('license_key', $body);
        $this->assertArrayHasKey('domain', $body);
        $this->assertArrayHasKey('package_version', $body);
        $this->assertArrayHasKey('nonce', $body);
        $this->assertArrayHasKey('timestamp', $body);

        // Simulate server-side persistence behavior:
        // $installation->last_heartbeat_at = now();
        // $installation->client_package_version = $body['package_version'];
        // HeartbeatLog::create([...]);
        $serverSimulatedInstallation = [
            'id' => $body['installation_id'],
            'installation_hash' => $body['installation_hash'],
            'last_heartbeat_at' => date('Y-m-d H:i:s', $body['timestamp']),
            'client_package_version' => $body['package_version'],
        ];

        $this->assertSame('6b110bc7-a2f0-466d-8e42-706f97b5e40e', $serverSimulatedInstallation['id']);
        $this->assertSame('1.0.0', $serverSimulatedInstallation['client_package_version']);
    }
}
