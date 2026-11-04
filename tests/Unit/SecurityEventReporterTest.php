<?php

namespace Rasel\CodeLock\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Rasel\CodeLock\Enums\SecurityEventCode;
use Rasel\CodeLock\LicenseClient;
use Rasel\CodeLock\SecurityEventReporter;
use Rasel\CodeLock\Tests\TestCase;

class SecurityEventReporterTest extends TestCase
{
    protected function createMockClient(array $responses, array &$historyContainer = []): LicenseClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        $http = new GuzzleClient(['handler' => $handlerStack]);

        return new LicenseClient(
            serverUrl: 'https://license.test',
            productId: 'PROD-TEST',
            timeout: 5,
            http: $http
        );
    }

    public function test_dispatches_all_standard_security_events(): void
    {
        $mockClient = $this->createMockClient([
            new Response(200, [], json_encode(['status' => 'logged'])),
            new Response(200, [], json_encode(['status' => 'logged'])),
            new Response(200, [], json_encode(['status' => 'logged'])),
            new Response(200, [], json_encode(['status' => 'logged'])),
            new Response(200, [], json_encode(['status' => 'logged'])),
            new Response(200, [], json_encode(['status' => 'logged'])),
        ]);

        $reporter = new SecurityEventReporter($mockClient);

        // 1. Integrity Mismatch
        $res1 = $reporter->reportIntegrityMismatch(['src/LicenseVerifier.php']);
        $this->assertTrue($res1['reported']);
        $this->assertSame('TAMPER_DETECTED', $res1['event_code']);

        // 2. Missing Protected File
        $res2 = $reporter->reportMissingProtectedFile(['src/Support/CanonicalJson.php']);
        $this->assertTrue($res2['reported']);
        $this->assertSame('MISSING_PROTECTED_FILE', $res2['event_code']);

        // 3. Invalid Signature
        $res3 = $reporter->reportInvalidSignature('license_check');
        $this->assertTrue($res3['reported']);
        $this->assertSame('INVALID_SIGNATURE', $res3['event_code']);

        // 4. Domain Mismatch
        $res4 = $reporter->reportDomainMismatch('malicious.domain', ['authorized.domain']);
        $this->assertTrue($res4['reported']);
        $this->assertSame('DOMAIN_MISMATCH', $res4['event_code']);

        // 5. Suspicious Config
        $res5 = $reporter->reportSuspiciousConfig(['codelock.enabled' => false]);
        $this->assertTrue($res5['reported']);
        $this->assertSame('SUSPICIOUS_CONFIG', $res5['event_code']);

        // 6. Repeated Verification Failures
        $res6 = $reporter->reportRepeatedVerificationFailures(5, 'login_route');
        $this->assertTrue($res6['reported']);
        $this->assertSame('REPEATED_VERIFICATION_FAILURES', $res6['event_code']);
    }

    public function test_strictly_redacts_sensitive_keys_passwords_and_sql_queries(): void
    {
        $reporter = new SecurityEventReporter();

        $dirtyDetails = [
            'admin_password' => 'SuperSecret123!',
            'db_password' => 'mysql_root_pass',
            'api_key' => 'live_sk_abcdef123456',
            'session_token' => 'jwt.token.here',
            'error_log' => 'Payment processor failure on card 4111 1111 1111 1111',
            'query_debug' => 'SELECT id, email, password_hash FROM users WHERE admin = 1',
            'nested' => [
                'auth_bearer' => 'Bearer sensitive_token',
                'harmless_info' => 'PHP 8.2',
                'raw_text' => 'Card charged: 5500 0000 0000 0004',
            ],
            'safe_param' => 'production_v1',
        ];

        $sanitized = $reporter->sanitizeDetails($dirtyDetails);

        $this->assertSame('[REDACTED]', $sanitized['admin_password']);
        $this->assertSame('[REDACTED]', $sanitized['db_password']);
        $this->assertSame('[REDACTED]', $sanitized['api_key']);
        $this->assertSame('[REDACTED]', $sanitized['session_token']);
        $this->assertSame('Payment processor failure on card [CARD_REDACTED]', $sanitized['error_log']);
        $this->assertSame('[SQL_QUERY_REDACTED]', $sanitized['query_debug']);

        $this->assertSame('[REDACTED]', $sanitized['nested']['auth_bearer']);
        $this->assertSame('PHP 8.2', $sanitized['nested']['harmless_info']);
        $this->assertSame('Card charged: [CARD_REDACTED]', $sanitized['nested']['raw_text']);
        $this->assertSame('production_v1', $sanitized['safe_param']);
    }

    public function test_enforces_client_side_rate_limiting(): void
    {
        $mockClient = $this->createMockClient([
            new Response(200, [], json_encode(['status' => 'logged'])),
            new Response(200, [], json_encode(['status' => 'logged'])),
        ]);

        // Max 2 reports per hour
        $reporter = new SecurityEventReporter($mockClient, maxReportsPerHour: 2);

        $event = SecurityEventCode::DOMAIN_MISMATCH;

        $r1 = $reporter->report($event, 'WARNING', ['domain' => 'spoof1.com']);
        $this->assertTrue($r1['reported']);
        $this->assertFalse($r1['rate_limited']);

        $r2 = $reporter->report($event, 'WARNING', ['domain' => 'spoof2.com']);
        $this->assertTrue($r2['reported']);
        $this->assertFalse($r2['rate_limited']);

        // 3rd report must be rate limited locally without network request
        $r3 = $reporter->report($event, 'WARNING', ['domain' => 'spoof3.com']);
        $this->assertFalse($r3['reported']);
        $this->assertTrue($r3['rate_limited']);

        // Resetting rate limits allows reporting again
        $reporter->resetRateLimits();
        $this->assertFalse($reporter->isRateLimited($event->value));
    }

    public function test_reporting_failure_does_not_throw_or_crash_application(): void
    {
        // Mock a connection failure
        $mockClient = $this->createMockClient([
            new \GuzzleHttp\Exception\ConnectException('Connection refused', new \GuzzleHttp\Psr7\Request('POST', '/api/v1/license/security-event')),
        ]);

        $reporter = new SecurityEventReporter($mockClient);

        // Must not throw an unhandled exception
        $outcome = $reporter->report(SecurityEventCode::INVALID_SIGNATURE, 'CRITICAL', ['reason' => 'bad signature']);

        $this->assertFalse($outcome['reported']);
        $this->assertArrayHasKey('response', $outcome);
        $this->assertSame('failed_to_report', $outcome['response']['status']);
    }

    public function test_tracks_verification_failures_and_automatically_triggers_report(): void
    {
        $mockClient = $this->createMockClient([
            new Response(200, [], json_encode(['status' => 'logged'])),
        ]);

        // Set threshold to 3 consecutive failures
        $reporter = new SecurityEventReporter($mockClient, repeatedFailureThreshold: 3);

        $reporter->recordVerificationFailure('domain_check', 'Invalid host');
        $this->assertSame(1, $reporter->getConsecutiveFailures());

        $reporter->recordVerificationFailure('domain_check', 'Invalid host 2');
        $this->assertSame(2, $reporter->getConsecutiveFailures());

        // 3rd failure reaches threshold: should dispatch repeated failures event and reset counter
        $reporter->recordVerificationFailure('domain_check', 'Invalid host 3');
        $this->assertSame(0, $reporter->getConsecutiveFailures());

        // Success resets counter
        $reporter->recordVerificationFailure('domain_check', 'Single failure');
        $this->assertSame(1, $reporter->getConsecutiveFailures());
        $reporter->resetVerificationFailures();
        $this->assertSame(0, $reporter->getConsecutiveFailures());
    }
}
