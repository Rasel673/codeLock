<?php

namespace Rasel\CodeLock\Tests\Feature;

use Rasel\CodeLock\Storage\LicenseStorage;
use Rasel\CodeLock\Tests\TestCase;

class CommandsTest extends TestCase
{
    protected LicenseStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new LicenseStorage($this->tempStoragePath, $this->tempStatusPath);
        $this->app->instance(LicenseStorage::class, $this->storage);
    }

    public function test_install_command_runs_successfully(): void
    {
        $this->artisan('codelock:install')
            ->expectsOutputToContain('Initializing CodeLock Licensing Engine...')
            ->expectsOutputToContain('Installation Fingerprint:')
            ->assertExitCode(0);
    }

    public function test_check_command_fails_when_unlicensed(): void
    {
        $this->artisan('codelock:check', ['--domain' => 'example.com'])
            ->expectsOutputToContain('License Check Failed')
            ->assertExitCode(1);
    }

    public function test_check_command_passes_when_valid(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);

        $this->artisan('codelock:check', ['--domain' => 'example.com'])
            ->expectsOutputToContain('License OK: Active and valid')
            ->assertExitCode(0);
    }

    public function test_status_command_displays_table(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);

        $this->artisan('codelock:status', ['--domain' => 'example.com', '--show-key' => true])
            ->expectsOutputToContain('CodeLock Licensing Engine: System Status')
            ->expectsOutputToContain('VALID')
            ->expectsOutputToContain('CLK-TEST-1234-5678-ABCD')
            ->assertExitCode(0);
    }

    public function test_deactivate_command_removes_certificate(): void
    {
        $cert = $this->createSignedCertificate(['dom' => ['example.com']]);
        $this->storage->saveCertificate($cert);

        $this->assertTrue($this->storage->hasCertificate());

        $this->artisan('codelock:deactivate', ['--force' => true, '--domain' => 'example.com'])
            ->expectsOutputToContain('License deactivated and local certificate removed')
            ->assertExitCode(0);

        $this->assertFalse($this->storage->hasCertificate());
    }
}

