<?php

namespace Rasel\CodeLock\Tests\Unit;

use Rasel\CodeLock\Support\MachineFingerprint;
use Rasel\CodeLock\Tests\TestCase;

class MachineFingerprintTest extends TestCase
{
    public function test_generates_valid_instance_fingerprint(): void
    {
        $id = MachineFingerprint::get();

        $this->assertNotEmpty($id);
        $this->assertStringStartsWith('inst_', $id);
        $this->assertGreaterThan(10, strlen($id));
    }

    public function test_is_deterministic_on_consecutive_calls(): void
    {
        $id1 = MachineFingerprint::generate();
        $id2 = MachineFingerprint::generate();

        $this->assertSame($id1, $id2);
    }

    public function test_respects_explicit_config_override(): void
    {
        config(['codelock.installation_id' => 'custom_server_instance_99']);

        $this->assertSame('custom_server_instance_99', MachineFingerprint::get());
    }

    public function test_collects_system_metadata(): void
    {
        $meta = MachineFingerprint::getSystemMetadata();

        $this->assertArrayHasKey('instance_id', $meta);
        $this->assertArrayHasKey('php_version', $meta);
        $this->assertArrayHasKey('laravel_version', $meta);
        $this->assertArrayHasKey('os_family', $meta);
    }
}

