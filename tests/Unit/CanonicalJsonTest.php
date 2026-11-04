<?php

namespace Rasel\CodeLock\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rasel\CodeLock\Support\CanonicalJson;

class CanonicalJsonTest extends TestCase
{
    public function test_sorts_keys_lexicographically(): void
    {
        $data1 = ['z' => 1, 'a' => 2, 'm' => 3];
        $data2 = ['a' => 2, 'm' => 3, 'z' => 1];

        $json1 = CanonicalJson::encode($data1);
        $json2 = CanonicalJson::encode($data2);

        $this->assertSame('{"a":2,"m":3,"z":1}', $json1);
        $this->assertSame($json1, $json2);
    }

    public function test_sorts_nested_associative_arrays(): void
    {
        $nested1 = [
            'license' => 'ABC',
            'policy' => [
                'offline' => true,
                'grace' => 7,
            ],
        ];

        $nested2 = [
            'policy' => [
                'grace' => 7,
                'offline' => true,
            ],
            'license' => 'ABC',
        ];

        $this->assertSame(
            CanonicalJson::encode($nested1),
            CanonicalJson::encode($nested2)
        );
    }

    public function test_preserves_sequential_list_order(): void
    {
        $list = ['domains' => ['b.com', 'a.com', 'c.com']];
        $encoded = CanonicalJson::encode($list);

        $this->assertSame('{"domains":["b.com","a.com","c.com"]}', $encoded);
    }

    public function test_preserves_slashes_and_unicode_without_escaping(): void
    {
        $data = [
            'url' => 'https://example.com/license',
            'title' => 'CodeLock™ Security 🔒',
        ];

        $encoded = CanonicalJson::encode($data);

        $this->assertStringContainsString('https://example.com/license', $encoded);
        $this->assertStringContainsString('CodeLock™ Security 🔒', $encoded);
    }
}

