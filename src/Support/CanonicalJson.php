<?php

namespace Rasel\CodeLock\Support;

class CanonicalJson
{
    /**
     * Encode an array or object into deterministic, canonical JSON (RFC 8785 subset).
     */
    public static function encode(mixed $data): string
    {
        $normalized = self::normalize($data);

        return json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Recursively sort keys of associative arrays lexicographically.
     */
    public static function normalize(mixed $data): mixed
    {
        if (!is_array($data)) {
            return $data;
        }

        // Check if array is sequential (list) or associative
        if (array_is_list($data)) {
            return array_map([self::class, 'normalize'], $data);
        }

        // Associative array: sort keys by Unicode code point
        ksort($data, SORT_STRING);

        foreach ($data as $key => $value) {
            $data[$key] = self::normalize($value);
        }

        return $data;
    }
}

