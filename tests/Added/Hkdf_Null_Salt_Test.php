<?php

declare(strict_types=1);

use Defuse\Crypto\Core;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

/**
 * Observes the salt value prepared for each HKDF code path (not HKDF output equality).
 */
class Hkdf_Null_Salt_Test extends TestCase
{
    public function test_native_null_salt_resolves_to_empty_string_for_hash_hkdf()
    {
        if (!function_exists('hash_hkdf')) {
            $this->markTestSkipped('Native hash_hkdf is unavailable in this runtime.');
        }

        $salt = Core::hkdf_prepare_salt_for_native(null);
        $this->assertSame('', $salt);

        $digest_len = strlen(hash_hmac('sha256', '', '', true));
        $this->assertNotSame(
            str_repeat("\x00", $digest_len),
            $salt,
            'Native null salt must not be RFC HashLen zero-byte salt'
        );
    }

    public function test_fallback_null_salt_resolves_to_hashlen_zero_bytes()
    {
        $digest_len = strlen(hash_hmac('sha256', '', '', true));
        $salt = Core::hkdf_prepare_salt_for_fallback(null, $digest_len);
        $this->assertSame(str_repeat("\x00", $digest_len), $salt);
        $this->assertNotSame('', $salt);
    }
}
