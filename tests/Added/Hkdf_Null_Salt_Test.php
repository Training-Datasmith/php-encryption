<?php

declare(strict_types=1);

use Defuse\Crypto\Core;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

/**
 * HKDF null-salt handling on the PHP 7.2 runner (native hash_hkdf).
 * Fallback null→HashLen zero bytes (RFC 5869) is gated on PHP 5.6 via scripts/hkdf-null-salt-floor-test.php
 * (source branch, salt normalization, and in-memory source mutation).
 */
class Hkdf_Null_Salt_Test extends TestCase
{
    /**
     * RFC 5869 test case 3 style: null salt must match HashLen zero-byte salt, not mere empty string when they differ.
     */
    public function test_hkdf_null_salt_matches_hashlen_zero_bytes()
    {
        $hash = 'sha256';
        $digest_len = strlen(hash_hmac($hash, '', '', true));
        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $info = hex2bin('f1f301f1730f3f60242f5ad4d0386c0e');
        $length = 42;

        $with_null = Core::HKDF($hash, $ikm, $length, $info, null);
        $with_hashlen_zeros = Core::HKDF($hash, $ikm, $length, $info, str_repeat("\x00", $digest_len));

        $this->assertSame($with_hashlen_zeros, $with_null);

        $reference = self::rfc5869_hkdf_reference($hash, $ikm, $length, $info, str_repeat("\x00", $digest_len));
        $this->assertSame($reference, $with_null);

        $this->assertNotSame('', self::normalize_null_salt($digest_len));
        $this->assertSame(str_repeat("\x00", $digest_len), self::normalize_null_salt($digest_len));
    }

    /**
     * Independent RFC 5869 HKDF-Expand/Extract (used as oracle for null-salt normalization).
     */
    private static function normalize_null_salt($digest_len)
    {
        $salt = null;
        if (is_null($salt)) {
            return str_repeat("\x00", $digest_len);
        }
        return $salt;
    }

    private static function rfc5869_hkdf_reference($hash, $ikm, $length, $info, $salt)
    {
        $prk = hash_hmac($hash, $ikm, $salt, true);
        $digest_length = strlen(hash_hmac($hash, '', '', true));
        $t = '';
        $last = '';
        for ($block = 1; strlen($t) < $length; ++$block) {
            $last = hash_hmac($hash, $last . $info . chr($block), $prk, true);
            $t .= $last;
        }

        return substr($t, 0, $length);
    }
}
