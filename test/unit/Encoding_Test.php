<?php

declare(strict_types=1);

use Defuse\Crypto\Core;
use Defuse\Crypto\Encoding;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class Encoding_Test extends TestCase
{
    public function test_encode_decode_equivalency()
    {
        for ($length = 0; $length < 50; $length++) {
            for ($i = 0; $i < 50; $i++) {
                $random = $length > 0 ? Core::secure_random($length) : '';

                $encode_a = Encoding::bin_to_hex($random);
                $encode_b = \bin2hex($random);

                $this->assertSame($encode_b, $encode_a);

                $decode_a = Encoding::hex_to_bin($encode_a);
                $decode_b = \hex2bin($encode_b);

                $this->assertSame($decode_b, $decode_a);
                // Just in case.
                $this->assertSame($random, $decode_b);
            }
        }
    }

    public function test_encode_decode_equivalency_two_bytes()
    {
        for ($b1 = 0; $b1 < 256; $b1++) {
            for ($b2 = 0; $b2 < 256; $b2++) {
                $str = \pack('C', $b1) . \pack('C', $b2);

                $encode_a = Encoding::bin_to_hex($str);
                $encode_b = \bin2hex($str);

                $this->assertSame($encode_b, $encode_a);

                $decode_a = Encoding::hex_to_bin($encode_a);
                $decode_b = \hex2bin($encode_b);

                $this->assertSame($decode_b, $decode_a);
                $this->assertSame($str, $decode_b);
            }
        }
    }

    public function test_incorrect_checksum()
    {
        $header = Core::secure_random(Core::HEADER_VERSION_SIZE);
        $str = Encoding::save_bytes_to_checksummed_ascii_safe_string(
            $header,
            Core::secure_random(Core::KEY_BYTE_SIZE)
        );
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 0] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 1] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 3] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 4] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 5] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 6] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 7] = 'f';
        $str[2 * Encoding::SERIALIZE_HEADER_BYTES + 8] = 'f';
        $this->expectException(\Defuse\Crypto\Exception\Bad_Format_Exception::class);
        $this->expectExceptionMessage("checksum doesn't match");
        Encoding::load_bytes_from_checksummed_ascii_safe_string($header, $str);
    }

    public function test_bad_hex_encoding()
    {
        $header = Core::secure_random(Core::HEADER_VERSION_SIZE);
        $str = Encoding::save_bytes_to_checksummed_ascii_safe_string(
            $header,
            Core::secure_random(Core::KEY_BYTE_SIZE)
        );
        $str[0] = 'Z';
        $this->expectException(\Defuse\Crypto\Exception\Bad_Format_Exception::class);
        $this->expectExceptionMessage('not a hex string');
        Encoding::load_bytes_from_checksummed_ascii_safe_string($header, $str);
    }

    /**
     * This shouldn't throw an exception.
     */
    public function test_padded_hex_encoding()
    {
        /* We're just ensuring that an empty string doesn't produce an error. */
        $this->assertSame('', Encoding::trim_trailing_whitespace(''));

        $header = Core::secure_random(Core::HEADER_VERSION_SIZE);
        $str = Encoding::save_bytes_to_checksummed_ascii_safe_string(
            $header,
            Core::secure_random(Core::KEY_BYTE_SIZE)
        );
        $orig = $str;
        $noise = ["\r", "\n", "\t", "\0"];
        for ($i = 0; $i < 1000; ++$i) {
            $c = $noise[\random_int(0, 3)];
            $str .= $c;
            $this->assertSame(
                Encoding::bin_to_hex($orig),
                Encoding::bin_to_hex(Encoding::trim_trailing_whitespace($str)),
                'Pass #' . $i . ' (' . \dechex(\ord($c)) . ')'
            );
        }
    }
}
