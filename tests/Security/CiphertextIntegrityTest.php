<?php

declare(strict_types=1);

namespace Defuse\Crypto\Tests\Security;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception;
use PHPUnit\Framework\TestCase;

/**
 * Security boundary tests for the Crypto class.
 *
 * These tests validate that security-critical properties of the encrypt/decrypt
 * pipeline hold: authenticate-then-decrypt, tamper detection, key isolation,
 * and correct error handling.
 */
class CiphertextIntegrityTest extends TestCase
{
    private Key $key;
    private Key $wrong_key;

    protected function setUp(): void
    {
        $this->key       = Key::create_new_random_key();
        $this->wrong_key = Key::create_new_random_key();
    }

    /**
     * Decrypting with a different key must throw, not return garbage plaintext.
     * Validates that HMAC verification fires before any decryption output.
     */
    public function test_wrong_key_rejected_before_decryption(): void
    {
        $ciphertext = Crypto::encrypt('secret', $this->key);

        $this->expectException(Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt($ciphertext, $this->wrong_key);
    }

    /**
     * A single bit flip anywhere in the ciphertext body must be detected.
     * This validates Encrypt-then-MAC: any modification breaks the HMAC.
     */
    public function test_single_byte_modification_detected(): void
    {
        $plaintext  = 'integrity check test';
        $ciphertext = Crypto::encrypt($plaintext, $this->key);

        // Flip the first byte of the actual ciphertext bytes (after hex decode).
        $binary     = hex2bin($ciphertext);
        $corrupted  = chr(ord($binary[0]) ^ 0x01) . substr($binary, 1);
        $hex        = bin2hex($corrupted);

        $this->expectException(Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt($hex, $this->key);
    }

    /**
     * Truncating the ciphertext must be detected before decryption.
     */
    public function test_truncated_ciphertext_detected(): void
    {
        $ciphertext = Crypto::encrypt('truncation test', $this->key);

        // Remove the last 10 hex chars (5 bytes from the HMAC tail).
        $truncated = substr($ciphertext, 0, -10);

        $this->expectException(Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt($truncated, $this->key);
    }

    /**
     * Encrypting the same plaintext twice must produce different ciphertexts
     * (due to fresh random IV and salt on each call).
     */
    public function test_encrypt_is_probabilistic(): void
    {
        $plaintext   = 'same message';
        $ciphertext1 = Crypto::encrypt($plaintext, $this->key);
        $ciphertext2 = Crypto::encrypt($plaintext, $this->key);

        $this->assertNotSame($ciphertext1, $ciphertext2, 'Encrypt must be probabilistic (random IV/salt)');
    }

    /**
     * A valid ciphertext decrypted with the correct key must return the original plaintext.
     * Basic round-trip sanity check.
     */
    public function test_round_trip_with_key(): void
    {
        $plaintext  = 'hello world';
        $ciphertext = Crypto::encrypt($plaintext, $this->key);
        $decrypted  = Crypto::decrypt($ciphertext, $this->key);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Wrong password in password-based decryption must throw.
     * Validates that PBKDF2+HMAC rejects incorrect passwords correctly.
     */
    public function test_wrong_password_rejected(): void
    {
        $ciphertext = Crypto::encrypt_with_password('data', 'correct-password');

        $this->expectException(Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt_with_password($ciphertext, 'wrong-password');
    }

    /**
     * The ciphertext must contain a recognisable version header.
     * Validates that a ciphertext with a mangled header is rejected.
     */
    public function test_bad_version_header_rejected(): void
    {
        $ciphertext = Crypto::encrypt('version test', $this->key);

        // Replace the first 8 hex chars (4 bytes = version header) with zeros.
        $mangled = '00000000' . substr($ciphertext, 8);

        $this->expectException(Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt($mangled, $this->key);
    }

    /**
     * raw_binary=true and raw_binary=false must be treated as distinct formats.
     * Passing raw binary to the hex-mode decrypt must throw, not produce garbage.
     */
    public function test_raw_binary_format_mismatch_detected(): void
    {
        // Encrypt as hex (default), then try to decrypt as raw binary.
        $hex_ciphertext = Crypto::encrypt('format test', $this->key);

        $this->expectException(Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        // Pass as raw_binary=true when the ciphertext is actually hex-encoded.
        Crypto::decrypt($hex_ciphertext, $this->key, true);
    }
}
