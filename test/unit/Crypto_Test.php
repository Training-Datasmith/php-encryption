<?php

declare(strict_types=1);

use Defuse\Crypto\Core;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception as Ex;
use Defuse\Crypto\Key;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class Crypto_Test extends TestCase
{
    # Test for issue #165 -- encrypting then decrypting empty string fails.
    public function test_empty_string()
    {
        $str    = '';
        $key    = Key::create_new_random_key();
        $cipher = Crypto::encrypt($str, $key);
        $this->assertSame(
            $str,
            Crypto::decrypt($cipher, $key)
        );
    }

    // This mirrors the one in Runtime_Tests.php, but for passwords.
    // We can't runtime-test the password stuff because it runs PBKDF2.
    public function test_encrypt_decrypt_with_password()
    {
        $data = "EnCrYpT EvErYThInG\x00\x00";
        $password = 'password';

        // Make sure encrypting then decrypting doesn't change the message.
        $ciphertext = Crypto::encrypt_with_password($data, $password, true);
        try {
            $decrypted = Crypto::decrypt_with_password($ciphertext, $password, true);
        } catch (Ex\Wrong_Key_Or_Modified_Ciphertext_Exception $ex) {
            // It's important to catch this and change it into a
            // Ex\Environment_Is_Broken_Exception, otherwise a test failure could trick
            // the user into thinking it's just an invalid ciphertext!
            throw new Ex\Environment_Is_Broken_Exception();
        }
        if ($decrypted !== $data) {
            throw new Ex\Environment_Is_Broken_Exception();
        }

        // Modifying the ciphertext: Appending a string.
        try {
            Crypto::decrypt_with_password($ciphertext . 'a', $password, true);
            throw new Ex\Environment_Is_Broken_Exception();
        } catch (Ex\Wrong_Key_Or_Modified_Ciphertext_Exception $e) { /* expected */
        }

        // Modifying the ciphertext: Changing an HMAC byte.
        $indices_to_change = [
            0, // The header.
            Core::HEADER_VERSION_SIZE + 1, // the salt
            Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + 1, // the IV
            Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + Core::BLOCK_BYTE_SIZE + 1, // the ciphertext
        ];

        foreach ($indices_to_change as $index) {
            try {
                $ciphertext[$index] = \chr((\ord($ciphertext[$index]) + 1) % 256);
                Crypto::decrypt_with_password($ciphertext, $password, true);
                throw new Ex\Environment_Is_Broken_Exception();
            } catch (Ex\Wrong_Key_Or_Modified_Ciphertext_Exception $e) { /* expected */
            }
        }

        // Decrypting with the wrong password.
        $password       = 'password';
        $data           = 'abcdef';
        $ciphertext     = Crypto::encrypt_with_password($data, $password, true);
        $wrong_password = 'wrong_password';
        try {
            Crypto::decrypt_with_password($ciphertext, $wrong_password, true);
            throw new Ex\Environment_Is_Broken_Exception();
        } catch (Ex\Wrong_Key_Or_Modified_Ciphertext_Exception $e) { /* expected */
        }

        // TypeError; password needs to be a string, not an object
        $password        = Key::create_new_random_key();
        try {
            $ciphertext     = Crypto::encrypt_with_password($data, $password, true);
            $this->fail('Crypto::encrypt_with_password() should not accept key objects');
        } catch (\TypeError $e) { /* expected */
        }

        // Ciphertext too small.
        $password        = \random_bytes(32);
        $ciphertext      = \str_repeat('A', Core::MINIMUM_CIPHERTEXT_SIZE - 1);
        try {
            Crypto::decrypt_with_password($ciphertext, $password, true);
            throw new Ex\Environment_Is_Broken_Exception();
        } catch (Ex\Wrong_Key_Or_Modified_Ciphertext_Exception $e) { /* expected */
        }
    }

    public function test_decrypt_raw_as_hex()
    {
        $ciphertext = Crypto::encrypt_with_password('testdata', 'password', true);
        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt_with_password($ciphertext, 'password', false);
    }

    public function test_decrypt_hex_as_raw()
    {
        $ciphertext = Crypto::encrypt_with_password('testdata', 'password', false);
        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        Crypto::decrypt_with_password($ciphertext, 'password', true);
    }

    public function test_encrypt_type_error_a()
    {
        $key = Key::create_new_random_key();
        $this->expectException(\TypeError::class);
        Crypto::encrypt(3, $key, false);
    }

    public function test_encrypt_type_error_b()
    {
        $this->expectException(\TypeError::class);
        Crypto::encrypt('plaintext', 3, false);
    }

    public function test_encrypt_type_error_c()
    {
        $key = Key::create_new_random_key();
        $this->expectException(\TypeError::class);
        Crypto::encrypt('plaintext', $key, 3);
    }

    public function test_encrypt_with_password_type_error_a()
    {
        $this->expectException(\TypeError::class);
        Crypto::encrypt_with_password(3, 'password', false);
    }

    public function test_encrypt_with_password_type_error_b()
    {
        $this->expectException(\TypeError::class);
        Crypto::encrypt_with_password('plaintext', 3, false);
    }

    public function test_encrypt_with_password_type_error_c()
    {
        $this->expectException(\TypeError::class);
        Crypto::encrypt_with_password('plaintext', 'password', 3);
    }

    public function test_decrypt_type_error_a()
    {
        $key = Key::create_new_random_key();
        $this->expectException(\TypeError::class);
        Crypto::decrypt(3, $key, false);
    }

    public function test_decrypt_type_error_b()
    {
        $this->expectException(\TypeError::class);
        Crypto::decrypt('ciphertext', 3, false);
    }

    public function test_decrypt_type_error_c()
    {
        $key = Key::create_new_random_key();
        $this->expectException(\TypeError::class);
        Crypto::decrypt('ciphertext', $key, 3);
    }

    public function test_decrypt_with_password_type_error_a()
    {
        $this->expectException(\TypeError::class);
        Crypto::decrypt_with_password(3, 'password', false);
    }

    public function test_decrypt_with_password_type_error_b()
    {
        $this->expectException(\TypeError::class);
        Crypto::decrypt_with_password('ciphertext', 3, false);
    }

    public function test_decrypt_with_password_type_error_c()
    {
        $this->expectException(\TypeError::class);
        Crypto::decrypt_with_password('ciphertext', 'password', 3);
    }

    public function test_legacy_decrypt_type_error_a()
    {
        $this->expectException(\TypeError::class);
        Crypto::legacy_decrypt(3, 'key');
    }

    public function test_legacy_decrypt_type_error_b()
    {
        $this->expectException(\TypeError::class);
        Crypto::legacy_decrypt('ciphertext', 3);
    }

}
