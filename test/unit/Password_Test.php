<?php

declare(strict_types=1);

use Defuse\Crypto\Key_Protected_By_Password;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class Password_Test extends TestCase
{
    public function test_key_protected_by_password_correct()
    {
        $pkey1 = Key_Protected_By_Password::create_random_password_protected_key('password');
        $pkey2 = Key_Protected_By_Password::load_from_ascii_safe_string($pkey1->save_to_ascii_safe_string());

        $key1 = $pkey1->unlock_key('password');
        $key2 = $pkey2->unlock_key('password');

        $this->assertSame($key1->get_raw_bytes(), $key2->get_raw_bytes());
    }

    public function test_key_protected_by_password_wrong()
    {
        $pkey = Key_Protected_By_Password::create_random_password_protected_key('rightpassword');
        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        $key1 = $pkey->unlock_key('wrongpassword');
    }

    /**
     * Check that a new password was set.
     */
    public function test_change_password()
    {
        $pkey1 = Key_Protected_By_Password::create_random_password_protected_key('password');
        $pkey1_enc_ascii = $pkey1->save_to_ascii_safe_string();
        $key1 = $pkey1->unlock_key('password')->save_to_ascii_safe_string();

        $pkey1->change_password('password', 'new password');

        $pkey1_enc_ascii_new = $pkey1->save_to_ascii_safe_string();
        $key1_new = $pkey1->unlock_key('new password')->save_to_ascii_safe_string();

        // The encrypted_key should not be the same.
        $this->assertNotSame($pkey1_enc_ascii, $pkey1_enc_ascii_new);

        // The actual key should be the same.
        $this->assertSame($key1, $key1_new);
    }

    /**
     * Check that changing the password actually changes the password.
     */
    public function test_password_actually_changes()
    {
        $pkey1 = Key_Protected_By_Password::create_random_password_protected_key('password');
        $pkey1->change_password('password', 'new password');

        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        $pkey1->unlock_key('password');
    }

    public function test_malformed_load()
    {
        $pkey1 = Key_Protected_By_Password::create_random_password_protected_key('password');
        $pkey1_enc_ascii = $pkey1->save_to_ascii_safe_string();

        $pkey1_enc_ascii[0] = "\xFF";

        $this->expectException(\Defuse\Crypto\Exception\Bad_Format_Exception::class);
        Key_Protected_By_Password::load_from_ascii_safe_string($pkey1_enc_ascii);
    }
}
