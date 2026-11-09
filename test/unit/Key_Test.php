<?php

declare(strict_types=1);

use Defuse\Crypto\Core;
use Defuse\Crypto\Key;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class Key_Test extends TestCase
{
    public function test_create_new_random_key()
    {
        $key = Key::create_new_random_key();
        $this->assertSame(32, Core::our_strlen($key->get_raw_bytes()));
    }

    public function test_save_and_load_key()
    {
        $key1 = Key::create_new_random_key();
        $str  = $key1->save_to_ascii_safe_string();
        $key2 = Key::load_from_ascii_safe_string($str);
        $this->assertSame($key1->get_raw_bytes(), $key2->get_raw_bytes());
    }

    public function test_incorrect_header()
    {
        $key    = Key::create_new_random_key();
        $str    = $key->save_to_ascii_safe_string();
        $str[0] = 'f';
        $this->expectException(\Defuse\Crypto\Exception\Bad_Format_Exception::class);
        $this->expectExceptionMessage('Invalid header.');
        Key::load_from_ascii_safe_string($str);
    }
}
