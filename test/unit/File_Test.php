<?php

declare(strict_types=1);

namespace Defuse\Crypto;

use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class File_Test extends TestCase
{
    private $key;
    private static $FILE_DIR;
    private static $TEMP_DIR;

    public function set_up()
    {
        self::$FILE_DIR = __DIR__ . '/File';
        self::$TEMP_DIR = self::$FILE_DIR . '/tmp';
        if (! is_dir(self::$TEMP_DIR)) {
            mkdir(self::$TEMP_DIR);
        }

        $this->key = Key::create_new_random_key();
    }

    public function tear_down()
    {
        array_map('unlink', glob(self::$TEMP_DIR . '/*'));
        rmdir(self::$TEMP_DIR);
    }

    /**
     * Test encryption from one file name to a destination file name
     *
     * @dataProvider file_to_file_provider
     *
     * @param string $src_name source file name
     */
    public function test_file_to_file($src_name)
    {
        $src = self::$FILE_DIR . '/' . $src_name;

        $dest1  = self::$TEMP_DIR . '/ff1';
        File::encrypt_file($src, $dest1, $this->key);
        $this->assertFileExists($dest1, 'destination file not created.');

        $reverse1 = self::$TEMP_DIR . '/rv1';
        File::decrypt_file($dest1, $reverse1, $this->key);
        $this->assertFileExists($reverse1);
        $this->assertSame(
            md5_file($src),
            md5_file($reverse1),
            'File and encrypted-decrypted file do not match.'
        );

        $dest2  = self::$TEMP_DIR . '/ff2';
        File::encrypt_file($reverse1, $dest2, $this->key);
        $this->assertFileExists($dest2);

        $this->assertNotEquals(
            md5_file($dest1),
            md5_file($dest2),
            'First and second encryption produced identical files.'
        );

        $reverse2 = self::$TEMP_DIR . '/rv2';
        File::decrypt_file($dest2, $reverse2, $this->key);
        $this->assertSame(
            md5_file($src),
            md5_file($reverse2),
            'File and encrypted-decrypted file do not match.'
        );
    }

    /**
     * Test encryption from one file name to a destination file name (password).
     *
     * @dataProvider file_to_file_provider
     *
     * @param string $src_name source file name
     */
    public function test_file_to_file_with_password($src_name)
    {
        $src = self::$FILE_DIR . '/' . $src_name;

        $dest1  = self::$TEMP_DIR . '/ff1';
        File::encrypt_file_with_password($src, $dest1, 'password');
        $this->assertFileExists($dest1, 'destination file not created.');

        $reverse1 = self::$TEMP_DIR . '/rv1';
        File::decrypt_file_with_password($dest1, $reverse1, 'password');
        $this->assertFileExists($reverse1);
        $this->assertSame(
            md5_file($src),
            md5_file($reverse1),
            'File and encrypted-decrypted file do not match.'
        );

        $dest2  = self::$TEMP_DIR . '/ff2';
        File::encrypt_file_with_password($reverse1, $dest2, 'password');
        $this->assertFileExists($dest2);

        $this->assertNotEquals(
            md5_file($dest1),
            md5_file($dest2),
            'First and second encryption produced identical files.'
        );

        $reverse2 = self::$TEMP_DIR . '/rv2';
        File::decrypt_file_with_password($dest2, $reverse2, 'password');
        $this->assertSame(
            md5_file($src),
            md5_file($reverse2),
            'File and encrypted-decrypted file do not match.'
        );
    }

    /**
     * @dataProvider file_to_file_provider
     *
     * @param string $src source handle
     */
    public function test_resource_to_resource($src_file)
    {
        $src_path = self::$FILE_DIR . '/' . $src_file;
        $destName = self::$TEMP_DIR . "/$src_file.dest";
        $src      = fopen($src_path, 'r');
        $dest     = fopen($destName, 'w');

        File::encrypt_resource($src, $dest, $this->key);

        fclose($src);
        fclose($dest);

        $src2  = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');

        File::decrypt_resource($src2, $dest2, $this->key);
        fclose($src2);
        fclose($dest2);

        $this->assertSame(
            md5_file($src_path),
            md5_file(self::$TEMP_DIR . '/dest2'),
            'Original file mismatches the result of encrypt and decrypt'
        );
    }

    /**
     * @dataProvider file_to_file_provider
     *
     * @param string $src source handle
     */
    public function test_resource_to_resource_with_password($src_file)
    {
        $src_path = self::$FILE_DIR . '/' . $src_file;
        $destName = self::$TEMP_DIR . "/$src_file.dest";
        $src      = fopen($src_path, 'r');
        $dest     = fopen($destName, 'w');

        File::encrypt_resource_with_password($src, $dest, 'password');

        fclose($src);
        fclose($dest);

        $src2  = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');

        File::decrypt_resource_with_password($src2, $dest2, 'password');
        fclose($src2);
        fclose($dest2);

        $this->assertSame(
            md5_file($src_path),
            md5_file(self::$TEMP_DIR . '/dest2'),
            'Original file mismatches the result of encrypt and decrypt'
        );
    }

    public function test_decrypt_bad_magic_number()
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, 'This file does not have the right magic number.');
        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        $this->expectExceptionMessage('Input file is too small to have been created by this library.');
        File::decrypt_file($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    /**
     * @dataProvider garbage_ciphertext_provider
     */
    public function test_decrypt_garbage($ciphertext)
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, $ciphertext);
        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        File::decrypt_file($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    public static function garbage_ciphertext_provider()
    {
        $ciphertexts = [
            [str_repeat('this is not anything that can be decrypted.', 100)],
        ];
        for ($i = 0; $i < 1024; $i++) {
            $ciphertexts[] = [Core::CURRENT_VERSION . str_repeat('A', $i)];
        }
        return $ciphertexts;
    }

    public function test_decrypt_empty_file()
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, '');
        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        File::decrypt_file($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    public function test_decrypt_truncated_ciphertext()
    {
        // This tests for issue #115 on GitHub.
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $truncated_path  = self::$TEMP_DIR . '/truncated';

        file_put_contents($plaintext_path, str_repeat('A', 1024));
        File::encrypt_file($plaintext_path, $ciphertext_path, $this->key);

        $ciphertext = file_get_contents($ciphertext_path);
        $truncated  = substr($ciphertext, 0, 64);
        file_put_contents($truncated_path, $truncated);

        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        File::decrypt_file($truncated_path, $plaintext_path, $this->key);
    }

    public function test_encrypt_with_crypto_decrypt_with_file()
    {
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';

        $key        = Key::create_new_random_key();
        $plaintext  = 'Plaintext!';
        $ciphertext = Crypto::encrypt($plaintext, $key, true);
        file_put_contents($ciphertext_path, $ciphertext);

        File::decrypt_file($ciphertext_path, $plaintext_path, $key);

        $plaintext_decrypted = file_get_contents($plaintext_path);
        $this->assertSame($plaintext, $plaintext_decrypted);
    }

    public function test_encrypt_with_file_decrypt_with_crypto()
    {
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';

        $key       = Key::create_new_random_key();
        $plaintext = 'Plaintext!';
        file_put_contents($plaintext_path, $plaintext);
        File::encrypt_file($plaintext_path, $ciphertext_path, $key);

        $ciphertext          = file_get_contents($ciphertext_path);
        $plaintext_decrypted = Crypto::decrypt($ciphertext, $key, true);
        $this->assertSame($plaintext, $plaintext_decrypted);
    }

    public function test_extra_data()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $dest = self::$TEMP_DIR . '/err';

        File::encrypt_file($src, $dest, $this->key);

        file_put_contents($dest, str_repeat('A', 2048), FILE_APPEND);

        $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
        $this->expectExceptionMessage('Integrity check failed.');
        File::decrypt_file($dest, $dest . '.jpg', $this->key);
    }

    public function test_file_create_random_key()
    {
        $result = Key::create_new_random_key();
        $this->assertInstanceOf('\Defuse\Crypto\Key', $result);
    }

    public function test_bad_source_path_encrypt()
    {
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('No such file or directory');
        File::encrypt_file('./i-do-not-exist', 'output-file', $this->key);
    }

    public function test_bad_source_path_decrypt()
    {
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('No such file or directory');
        File::decrypt_file('./i-do-not-exist', 'output-file', $this->key);
    }

    public function test_bad_source_path_encrypt_with_password()
    {
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('No such file or directory');
        File::encrypt_file_with_password('./i-do-not-exist', 'output-file', 'password');
    }

    public function test_bad_source_path_decrypt_with_password()
    {
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('No such file or directory');
        File::decrypt_file_with_password('./i-do-not-exist', 'output-file', 'password');
    }

    public function test_bad_destination_path_encrypt()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('Is a directory');
        File::encrypt_file($src, './', $this->key);
    }

    public function test_bad_destination_path_decrypt()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('Is a directory');
        File::decrypt_file($src, './', $this->key);
    }

    public function test_bad_destination_path_encrypt_with_password()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('Is a directory');
        File::encrypt_file_with_password($src, './', 'password');
    }

    public function test_bad_destination_path_decrypt_with_password()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('Is a directory');
        File::decrypt_file_with_password($src, './', 'password');
    }

    public function test_non_resource_input_encrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('must be a resource');
        File::encrypt_resource('not a resource', $resource, $this->key);
        fclose($resource);
    }

    public function test_non_resource_output_encrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('must be a resource');
        File::encrypt_resource($resource, 'not a resource', $this->key);
        fclose($resource);
    }

    public function test_non_resource_input_decrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('must be a resource');
        File::decrypt_resource('not a resource', $resource, $this->key);
        fclose($resource);
    }

    public function test_non_resource_output_decrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\Io_Exception::class);
        $this->expectExceptionMessage('must be a resource');
        File::decrypt_resource($resource, 'not a resource', $this->key);
        fclose($resource);
    }

    public function test_non_file_resource_decrypt()
    {
        /* This should behave equivalently to an empty file. Calling fstat() on
            stdin returns a result saying it has zero size. */
        $stdin = fopen('php://stdin', 'r');
        $output = fopen('php://memory', 'wb');
        try {
            File::decrypt_resource($stdin, $output, $this->key);
        } catch (\Exception $ex) {
            fclose($output);
            fclose($stdin);
            $this->expectException(\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception::class);
            throw $ex;
        }
    }

    public static function file_to_file_provider()
    {
        $data = [];

        $data['empty-file']         = ['empty-file.txt'];
        $data['wat-giagantic-duck'] = ['wat-gigantic-duck.jpg'];
        # Created from /dev/urandom in test.sh
        $data['extra-large'] = ['big-generated-file'];

        return $data;
    }
}
