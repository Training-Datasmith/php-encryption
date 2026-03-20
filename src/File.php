<?php

declare (strict_types=1);
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
final class File
{
    /**
     * Encrypts the input file, saving the ciphertext to the output file.
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     */
    public static function encrypt_file($input_filename, $output_filename, Key $key)
    {
        self::encrypt_file_internal($input_filename, $output_filename, Key_Or_Password::create_from_key($key));
    }
    /**
     * Encrypts a file with a password, using a slow key derivation function to
     * make password cracking more expensive.
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @param string $password
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     */
    public static function encrypt_file_with_password(
        $input_filename,
        $output_filename,
        #[\Sensitive_Parameter]
        $password
    )
    {
        self::encrypt_file_internal($input_filename, $output_filename, Key_Or_Password::create_from_password($password));
    }
    /**
     * Decrypts the input file, saving the plaintext to the output file.
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     */
    public static function decrypt_file($input_filename, $output_filename, Key $key)
    {
        self::decrypt_file_internal($input_filename, $output_filename, Key_Or_Password::create_from_key($key));
    }
    /**
     * Decrypts a file with a password, using a slow key derivation function to
     * make password cracking more expensive.
     *
     * @param string $inputFilename
     * @param string $outputFilename
     * @param string $password
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     */
    public static function decrypt_file_with_password(
        $input_filename,
        $output_filename,
        #[\Sensitive_Parameter]
        $password
    )
    {
        self::decrypt_file_internal($input_filename, $output_filename, Key_Or_Password::create_from_password($password));
    }
    /**
     * Takes two resource handles and encrypts the contents of the first,
     * writing the ciphertext into the second.
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     */
    public static function encrypt_resource($input_handle, $output_handle, Key $key)
    {
        self::encrypt_resource_internal($input_handle, $output_handle, Key_Or_Password::create_from_key($key));
    }
    /**
     * Encrypts the contents of one resource handle into another with a
     * password, using a slow key derivation function to make password cracking
     * more expensive.
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param string   $password
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     */
    public static function encrypt_resource_with_password(
        $input_handle,
        $output_handle,
        #[\Sensitive_Parameter]
        $password
    )
    {
        self::encrypt_resource_internal($input_handle, $output_handle, Key_Or_Password::create_from_password($password));
    }
    /**
     * Takes two resource handles and decrypts the contents of the first,
     * writing the plaintext into the second.
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     */
    public static function decrypt_resource($input_handle, $output_handle, Key $key)
    {
        self::decrypt_resource_internal($input_handle, $output_handle, Key_Or_Password::create_from_key($key));
    }
    /**
     * Decrypts the contents of one resource into another with a password, using
     * a slow key derivation function to make password cracking more expensive.
     *
     * @param resource $inputHandle
     * @param resource $outputHandle
     * @param string   $password
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     */
    public static function decrypt_resource_with_password(
        $input_handle,
        $output_handle,
        #[\Sensitive_Parameter]
        $password
    )
    {
        self::decrypt_resource_internal($input_handle, $output_handle, Key_Or_Password::create_from_password($password));
    }
    /**
     * Encrypts a file with either a key or a password.
     *
     * @param string        $inputFilename
     * @param string        $outputFilename
     * @return void
     *
     * @throws Ex\CryptoException
     * @throws Ex\IOException
     */
    private static function encrypt_file_internal($input_filename, $output_filename, Key_Or_Password $secret)
    {
        if (file_exists($input_filename) && file_exists($output_filename) && realpath($input_filename) === realpath($output_filename)) {
            throw new Ex\Io_Exception('Input and output filenames must be different.');
        }
        /* Open the input file. */
        self::remove_php_unit_error_handler();
        $if = @\fopen($input_filename, 'rb');
        self::restore_php_unit_error_handler();
        if ($if === false) {
            throw new Ex\Io_Exception('Cannot open input file for encrypting: ' . self::get_last_error_message());
        }
        if (\is_callable('\stream_set_read_buffer')) {
            /* This call can fail, but the only consequence is performance. */
            \stream_set_read_buffer($if, 0);
        }
        /* Open the output file. */
        self::remove_php_unit_error_handler();
        $of = @\fopen($output_filename, 'wb');
        self::restore_php_unit_error_handler();
        if ($of === false) {
            \fclose($if);
            throw new Ex\Io_Exception('Cannot open output file for encrypting: ' . self::get_last_error_message());
        }
        if (\is_callable('\stream_set_write_buffer')) {
            /* This call can fail, but the only consequence is performance. */
            \stream_set_write_buffer($of, 0);
        }
        /* Perform the encryption. */
        try {
            self::encrypt_resource_internal($if, $of, $secret);
        } catch (Ex\Crypto_Exception $ex) {
            \fclose($if);
            \fclose($of);
            throw $ex;
        }
        /* Close the input file. */
        if (\fclose($if) === false) {
            \fclose($of);
            throw new Ex\Io_Exception('Cannot close input file after encrypting');
        }
        /* Close the output file. */
        if (\fclose($of) === false) {
            throw new Ex\Io_Exception('Cannot close output file after encrypting');
        }
    }
    /**
     * Decrypts a file with either a key or a password.
     *
     * @param string        $inputFilename
     * @param string        $outputFilename
     * @return void
     *
     * @throws Ex\CryptoException
     * @throws Ex\IOException
     */
    private static function decrypt_file_internal($input_filename, $output_filename, Key_Or_Password $secret)
    {
        if (file_exists($input_filename) && file_exists($output_filename) && realpath($input_filename) === realpath($output_filename)) {
            throw new Ex\Io_Exception('Input and output filenames must be different.');
        }
        /* Open the input file. */
        self::remove_php_unit_error_handler();
        $if = @\fopen($input_filename, 'rb');
        self::restore_php_unit_error_handler();
        if ($if === false) {
            throw new Ex\Io_Exception('Cannot open input file for decrypting: ' . self::get_last_error_message());
        }
        if (\is_callable('\stream_set_read_buffer')) {
            /* This call can fail, but the only consequence is performance. */
            \stream_set_read_buffer($if, 0);
        }
        /* Open the output file. */
        self::remove_php_unit_error_handler();
        $of = @\fopen($output_filename, 'wb');
        self::restore_php_unit_error_handler();
        if ($of === false) {
            \fclose($if);
            throw new Ex\Io_Exception('Cannot open output file for decrypting: ' . self::get_last_error_message());
        }
        if (\is_callable('\stream_set_write_buffer')) {
            /* This call can fail, but the only consequence is performance. */
            \stream_set_write_buffer($of, 0);
        }
        /* Perform the decryption. */
        try {
            self::decrypt_resource_internal($if, $of, $secret);
        } catch (Ex\Crypto_Exception $ex) {
            \fclose($if);
            \fclose($of);
            throw $ex;
        }
        /* Close the input file. */
        if (\fclose($if) === false) {
            \fclose($of);
            throw new Ex\Io_Exception('Cannot close input file after decrypting');
        }
        /* Close the output file. */
        if (\fclose($of) === false) {
            throw new Ex\Io_Exception('Cannot close output file after decrypting');
        }
    }
    /**
     * Encrypts a resource with either a key or a password.
     *
     * @param resource      $inputHandle
     * @param resource      $outputHandle
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @psalm-suppress PossiblyInvalidArgument
     *      Fixes erroneous errors caused by PHP 7.2 switching the return value
     *      of hash_init from a resource to a HashContext.
     */
    private static function encrypt_resource_internal($input_handle, $output_handle, Key_Or_Password $secret)
    {
        if (!\is_resource($input_handle)) {
            throw new Ex\Io_Exception('Input handle must be a resource!');
        }
        if (!\is_resource($output_handle)) {
            throw new Ex\Io_Exception('Output handle must be a resource!');
        }
        $input_stat = \fstat($input_handle);
        $input_size = $input_stat['size'];
        $file_salt = Core::secure_random(Core::SALT_BYTE_SIZE);
        $keys = $secret->derive_keys($file_salt);
        $ekey = $keys->get_encryption_key();
        $akey = $keys->get_authentication_key();
        $ivsize = Core::BLOCK_BYTE_SIZE;
        $iv = Core::secure_random($ivsize);
        /* Initialize a streaming HMAC state. */
        /** @var mixed $hmac */
        $hmac = \hash_init(Core::HASH_FUNCTION_NAME, HASH_HMAC, $akey);
        Core::ensure_true(\is_resource($hmac) || \is_object($hmac), 'Cannot initialize a hash context');
        /* Write the header, salt, and IV. */
        self::write_bytes($output_handle, Core::CURRENT_VERSION . $file_salt . $iv, Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + $ivsize);
        /* Add the header, salt, and IV to the HMAC. */
        \hash_update($hmac, Core::CURRENT_VERSION);
        \hash_update($hmac, $file_salt);
        \hash_update($hmac, $iv);
        /* $thisIv will be incremented after each call to the encryption. */
        $this_iv = $iv;
        /* How many blocks do we encrypt at a time? We increment by this value. */
        /**
         * @psalm-suppress RedundantCast
         */
        $inc = Core::BUFFER_BYTE_SIZE / Core::BLOCK_BYTE_SIZE;
        /* Loop until we reach the end of the input file. */
        $at_file_end = false;
        while (!(\feof($input_handle) || $at_file_end)) {
            /* Find out if we can read a full buffer, or only a partial one. */
            /** @var int */
            $pos = \ftell($input_handle);
            if (!\is_int($pos)) {
                throw new Ex\Io_Exception('Could not get current position in input file during encryption');
            }
            if ($pos + Core::BUFFER_BYTE_SIZE >= $input_size) {
                /* We're at the end of the file, so we need to break out of the loop. */
                $at_file_end = true;
                $read = self::read_bytes($input_handle, $input_size - $pos);
            } else {
                $read = self::read_bytes($input_handle, Core::BUFFER_BYTE_SIZE);
            }
            /* Encrypt this buffer. */
            /** @var string */
            $encrypted = \openssl_encrypt($read, Core::CIPHER_METHOD, $ekey, OPENSSL_RAW_DATA, $this_iv);
            Core::ensure_true(\is_string($encrypted), 'OpenSSL encryption error');
            /* Write this buffer's ciphertext. */
            self::write_bytes($output_handle, $encrypted, Core::our_strlen($encrypted));
            /* Add this buffer's ciphertext to the HMAC. */
            \hash_update($hmac, $encrypted);
            /* Increment the counter by the number of blocks in a buffer. */
            $this_iv = Core::increment_counter($this_iv, $inc);
            /* WARNING: Usually, unless the file is a multiple of the buffer
             * size, $thisIv will contain an incorrect value here on the last
             * iteration of this loop. */
        }
        /* Get the HMAC and append it to the ciphertext. */
        $final_mac = \hash_final($hmac, true);
        self::write_bytes($output_handle, $final_mac, Core::MAC_BYTE_SIZE);
    }
    /**
     * Decrypts a file-backed resource with either a key or a password.
     *
     * @param resource      $inputHandle
     * @param resource      $outputHandle
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\IOException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     * @psalm-suppress PossiblyInvalidArgument
     *      Fixes erroneous errors caused by PHP 7.2 switching the return value
     *      of hash_init from a resource to a HashContext.
     */
    private static function decrypt_resource_internal($input_handle, $output_handle, Key_Or_Password $secret)
    {
        if (!\is_resource($input_handle)) {
            throw new Ex\Io_Exception('Input handle must be a resource!');
        }
        if (!\is_resource($output_handle)) {
            throw new Ex\Io_Exception('Output handle must be a resource!');
        }
        /* Make sure the file is big enough for all the reads we need to do. */
        $stat = \fstat($input_handle);
        if ($stat['size'] < Core::MINIMUM_CIPHERTEXT_SIZE) {
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Input file is too small to have been created by this library.');
        }
        /* Check the version header. */
        $header = self::read_bytes($input_handle, Core::HEADER_VERSION_SIZE);
        if ($header !== Core::CURRENT_VERSION) {
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Bad version header.');
        }
        /* Get the salt. */
        $file_salt = self::read_bytes($input_handle, Core::SALT_BYTE_SIZE);
        /* Get the IV. */
        $ivsize = Core::BLOCK_BYTE_SIZE;
        $iv = self::read_bytes($input_handle, $ivsize);
        /* Derive the authentication and encryption keys. */
        $keys = $secret->derive_keys($file_salt);
        $ekey = $keys->get_encryption_key();
        $akey = $keys->get_authentication_key();
        /* We'll store the MAC of each buffer-sized chunk as we verify the
         * actual MAC, so that we can check them again when decrypting. */
        $macs = [];
        /* $thisIv will be incremented after each call to the decryption. */
        $this_iv = $iv;
        /* How many blocks do we encrypt at a time? We increment by this value. */
        /**
         * @psalm-suppress RedundantCast
         */
        $inc = Core::BUFFER_BYTE_SIZE / Core::BLOCK_BYTE_SIZE;
        /* Get the HMAC. */
        if (\fseek($input_handle, -1 * Core::MAC_BYTE_SIZE, SEEK_END) === -1) {
            throw new Ex\Io_Exception('Cannot seek to beginning of MAC within input file');
        }
        /* Get the position of the last byte in the actual ciphertext. */
        /** @var int $cipher_end */
        $cipher_end = \ftell($input_handle);
        if (!\is_int($cipher_end)) {
            throw new Ex\Io_Exception('Cannot read input file');
        }
        /* We have the position of the first byte of the HMAC. Go back by one. */
        --$cipher_end;
        /* Read the HMAC. */
        /** @var string $stored_mac */
        $stored_mac = self::read_bytes($input_handle, Core::MAC_BYTE_SIZE);
        /* Initialize a streaming HMAC state. */
        /** @var mixed $hmac */
        $hmac = \hash_init(Core::HASH_FUNCTION_NAME, HASH_HMAC, $akey);
        Core::ensure_true(\is_resource($hmac) || \is_object($hmac), 'Cannot initialize a hash context');
        /* Reset file pointer to the beginning of the file after the header */
        if (\fseek($input_handle, Core::HEADER_VERSION_SIZE, SEEK_SET) === -1) {
            throw new Ex\Io_Exception('Cannot read seek within input file');
        }
        /* Seek to the start of the actual ciphertext. */
        if (\fseek($input_handle, Core::SALT_BYTE_SIZE + $ivsize, SEEK_CUR) === -1) {
            throw new Ex\Io_Exception('Cannot seek input file to beginning of ciphertext');
        }
        /* PASS #1: Calculating the HMAC. */
        \hash_update($hmac, $header);
        \hash_update($hmac, $file_salt);
        \hash_update($hmac, $iv);
        /** @var mixed $hmac2 */
        $hmac2 = \hash_copy($hmac);
        $break = false;
        while (!$break) {
            /** @var int $pos */
            $pos = \ftell($input_handle);
            if (!\is_int($pos)) {
                throw new Ex\Io_Exception('Could not get current position in input file during decryption');
            }
            /* Read the next buffer-sized chunk (or less). */
            if ($pos + Core::BUFFER_BYTE_SIZE >= $cipher_end) {
                $break = true;
                $read = self::read_bytes($input_handle, $cipher_end - $pos + 1);
            } else {
                $read = self::read_bytes($input_handle, Core::BUFFER_BYTE_SIZE);
            }
            /* Update the HMAC. */
            \hash_update($hmac, $read);
            /* Remember this buffer-sized chunk's HMAC. */
            /** @var mixed $chunk_mac */
            $chunk_mac = \hash_copy($hmac);
            Core::ensure_true(\is_resource($chunk_mac) || \is_object($chunk_mac), 'Cannot duplicate a hash context');
            $macs[] = \hash_final($chunk_mac);
        }
        /* Get the final HMAC, which should match the stored one. */
        /** @var string $final_mac */
        $final_mac = \hash_final($hmac, true);
        /* Verify the HMAC. */
        if (!Core::hash_equals($final_mac, $stored_mac)) {
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Integrity check failed.');
        }
        /* PASS #2: Decrypt and write output. */
        /* Rewind to the start of the actual ciphertext. */
        if (\fseek($input_handle, Core::SALT_BYTE_SIZE + $ivsize + Core::HEADER_VERSION_SIZE, SEEK_SET) === -1) {
            throw new Ex\Io_Exception('Could not move the input file pointer during decryption');
        }
        $at_file_end = false;
        while (!$at_file_end) {
            /** @var int $pos */
            $pos = \ftell($input_handle);
            if (!\is_int($pos)) {
                throw new Ex\Io_Exception('Could not get current position in input file during decryption');
            }
            /* Read the next buffer-sized chunk (or less). */
            if ($pos + Core::BUFFER_BYTE_SIZE >= $cipher_end) {
                $at_file_end = true;
                $read = self::read_bytes($input_handle, $cipher_end - $pos + 1);
            } else {
                $read = self::read_bytes($input_handle, Core::BUFFER_BYTE_SIZE);
            }
            /* Recalculate the MAC (so far) and compare it with the one we
             * remembered from pass #1 to ensure attackers didn't change the
             * ciphertext after MAC verification. */
            \hash_update($hmac2, $read);
            /** @var mixed $calc_mac */
            $calc_mac = \hash_copy($hmac2);
            Core::ensure_true(\is_resource($calc_mac) || \is_object($calc_mac), 'Cannot duplicate a hash context');
            $calc = \hash_final($calc_mac);
            if (empty($macs)) {
                throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('File was modified after MAC verification');
            }
            if (!Core::hash_equals(\array_shift($macs), $calc)) {
                throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('File was modified after MAC verification');
            }
            /* Decrypt this buffer-sized chunk. */
            /** @var string $decrypted */
            $decrypted = \openssl_decrypt($read, Core::CIPHER_METHOD, $ekey, OPENSSL_RAW_DATA, $this_iv);
            Core::ensure_true(\is_string($decrypted), 'OpenSSL decryption error');
            /* Write the plaintext to the output file. */
            self::write_bytes($output_handle, $decrypted, Core::our_strlen($decrypted));
            /* Increment the IV by the amount of blocks in a buffer. */
            /** @var string $thisIv */
            $this_iv = Core::increment_counter($this_iv, $inc);
            /* WARNING: Usually, unless the file is a multiple of the buffer
             * size, $thisIv will contain an incorrect value here on the last
             * iteration of this loop. */
        }
    }
    /**
     * Read from a stream; prevent partial reads.
     *
     * @param resource $stream
     * @param int      $num_bytes
     * @return string
     *
     * @throws Ex\IOException
     * @throws Ex\EnvironmentIsBrokenException
     */
    public static function read_bytes($stream, $num_bytes)
    {
        Core::ensure_true($num_bytes >= 0, 'Tried to read less than 0 bytes');
        if ($num_bytes === 0) {
            return '';
        }
        $buf = '';
        $remaining = $num_bytes;
        while ($remaining > 0 && !\feof($stream)) {
            /** @var string $read */
            $read = \fread($stream, $remaining);
            if (!\is_string($read)) {
                throw new Ex\Io_Exception('Could not read from the file');
            }
            $buf .= $read;
            $remaining -= Core::our_strlen($read);
        }
        if (Core::our_strlen($buf) !== $num_bytes) {
            throw new Ex\Io_Exception('Tried to read past the end of the file');
        }
        return $buf;
    }
    /**
     * Write to a stream; prevents partial writes.
     *
     * @param resource $stream
     * @param string   $buf
     * @param int      $num_bytes
     * @return int
     *
     * @throws Ex\IOException
     */
    public static function write_bytes($stream, $buf, $num_bytes = null)
    {
        $buf_size = Core::our_strlen($buf);
        if ($num_bytes === null) {
            $num_bytes = $buf_size;
        }
        if ($num_bytes > $buf_size) {
            throw new Ex\Io_Exception('Trying to write more bytes than the buffer contains.');
        }
        if ($num_bytes < 0) {
            throw new Ex\Io_Exception('Tried to write less than 0 bytes');
        }
        $remaining = $num_bytes;
        while ($remaining > 0) {
            /** @var int $written */
            $written = \fwrite($stream, $buf, $remaining);
            if (!\is_int($written)) {
                throw new Ex\Io_Exception('Could not write to the file');
            }
            $buf = (string) Core::our_substr($buf, $written);
            $remaining -= $written;
        }
        return $num_bytes;
    }
    /**
     * Returns the last PHP error's or warning's message string.
     *
     * @return string
     */
    private static function get_last_error_message()
    {
        $error = error_get_last();
        if ($error === null) {
            return '[no PHP error, or you have a custom error handler set]';
        }
        return $error['message'];
    }
    /**
     * PHPUnit sets an error handler, which prevents getLastErrorMessage() from working,
     * because error_get_last does not work when custom handlers are set.
     *
     * This is a workaround, which should be a no-op in production deployments, to make
     * getLastErrorMessage() return the error messages that the PHPUnit tests expect.
     *
     * If, in a production deployment, a custom error handler is set, the exception
     * handling will still work as usual, but the error messages will be confusing.
     *
     * @return void
     */
    private static function remove_php_unit_error_handler()
    {
        if (defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_PHAR__')) {
            set_error_handler(null);
        }
    }
    /**
     * Undoes what removePHPUnitErrorHandler did.
     *
     * @return void
     */
    private static function restore_php_unit_error_handler()
    {
        if (defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_PHAR__')) {
            restore_error_handler();
        }
    }
}