<?php

declare (strict_types=1);
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
class Crypto
{
    /**
     * Encrypts a string with a Key.
     *
     * @param string $plaintext
     * @param Key    $key
     * @param bool   $raw_binary
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws \TypeError
     *
     * @return string
     */
    public static function encrypt($plaintext, $key, $raw_binary = false)
    {
        if (!\is_string($plaintext)) {
            throw new \TypeError('String expected for argument 1. ' . \ucfirst(\gettype($plaintext)) . ' given instead.');
        }
        if (!$key instanceof Key) {
            throw new \TypeError('Key expected for argument 2. ' . \ucfirst(\gettype($key)) . ' given instead.');
        }
        if (!\is_bool($raw_binary)) {
            throw new \TypeError('Boolean expected for argument 3. ' . \ucfirst(\gettype($raw_binary)) . ' given instead.');
        }
        return self::encrypt_internal($plaintext, Key_Or_Password::create_from_key($key), $raw_binary);
    }
    /**
     * Encrypts a string with a password, using a slow key derivation function
     * to make password cracking more expensive.
     *
     * @param string $plaintext
     * @param string $password
     * @param bool   $raw_binary
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws \TypeError
     *
     * @return string
     */
    public static function encrypt_with_password(
        $plaintext,
        #[\Sensitive_Parameter]
        $password,
        $raw_binary = false
    )
    {
        if (!\is_string($plaintext)) {
            throw new \TypeError('String expected for argument 1. ' . \ucfirst(\gettype($plaintext)) . ' given instead.');
        }
        if (!\is_string($password)) {
            throw new \TypeError('String expected for argument 2. ' . \ucfirst(\gettype($password)) . ' given instead.');
        }
        if (!\is_bool($raw_binary)) {
            throw new \TypeError('Boolean expected for argument 3. ' . \ucfirst(\gettype($raw_binary)) . ' given instead.');
        }
        return self::encrypt_internal($plaintext, Key_Or_Password::create_from_password($password), $raw_binary);
    }
    /**
     * Decrypts a ciphertext to a string with a Key.
     *
     * @param string $ciphertext
     * @param Key    $key
     * @param bool   $raw_binary
     *
     * @throws \TypeError
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     *
     * @return string
     */
    public static function decrypt($ciphertext, $key, $raw_binary = false)
    {
        if (!\is_string($ciphertext)) {
            throw new \TypeError('String expected for argument 1. ' . \ucfirst(\gettype($ciphertext)) . ' given instead.');
        }
        if (!$key instanceof Key) {
            throw new \TypeError('Key expected for argument 2. ' . \ucfirst(\gettype($key)) . ' given instead.');
        }
        if (!\is_bool($raw_binary)) {
            throw new \TypeError('Boolean expected for argument 3. ' . \ucfirst(\gettype($raw_binary)) . ' given instead.');
        }
        return self::decrypt_internal($ciphertext, Key_Or_Password::create_from_key($key), $raw_binary);
    }
    /**
     * Decrypts a ciphertext to a string with a password, using a slow key
     * derivation function to make password cracking more expensive.
     *
     * @param string $ciphertext
     * @param string $password
     * @param bool   $raw_binary
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     * @throws \TypeError
     *
     * @return string
     */
    public static function decrypt_with_password(
        $ciphertext,
        #[\Sensitive_Parameter]
        $password,
        $raw_binary = false
    )
    {
        if (!\is_string($ciphertext)) {
            throw new \TypeError('String expected for argument 1. ' . \ucfirst(\gettype($ciphertext)) . ' given instead.');
        }
        if (!\is_string($password)) {
            throw new \TypeError('String expected for argument 2. ' . \ucfirst(\gettype($password)) . ' given instead.');
        }
        if (!\is_bool($raw_binary)) {
            throw new \TypeError('Boolean expected for argument 3. ' . \ucfirst(\gettype($raw_binary)) . ' given instead.');
        }
        return self::decrypt_internal($ciphertext, Key_Or_Password::create_from_password($password), $raw_binary);
    }
    /**
     * Decrypts a legacy ciphertext produced by version 1 of this library.
     *
     * @param string $ciphertext
     * @param string $key
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     * @throws \TypeError
     *
     * @return string
     */
    public static function legacy_decrypt(
        $ciphertext,
        #[\Sensitive_Parameter]
        $key
    )
    {
        if (!\is_string($ciphertext)) {
            throw new \TypeError('String expected for argument 1. ' . \ucfirst(\gettype($ciphertext)) . ' given instead.');
        }
        if (!\is_string($key)) {
            throw new \TypeError('String expected for argument 2. ' . \ucfirst(\gettype($key)) . ' given instead.');
        }
        Runtime_Tests::runtime_test();
        // Extract the HMAC from the front of the ciphertext.
        if (Core::our_strlen($ciphertext) <= Core::LEGACY_MAC_BYTE_SIZE) {
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Ciphertext is too short.');
        }
        /**
         * @var string
         */
        $hmac = Core::our_substr($ciphertext, 0, Core::LEGACY_MAC_BYTE_SIZE);
        Core::ensure_true(\is_string($hmac));
        /**
         * @var string
         */
        $message_ciphertext = Core::our_substr($ciphertext, Core::LEGACY_MAC_BYTE_SIZE);
        Core::ensure_true(\is_string($message_ciphertext));
        // Regenerate the same authentication sub-key.
        $akey = Core::HKDF(Core::LEGACY_HASH_FUNCTION_NAME, $key, Core::LEGACY_KEY_BYTE_SIZE, Core::LEGACY_AUTHENTICATION_INFO_STRING);
        if (self::verify_hmac($hmac, $message_ciphertext, $akey)) {
            // Regenerate the same encryption sub-key.
            $ekey = Core::HKDF(Core::LEGACY_HASH_FUNCTION_NAME, $key, Core::LEGACY_KEY_BYTE_SIZE, Core::LEGACY_ENCRYPTION_INFO_STRING);
            // Extract the IV from the ciphertext.
            if (Core::our_strlen($message_ciphertext) <= Core::LEGACY_BLOCK_BYTE_SIZE) {
                throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Ciphertext is too short.');
            }
            /**
             * @var string
             */
            $iv = Core::our_substr($message_ciphertext, 0, Core::LEGACY_BLOCK_BYTE_SIZE);
            Core::ensure_true(\is_string($iv));
            /**
             * @var string
             */
            $actual_ciphertext = Core::our_substr($message_ciphertext, Core::LEGACY_BLOCK_BYTE_SIZE);
            Core::ensure_true(\is_string($actual_ciphertext));
            // Do the decryption.
            $plaintext = self::plain_decrypt($actual_ciphertext, $ekey, $iv, Core::LEGACY_CIPHER_METHOD);
            return $plaintext;
        }
        throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Integrity check failed.');
    }
    /**
     * Encrypts a string with either a key or a password.
     *
     * @param string        $plaintext
     * @param bool          $raw_binary
     * @return string
     */
    private static function encrypt_internal($plaintext, Key_Or_Password $secret, $raw_binary)
    {
        Runtime_Tests::runtime_test();
        $salt = Core::secure_random(Core::SALT_BYTE_SIZE);
        $keys = $secret->derive_keys($salt);
        $ekey = $keys->get_encryption_key();
        $akey = $keys->get_authentication_key();
        $iv = Core::secure_random(Core::BLOCK_BYTE_SIZE);
        $ciphertext = Core::CURRENT_VERSION . $salt . $iv . self::plain_encrypt($plaintext, $ekey, $iv);
        $auth = \hash_hmac(Core::HASH_FUNCTION_NAME, $ciphertext, $akey, true);
        $ciphertext = $ciphertext . $auth;
        if ($raw_binary) {
            return $ciphertext;
        }
        return Encoding::bin_to_hex($ciphertext);
    }
    /**
     * Decrypts a ciphertext to a string with either a key or a password.
     *
     * @param string        $ciphertext
     * @param bool          $raw_binary
     *
     * @throws Ex\EnvironmentIsBrokenException
     * @throws Ex\WrongKeyOrModifiedCiphertextException
     * @return string
     */
    private static function decrypt_internal($ciphertext, Key_Or_Password $secret, $raw_binary)
    {
        Runtime_Tests::runtime_test();
        if (!$raw_binary) {
            try {
                $ciphertext = Encoding::hex_to_bin($ciphertext);
            } catch (Ex\Bad_Format_Exception $ex) {
                throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Ciphertext has invalid hex encoding.');
            }
        }
        if (Core::our_strlen($ciphertext) < Core::MINIMUM_CIPHERTEXT_SIZE) {
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Ciphertext is too short.');
        }
        // Get and check the version header.
        /** @var string $header */
        $header = Core::our_substr($ciphertext, 0, Core::HEADER_VERSION_SIZE);
        if ($header !== Core::CURRENT_VERSION) {
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Bad version header.');
        }
        // Get the salt.
        /** @var string $salt */
        $salt = Core::our_substr($ciphertext, Core::HEADER_VERSION_SIZE, Core::SALT_BYTE_SIZE);
        Core::ensure_true(\is_string($salt));
        // Get the IV.
        /** @var string $iv */
        $iv = Core::our_substr($ciphertext, Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE, Core::BLOCK_BYTE_SIZE);
        Core::ensure_true(\is_string($iv));
        // Get the HMAC.
        /** @var string $hmac */
        $hmac = Core::our_substr($ciphertext, Core::our_strlen($ciphertext) - Core::MAC_BYTE_SIZE, Core::MAC_BYTE_SIZE);
        Core::ensure_true(\is_string($hmac));
        // Get the actual encrypted ciphertext.
        /** @var string $encrypted */
        $encrypted = Core::our_substr($ciphertext, Core::HEADER_VERSION_SIZE + Core::SALT_BYTE_SIZE + Core::BLOCK_BYTE_SIZE, Core::our_strlen($ciphertext) - Core::MAC_BYTE_SIZE - Core::SALT_BYTE_SIZE - Core::BLOCK_BYTE_SIZE - Core::HEADER_VERSION_SIZE);
        Core::ensure_true(\is_string($encrypted));
        // Derive the separate encryption and authentication keys from the key
        // or password, whichever it is.
        $keys = $secret->derive_keys($salt);
        if (self::verify_hmac($hmac, $header . $salt . $iv . $encrypted, $keys->get_authentication_key())) {
            return self::plain_decrypt($encrypted, $keys->get_encryption_key(), $iv, Core::CIPHER_METHOD);
        }
        throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('Integrity check failed.');
    }
    /**
     * Raw unauthenticated encryption (insecure on its own).
     *
     * @param string $plaintext
     * @param string $key
     * @param string $iv
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return string
     */
    protected static function plain_encrypt(
        $plaintext,
        #[\Sensitive_Parameter]
        $key,
        #[\Sensitive_Parameter]
        $iv
    )
    {
        Core::ensure_constant_exists('OPENSSL_RAW_DATA');
        Core::ensure_function_exists('openssl_encrypt');
        /** @var string $ciphertext */
        $ciphertext = \openssl_encrypt($plaintext, Core::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);
        Core::ensure_true(\is_string($ciphertext), 'openssl_encrypt() failed');
        return $ciphertext;
    }
    /**
     * Raw unauthenticated decryption (insecure on its own).
     *
     * @param string $ciphertext
     * @param string $key
     * @param string $iv
     * @param string $cipherMethod
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return string
     */
    protected static function plain_decrypt(
        $ciphertext,
        #[\Sensitive_Parameter]
        $key,
        #[\Sensitive_Parameter]
        $iv,
        $cipher_method
    )
    {
        Core::ensure_constant_exists('OPENSSL_RAW_DATA');
        Core::ensure_function_exists('openssl_decrypt');
        /** @var string $plaintext */
        $plaintext = \openssl_decrypt($ciphertext, $cipher_method, $key, OPENSSL_RAW_DATA, $iv);
        Core::ensure_true(\is_string($plaintext), 'openssl_decrypt() failed.');
        return $plaintext;
    }
    /**
     * Verifies an HMAC without leaking information through side-channels.
     *
     * @param string $expected_hmac
     * @param string $message
     * @param string $key
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return bool
     */
    protected static function verify_hmac(
        $expected_hmac,
        $message,
        #[\Sensitive_Parameter]
        $key
    )
    {
        $message_hmac = \hash_hmac(Core::HASH_FUNCTION_NAME, $message, $key, true);
        return Core::hash_equals($message_hmac, $expected_hmac);
    }
}