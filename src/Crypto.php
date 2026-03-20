<?php

declare (strict_types=1);
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
class Crypto
{
    /**
     * Encrypts a string with a Key.
     *
     * Produces an authenticated ciphertext using AES-256-CTR for encryption
     * and HMAC-SHA256 for integrity (Encrypt-then-MAC).  A fresh random salt
     * and IV are generated on every call, so encrypting the same plaintext
     * twice with the same key produces different ciphertexts.
     *
     * @security Uses HKDF to derive independent encryption and authentication
     *           sub-keys from the root Key, preventing key-reuse vulnerabilities.
     *           The HMAC covers VERSION || SALT || IV || CIPHERTEXT so any
     *           tampering is detected before decryption begins.
     *
     * @param string $plaintext  The plaintext string to encrypt; may be empty.
     * @param Key    $key        A Key object created by Key::create_new_random_key()
     *                           or loaded from storage via Key::load_from_ascii_safe_string().
     * @param bool   $raw_binary When true, returns raw binary ciphertext; otherwise
     *                           returns a hex-encoded string safe for text storage.
     *
     * @throws Ex\EnvironmentIsBrokenException if the runtime crypto environment is broken
     * @throws \TypeError if $plaintext is not a string, $key is not a Key, or $raw_binary is not a bool
     *
     * @return string Authenticated ciphertext (hex-encoded unless $raw_binary is true).
     *
     * @since 2.0.0
     * @see self::decrypt()
     * @see Key::create_new_random_key()
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
     * Internally derives a Key from the password using PBKDF2-SHA256 with a
     * random 32-byte salt, then delegates to the standard encrypt path.
     *
     * @security The password is annotated with #[SensitiveParameter] so it is
     *           redacted from PHP stack traces.  PBKDF2 iteration count is chosen
     *           to impose computational cost on brute-force attempts; prefer
     *           key-based encryption for high-value secrets.
     *
     * @param string $plaintext  The plaintext string to encrypt.
     * @param string $password   A secret password used to derive the encryption key.
     *                           Must be non-empty; longer and more random is better.
     * @param bool   $raw_binary When true, returns raw binary ciphertext.
     *
     * @throws Ex\EnvironmentIsBrokenException if the runtime crypto environment is broken
     * @throws \TypeError if any argument has the wrong type
     *
     * @return string Authenticated ciphertext (hex-encoded unless $raw_binary is true).
     *
     * @since 2.0.0
     * @see self::decrypt_with_password()
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
     * Verifies the HMAC-SHA256 authentication tag before performing any
     * decryption.  If the tag does not match — due to a wrong key, truncation,
     * or any modification of the ciphertext — a
     * Wrong_Key_Or_Modified_Ciphertext_Exception is thrown and no decryption
     * output is produced.
     *
     * @security HMAC verification uses Core::hash_equals() for constant-time
     *           comparison, preventing timing side-channel leakage of the correct
     *           HMAC value.  Decrypt-after-verify (Encrypt-then-MAC) prevents
     *           chosen-ciphertext attacks such as padding oracles.
     *
     * @param string $ciphertext  The authenticated ciphertext produced by encrypt().
     * @param Key    $key         The same Key used to encrypt the ciphertext.
     * @param bool   $raw_binary  Must match the $raw_binary flag used during encryption.
     *
     * @throws \TypeError                                      if argument types are wrong
     * @throws Ex\EnvironmentIsBrokenException                 if the runtime environment is broken
     * @throws Ex\Wrong_Key_Or_Modified_Ciphertext_Exception   if the key is wrong or the
     *                                                         ciphertext has been altered
     *
     * @return string The original plaintext.
     *
     * @since 2.0.0
     * @see self::encrypt()
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
     * Derives the same Key that was produced during encryption from the password
     * and the random salt embedded in the ciphertext, then verifies the HMAC
     * before decrypting.
     *
     * @security The password is annotated with #[SensitiveParameter].  A wrong
     *           password and a tampered ciphertext both throw the same exception
     *           with an identical message to prevent oracle attacks.
     *
     * @param string $ciphertext  The authenticated ciphertext produced by encrypt_with_password().
     * @param string $password    The same password used to encrypt the ciphertext.
     * @param bool   $raw_binary  Must match the $raw_binary flag used during encryption.
     *
     * @throws Ex\EnvironmentIsBrokenException                 if the runtime environment is broken
     * @throws Ex\Wrong_Key_Or_Modified_Ciphertext_Exception   if the password is wrong or
     *                                                         the ciphertext has been altered
     * @throws \TypeError if argument types are wrong
     *
     * @return string The original plaintext.
     *
     * @since 2.0.0
     * @see self::encrypt_with_password()
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
     * Supports the V1 format: HMAC (32 bytes) || IV (16 bytes) || CIPHERTEXT.
     * V1 used AES-128-CBC rather than AES-256-CTR.  New code should not produce
     * V1 ciphertexts; this method exists solely for migration purposes.
     *
     * @deprecated since 2.0.0 — Migrate V1 ciphertexts by decrypting with
     *             legacy_decrypt() and re-encrypting with encrypt().  This method
     *             will be removed in a future major version.
     *
     * @security The raw key argument is a plain string (V1 did not use the
     *           Key class).  The #[SensitiveParameter] attribute ensures it is
     *           redacted from stack traces.  The HMAC is verified before decryption
     *           to prevent chosen-ciphertext attacks even against the legacy format.
     *
     * @param string $ciphertext  A ciphertext produced by the version 1 library.
     * @param string $key         The raw binary key string used with the V1 library.
     *
     * @throws Ex\EnvironmentIsBrokenException                if the runtime environment is broken
     * @throws Ex\Wrong_Key_Or_Modified_Ciphertext_Exception  if the key is wrong or the
     *                                                        ciphertext has been altered
     * @throws \TypeError if argument types are wrong
     *
     * @return string The original plaintext.
     *
     * @since 1.0.0
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
        trigger_error(
            'Crypto::legacy_decrypt() is deprecated since 2.0.0. Decrypt V1 ciphertexts and re-encrypt with Crypto::encrypt().',
            \E_USER_DEPRECATED
        );
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