<?php
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
final class Key_Protected_By_Password
{
    const PASSWORD_KEY_CURRENT_VERSION = "\xde\xf1\x00\x00";
    /**
     * @var string
     */
    private $encrypted_key = '';
    /**
     * Creates a random key protected by the provided password.
     *
     * @param string $password
     *
     * @throws Ex\Environment_Is_Broken_Exception
     *
     * @return Key_Protected_By_Password
     */
    public static function create_random_password_protected_key(
        #[\SensitiveParameter]
        $password
    )
    {
        $inner_key = Key::create_new_random_key();
        /* The password is hashed as a form of poor-man's domain separation
         * between this use of encrypt_with_password() and other uses of
         * encrypt_with_password() that the user may also be using as part of the
         * same protocol. */
        $encrypted_key = Crypto::encrypt_with_password($inner_key->save_to_ascii_safe_string(), \hash(Core::HASH_FUNCTION_NAME, $password, true), true);
        return new Key_Protected_By_Password($encrypted_key);
    }
    /**
     * Loads a Key_Protected_By_Password from its encoded form.
     *
     * @param string $saved_key_string
     *
     * @throws Ex\Bad_Format_Exception
     *
     * @return Key_Protected_By_Password
     */
    public static function load_from_ascii_safe_string(
        #[\SensitiveParameter]
        $saved_key_string
    )
    {
        $encrypted_key = Encoding::load_bytes_from_checksummed_ascii_safe_string(self::PASSWORD_KEY_CURRENT_VERSION, $saved_key_string);
        return new Key_Protected_By_Password($encrypted_key);
    }
    /**
     * Encodes the Key_Protected_By_Password into a string of printable ASCII
     * characters.
     *
     * @throws Ex\Environment_Is_Broken_Exception
     *
     * @return string
     */
    public function save_to_ascii_safe_string()
    {
        return Encoding::save_bytes_to_checksummed_ascii_safe_string(self::PASSWORD_KEY_CURRENT_VERSION, $this->encrypted_key);
    }
    /**
     * Decrypts the protected key, returning an unprotected Key object that can
     * be used for encryption and decryption.
     *
     * @throws Ex\Environment_Is_Broken_Exception
     * @throws Ex\Wrong_Key_Or_Modified_Ciphertext_Exception
     *
     * @param string $password
     * @return Key
     */
    public function unlock_key(
        #[\SensitiveParameter]
        $password
    )
    {
        try {
            $inner_key_encoded = Crypto::decrypt_with_password($this->encrypted_key, \hash(Core::HASH_FUNCTION_NAME, $password, true), true);
            return Key::load_from_ascii_safe_string($inner_key_encoded);
        } catch (Ex\Bad_Format_Exception $ex) {
            /* This should never happen unless an attacker replaced the
             * encrypted key ciphertext with some other ciphertext that was
             * encrypted with the same password. We transform the exception type
             * here in order to make the API simpler, avoiding the need to
             * document that this method might throw an Ex\Bad_Format_Exception. */
            throw new Ex\Wrong_Key_Or_Modified_Ciphertext_Exception('The decrypted key was found to be in an invalid format. ' . 'This very likely indicates it was modified by an attacker.');
        }
    }
    /**
     * Changes the password.
     *
     * @param string $current_password
     * @param string $new_password
     *
     * @throws Ex\Environment_Is_Broken_Exception
     * @throws Ex\Wrong_Key_Or_Modified_Ciphertext_Exception
     *
     * @return Key_Protected_By_Password
     */
    public function change_password(
        #[\SensitiveParameter]
        $current_password,
        #[\SensitiveParameter]
        $new_password
    )
    {
        $inner_key = $this->unlock_key($current_password);
        /* The password is hashed as a form of poor-man's domain separation
         * between this use of encrypt_with_password() and other uses of
         * encrypt_with_password() that the user may also be using as part of the
         * same protocol. */
        $encrypted_key = Crypto::encrypt_with_password($inner_key->save_to_ascii_safe_string(), \hash(Core::HASH_FUNCTION_NAME, $new_password, true), true);
        $this->encrypted_key = $encrypted_key;
        return $this;
    }
    /**
     * Constructor for Key_Protected_By_Password.
     *
     * @param string $encrypted_key
     */
    private function __construct($encrypted_key)
    {
        $this->encrypted_key = $encrypted_key;
    }
}