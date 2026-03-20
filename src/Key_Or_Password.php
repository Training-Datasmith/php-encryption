<?php

declare (strict_types=1);
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
final class Key_Or_Password
{
    public const PBKDF2_ITERATIONS = 100000;
    public const SECRET_TYPE_KEY = 1;
    public const SECRET_TYPE_PASSWORD = 2;
    /**
     * @var int
     */
    private $secret_type = 0;
    /**
     * @var Key|string
     */
    private $secret;
    /**
     * Initializes an instance of Key_Or_Password from a Key object.
     *
     * @param Key $key  A Key loaded via Key::create_new_random_key() or Key::load_from_ascii_safe_string().
     *
     * @return self
     */
    public static function create_from_key(Key $key): self
    {
        return new Key_Or_Password(self::SECRET_TYPE_KEY, $key);
    }
    /**
     * Initializes an instance of Key_Or_Password from a password string.
     *
     * @param string $password  The human-chosen password; must be a non-empty string.
     *
     * @return self
     */
    public static function create_from_password(
        #[\Sensitive_Parameter]
        string $password
    ): self {
        return new Key_Or_Password(self::SECRET_TYPE_PASSWORD, $password);
    }
    /**
     * Derives authentication and encryption sub-keys from the secret.
     *
     * If the secret is a Key, HKDF-SHA256 is applied directly to the raw key bytes.
     * If the secret is a password, PBKDF2-SHA256 (100 000 iterations) is applied
     * first to produce a pseudo-random key, then HKDF derives the sub-keys.
     * The HKDF info strings ('DefusePHP|V2|KeyForEncryption' and
     * 'DefusePHP|V2|KeyForAuthentication') provide cryptographic domain separation.
     *
     * @security Both sub-keys are derived from the same root secret but using
     *           distinct HKDF info strings.  This is the standard RFC 5869 pattern
     *           for deriving multiple independent keys from one source.
     *
     * @param string $salt  A SALT_BYTE_SIZE (32) byte random salt, freshly generated
     *                      per encryption operation and stored in the ciphertext.
     *
     * @throws Ex\Crypto_Exception              if the salt has the wrong length
     * @throws Ex\Environment_Is_Broken_Exception if internal assertion fails
     *
     * @return Derived_Keys The two derived sub-keys.
     */
    public function derive_keys(string $salt): Derived_Keys
    {
        Core::ensure_true(Core::our_strlen($salt) === Core::SALT_BYTE_SIZE, 'Bad salt.');
        if ($this->secret_type === self::SECRET_TYPE_KEY) {
            Core::ensure_true($this->secret instanceof Key);
            /**
             * @psalm-suppress PossiblyInvalidMethodCall
             */
            $akey = Core::HKDF(Core::HASH_FUNCTION_NAME, $this->secret->get_raw_bytes(), Core::KEY_BYTE_SIZE, Core::AUTHENTICATION_INFO_STRING, $salt);
            /**
             * @psalm-suppress PossiblyInvalidMethodCall
             */
            $ekey = Core::HKDF(Core::HASH_FUNCTION_NAME, $this->secret->get_raw_bytes(), Core::KEY_BYTE_SIZE, Core::ENCRYPTION_INFO_STRING, $salt);
            return new Derived_Keys($akey, $ekey);
        }
        if ($this->secret_type === self::SECRET_TYPE_PASSWORD) {
            Core::ensure_true(\is_string($this->secret));
            /* Our PBKDF2 polyfill is vulnerable to a DoS attack documented in
             * GitHub issue #230. The fix is to pre-hash the password to ensure
             * it is short. We do the prehashing here instead of in pbkdf2() so
             * that pbkdf2() still computes the function as defined by the
             * standard. */
            /**
             * @psalm-suppress PossiblyInvalidArgument
             */
            $prehash = \hash(Core::HASH_FUNCTION_NAME, $this->secret, true);
            $prekey = Core::pbkdf2(Core::HASH_FUNCTION_NAME, $prehash, $salt, self::PBKDF2_ITERATIONS, Core::KEY_BYTE_SIZE, true);
            $akey = Core::HKDF(Core::HASH_FUNCTION_NAME, $prekey, Core::KEY_BYTE_SIZE, Core::AUTHENTICATION_INFO_STRING, $salt);
            /*
             * The same $salt and $prekey are reused here, but this is safe:
             * HKDF's info parameter ('encryption' vs 'authentication') provides
             * cryptographic domain separation between the two derived keys.
             * Per RFC 5869, deriving multiple keys from the same PRK using
             * distinct info strings is the standard and correct HKDF pattern.
             */
            $ekey = Core::HKDF(Core::HASH_FUNCTION_NAME, $prekey, Core::KEY_BYTE_SIZE, Core::ENCRYPTION_INFO_STRING, $salt);
            return new Derived_Keys($akey, $ekey);
        }
        throw new Ex\Environment_Is_Broken_Exception('Bad secret type.');
    }
    /**
     * Constructor for KeyOrPassword.
     *
     * @param int   $secret_type
     * @param mixed $secret      (either a Key or a password string)
     */
    private function __construct(
        $secret_type,
        #[\Sensitive_Parameter]
        $secret
    )
    {
        // The constructor is private, so these should never throw.
        if ($secret_type === self::SECRET_TYPE_KEY) {
            Core::ensure_true($secret instanceof Key);
        } elseif ($secret_type === self::SECRET_TYPE_PASSWORD) {
            Core::ensure_true(\is_string($secret));
        } else {
            throw new Ex\Environment_Is_Broken_Exception('Bad secret type.');
        }
        $this->secret_type = $secret_type;
        $this->secret = $secret;
    }
}