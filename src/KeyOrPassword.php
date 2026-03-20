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
     * Initializes an instance of KeyOrPassword from a key.
     *
     *
     * @return KeyOrPassword
     */
    public static function create_from_key(Key $key)
    {
        return new Key_Or_Password(self::SECRET_TYPE_KEY, $key);
    }
    /**
     * Initializes an instance of KeyOrPassword from a password.
     *
     * @param string $password
     *
     * @return KeyOrPassword
     */
    public static function create_from_password(
        #[\Sensitive_Parameter]
        $password
    )
    {
        return new Key_Or_Password(self::SECRET_TYPE_PASSWORD, $password);
    }
    /**
     * Derives authentication and encryption keys from the secret, using a slow
     * key derivation function if the secret is a password.
     *
     * @param string $salt
     *
     * @throws Ex\CryptoException
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return DerivedKeys
     */
    public function derive_keys($salt)
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