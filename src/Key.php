<?php

declare (strict_types=1);
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
final class Key
{
    public const KEY_CURRENT_VERSION = "\xde\xf0\x00\x00";
    public const KEY_BYTE_SIZE = 32;
    /**
     * @var string
     */
    private $key_bytes;
    /**
     * Creates new random key.
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return Key
     */
    public static function create_new_random_key()
    {
        return new Key(Core::secure_random(self::KEY_BYTE_SIZE));
    }
    /**
     * Loads a Key from its encoded form.
     *
     * By default, this function will call Encoding::trimTrailingWhitespace()
     * to remove trailing CR, LF, NUL, TAB, and SPACE characters, which are
     * commonly appended to files when working with text editors.
     *
     * @param string $saved_key_string
     * @param bool $do_not_trim (default: false)
     *
     * @throws Ex\BadFormatException
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return Key
     */
    public static function load_from_ascii_safe_string(
        #[\Sensitive_Parameter]
        $saved_key_string,
        $do_not_trim = false
    )
    {
        if (!$do_not_trim) {
            $saved_key_string = Encoding::trim_trailing_whitespace($saved_key_string);
        }
        $key_bytes = Encoding::load_bytes_from_checksummed_ascii_safe_string(self::KEY_CURRENT_VERSION, $saved_key_string);
        return new Key($key_bytes);
    }
    /**
     * Encodes the Key into a string of printable ASCII characters.
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return string
     */
    public function save_to_ascii_safe_string()
    {
        return Encoding::save_bytes_to_checksummed_ascii_safe_string(self::KEY_CURRENT_VERSION, $this->key_bytes);
    }
    /**
     * Gets the raw bytes of the key.
     *
     * @return string
     */
    public function get_raw_bytes()
    {
        return $this->key_bytes;
    }
    /**
     * Constructs a new Key object from a string of raw bytes.
     *
     * @param string $bytes
     *
     * @throws Ex\EnvironmentIsBrokenException
     */
    private function __construct(
        #[\Sensitive_Parameter]
        $bytes
    )
    {
        Core::ensure_true(Core::our_strlen($bytes) === self::KEY_BYTE_SIZE, 'Bad key length.');
        $this->key_bytes = $bytes;
    }
}