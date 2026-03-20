<?php

declare (strict_types=1);
namespace Defuse\Crypto;

use Defuse\Crypto\Exception as Ex;
final class Core
{
    public const HEADER_VERSION_SIZE = 4;
    public const MINIMUM_CIPHERTEXT_SIZE = 84;
    public const CURRENT_VERSION = "\xde\xf5\x02\x00";
    public const CIPHER_METHOD = 'aes-256-ctr';
    public const BLOCK_BYTE_SIZE = 16;
    public const KEY_BYTE_SIZE = 32;
    public const SALT_BYTE_SIZE = 32;
    public const MAC_BYTE_SIZE = 32;
    public const HASH_FUNCTION_NAME = 'sha256';
    public const ENCRYPTION_INFO_STRING = 'DefusePHP|V2|KeyForEncryption';
    public const AUTHENTICATION_INFO_STRING = 'DefusePHP|V2|KeyForAuthentication';
    public const BUFFER_BYTE_SIZE = 1048576;
    public const LEGACY_CIPHER_METHOD = 'aes-128-cbc';
    public const LEGACY_BLOCK_BYTE_SIZE = 16;
    public const LEGACY_KEY_BYTE_SIZE = 16;
    public const LEGACY_HASH_FUNCTION_NAME = 'sha256';
    public const LEGACY_MAC_BYTE_SIZE = 32;
    public const LEGACY_ENCRYPTION_INFO_STRING = 'DefusePHP|KeyForEncryption';
    public const LEGACY_AUTHENTICATION_INFO_STRING = 'DefusePHP|KeyForAuthentication';
    /*
     * V2.0 Format: VERSION (4 bytes) || SALT (32 bytes) || IV (16 bytes) ||
     *              CIPHERTEXT (varies) || HMAC (32 bytes)
     *
     * V1.0 Format: HMAC (32 bytes) || IV (16 bytes) || CIPHERTEXT (varies).
     */
    /**
     * Adds an integer to a block-sized counter.
     *
     * Used to advance a CTR-mode nonce by $inc blocks without external BigInt
     * dependencies.  Arithmetic is performed byte-by-byte in big-endian order,
     * matching OpenSSL's CTR mode nonce increment order.
     *
     * @complexity O(BLOCK_BYTE_SIZE) = O(16) — constant time in practice.
     *
     * @security The counter must never wrap around to a previously used value
     *           for the same key.  Callers must ensure $inc > 0 and that the
     *           total increment does not overflow the 128-bit counter space.
     *
     * @param string $ctr  A BLOCK_BYTE_SIZE (16) byte counter string (big-endian).
     * @param int    $inc  The positive integer amount to add to the counter.
     *                     Must be > 0 and ≤ PHP_INT_MAX - 255.
     *
     * @throws Ex\EnvironmentIsBrokenException if $ctr has wrong length, $inc is non-positive,
     *                                         or integer overflow would occur
     *
     * @return string The incremented counter as a BLOCK_BYTE_SIZE byte string.
     *
     * @psalm-suppress RedundantCondition - It's valid to use is_int to check for overflow.
     */
    public static function increment_counter($ctr, $inc)
    {
        Core::ensure_true(Core::our_strlen($ctr) === Core::BLOCK_BYTE_SIZE, 'Trying to increment a nonce of the wrong size.');
        Core::ensure_true(\is_int($inc), 'Trying to increment nonce by a non-integer.');
        // The caller is probably re-using CTR-mode keystream if they increment by 0.
        Core::ensure_true($inc > 0, 'Trying to increment a nonce by a nonpositive amount');
        Core::ensure_true($inc <= PHP_INT_MAX - 255, 'Integer overflow may occur');
        /*
         * We start at the rightmost byte (big-endian)
         * So, too, does OpenSSL: http://stackoverflow.com/a/3146214/2224584
         */
        for ($i = Core::BLOCK_BYTE_SIZE - 1; $i >= 0; --$i) {
            $sum = \ord($ctr[$i]) + $inc;
            /* Detect integer overflow and fail. */
            Core::ensure_true(\is_int($sum), 'Integer overflow in CTR mode nonce increment');
            $ctr[$i] = \pack('C', $sum & 0xff);
            $inc = $sum >> 8;
        }
        return $ctr;
    }
    /**
     * Returns a cryptographically secure random byte string of the specified length.
     *
     * Delegates to PHP's random_bytes() which sources entropy from the OS
     * CSPRNG (e.g., /dev/urandom on Linux, CryptGenRandom on Windows).
     *
     * @security This function MUST NOT be replaced with a userland PRNG (mt_rand,
     *           array_rand, etc.).  Doing so would produce predictable IVs, salts,
     *           and keys, completely breaking the security of all derived material.
     *
     * @param int $octets  The number of random bytes to return; must be > 0.
     *
     * @throws Ex\Crypto_Exception               if $octets ≤ 0
     * @throws Ex\Environment_Is_Broken_Exception if the OS CSPRNG is unavailable
     *
     * @return string A string of $octets random bytes.
     */
    public static function secure_random($octets)
    {
        if ($octets <= 0) {
            throw new Ex\Crypto_Exception('A zero or negative amount of random bytes was requested.');
        }
        self::ensure_function_exists('random_bytes');
        try {
            return \random_bytes(max(1, $octets));
        } catch (\Exception $ex) {
            throw new Ex\Environment_Is_Broken_Exception('Your system does not have a secure random number generator.');
        }
    }
    /**
     * Computes the HKDF key derivation function specified in RFC 5869.
     *
     * Uses the native hash_hkdf() when available (PHP 7.1.2+) and falls back
     * to a pure-PHP implementation using HMAC-Hash.
     *
     * @complexity O(ceil(length / digest_length)) HMAC invocations — constant for
     *             fixed length values; typically 1–2 calls for KEY_BYTE_SIZE output.
     *
     * @security HKDF is a two-step function: Extract produces a pseudorandom key
     *           (PRK) from the IKM and salt, then Expand derives output keying
     *           material.  The info parameter provides domain separation — always
     *           pass distinct info strings when deriving multiple keys from the
     *           same IKM to prevent key-reuse attacks.
     *
     * @param string      $hash    Hash algorithm name (e.g., 'sha256').
     * @param string      $ikm     Initial keying material (the root secret).
     * @param int         $length  Desired output length in bytes (1 – 255 × digest_length).
     * @param string      $info    Context-specific info string for domain separation.
     * @param string|null $salt    Optional salt; if null, defaults to a string of zero bytes.
     *
     * @throws Ex\Environment_Is_Broken_Exception if $length is out of range or the
     *                                             output length does not match
     *
     * @psalm-suppress UndefinedFunction - We're checking if the function exists first.
     *
     * @return string $length bytes of output keying material.
     */
    public static function HKDF($hash, $ikm, $length, $info = '', $salt = null)
    {
        static $native_hkdf = null;
        if ($native_hkdf === null) {
            $native_hkdf = \is_callable('\hash_hkdf');
        }
        if ($native_hkdf) {
            if (\is_null($salt)) {
                $salt = '';
            }
            return \hash_hkdf($hash, $ikm, $length, $info, $salt);
        }
        $digest_length = Core::our_strlen(\hash_hmac($hash, '', '', true));
        // Sanity-check the desired output length.
        Core::ensure_true(!empty($length) && \is_int($length) && $length >= 0 && $length <= 255 * $digest_length, 'Bad output length requested of HDKF.');
        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (\is_null($salt)) {
            $salt = \str_repeat("\x00", $digest_length);
        }
        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = \hash_hmac($hash, $ikm, $salt, true);
        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        Core::ensure_true(Core::our_strlen($prk) >= $digest_length);
        // T(0) = ''
        $t = '';
        $last_block = '';
        for ($block_index = 1; Core::our_strlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = \hash_hmac($hash, $last_block . $info . \chr($block_index), $prk, true);
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }
        // ORM = first L octets of T
        /** @var string $orm */
        $orm = Core::our_substr($t, 0, $length);
        Core::ensure_true(\is_string($orm));
        Core::ensure_true(Core::our_strlen($orm) === $length, 'HKDF output length mismatch.');
        return $orm;
    }
    /**
     * Checks if two equal-length strings are the same without leaking
     * information through side channels.
     *
     * When the native hash_equals() is available it is used directly.
     * Otherwise both strings are HMACed with a random blinding key and the
     * HMACs are compared with '===', making timing attacks infeasible even
     * in interpreted PHP.
     *
     * @security Both strings MUST have the same byte length before calling
     *           this function.  Variable-length comparison is not covered by
     *           this implementation; an EnvironmentIsBrokenException is thrown
     *           if the lengths differ.  This function prevents the HMAC timing
     *           side channel described in CVE-2013-4294 and similar advisories.
     *
     * @param string $expected  The expected (correct) value, e.g. a computed HMAC.
     * @param string $given     The value supplied by the caller to compare against.
     *
     * @throws Ex\Environment_Is_Broken_Exception if the two strings have different lengths
     *
     * @return bool True if and only if the strings are identical.
     */
    public static function hash_equals($expected, $given)
    {
        static $native = null;
        if ($native === null) {
            $native = \function_exists('hash_equals');
        }
        if ($native) {
            return \hash_equals($expected, $given);
        }
        // We can't just compare the strings with '==', since it would make
        // timing attacks possible. We could use the XOR-OR constant-time
        // comparison algorithm, but that may not be a reliable defense in an
        // interpreted language. So we use the approach of HMACing both strings
        // with a random key and comparing the HMACs.
        // We're not attempting to make variable-length string comparison
        // secure, as that's very difficult. Make sure the strings are the same
        // length.
        Core::ensure_true(Core::our_strlen($expected) === Core::our_strlen($given));
        $blind = Core::secure_random(32);
        $message_compare = \hash_hmac(Core::HASH_FUNCTION_NAME, $given, $blind);
        $correct_compare = \hash_hmac(Core::HASH_FUNCTION_NAME, $expected, $blind);
        return $correct_compare === $message_compare;
    }
    /**
     * Throws an exception if the constant doesn't exist.
     *
     * @param string $name
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     */
    public static function ensure_constant_exists($name)
    {
        Core::ensure_true(\defined($name), 'Constant ' . $name . ' does not exists');
    }
    /**
     * Throws an exception if the function doesn't exist.
     *
     * @param string $name
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     */
    public static function ensure_function_exists($name)
    {
        Core::ensure_true(\function_exists($name), 'function ' . $name . ' does not exists');
    }
    /**
     * Throws an exception if the condition is false.
     *
     * @param bool $condition
     * @param string $message
     * @return void
     *
     * @throws Ex\EnvironmentIsBrokenException
     */
    public static function ensure_true($condition, $message = '')
    {
        if (!$condition) {
            throw new Ex\Environment_Is_Broken_Exception($message);
        }
    }
    /*
     * We need these strlen() and substr() functions because when
     * 'mbstring.func_overload' is set in php.ini, the standard strlen() and
     * substr() are replaced by mb_strlen() and mb_substr().
     */
    /**
     * Computes the length of a string in bytes.
     *
     * @param string $str
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return int
     */
    public static function our_strlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \extension_loaded('mbstring') && \function_exists('mb_strlen');
        }
        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            Core::ensure_true($length !== false);
            return $length;
        }
        return \strlen($str);
    }
    /**
     * Behaves roughly like the function substr() in PHP 7 does.
     *
     * @param string $str
     * @param int    $start
     * @param int    $length
     *
     * @throws Ex\EnvironmentIsBrokenException
     *
     * @return string|bool
     */
    public static function our_substr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \extension_loaded('mbstring') && \function_exists('mb_substr');
        }
        // This is required to make mb_substr behavior identical to substr.
        // Without this, mb_substr() would return false, contra to what the
        // PHP documentation says (it doesn't say it can return false.)
        $input_len = Core::our_strlen($str);
        if ($start === $input_len && !$length) {
            return '';
        }
        if ($start > $input_len) {
            return false;
        }
        // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP 5.3,
        // so we have to find the length ourselves. Also, substr() doesn't
        // accept null for the length.
        if (!isset($length)) {
            if ($start >= 0) {
                $length = $input_len - $start;
            } else {
                $length = -$start;
            }
        }
        if ($length < 0) {
            throw new \InvalidArgumentException('Negative lengths are not supported with ourSubstr.');
        }
        if ($exists) {
            $substr = \mb_substr($str, $start, $length, '8bit');
            // At this point there are two cases where mb_substr can
            // legitimately return an empty string. Either $length is 0, or
            // $start is equal to the length of the string (both mb_substr and
            // substr return an empty string when this happens). It should never
            // ever return a string that's longer than $length.
            if (Core::our_strlen($substr) > $length || Core::our_strlen($substr) === 0 && $length !== 0 && $start !== $input_len) {
                throw new Ex\Environment_Is_Broken_Exception('Your version of PHP has bug #66797. Its implementation of
                    mb_substr() is incorrect. See the details here:
                    https://bugs.php.net/bug.php?id=66797');
            }
            return $substr;
        }
        return \substr($str, $start, $length);
    }
    /**
     * Computes the PBKDF2 password-based key derivation function (RFC 2898).
     *
     * Uses the native hash_pbkdf2() when available (PHP 5.5+) and falls back to
     * a pure-PHP HMAC-based implementation.  The algorithm is whitelisted to
     * secure cryptographic hash functions; CRC32 and other non-cryptographic
     * functions are rejected.
     *
     * @complexity O(count * key_length / digest_length) HMAC invocations.
     *             With count = 100 000 and sha256, this is ~100 000 HMAC calls.
     *             This is intentionally expensive to slow brute-force attacks.
     *
     * @security The password is pre-hashed before being passed to PBKDF2 to
     *           defend against the DoS attack described in GitHub issue #230
     *           (passwords longer than the HMAC block size cause extra iterations).
     *           The iteration count PBKDF2_ITERATIONS = 100 000 follows NIST SP
     *           800-132 recommendations; do not reduce it.
     *
     * @param string $algorithm  Hash algorithm name; must be in the approved list (e.g., 'sha256').
     * @param string $password   The password (or pre-hashed password) to derive from.
     * @param string $salt       A random, per-password salt (at least 8 bytes recommended by RFC 2898).
     * @param int    $count      Iteration count; must be > 0.  Higher = slower brute-force.
     * @param int    $key_length Desired output key length in bytes.
     * @param bool   $raw_output When true, returns raw binary; otherwise returns hex string.
     *
     * @throws Ex\Environment_Is_Broken_Exception if the algorithm is not approved or parameters are invalid
     *
     * @return string A derived key of $key_length bytes.
     *
     * @see https://tools.ietf.org/html/rfc2898
     */
    public static function pbkdf2(
        $algorithm,
        #[\Sensitive_Parameter]
        $password,
        $salt,
        $count,
        $key_length,
        $raw_output = false
    )
    {
        // Type checks:
        if (!\is_string($algorithm)) {
            throw new \InvalidArgumentException('pbkdf2(): algorithm must be a string');
        }
        if (!\is_string($password)) {
            throw new \InvalidArgumentException('pbkdf2(): password must be a string');
        }
        if (!\is_string($salt)) {
            throw new \InvalidArgumentException('pbkdf2(): salt must be a string');
        }
        // Coerce strings to integers with no information loss or overflow
        $count += 0;
        $key_length += 0;
        $algorithm = \strtolower($algorithm);
        Core::ensure_true(\in_array($algorithm, \hash_algos(), true), 'Invalid or unsupported hash algorithm.');
        // Whitelist, or we could end up with people using CRC32.
        $ok_algorithms = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160', 'ripemd256', 'ripemd320', 'whirlpool'];
        Core::ensure_true(\in_array($algorithm, $ok_algorithms, true), 'Algorithm is not a secure cryptographic hash function.');
        Core::ensure_true($count > 0 && $key_length > 0, 'Invalid PBKDF2 parameters.');
        if (\function_exists('hash_pbkdf2')) {
            // The output length is in NIBBLES (4-bits) if $raw_output is false!
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return \hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }
        $hash_length = Core::our_strlen(\hash($algorithm, '', true));
        $block_count = \ceil($key_length / $hash_length);
        $output = '';
        for ($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . \pack('N', $i);
            // first iteration
            $last = $xorsum = \hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                /**
                 * @psalm-suppress InvalidOperand
                 */
                $xorsum ^= $last = \hash_hmac($algorithm, $last, $password, true);
            }
            $output .= $xorsum;
        }
        if ($raw_output) {
            return (string) Core::our_substr($output, 0, $key_length);
        }
        return Encoding::bin_to_hex((string) Core::our_substr($output, 0, $key_length));
    }
}