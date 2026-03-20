<?php

declare (strict_types=1);
namespace Defuse\Crypto;

/**
 * Class DerivedKeys
 * @package Defuse\Crypto
 */
final class Derived_Keys
{
    /**
     * @var string
     */
    private $akey = '';
    /**
     * @var string
     */
    private $ekey = '';
    /**
     * Returns the authentication key (used for HMAC verification).
     *
     * @security Do not log or expose this value; it is derived key material.
     *
     * @return string The raw binary authentication sub-key (KEY_BYTE_SIZE bytes).
     */
    public function get_authentication_key(): string
    {
        return $this->akey;
    }
    /**
     * Returns the encryption key (used for AES-256-CTR encryption).
     *
     * @security Do not log or expose this value; it is derived key material.
     *
     * @return string The raw binary encryption sub-key (KEY_BYTE_SIZE bytes).
     */
    public function get_encryption_key(): string
    {
        return $this->ekey;
    }
    /**
     * Constructor for Derived_Keys.
     *
     * @param string $akey  Raw binary authentication sub-key (output of HKDF).
     * @param string $ekey  Raw binary encryption sub-key (output of HKDF).
     */
    public function __construct(
        #[\SensitiveParameter] string $akey,
        #[\SensitiveParameter] string $ekey
    )
    {
        $this->akey = $akey;
        $this->ekey = $ekey;
    }
}