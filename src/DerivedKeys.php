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
     * Returns the authentication key.
     * @return string
     */
    public function get_authentication_key()
    {
        return $this->akey;
    }
    /**
     * Returns the encryption key.
     * @return string
     */
    public function get_encryption_key()
    {
        return $this->ekey;
    }
    /**
     * Constructor for DerivedKeys.
     *
     * @param string $akey
     * @param string $ekey
     */
    public function __construct($akey, $ekey)
    {
        $this->akey = $akey;
        $this->ekey = $ekey;
    }
}