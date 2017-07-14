<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2\Partner;

use PHPAS2\Exception\UnknownAuthenticationMethodException;

/**
 * Class Authentication
 *
 * @package  PHPAS2\Partner
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Authentication
{
    const METHOD_NONE   = 'none';
    const METHOD_AUTO   = CURLAUTH_ANY;
    const METHOD_BASIC  = CURLAUTH_BASIC;
    const METHOD_DIGEST = CURLAUTH_DIGEST;
    const METHOD_NTLM   = CURLAUTH_NTLM;
    const METHOD_GSS    = CURLAUTH_GSSNEGOTIATE;

    /** @var string Authentication method */
    protected $method = self::METHOD_NONE;
    /** @var  string|null Username to authenticate with */
    protected $username;
    /** @var  string|null Password for $username */
    protected $password;

    /**
     * Get authentication method
     *
     * @return string
     */
    public function getMethod() {
        return $this->method;
    }

    /**
     * Get authentication password
     *
     * @return null|string
     */
    public function getPassword() {
        return $this->password;
    }

    /**
     * Get authentication username
     *
     * @return null|string
     */
    public function getUsername() {
        return $this->username;
    }

    /**
     * Check whether or not authentication is configured
     *
     * @return bool If true, authentication is configured; otherwise, false
     */
    public function hasAuthentication() {
        return (boolean) ($this->method && $this->method !== self::METHOD_NONE);
    }

    /**
     * Set authentication method.  Checks that $method is a valid METHOD_* constant value before setting method.
     *
     * @param string|int $method Authentication method.  One of the self::METHOD_* constants
     *
     * @return $this
     * @throws UnknownAuthenticationMethodException
     */
    public function setMethod($method) {
        if (!$this->_isValidMethod($method)) {
            throw new UnknownAuthenticationMethodException(
                'Unknown authenticatoin method.  Please use one of the METHOD_* constants'
            );
        }

        $this->method = $method;
        return $this;
    }

    /**
     * Set password for authentication
     *
     * @param string $password The password
     *
     * @return $this
     */
    public function setPassword($password) {
        $this->password = $password;
        return $this;
    }

    /**
     * Set the username to authenticate with
     *
     * @param $username
     *
     * @return $this
     */
    public function setUsername($username) {
        $this->username = $username;
        return $this;
    }

    /**
     * Check method to make sure it matches one of the defined METHOD_* constants
     *
     * @param $method
     *
     * @return bool
     */
    protected function _isValidMethod($method) {
        $validMethod = false;
        $reflection = new \ReflectionClass(__CLASS__);
        foreach ($reflection->getConstants() as $constant => $value) {
            if (substr($constant, 0, 7) !== 'METHOD_') {
                continue;
            }

            if ($value == $method) {
                $validMethod = true;
                break;
            }
        }

        return $validMethod;
    }
}