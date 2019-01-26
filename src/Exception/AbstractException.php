<?php
/**
 * Created by PhpStorm.
 * User: bapat
 * Date: 1/26/2019
 * Time: 3:29 PM
 */

namespace PHPAS2\Exception;

/**
 * Class AbstractException
 * @package PHPAS2\Exception
 * @author   Brett P. <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class AbstractException extends \Exception
{
    const ERROR_AUTHENTICATION  = 1;
    const ERROR_DECOMPRESSION   = 2;
    const ERROR_DECRYPTION      = 3;
    const ERROR_LOW_SECURITY    = 4;
    const ERROR_INTEGRITY_CHECK = 5;
    const ERROR_UNEXPECTED      = 6;
    const ERROR_FORMAT          = 101;
    const ERROR_MIC_ALGORITHM   = 102;
    const ERROR_DUPLICATE       = 201;
    const ERROR_IDENTICAL       = 202;

    protected static $levelError = [
        self::ERROR_AUTHENTICATION  => 'authentication-failed',
        self::ERROR_DECOMPRESSION   => 'decompression-failed',
        self::ERROR_DECRYPTION      => 'decryption-failed',
        self::ERROR_LOW_SECURITY    => 'insufficient-message-security',
        self::ERROR_INTEGRITY_CHECK => 'integrity-check-failed',
        self::ERROR_UNEXPECTED      => 'unexpected-processing-error'
    ];

    protected static $levelFail = [
        self::ERROR_FORMAT        => 'unsupported format',
        self::ERROR_MIC_ALGORITHM => 'unsupported MIC-algorithm'
    ];

    protected static $levelWarn = [
        self::ERROR_DUPLICATE => 'duplicate-document',
        self::ERROR_IDENTICAL => 'sender-equals-receiver'
    ];

    public function getLevelText() {
        $returnVal = 'error';
        if (array_key_exists($this->code, self::$levelFail)) {
            $returnVal = 'failure';
        }
        else if (array_key_exists($this->code, self::$levelWarn)) {
            $returnVal = 'warning';
        }
        return $returnVal;
    }

    public function getMessageShort() {
        $messages = [
            self::ERROR_AUTHENTICATION  => 'authentication-failed',
            self::ERROR_DECOMPRESSION   => 'decompression-failed',
            self::ERROR_DECRYPTION      => 'decryption-failed',
            self::ERROR_LOW_SECURITY    => 'insufficient-message-security',
            self::ERROR_INTEGRITY_CHECK => 'integrity-check-failed',
            self::ERROR_UNEXPECTED      => 'unexpected-processing-error',
            self::ERROR_FORMAT          => 'unsupported format',
            self::ERROR_MIC_ALGORITHM   => 'unsupported MIC-algorithm',
            self::ERROR_DUPLICATE       => 'duplicate-document',
            self::ERROR_IDENTICAL       => 'sender-equals-receiver'
        ];
        $returnVal = $messages[self::ERROR_UNEXPECTED];
        if (array_key_exists($this->code, $messages)) {
            $returnVal = $messages[$this->code];
        }
        return $returnVal;
    }

    /**
     * Get a summary of the exception message.
     *
     * @param int $length Max length summary can be
     * @return string
     */
    public function getSummary($length=140) {
        return substr($this->getMessage(), 0, $length);
    }
}