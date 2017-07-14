<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2\Exception;

/**
 * Class AbstractException
 *
 * @package  PHPAS2\Exception
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
abstract class AbstractException extends \Exception
{
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