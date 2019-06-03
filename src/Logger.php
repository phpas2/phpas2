<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2;

use Monolog\Handler\StreamHandler;
use PHPAS2\Logger\Monolog;
use Psr\Log\LoggerInterface;

class Logger
{
    /**
     * Detailed debug information
     */
    const DEBUG = 100;

    /**
     * Interesting events
     *
     * Examples: User logs in, SQL logs.
     */
    const INFO = 200;

    /**
     * Uncommon events
     */
    const NOTICE = 250;

    /**
     * Exceptional occurrences that are not errors
     *
     * Examples: Use of deprecated APIs, poor use of an API,
     * undesirable things that are not necessarily wrong.
     */
    const WARNING = 300;

    /**
     * Runtime errors
     */
    const ERROR = 400;

    /**
     * Critical conditions
     *
     * Example: Application component unavailable, unexpected exception.
     */
    const CRITICAL = 500;

    /**
     * Action must be taken immediately
     *
     * Example: Entire website down, database unavailable, etc.
     * This should trigger the SMS alerts and wake you up.
     */
    const ALERT = 550;

    /**
     * Urgent alert.
     */
    const EMERGENCY = 600;

    protected $logFileDirPath;

    final public static function getInstance($config=[])
    {
        static $instance = null;

        if ($instance === null) {
            if (array_key_exists('logger', $config) && $config['logger'] instanceof LoggerInterface) {
                $instance = new $config['logger']('phpas2');
            } else {
                $instance = new Monolog('phpas2');
                $instance->pushHandler(
                    new StreamHandler(
                        self::getLogFileDirPath() . 'phpas2.log'
                    )
                );
            }
        }

        return $instance;
    }

    final public static function getLogFileDirPath()
    {
        static $logPath = null;

        if ($logPath === null) {
            $logPath = realpath(dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'logs') . DIRECTORY_SEPARATOR;
        }

        return $logPath;
    }
}