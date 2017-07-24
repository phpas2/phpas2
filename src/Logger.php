<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

/**
 * Class Logger
 *
 * @package PHPAS2
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Logger
{
    const LEVEL_DEBUG = 'debug';
    const LEVEL_INFO  = 'info';
    const LEVEL_WARN  = 'warn';
    const LEVEL_ERROR = 'error';
    const LEVEL_FATAL = 'fatal';

    protected $logFilePath;

    /**
     * Singleton pattern definition.
     *
     * @return Logger
     */
    final public static function getInstance() {
        static $instance = null;
        if ($instance === null) {
            $instance = new self();
        }

        return $instance;
    }

    /**
     * Get path to log files.
     *
     * @return string
     */
    public function getLogFilePath() {
        return $this->logFilePath;
    }

    /**
     * Write a message to the log.
     *
     * @param string $level One of the self::LEVEL_* constants.
     * @param string $message The message to be logged.
     * @param null|string $messageId The unique message ID (if any)
     * @return $this
     */
    public function log($level, $message, $messageId=null) {
        $line = '[' . date('Y-m-d H:i:s') . '] ';
        if ($messageId) {
            $line .= trim($messageId, '<>') . ' ';
        }
        $line .= '(' . strtoupper($level) . ') ' . $message . PHP_EOL;

        file_put_contents($this->getLogFilePath() . DIRECTORY_SEPARATOR . 'events.log', $line, FILE_APPEND);

        return $this;
    }

    /**
     * Specify the path to write log file(s) to.
     *
     * @param string $path
     * @return $this
     */
    public function setLogFilePath($path) {
        $this->logFilePath = realpath($path);
        return $this;
    }

    /**
     * Logger constructor
     *
     * Use Logger::getInstance() to get a new (or the current) instance of the logger class.
     */
    private function __construct() {
        $this->setLogFilePath(realpath(dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_logs') . DIRECTORY_SEPARATOR);
    }
}