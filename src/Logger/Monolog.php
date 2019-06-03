<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2\Logger;

use Monolog\Logger;

class Monolog extends Logger
{
    public function alert($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::alert($message, $context);
    }

    public function crit($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::crit($message, $context);
    }

    public function critical($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::critical($message, $context);
    }

    public function debug($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::debug($message, $context);
    }

    public function emerg($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::emerg($message, $context);
    }

    public function emergency($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::emergency($message, $context);
    }

    public function err($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::err($message, $context);
    }

    public function error($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::error($message, $context);
    }

    public function info($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::info($message, $context);
    }

    public function log($level, $message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::log($level, $message, $context);
    }

    public function notice($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::notice($message, $context);
    }

    public function warn($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::warn($message, $context);
    }

    public function warning($message, array $context = [], $messageId=null)
    {
        if ($messageId) {
            $message = substr(sha1(trim($messageId, '<>')), -8) . ' ' . $message;
        }

        return parent::warning($message, $context);
    }
}