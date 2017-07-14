<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

/**
 * Class PostPackageInstall
 *
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class PostPackageInstall
{
    /**
     * Create logs directory to store AS2 logs.
     *
     * @param PackageEvent $event
     */
    public static function createLogsDir(PackageEvent $event) {
        $package = $event->getOperation()->getPackage();
        if ($package->getName() == 'phpas2/phpas2') {
            mkdir(realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_logs', 0777);
        }
    }

    /**
     * Create messages directory to store inbound/outbound messages.
     *
     * @param PackageEvent $event
     */
    public static function createMessageDirs(PackageEvent $event) {
        $package = $event->getOperation()->getPackage();
        if ($package->getName() == 'phpas2/phpas2') {
            mkdir(realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_private', 0777, true);
            mkdir(realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_messages', 0777, true);
        }
    }
}