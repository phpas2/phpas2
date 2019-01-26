<?php
/**
 * Created by PhpStorm.
 * User: bapat
 * Date: 1/25/2019
 * Time: 10:55 PM
 */

namespace PHPAS2\Api;

interface PartnerInterface
{


    /**
     * Sets the path to "known" partner configurations.
     *
     * @param string $path Absolute path to directory containing partner configurations
     * @return null
     */
    public function setPartnerConfigsDirectory($path);
}