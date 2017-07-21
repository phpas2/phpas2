<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

require_once(dirname(dirname(dirname(dirname(dirname(__FILE__))))) . DIRECTORY_SEPARATOR . 'autoload.php');

use PHPAS2\Partner;

return [
    'id'                       => 'mycompanyAS2',
    'email'                    => '',
    'comment'                  => 'Test AS2 sender for Mendelson Test AS2 Server',
    'is_local'                 => true,
    'name'                     => 'My Company AS2',
    'mdn_authentication'       => new Partner\Authentication(),
    'mdn_request'              => Partner::MDN_SYNC,
    'mdn_signed'               => true,
    'mdn_subject'              => 'AS2 MDN Subject',
    'mdn_url'                  => 'http://phpas2.pattebre.mssit.net/server.php',
    'sec_certificate'          => null,
    'sec_encryption_algorithm' => Partner::CRYPT_3DES,
    'sec_pkcs12'               => realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'key1.pfx',
    'sec_pkcs12_password'      => 'test',
    'sec_signature_algorithm'  => Partner::SIGN_SHA1,
    'send_authentication'      => new Partner\Authentication(),
    'send_compress'            => false,
    'send_content_type'        => 'application/EDI-Consent',
    'send_encoding'            => Partner::ENCODING_BASE64,
    'send_subject'             => 'AS2 Message Subject',
    'send_url'                 => 'http://phpas2.pattebre.mssit.net/server.php'
];