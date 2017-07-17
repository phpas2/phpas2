<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

require_once(realpath(dirname(dirname(dirname(__FILE__)))) . DIRECTORY_SEPARATOR . 'vendor/autoload.php');

use PHPAS2\Partner;

return [
    'id'                       => 'mendelsontestAS2',
    'email'                    => '',
    'comment'                  => 'Test AS2 endpoint powered by Mendelson AS2 Software',
    'is_local'                 => false,
    'name'                     => 'Mendelson Test AS2',
    'mdn_authentication'       => new Partner\Authentication(),
    'mdn_request'              => Partner::MDN_SYNC,
    'mdn_signed'               => true,
    'mdn_subject'              => 'AS2 MDN Subject',
    'mdn_url'                  => 'http://testas2.mendelson-e-c.com:8080/as2/HttpReceiver',
    'sec_certificate'          => 'security-certificate.cer',
    'sec_encryption_algorithm' => Partner::CRYPT_3DES,
    'sec_pkcs12'               => null,
    'sec_pkcs12_password'      => null,
    'sec_signature_algorithm'  => Partner::SIGN_SHA1,
    'send_authentication'      => new Partner\Authentication(),
    'send_compress'            => false,
    'send_content_type'        => 'application/EDI-Consent',
    'send_encoding'            => Partner::ENCODING_BASE64,
    'send_url'                 => 'http://testas2.mendelson-e-c.com:8080/as2/HttpReceiver'
];