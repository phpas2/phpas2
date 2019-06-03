<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

require_once(realpath(dirname(dirname(dirname(dirname(dirname(__FILE__))))) . DIRECTORY_SEPARATOR . 'autoload.php'));

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
    'sec_certificate'          => realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'key4.cer',
    'sec_encryption_algorithm' => Partner::CRYPT_3DES,
    'sec_pkcs12'               => null,
    'sec_pkcs12_password'      => null,
    'sec_signature_algorithm'  => Partner::SIGN_SHA1,
    'send_authentication'      => new Partner\Authentication(),
    'send_compress'            => false,
    'send_content_type'        => 'application/EDI-Consent',
    'send_encoding'            => Partner::ENCODING_BASE64,
    'send_subject'             => 'AS2 Message Subject',
    'send_url'                 => 'http://testas2.mendelson-e-c.com:8080/as2/HttpReceiver'
];