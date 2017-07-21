<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

use PHPAS2\Exception\InvalidEncodingException;
use PHPAS2\Exception\InvalidEncryptionAlgorithmException;
use PHPAS2\Exception\InvalidSignatureAlgorithmException;
use PHPAS2\Exception\InvalidX509CertificateException;
use PHPAS2\Exception\Pkcs12BundleException;
use PHPAS2\Message\Adapter;
use PHPAS2\Partner\Authentication;

/**
 * Class Partner
 *
 * @package  PHPAS2
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Partner
{
    // Message encryption methods
    const CRYPT_NONE    = 'none';
    const CRYPT_AES_128 = 'aes128';
    const CRYPT_AES_192 = 'aes192';
    const CRYPT_AES_256 = 'aes256';
    const CRYPT_DES     = 'des';
    const CRYPT_3DES    = 'des3';
    const CRYPT_RC2_40  = 'rc2-40';
    const CRYPT_RC2_64  = 'rc2-64';
    const CRYPT_RC2_128 = 'rc2-128';
    const CRYPT_RC4_40  = 'rc4-40';
    const CRYPT_RC4_64  = 'rc4-64';
    const CRYPT_RC4_128 = 'rc4-128';

    // Message encoding types
    const ENCODING_BINARY = 'binary';
    const ENCODING_BASE64 = 'base64';

    // MDN type
    const MDN_ASYNC = 'async';
    const MDN_SYNC  = 'sync';

    // Message signature algorithms
    const SIGN_NONE   = 'none';
    const SIGN_MD5    = 'md5';
    const SIGN_SHA1   = 'sha1';
    // TODO: Verify implemntation of sha256 and up in JAR file
    const SIGN_SHA256 = 'sha256';
    const SIGN_SHA384 = 'sha384';
    const SIGN_SHA512 = 'sha512';

    /** @var  Message\Adapter */
    protected $adapter;
    /** @var  string */
    protected $comment;
    /** @var  string */
    protected $email;
    /** @var  string */
    protected $id;
    /** @var  boolean */
    protected $isLocal;
    /** @var  Authentication */
    protected $mdnAuthentication;
    /** @var  string */
    protected $mdnRequest;
    /** @var  boolean */
    protected $mdnSigned;
    /** @var  string */
    protected $mdnSubject;
    /** @var  string */
    protected $mdnUrl;
    /** @var  string */
    protected $name;
    /** @var string Path to folder containing partner configuration folders */
    protected $partnerConfigDir;
    /** @var  string */
    protected $secCertificate;
    /** @var  string */
    protected $secEncryptionAlgorithm;
    /** @var  string */
    protected $secPkcs12;
    /** @var  array */
    protected $secPkcs12Contents;
    /** @var  string */
    protected $secPkcs12Password;
    /** @var  string */
    protected $secSignatureAlgorithm;
    /** @var  Authentication */
    protected $sendAuthentication;
    /** @var  boolean */
    protected $sendCompress;
    /** @var  string */
    protected $sendContentType;
    /** @var  string */
    protected $sendEncoding;
    /** @var  string */
    protected $sendSubject;
    /** @var  string */
    protected $sendUrl;

    /**
     * Partner constructor.
     *
     * @param array $data
     */
    public function __construct(array $data=[]) {
        $this->setPartnerConfigsDir(realpath(dirname(dirname(__FILE__))) . DIRECTORY_SEPARATOR . 'partners');
        $this->loadFromArray($data);
    }

    /**
     * Get list of available MDN request types
     *
     * @return array
     */
    public function getAvailableMDNRequestTypes() {
        return [
            self::MDN_ASYNC => 'Asynchronous',
            self::MDN_SYNC  => 'Synchronous'
        ];
    }

    /**
     * Get list of available encoding methods
     *
     * @return array
     */
    public function getAvailableEncodingMethods() {
        return [
            self::ENCODING_BINARY => 'Binary',
            self::ENCODING_BASE64 => 'Base64'
        ];
    }

    /**
     * Get list of available encryption algorithms
     *
     * @return array
     */
    public function getAvailableEncryptionAlgorithms() {
        return [
            self::CRYPT_NONE    => 'None',
            self::CRYPT_AES_128 => 'AES_128',
            self::CRYPT_AES_192 => 'AES_192',
            self::CRYPT_AES_256 => 'AES_256',
            self::CRYPT_DES     => 'DES',
            self::CRYPT_3DES    => '3DES',
            self::CRYPT_RC2_40  => 'RC2_40',
            self::CRYPT_RC2_64  => 'RC2_64',
            self::CRYPT_RC2_128 => 'RC2_128',
            self::CRYPT_RC4_40  => 'RC4_40',
            self::CRYPT_RC4_64  => 'RC4_64',
            self::CRYPT_RC4_128 => 'RC4_128'
        ];
    }

    /**
     * Get list of available signature algorithms
     *
     * @return array
     */
    public function getAvailableSignatureAlgorithms() {
        return [
            self::SIGN_NONE   => 'none',
            self::SIGN_MD5    => 'MD5',
            self::SIGN_SHA1   => 'SHA1',
            self::SIGN_SHA256 => 'SHA256',
            self::SIGN_SHA384 => 'SHA384',
            self::SIGN_SHA512 => 'SHA512'
        ];
    }

    /**
     * Get Certificate Authority cert chain from PKCS12 bundle.
     *
     * @return string
     */
    public function getCA() {
        return $this->_getPkcs12Element('extracerts');
    }

    /**
     * Get comment/notes about partner.
     *
     * @return string
     */
    public function getComment() {
        return $this->comment;
    }

    /**
     * Get partner email address.
     *
     * @return string
     */
    public function getEmail() {
        return $this->email;
    }

    /**
     * Get partner ID. Optionally enclose with quotes.
     *
     * @param bool $enclosedWithQuotes Whether to enclose the ID within double-quotes. Default: false.
     * @return string
     */
    public function getId($enclosedWithQuotes=false) {
        return sprintf('%s%s%1$s', ($enclosedWithQuotes ? '"' : ''), $this->id);
    }

    /**
     * Get whether this partner is hosted by this server (true), or a remote server (false). Default: false;
     *
     * @return bool
     */
    public function getIsLocal() {
        return (boolean) $this->isLocal;
    }

    /**
     * Get the Authentication object for MDN endpoint
     *
     * @return Authentication
     */
    public function getMdnAuthentication() {
        return $this->mdnAuthentication;
    }

    /**
     * Get MDN request type.
     *
     * @return string
     */
    public function getMdnRequest() {
        return $this->mdnRequest;
    }

    /**
     * Get whether the MDN is to be signed.
     *
     * @return bool
     */
    public function getMdnSigned() {
        return (boolean) $this->mdnSigned;
    }

    /**
     * Get subject of MDN message.
     *
     * @return string
     */
    public function getMdnSubject() {
        return $this->mdnSubject;
    }

    /**
     * Get endpoint to send MDN to.
     *
     * @return string
     */
    public function getMdnUrl() {
        return $this->mdnUrl;
    }

    /**
     * Get path to directory containing partner configurations.
     *
     * @return string
     */
    public function getPartnerConfigsDir() {
        return $this->partnerConfigDir . DIRECTORY_SEPARATOR;
    }

    /**
     * Get private key from PKCS12 bundle.
     *
     * @return string
     */
    public function getPrivateKey() {
        return $this->_getPkcs12Element('pkey');
    }

    /**
     * Get the path to the private key file from PKCS12 bundle.
     *
     * @return string
     */
    public function getPrivateKeyFile() {
        return $this->_writeFile($this->getId() . '.key', file_get_contents($this->getPrivateKey()));
    }

    /**
     * Get public certificate from PKCS12 bundle.
     *
     * @return string
     */
    public function getPublicCert() {
        return $this->_getPkcs12Element('cert');
    }

    /**
     * Get the path to the public key file from PKCS12 bundle.
     *
     * @return mixed
     */
    public function getPublicCertFile() {
        return $this->_writeFile($this->getId() . '.pub', file_get_contents($this->getPublicCert()));
    }

    /**
     * Get the base64 encoded security certificate.
     *
     * @return string
     */
    public function getSecCertificate() {
        return $this->secCertificate;
    }

    /**
     * Get path to the security certificate file from the PKCS12 bundle.
     *
     * @return string
     */
    public function getSecCertificateFile() {
        if (is_file($this->secCertificate)) {
            return $this->secCertificate;
        }
        else {
            return $this->_writeFile($this->getId() . '.cer', $this->getSecCertificate());
        }
    }

    /**
     * Get security encryption algorithm.
     *
     * @return string
     */
    public function getSecEncryptionAlgorithm() {
        return $this->secEncryptionAlgorithm;
    }

    /**
     * Get PKCS12 bundle.
     *
     * @return string
     */
    public function getSecPkcs12() {
        return $this->secPkcs12;
    }

    /**
     * Get path to PKCS12 bundle file.
     *
     * @return string
     */
    public function getSecPkcs12File() {
        if (is_file($this->getSecPkcs12())) {
            return $this->getSecPkcs12();
        }
        else {
            return $this->_writeFile($this->getId() . '.p12', $this->getSecPkcs12());
        }
    }

    /**
     * Get the password for the PKCS12 bundle.
     *
     * @return string
     */
    public function getSecPkcs12Password() {
        return $this->secPkcs12Password;
    }

    /**
     * Get message signature algorithm.
     *
     * @return string
     */
    public function getSecSignatureAlgorithm() {
        return $this->secSignatureAlgorithm;
    }

    /**
     * Get the authentication object for message destination.
     *
     * @return Authentication
     */
    public function getSendAuthentication() {
        return $this->sendAuthentication;
    }

    /**
     * Get flag to compress the data or not.
     *
     * @return bool
     */
    public function getSendCompress() {
        return (boolean) $this->sendCompress;
    }

    /**
     * Get content-type of message.
     *
     * @return string
     */
    public function getSendContentType() {
        return $this->sendContentType;
    }

    /**
     * Get encoding of message.
     *
     * @return string
     */
    public function getSendEncoding() {
        return $this->sendEncoding;
    }

    /**
     * Get subject of message.
     *
     * @return string
     */
    public function getSendSubject() {
        return $this->sendSubject;
    }

    /**
     * Get the endpoint for message delivery.
     *
     * @return string
     */
    public function getSendUrl() {
        return $this->sendUrl;
    }

    /**
     * Load configuration parameters from an array of data
     *
     * @param array $data Array of data:
     * <pre>
     *   - comment: (string) Description / comment about this Partner.
     *   - email: (string) Email address for partner contact.
     *   - id: (string) AS2 partner identifier.
     *   - is_local: (boolean) If true, this partner is served from this server; if false, this partner is external
     *               to this server. Default: false.
     *   - name: (string) Friendly name of the partner.
     *   - mdn_authentication (Authentication) HTTP/s authentication parameters (method, username, password). Default:
     *                        Empty \PHPAS2\Partner\Authentication object with no authentication.
     *   - mdn_request (string) Type of MDN expected (synchronous or asynchronous). Use self::MDN_* constants.
     *                 Default: MDN_SYNC
     *   - mdn_signed (boolean) Whether or not MDNs are expected to be signed.
     *   - mdn_subject (string) Subject for MDNs. Default: "AS2 MDN Subject"
     *   - mdn_url (string) URL to send MDNs to (typically the same as send_url).
     *   - sec_certificate (string) Path to base64 encoded certificate used for encryption.
     *   - sec_encryption_algorithm (string) Encryption algorithm to use when encrypting the message. Use self::CRYPT_*
     *                              constants. Default: CRYPT_3DES.
     *   - sec_pkcs12 (string) Path to PKCS12 bundle used for message encryption.
     *   - sec_pkcs12_password (string) Password to open PKCS12 bundle and retrieve private key.
     *   - sec_signature_algorithm (string) Message signature algorithm. Use self::SIGN_* constants. Default: SIGN_SHA1.
     *   - send_authentication (Authentication) HTTP/s authentication parameters (method, username, password). Default:
     *                         Empty \PHPAS2\Partner\Authentication object with no authentication.
     *   - send_compress (boolean) Whether to compress messages. Default: false.
     *   - send_content_type (string) Content type message. Default: 'application/EDI-Consent'.
     *   - send_encoding (string) Encoding method used for message. Use self::ENCODING_* constants.
     *                   Default: ENCODING_BASE64
     *   - send_subject (string) Subject of AS2 message. Default: 'AS2 Message Subject'.
     *   - send_url (string) Destination URL to deliver AS2 messages to.
     * </pre>
     * @return $this
     */
    public function loadFromArray(array $data) {
        $baseConfig = [
            'comment'                  => '',
            'email'                    => '',
            'id'                       => '',
            'is_local'                 => false,
            'name'                     => '',
            'mdn_authentication'       => new Authentication(),
            'mdn_request'              => self::MDN_SYNC,
            'mdn_signed'               => true,
            'mdn_subject'              => 'AS2 MDN Subject',
            'mdn_url'                  => '',
            'sec_certificate'          => '',
            'sec_encryption_algorithm' => self::CRYPT_3DES,
            'sec_pkcs12'               => '',
            'sec_pkcs12_password'      => '',
            'sec_signature_algorithm'  => self::SIGN_SHA1,
            'send_authentication'      => new Authentication(),
            'send_compress'            => false,
            'send_content_type'        => 'application/EDI-Consent',
            'send_encoding'            => self::ENCODING_BASE64,
            'send_subject'             => 'AS2 Message Subject',
            'send_url'                 => ''
        ];

        $data = array_merge($baseConfig, $data);

        foreach ($data as $key => $value) {
            $methodName = 'set' . str_replace(
                ' ',
                '',
                ucwords(str_replace('_', ' ', $key))
            );

            $this->$methodName($value);
        }

        return $this;
    }

    /**
     * Load configuration parameters from
     *
     * @param string $partnerID The Partner ID to load
     *
     * @return $this
     */
    public function loadFromConfig($partnerID) {
        $data = include($this->partnerConfigDir . $partnerID . DIRECTORY_SEPARATOR . 'config.php');

        $this->loadFromArray($data);
        return $this;
    }

    /**
     * Set the message adapter for this partner.
     *
     * @param Message\Adapter $adapter
     * @return $this
     */
    public function setAdapter(Message\Adapter $adapter) {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * Set the comment/notes about this partner.
     *
     * @param string $comment
     * @return $this
     */
    public function setComment($comment='') {
        $this->comment = $comment;
        return $this;
    }

    /**
     * Set partner email address.
     *
     * @param string $email
     * @return $this
     */
    public function setEmail($email) {
        $this->email = $email;
        return $this;
    }

    /**
     * Set partner ID. Optionally enclose with quotes.
     *
     * @param string $id
     * @return $this
     */
    public function setId($id) {
        $this->id = $id;
        return $this;
    }

    /**
     * Set whether this partner is hosted by this server (true), or a remote server (false).
     *
     * @param boolean $isLocal
     * @return $this
     */
    public function setIsLocal($isLocal) {
        $this->isLocal = (boolean) $isLocal;
        return $this;
    }

    /**
     * Set the Authentication object for MDN endpoint
     *
     * @param Authentication $authentication
     * @return $this
     */
    public function setMdnAuthentication(Authentication $authentication) {
        $this->mdnAuthentication = $authentication;
        return $this;
    }

    /**
     * Set MDN request type.
     *
     * @param string $type
     * @return $this
     */
    public function setMdnRequest($type) {
        $this->mdnRequest = $type;
        return $this;
    }

    /**
     * Set whether the MDN is to be signed.
     *
     * @param boolean $signed
     * @return $this
     */
    public function setMdnSigned($signed) {
        $this->mdnSigned = (boolean) $signed;
        return $this;
    }

    /**
     * Set subject of MDN message.
     *
     * @param string $subject
     * @return $this
     */
    public function setMdnSubject($subject) {
        $this->mdnSubject = $subject;
        return $this;
    }

    /**
     * Set endpoint to send MDN to.
     *
     * @param string $url
     * @return $this
     */
    public function setMdnUrl($url) {
        $this->mdnUrl = $url;
        return $this;
    }

    /**
     * Set the friendly name of the partner.
     *
     * @param string $name
     *
     * @return $this
     */
    public function setName($name) {
        $this->name = $name;
        return $this;
    }

    /**
     * Set the base64 encoded security certificate.
     *
     * @param string $certificate Base64 encoded certificate
     * @return $this
     * @throws InvalidX509CertificateException
     */
    public function setSecCertificate($certificate) {
        if (is_file($certificate)) {
            $this->secCertificate = $certificate;
        }
        else if (mb_strlen(trim($certificate)) > 0) {
            $certInfo = openssl_x509_parse($certificate);
            if (!is_array($certInfo)) {
                throw new InvalidX509CertificateException(
                    'Security certificate was not able to be parsed as x509 certificate'
                );
            }

            unset ($certInfo);

            $this->secCertificate = $certificate;
        }
        else {
            $this->secCertificate = null;
        }

        return $this;
    }

    /**
     * Set security encryption algorithm.
     *
     * @param string $algorithm
     * @return $this
     * @throws InvalidEncryptionAlgorithmException
     */
    public function setSecEncryptionAlgorithm($algorithm) {
        if (!in_array($algorithm, array_keys($this->getAvailableEncryptionAlgorithms()))) {
            throw new InvalidEncryptionAlgorithmException(
                sprintf('Unknown encryption algorithm "%s".', $algorithm)
            );
        }
        $this->secEncryptionAlgorithm = $algorithm;
        return $this;
    }

    /**
     * Set PKCS12 bundle.
     *
     * @param string $pkcs12
     * @return $this
     * @throws Pkcs12BundleException
     */
    public function setSecPkcs12($pkcs12) {
        if (is_file($pkcs12)) {
            $this->secPkcs12 = $pkcs12;
        }
        else if (strlen(trim($pkcs12))) {
            $bundle = [];
            $valid = openssl_pkcs12_read($pkcs12, $bundle, $this->getSecPkcs12Password());
            if (!$valid) {
                throw new Pkcs12BundleException('Unable to verify PKCS12 bundle');
            }
            unset($bundle, $valid);
            $this->secPkcs12 = $pkcs12;
        }
        else {
            $this->secPkcs12 = null;
        }

        return $this;
    }

    /**
     * Get the password for the PKCS12 bundle.
     *
     * @param string $password
     * @return $this
     */
    public function setSecPkcs12Password($password) {
        $this->secPkcs12Password = $password;
        return $this;
    }

    /**
     * Get message signature algorithm.
     *
     * @param string $algorithm
     * @return $this
     * @throws InvalidSignatureAlgorithmException
     */
    public function setSecSignatureAlgorithm($algorithm) {
        if (!in_array($algorithm, array_keys($this->getAvailableSignatureAlgorithms()))) {
            throw new InvalidSignatureAlgorithmException(
                sprintf('Unknown signature algorithm "%s".', $algorithm)
            );
        }
        $this->secSignatureAlgorithm = $algorithm;
        return $this;
    }

    /**
     * Set the authentication object for message destination.
     *
     * @param Authentication $authentication
     * @return $this
     */
    public function setSendAuthentication(Authentication $authentication) {
        $this->sendAuthentication = $authentication;
        return $this;
    }

    /**
     * Set flag to compress the data or not.
     *
     * @param boolean $compress
     * @return $this
     */
    public function setSendCompress($compress) {
        $this->sendCompress = $compress;
        return $this;
    }

    /**
     * Set content-type of message.
     *
     * @param string $contentType
     * @return $this
     */
    public function setSendContentType($contentType) {
        $this->sendContentType = $contentType;
        return $this;
    }

    /**
     * Set encoding of message.
     *
     * @param string $encoding
     * @return $this
     * @throws InvalidEncodingException
     */
    public function setSendEncoding($encoding) {
        if (!in_array($encoding, array_keys($this->getAvailableEncodingMethods()))) {
            throw new InvalidEncodingException(sprintf('Unsupported encoding "%s"', $encoding));
        }
        $this->sendEncoding = $encoding;
        return $this;
    }

    /**
     * Set subject of message.
     *
     * @param string $subject
     * @return $this
     */
    public function setSendSubject($subject) {
        $this->sendSubject = $subject;
        return $this;
    }

    /**
     * Set the endpoint for message delivery.
     *
     * @param string $url
     * @return $this
     */
    public function setSendUrl($url) {
        $this->sendUrl = $url;
        return $this;
    }

    /**
     * Set the directory containing partner configuration directories
     *
     * @param string $path Path on filesystem to directory containing partner directories
     *
     * @return $this
     */
    public function setPartnerConfigsDir($path) {
        $this->partnerConfigDir = realpath($path) . DIRECTORY_SEPARATOR;
        return $this;
    }

    /**
     * Extract PKCS12 element from bundle
     *
     * @param string $key The element to extract from the PKCS12 bundle
     *
     * @return string Path to extract contents file
     * @throws Pkcs12BundleException
     */
    protected function _getPkcs12Element($key) {
        if (!$this->secPkcs12Contents) {
            $this->secPkcs12Contents = [];
            openssl_pkcs12_read($this->getSecPkcs12(), $this->getSecPkcas12Password());
        }

        if (!array_key_exists($key, $this->secPkcs12Contents)) {
            throw new Pkcs12BundleException(sprintf('Unable to locate "%s" within PKCS12 bundle', $key));
        }

        $destinationFile = $this->adapter->getTempFilename();
        file_put_contents($this->secPkcs12Contents[$key]);

        return $destinationFile;
    }

    /**
     * Write a file to the private directory
     *
     * @param string $filename Filename to store contents as
     * @param string $contents File contents to be written
     * @return string Path to written file
     */
    protected function _writeFile($filename, $contents) {
        if (!($this->adapter instanceof Adapter)) {
            throw new InvalidAdapterException('No adapter set, or adapter is not a PHPAS2\Message\Adapter');
        }

        $filePath = $this->adapter->getPrivateDir() . $filename;

        $writeNewFile = true;
        if (file_exists($filePath)) {
            $existing = file_get_contents($filePath);
            if ($existing == $contents) {
                $writeNewFile = false;
            }
        }

        if ($writeNewFile) {
            $fp = fopen($filePath, 'w+b');
            file_put_contents($fp, $contents);
            @fclose($fp);
        }

        return $filePath;
    }
}