<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2;

use PHPAS2\Exception\InvalidAdapterException;
use PHPAS2\Exception\InvalidEncodingException;
use PHPAS2\Exception\InvalidSignatureAlgorithmException;
use PHPAS2\Exception\Pkcs12BundleException;
use PHPAS2\Message\Adapter;
use PHPAS2\Partner\Authentication;

class Partner
{
    // Message encryption methods
    const CRYPT_NONE = 'none';
    const CRYPT_AES_128 = 'aes128';
    const CRYPT_AES_192 = 'aes192';
    const CRYPT_AES_256 = 'aes256';
    const CRYPT_DES = 'des';
    const CRYPT_3DES = 'des3';
    const CRYPT_RC2_40 = 'rc2-40';
    const CRYPT_RC2_64 = 'rc2-64';
    const CRYPT_RC2_128 = 'rc2-128';
    const CRYPT_RC4_40 = 'rc4-40';
    const CRYPT_RC4_64 = 'rc4-64';
    const CRYPT_RC4_128 = 'rc4-128';

    // Message encoding types
    const ENCODING_BINARY = 'binary';
    const ENCODING_BASE64 = 'base64';

    // MDN type
    const MDN_ASYNC = 'async';
    const MDN_SYNC = 'sync';

    // Message signature algorithms
    const SIGN_NONE = 'none';
    const SIGN_MD5 = 'md5';
    const SIGN_SHA1 = 'sha1';
    const SIGN_SHA256 = 'sha256';
    const SIGN_SHA384 = 'sha384';
    const SIGN_SHA512 = 'sha512';

    protected $adapter;
    /** @var  string */
    protected $comment;
    /** @var  string */
    protected $email;
    /** @var  string */
    protected $id;
    /** @var  boolean */
    protected $isLocal;
    /** @var  Partner\Authentication */
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
    protected $secPkcs12Contents = [];
    /** @var  string */
    protected $secPkcs12Password;
    /** @var  string */
    protected $secSignatureAlgorithm;
    /** @var  Partner\Authentication */
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
    public function __construct(array $data = [])
    {
        $this->setPartnerConfigsDir(
            realpath(dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'partners')
        );
        $this->loadFromArray($data);
    }

    /**
     * Retrieve array of available MDN request types
     *
     * @return array
     */
    public function getAvailableMDNRequestTypes()
    {
        return [
            self::MDN_ASYNC => 'Asynchronous',
            self::MDN_SYNC => 'Synchronous'
        ];
    }

    /**
     * Retrieve array of available encoding methods
     *
     * @return array
     */
    public function getAvailableEncodingMethods()
    {
        return [
            self::ENCODING_BASE64 => 'Base-64',
            self::ENCODING_BINARY => 'Binary'
        ];
    }

    /**
     * Retrieve array of available encryption algorithms
     *
     * @return array
     */
    public function getAvailableEncryptionAlgorithms()
    {
        return [
            self::CRYPT_NONE => 'None',
            self::CRYPT_AES_128 => 'AES_128',
            self::CRYPT_AES_192 => 'AES_192',
            self::CRYPT_AES_256 => 'AES_256',
            self::CRYPT_DES => 'DES',
            self::CRYPT_3DES => '3DES',
            self::CRYPT_RC2_40 => 'RC2_40',
            self::CRYPT_RC2_64 => 'RC2_64',
            self::CRYPT_RC2_128 => 'RC2_128',
            self::CRYPT_RC4_40 => 'RC4_40',
            self::CRYPT_RC4_64 => 'RC4_64',
            self::CRYPT_RC4_128 => 'RC4_128'
        ];
    }

    /**
     * Retrieve array of available signature algorithms
     *
     * @return array
     */
    public function getAvailableSignatureAlgorithms()
    {
        return [
            self::SIGN_NONE => 'none',
            self::SIGN_MD5 => 'MD5',
            self::SIGN_SHA1 => 'SHA1',
            self::SIGN_SHA256 => 'SHA256',
            self::SIGN_SHA384 => 'SHA384',
            self::SIGN_SHA512 => 'SHA512'
        ];
    }

    /**
     * Retrieve partner comment value
     *
     * @return string
     */
    public function getComment()
    {
        return $this->comment;
    }

    /**
     * Retrieve partner contact email
     *
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Retrieve CA Certificate Chain for packed PKCS12 certificate
     *
     * @return string|null Path to extra certificates
     */
    public function getExtraCerts()
    {
        try {
            return $this->getPkcs12Element('extracerts');
        } catch (Pkcs12BundleException $e) {
            return null;
        }
    }

    /**
     * Retrieve extra certificates contents and write them to a file
     *
     * TODO: Cache file path and only write when necessary
     *
     * @return string
     * @throws InvalidAdapterException
     */
    public function getExtraCertsFile()
    {
        $certs = $this->getExtraCerts();
        $fileContents = '';
        if ($certs) {
            $fileContents = implode("\n", $certs);
        }

        return $this->writeFile($this->getId() . '.ca-chain', $fileContents);
    }

    /**
     * Retrieve Partner ID
     *
     * @param bool $enclosedWithQuotes
     *
     * @return string
     */
    public function getId($enclosedWithQuotes = false)
    {
        return sprintf('%s%s%1$s', ($enclosedWithQuotes ? '"' : ''), $this->id);
    }

    /**
     * Retrieve whether this partner is local (on this server)
     *
     * @return bool
     */
    public function getIsLocal()
    {
        return (boolean)$this->isLocal;
    }

    /**
     * Retrieve MDN Authentication object
     *
     * @return Partner\Authentication
     */
    public function getMdnAuthentication()
    {
        return $this->mdnAuthentication;
    }

    /**
     * Retrieve MDN Request string
     *
     * @return string
     */
    public function getMdnRequest()
    {
        return $this->mdnRequest;
    }

    /**
     * Retrieve whether or not the MDN is to be signed or unsigned. True = Signed; False = Unsigned.
     *
     * @return bool
     */
    public function getMdnSigned()
    {
        return (boolean)$this->mdnSigned;
    }

    /**
     * Retrieve MDN subject
     *
     * @return string
     */
    public function getMdnSubject()
    {
        return $this->mdnSubject;
    }

    /**
     * Retrieve URL to post MDN to
     *
     * @return string
     */
    public function getMdnUrl()
    {
        return $this->mdnUrl;
    }

    /**
     * Retrieve path to where partner configurations are stored. If optional $partnerId argument is supplied, will
     * return path to that specific partner's configuration directory
     *
     * @param string|null $partnerId
     *
     * @return string
     */
    public function getPartnerConfigsDir($partnerId = null)
    {
        $returnValue = $this->partnerConfigDir;
        if ($partnerId !== null) {
            $returnValue .= $partnerId . DIRECTORY_SEPARATOR;
        }
        return $returnValue;
    }

    /**
     * Retrieve private key contents
     *
     * // TODO: Optimize to cache private key element and skip writing multiple times
     *
     * @return string|null
     * @throws Pkcs12BundleException
     */
    public function getPrivateKey()
    {
        return $this->getPkcs12Element('pkey');
    }

    /**
     * Retrieve stored private key file path
     *
     * @return string
     * @throws InvalidAdapterException
     * @throws Pkcs12BundleException
     */
    public function getPrivateKeyFile()
    {
        return $this->writeFile(
            $this->getId() . '.key',
            trim(file_get_contents($this->getPrivateKey()))
        );
    }

    public function getPublicCert()
    {
        return $this->getPkcs12Element('cert');
    }

    public function getPublicCertFile()
    {
        return $this->writeFile($this->getId() . '.cer', trim(file_get_contents($this->getPublicCert())));
    }

    public function getSecCertificate()
    {
        return $this->secCertificate;
    }

    public function getSecCertificateFile()
    {
        if (is_file($this->secCertificate)) {
            return $this->secCertificate;
        } else {
            $this->secCertificate = $this->writeFile($this->getId() . '.cer', $this->getSecCertificate());
            return $this->secCertificate;
        }
    }

    public function getSecEncryptionAlgorithm()
    {
        return $this->secEncryptionAlgorithm;
    }

    public function getSecPem()
    {
        return trim(file_get_contents($this->getPublicCertFile())) .
            PHP_EOL .
            trim(file_get_contents($this->getPrivateKeyFile()));
    }

    public function getSecPemFile()
    {
        return $this->writeFile($this->getId() . '.pem', $this->getSecPem());
    }

    public function getSecPkcs12()
    {
        return $this->secPkcs12;
    }

    public function getSecPkcs12Contents()
    {
        if (ctype_print($this->secPkcs12) && is_file($this->secPkcs12)) {
            return file_get_contents($this->secPkcs12);
        } else {
            return $this->secPkcs12;
        }
    }

    public function getSecPkcs12File()
    {
        if (ctype_print($this->getSecPkcs12()) && is_file($this->getSecPkcs12())) {
            return $this->getSecPkcs12();
        } else {
            $this->setSecPkcs12($this->writeFile($this->getId() . '.p12', $this->getSecPkcs12()));
            return $this->getSecPkcs12();
        }
    }

    public function getSecSignatureAlgorithm()
    {
        return $this->secSignatureAlgorithm;
    }

    public function getSendAuthentication()
    {
        return $this->sendAuthentication;
    }

    public function getSendCompress()
    {
        return (boolean)$this->sendCompress;
    }

    public function getSecPkcs12Password()
    {
        return $this->secPkcs12Password;
    }

    public function getSendContentType()
    {
        return $this->sendContentType;
    }

    public function getSendEncoding()
    {
        return $this->sendEncoding;
    }

    public function getSendSubject()
    {
        return $this->sendSubject;
    }

    public function getSendUrl()
    {
        return $this->sendUrl;
    }

    public function loadFromArray(array $data)
    {
        $baseConfig = [
            'comment' => '',
            'email' => '',
            'id' => '',
            'is_local' => false,
            'name' => '',
            'mdn_authentication' => new Authentication(),
            'mdn_request' => self::MDN_SYNC,
            'mdn_signed' => true,
            'mdn_subject' => 'AS2 MDN Subject',
            'mdn_url' => '',
            'sec_certificate' => '',
            'sec_encryption_algorithm' => self::CRYPT_3DES,
            'sec_pkcs12' => '',
            'sec_pkcs12_password' => '',
            'sec_signature_algorithm' => self::SIGN_SHA1,
            'send_authentication' => new Authentication(),
            'send_compress' => false,
            'send_content_type' => 'application/EDI-Consent',
            'send_encoding' => self::ENCODING_BASE64,
            'send_subject' => 'AS2 Message Subject',
            'send_url' => ''
        ];
        $data = array_merge($baseConfig, $data);
        foreach ($data as $key => $value) {
            /* Because PKCS12 bundle may have a password necessary for reading */
            if ($key == 'sec_pkcs12') {
                continue;
            }
            $methodName = 'set' . str_replace(
                    ' ',
                    '',
                    ucwords(str_replace('_', ' ', $key))
                );
            $this->$methodName($value);
        }
        $this->setSecPkcs12($data['sec_pkcs12']);
        return $this;
    }

    public function loadFromConfig($partnerID)
    {
        $partnerConfig = $this->getPartnerConfigsDir($partnerID) . 'config.php';
        $data = include($partnerConfig);
        $this->loadFromArray($data);
        return $this;
    }

    /**
     * Set the message adapter for this partner.
     *
     * @param Message\Adapter $adapter
     *
     * @return $this
     */
    public function setAdapter(Message\Adapter $adapter)
    {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * Set the comment/notes about this partner.
     *
     * @param string $comment
     *
     * @return $this
     */
    public function setComment($comment = '')
    {
        $this->comment = $comment;
        return $this;
    }

    /**
     * Set partner email address.
     *
     * @param string $email
     *
     * @return $this
     */
    public function setEmail($email)
    {
        $this->email = $email;
        return $this;
    }

    /**
     * Set partner ID. Optionally enclose with quotes.
     *
     * @param string $id
     *
     * @return $this
     */
    public function setId($id)
    {
        $this->id = $id;
        return $this;
    }

    /**
     * Set whether this partner is hosted by this server (true), or a remote server (false).
     *
     * @param boolean $isLocal
     *
     * @return $this
     */
    public function setIsLocal($isLocal)
    {
        $this->isLocal = (boolean)$isLocal;
        return $this;
    }

    /**
     * Set the Authentication object for MDN endpoint
     *
     * @param Authentication $authentication
     *
     * @return $this
     */
    public function setMdnAuthentication(Authentication $authentication)
    {
        $this->mdnAuthentication = $authentication;
        return $this;
    }

    /**
     * Set MDN request type.
     *
     * @param string $type
     *
     * @return $this
     */
    public function setMdnRequest($type)
    {
        $this->mdnRequest = $type;
        return $this;
    }

    /**
     * Set whether the MDN is to be signed.
     *
     * @param boolean $signed
     *
     * @return $this
     */
    public function setMdnSigned($signed)
    {
        $this->mdnSigned = (boolean)$signed;
        return $this;
    }

    /**
     * Set subject of MDN message.
     *
     * @param string $subject
     *
     * @return $this
     */
    public function setMdnSubject($subject)
    {
        $this->mdnSubject = $subject;
        return $this;
    }

    /**
     * Set endpoint to send MDN to.
     *
     * @param string $url
     *
     * @return $this
     */
    public function setMdnUrl($url)
    {
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
    public function setName($name)
    {
        $this->name = $name;
        return $this;
    }

    /**
     * Set the base64 encoded security certificate.
     *
     * @param string $certificate Base64 encoded certificate
     *
     * @return $this
     * @throws InvalidX509CertificateException
     */
    public function setSecCertificate($certificate)
    {
        if (is_file($certificate)) {
            $this->secCertificate = $certificate;
        } else {
            if (mb_strlen(trim($certificate)) > 0) {
                $certInfo = openssl_x509_parse($certificate);
                if (!is_array($certInfo)) {
                    throw new InvalidX509CertificateException(
                        'Security certificate was not able to be parsed as x509 certificate'
                    );
                }
                unset ($certInfo);
                $this->secCertificate = $certificate;
            } else {
                $this->secCertificate = null;
            }
        }
        return $this;
    }

    /**
     * Set security encryption algorithm.
     *
     * @param string $algorithm
     *
     * @return $this
     * @throws InvalidEncryptionAlgorithmException
     */
    public function setSecEncryptionAlgorithm($algorithm)
    {
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
     *
     * @return $this
     * @throws Pkcs12BundleException
     */
    public function setSecPkcs12($pkcs12)
    {
        $this->secPkcs12Contents = [];
        if (is_file($pkcs12)) {
            $this->secPkcs12 = $pkcs12;
            $result = openssl_pkcs12_read(
                $this->getSecPkcs12Contents(),
                $this->secPkcs12Contents,
                $this->getSecPkcs12Password()
            );
            if ($result === false) {
                throw new Pkcs12BundleException(sprintf('Unable to read data from PKCS12 bundle "%s"', $pkcs12));
            }
        } else {
            if (strlen(trim($pkcs12))) {
                $valid = openssl_pkcs12_read($pkcs12, $this->secPkcs12Contents, $this->getSecPkcs12Password());
                if (!$valid) {
                    throw new Pkcs12BundleException('Unable to verify PKCS12 bundle');
                }
                unset($bundle, $valid);
                $this->secPkcs12 = $this->writeFile($this->getId() . '.p12', $pkcs12);
            } else {
                $this->secPkcs12 = null;
            }
        }
        return $this;
    }

    /**
     * Get the password for the PKCS12 bundle.
     *
     * @param string $password
     *
     * @return $this
     */
    public function setSecPkcs12Password($password)
    {
        $this->secPkcs12Password = $password;
        return $this;
    }

    /**
     * Get message signature algorithm.
     *
     * @param string $algorithm
     *
     * @return $this
     * @throws InvalidSignatureAlgorithmException
     */
    public function setSecSignatureAlgorithm($algorithm)
    {
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
     *
     * @return $this
     */
    public function setSendAuthentication(Authentication $authentication)
    {
        $this->sendAuthentication = $authentication;
        return $this;
    }

    /**
     * Set flag to compress the data or not.
     *
     * @param boolean $compress
     *
     * @return $this
     */
    public function setSendCompress($compress)
    {
        $this->sendCompress = $compress;
        return $this;
    }

    /**
     * Set content-type of message.
     *
     * @param string $contentType
     *
     * @return $this
     */
    public function setSendContentType($contentType)
    {
        $this->sendContentType = $contentType;
        return $this;
    }

    /**
     * Set encoding of message.
     *
     * @param string $encoding
     *
     * @return $this
     * @throws InvalidEncodingException
     */
    public function setSendEncoding($encoding)
    {
        if (!in_array($encoding, array_keys($this->getAvailableEncodingMethods()))) {
            throw new InvalidEncodingException(
                sprintf('Unsupported encoding "%s"', $encoding),
                InvalidEncodingException::ERROR_FORMAT
            );
        }
        $this->sendEncoding = $encoding;
        return $this;
    }

    /**
     * Set subject of message.
     *
     * @param string $subject
     *
     * @return $this
     */
    public function setSendSubject($subject)
    {
        $this->sendSubject = $subject;
        return $this;
    }

    /**
     * Set the endpoint for message delivery.
     *
     * @param string $url
     *
     * @return $this
     */
    public function setSendUrl($url)
    {
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
    public function setPartnerConfigsDir($path)
    {
        $this->partnerConfigDir = realpath($path) . DIRECTORY_SEPARATOR;
        return $this;
    }

    /**
     * Get a specific element from PKCS12 bundle
     *
     * @param $key
     *
     * @return mixed
     * @throws Pkcs12BundleException
     */
    protected function getPkcs12Element($key)
    {
        if (empty($this->secPkcs12Contents)) {
            $secPkcs12Contents = [];
            $result = openssl_pkcs12_read($this->getSecPkcs12(), $secPkcs12Contents, $this->getSecPkcs12Password());
            if ($result) {
                $this->secPkcs12Contents = $secPkcs12Contents;
            } else {
                throw new Pkcs12BundleException('Unable to read PKCS12 bundle');
            }
        }
        if (!array_key_exists($key, $this->secPkcs12Contents)) {
            throw new Pkcs12BundleException(sprintf('Unable to locate "%s" within PKCS12 bundle', $key));
        }
        $destinationFile = $this->adapter->getTempFilename();
        file_put_contents($destinationFile, $this->secPkcs12Contents[$key]);
        return $destinationFile;
    }

    /**
     * Write file using current storage adapter
     *
     * @param string $filename
     * @param string $contents
     *
     * @return string
     * @throws InvalidAdapterException
     */
    protected function writeFile($filename, $contents = '')
    {
        if (!($this->adapter instanceof Adapter)) {
            throw new InvalidAdapterException('No adapter set, or adapter is not a \PHPAS2\Message\Adapter');
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
            file_put_contents($filePath, $contents);
        }
        return $filePath;
    }
}