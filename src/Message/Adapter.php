<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2\Message;

use PHPAS2\Exception\CommandExecutionException;
use PHPAS2\Exception\InvalidDataStructureException;
use PHPAS2\Exception\InvalidMessageException;
use PHPAS2\Exception\InvalidPartnerException;
use PHPAS2\Exception\InvalidPathException;
use PHPAS2\Exception\InvalidSignatureAlgorithmException;
use PHPAS2\Exception\MessageEncryptionException;
use PHPAS2\Exception\MimeMessageException;
use PHPAS2\Exception\NoFilesProvidedException;
use PHPAS2\Exception\Pkcs12BundleException;
use PHPAS2\Exception\UnknownAuthenticationMethodException;
use PHPAS2\Exception\UnsignedMessageException;
use PHPAS2\Exception\UnverifiedMessageException;
use PHPAS2\Logger;
use PHPAS2\Message as PHPAS2Message;
use PHPAS2\Partner;
use phpseclib\File\ASN1;
use Zend\Mime\Message;
use Zend\Mime\Mime;
use Zend\Mime\Part as MimePart;

/**
 * Class Adapter
 *
 * @package PHPAS2\Message
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Adapter
{
    const MIC_MD5  = 'md5';
    const MIC_SHA1 = 'sha1';

    /** @var string */
    protected $binDir;
    /** @var string */
    protected $jarPath;
    /** @var string */
    protected $javaPath;
    /** @var string */
    protected $micAlgorithm;
    /** @var string */
    protected $opensslPath;
    /** @var Partner */
    protected $receivingPartner;
    /** @var Partner */
    protected $sendingPartner;
    /** @var array */
    protected static $tmpFiles = null;

    /**
     * Adapter constructor.
     */
    public function __construct()
    {
        // Default to the composer "vendor/bin" directory above this module
        /*
        $vendorBin = realpath(
            dirname(dirname(dirname(dirname(dirname(__FILE__))))) . DIRECTORY_SEPARATOR . 'bin'
        );
        $this->setJavaPath('/usr/bin/java');
        $this->setJarPath($vendorBin . DIRECTORY_SEPARATOR . 'AS2Secure.jar');
        */
        $this->setOpensslPath('/usr/bin/openssl');
    }

    /**
     * Add a file to the list of files to delete after shutdown of process
     *
     * @param string $filePath Path to file.
     */
    public function addTempFileForDelete($filePath) {
        if (is_null(self::$tmpFiles)) {
            self::$tmpFiles = [];
            register_shutdown_function(array($this, 'deleteTempFiles'));
        }

        self::$tmpFiles[] = $filePath;
    }

    /**
     *
     * @param $message
     * @param string $algorithm Algorithm to use to calculate MIC Checksum. Default: Adapter::MIC_SHA1.
     * @return string
     * @throws UnknownAuthenticationMethodException
     */
    public function calculateMicChecksum($message, $algorithm=self::MIC_SHA1) {
        if ($algorithm === self::MIC_SHA1) {
            $fileContents = sha1_file($message);
        }
        else if ($algorithm === self::MIC_MD5) {
            $fileContents = md5_file($message);
        }
        else {
            throw new UnknownAuthenticationMethodException(
                sprintf('Unknown checksum algorithm "%s"', $algorithm),
                UnknownAuthenticationMethodException::ERROR_AUTHENTICATION
            );
        }

        return base64_encode($this->hex2bin($fileContents)) . ', ' . $algorithm;
    }

    /**
     * Compose a new message
     *
     * @param array $files Array of paths to files.
     * @return $this
     * @throws NoFilesProvidedException
     */
    public function compose(array $files) {
        /**
         * While inspecting the AS2Secure.jar file, it appears nothing is done with the file(s) during the "compose"
         * action. So a call to self::compose may no longer be necessary.
         */
        return $this;
    }

    /**
     * Compress a file message
     *
     * @param string $file Path to file.
     * @return bool|string
     */
    public function compress($file) {
        $destinationFile = $this->getTempFilename();

        $compressed = gzcompress(file_get_contents($file));

        $part = new MimePart();
        $part->setDescription('S/MIME Compressed Message');
        $part->setDisposition(Mime::DISPOSITION_ATTACHMENT);
        $part->setFileName('smime.p7z');
        $part->setType('application/pkcs7-mime; smime-type="compressed-data"; name="smime.p7z"');
        $part->setEncoding('binary');
        $part->setContent($compressed);

        file_put_contents(
            $destinationFile,
            $part->getHeaders(PHPAS2Message::EOL_CRLF) . PHPAS2Message::EOL_CRLF
                . $part->getContent(PHPAS2Message::EOL_CRLF)
        );

        return $destinationFile;
    }

    /**
     * Decompress file contents.
     *
     * @param string $file Path to file.
     * @return bool|string
     */
    public function decompress($file) {
        $destinationFile = $this->getTempFilename();

        $message = Message::createFromMessage(file_get_contents($file));
        $part = $message->getParts()[0];

        $uncompressed = gzuncompress($part);

        file_put_contents($destinationFile, $uncompressed);

        return $destinationFile;
    }

    /**
     * Decrypt an incoming encrypted message.
     *
     * @deprecated
     * @param string $file Path to file.
     * @return bool|string
     * @throws Pkcs12BundleException
     * @throws MessageEncryptionException
     */
    public function decrypt($file) {
        $privateKey = $this->receivingPartner->getPrivateKeyFile();
        if (!$privateKey) {
            throw new Pkcs12BundleException('Unable to extract private key from PKCS12 bundle');
        }

        $cert = $this->receivingPartner->getPublicCert();

        $destinationFile = $this->getTempFilename();

        $result = openssl_pkcs7_decrypt($file, $destinationFile, $cert, $privateKey);
        if (!$result) {
            throw new MessageEncryptionException('OpenSSL failed to decrypt the message');
        }

        return $destinationFile;
    }

    /**
     * Delete all temporary files at end of session.
     */
    public function deleteTempFiles() {
        foreach (self::$tmpFiles as $file) {
            @unlink($file);
        }
    }

    /**
     * Get the mime-type of a file.
     *
     * @param string $file Path to file.
     * @return mixed
     */
    public function detectMimeType($file) {
        $fileInfo = finfo_open(FILEINFO_MIME);
        $mimeType = finfo_file($fileInfo, $file);
        finfo_close($fileInfo);
        return $mimeType;
    }

    /**
     * Encrypt a file.
     *
     * @param string $file The path to the file to encrypt
     * @param integer $cipher The encryption cipher to use (one of the OPENSSL_CIPHER_* constants).
     * @return string Path to encrypted file
     * @throws InvalidPartnerException
     * @throws MessageEncryptionException
     */
    public function encrypt($file, $cipher=OPENSSL_CIPHER_3DES) {
        $certificate = null;

        if (!$this->receivingPartner->getSecCertificate()) {
            $certificate = $this->receivingPartner->getPublicCertFile();
        }
        else {
            $certificate = $this->receivingPartner->getSecCertificateFile();
        }

        if (!$certificate || !is_file($certificate)) {
            throw new InvalidPartnerException(
                sprintf('Missing public certificate for partner %s', $this->receivingPartner->getId())
            );
        }

        $returnValue = $this->getTempFilename();

        $result = openssl_pkcs7_encrypt(
            $file,
            $returnValue,
            file_get_contents($certificate),
            [],
            0,
            $cipher
        );
        if (!$result) {
            throw new MessageEncryptionException('OpenSSL was unable to encrypt the file');
        }

        /*
         * This is necessary for Mendelson AS2 server.  They don't seem to like the "x-pkcs7-mime" content type.
         * Will just keep it this way for all AS2 partners.
         *
         * TODO: Verify this is actually correct
         */
        $contents = file_get_contents($returnValue);
        $contents = str_replace('application/x-pkcs7-mime', 'application/pkcs7-mime', $contents);

        $contents = str_replace(PHPAS2Message::EOL_CR, "", $contents);
        $contents = str_replace(PHPAS2Message::EOL_LF, PHPAS2Message::EOL_CRLF, $contents);

        file_put_contents($returnValue, $contents);

        return $returnValue;
    }

    /**
     * Execute the jar file
     * @param string $command The command to run on the Jar file
     * @param array $parameters Array of parameters for the command. Keys are options, values are values. Values are
     *              automatically escaped. Values with non-string keys (i.e. integer keys) will not be escaped and are
     *              passed through as-is. To get the parameter string "-in path/to/in.file -out path/to/out.file -flag"
     *              pass the following:
     * <pre>
     * [
     *   '-in' => 'path/to/in.file'
     *   '-out' => 'path/to/out.file'
     *   '-flag'
     * ]
     * </pre>
     * @param bool $returnOutput
     * @return array|integer|null
     * @throws CommandExecutionException
     */
    public function exec($command, array $parameters=[], $returnOutput=false) {
        $command = sprintf(
            '%s -jar %s %s',
            $this->getJavaPath(),
            escapeshellarg($this->getJarPath()),
            $command
        );

        $params = '';
        foreach ($parameters as $key => $value) {
            // Add preceding space to this parameter
            $params .= ' ';

            if (is_string($key)) {
                $params .= sprintf('%s %s', $key, escapeshellarg($value));
            }
            else {
                $params .= escapeshellarg($value);
            }
        }

        if ($params) {
            $command .= $params;
        }

        $output = [];
        $exitCode = null;

        Logger::getInstance()->log(Logger::LEVEL_DEBUG, 'Executing: ' . $command);

        exec($command, $output, $exitCode);

        Logger::getInstance()->log(Logger::LEVEL_DEBUG, 'Result (' . $exitCode . '): ' . implode("\n", $output));

        if ($exitCode) {
            $message = sprintf(
                'Unexpected error in command: %s',
                $command
            );
            if ($output[0]) {
                $message .= ' -- ' . $output[0];
            }

            throw new CommandExecutionException($message);
        }

        if ($returnOutput) {
            return $output;
        }

        return $exitCode;
    }

    /**
     * Extract attachments from message.
     *
     * @param string $file Path to file.
     * @return array
     * @throws InvalidDataStructureException
     */
    public function extract($file) {
        $files = [];

        $message = Message::createFromMessage(file_get_contents($file));
        if ($message->isMultiPart()) {
            foreach ($message->getParts() as $part) {
                $destinationFile = $this->getTempFilename();

                file_put_contents($destinationFile, $part->getRawContent());

                $files[] = [
                    'path' => $destinationFile,
                    'mimeType' => $part->getType(),
                    'filename' => $part->getFileName()
                ];
            }
        }
        else {
            $destinationFile = $this->getTempFilename();

            $part = $message->getParts()[0];

            file_put_contents($destinationFile, $part->getRawContent());

            $files[] = [
                'path' => $destinationFile,
                'mimeType' => $part->getType(),
                'filename' => $part->getFileName()
            ];
        }

        return $files;
    }

    /**
     * Given an OID string, provide the friendly algorithm name
     *
     * @param string $oid
     *
     * @return string
     * @throws InvalidSignatureAlgorithmException
     */
    public function getAlgorithmNameFromOid($oid) {
        $algorithms = [
            '1.2.840.113549.2.5'      => 'md5',
            '1.3.14.3.2.26'           => 'sha1',
            '2.16.840.1.101.3.4.1'    => 'aes',
            '2.16.840.1.101.3.4.1.1'  => 'aes-128-ecb',
            '2.16.840.1.101.3.4.1.2'  => 'aes-128-cbc',
            '2.16.840.1.101.3.4.1.3'  => 'aes-128-ofb',
            '2.16.840.1.101.3.4.1.4'  => 'aes-128-cfb',
            '2.16.840.1.101.3.4.1.5'  => 'id-aes128-wrap',
            '2.16.840.1.101.3.4.1.6'  => 'aes-128-gcm',
            '2.16.840.1.101.3.4.1.7'  => 'aes-128-ccm',
            '2.16.840.1.101.3.4.1.8'  => 'id-aes128-wrap-pad',
            '2.16.840.1.101.3.4.1.21' => 'aes-192-ecb',
            '2.16.840.1.101.3.4.1.22' => 'aes-192-cbc',
            '2.16.840.1.101.3.4.1.23' => 'aes-192-ofb',
            '2.16.840.1.101.3.4.1.24' => 'aes-192-cfb',
            '2.16.840.1.101.3.4.1.25' => 'id-aes192-wrap',
            '2.16.840.1.101.3.4.1.26' => 'aes-192-gcm',
            '2.16.840.1.101.3.4.1.27' => 'aes-192-ccm',
            '2.16.840.1.101.3.4.1.28' => 'id-aes192-wrap-pad',
            '2.16.840.1.101.3.4.1.41' => 'aes-256-ecb',
            '2.16.840.1.101.3.4.1.42' => 'aes-256-cbc',
            '2.16.840.1.101.3.4.1.43' => 'aes-256-ofb',
            '2.16.840.1.101.3.4.1.44' => 'aes-256-cfb',
            '2.16.840.1.101.3.4.1.45' => 'id-aes256-wrap',
            '2.16.840.1.101.3.4.1.46' => 'aes-256-gcm',
            '2.16.840.1.101.3.4.1.47' => 'aes-256-ccm',
            '2.16.840.1.101.3.4.1.48' => 'id-aes256-wrap-pad',
            '2.16.840.1.101.3.4.2'    => 'nist_hashalgs',
            '2.16.840.1.101.3.4.2.1'  => 'sha256',
            '2.16.840.1.101.3.4.2.2'  => 'sha384',
            '2.16.840.1.101.3.4.2.3'  => 'sha512',
            '2.16.840.1.101.3.4.2.4'  => 'sha224',
            '2.16.840.1.101.3.4.3'    => 'dsa_with_sha2',
            '2.16.840.1.101.3.4.3.1'  => 'dsa_with_SHA224',
            '2.16.840.1.101.3.4.3.2'  => 'dsa_with_SHA256'
        ];

        if (!array_key_exists($oid, $algorithms)) {
            throw new InvalidSignatureAlgorithmException(sprintf('Unknown algorithm OID "%s"', $oid));
        }

        return $algorithms[$oid];
    }

    /**
     * Get path to `AS2Secure.jar` file
     *
     * @return string
     */
    public function getJarPath() {
        return $this->jarPath;
    }

    /**
     * Get path to `java` executable.
     *
     * @return string
     */
    public function getJavaPath() {
        return $this->javaPath;
    }

    /**
     * Get directory to store incoming messages.
     *
     * @param null $path Subdirectories of base messages directory.
     * @return string
     * @throws InvalidPathException
     */
    public function getMessagesDir($path=null) {
        $returnValue = $this->getTopDir() . '_messages' . DIRECTORY_SEPARATOR;
        if ($path !== null) {
            $returnValue .= $path . DIRECTORY_SEPARATOR;
        }
        if (!is_dir($returnValue)) {
            mkdir($returnValue, 0777, true);
        }
        if (!is_writable($returnValue)) {
            if (!chmod($returnValue, 0777)) {
                throw new InvalidPathException('Incoming messages directory is not writable');
            }
        }
        return $returnValue;
    }

    /**
     * Get the MIC Algorithm used with the message
     *
     * @return string
     */
    public function getMicAlgorithm() {
        return $this->micAlgorithm;
    }

    /**
     * Calculate the MIC Checksum of a file.
     *
     * @param string $file Path to file.
     * @return bool|string
     * @throws UnsignedMessageException|InvalidSignatureAlgorithmException
     */
    public function getMicChecksum($file) {
        $boundary = $this->parseMessageBoundary($file);

        $message = Message::createFromMessage(file_get_contents($file), $boundary);

        $content = $message->getPartContent(0);
        $signature = $message->getPartContent(1);

        $asn1 = new ASN1();
        $decoded = $asn1->decodeBER(base64_decode($signature));

        $mapping = [
            'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
            'explicit' => true
        ];

        $mapped = $asn1->asn1map($decoded[0], $mapping);

        // We need PKCS7 Signed Data
        if ($mapped !== '1.2.840.113549.1.7.2') {
            throw new UnsignedMessageException('Message is not PKCS7 signed message');
        }

        // Signature algorithms should be one of nistAlgorithms
        $signatureOid = $asn1->asn1map($decoded[0]['content'][1]['content'][0]['content'][1]['content'][0], $mapping);

        /*
        if (substr($signatureOid, 0, 18) !== '2.16.840.1.101.3.4') {
            throw new InvalidSignatureAlgorithmException('Unknown algorithm OID');
        }
        */

        $algorithm = $this->getAlgorithmNameFromOid($signatureOid);
        $this->micAlgorithm = $algorithm;

        return sprintf(
            '%s, %s',
            base64_encode(openssl_digest($content, $algorithm, true)),
            $algorithm
        );
    }

    /**
     * Get path to OpenSSL
     *
     * @return string
     */
    public function getOpensslPath() {
        return $this->opensslPath;
    }

    /**
     * Get path to private directory
     *
     * @param null $path
     *
     * @return string
     */
    public function getPrivateDir($path=null) {
        $returnValue = $this->getTopDir() . '_private' . DIRECTORY_SEPARATOR;
        if ($path !== null) {
            $returnValue .= $path . DIRECTORY_SEPARATOR;
        }
        return $returnValue;
    }

    /**
     * Get string useful for server signature or user-agent.
     *
     * @return string
     */
    public static function getServerSignature() {
        return self::getSoftwareName() . ' / PHP ' . PHP_VERSION;
    }

    /**
     * Get library name.
     *
     * @return string
     */
    public static function getSoftwareName() {
        return 'PHPAS2 - PHP Library for AS2 Message Handling';
    }

    /**
     * Create a temporary file which will be deleted at shutdown of process.
     *
     * @return bool|string
     */
    public function getTempFilename() {
        if (is_null(self::$tmpFiles)) {
            self::$tmpFiles = [];
            register_shutdown_function(array($this, 'deleteTempFiles'));
        }

        $filename = tempnam(sys_get_temp_dir(), 'as2file_');
        self::$tmpFiles[] = $filename;

        return $filename;
    }

    /**
     * Get the path to `phpas2` directory
     *
     * @return string
     */
    public function getTopDir() {
        return realpath(dirname(dirname(dirname(__FILE__)))) . DIRECTORY_SEPARATOR;
    }

    /**
     * Convert hexadecimal string to binary string.
     *
     * @param string $string String to convert.
     * @return string
     */
    public function hex2bin($string) {
        $bin = '';
        $characters = str_split($string);
        for ($i=0; $i<count($characters);) {
            $bin .= chr(hexdec($characters[$i] . $characters[$i + 1]));
            $i += 2;
        }
        return $bin;
    }

    /**
     * Given a message file, parse the mime boundary from its header
     *
     * @param string $file
     *
     * @return string
     * @throws MimeMessageException
     */
    public function parseMessageBoundary($file) {
        // boundary="([^\"]+)"
        $fp = fopen($file, 'r');
        $startPos = false;
        $line = '';
        while ($startPos === false && ($line .= fread($fp, 8192))) {
            $startPos = strpos($line, 'boundary="');
            if ($startPos !== false) {
                $line .= fread($fp, 8192);
                break;
            }
        }
        $line = substr($line, $startPos);

        $matches = [];
        if (!preg_match('/boundary="([^"]+)"/', $line, $matches)) {
            throw new MimeMessageException('Unable to parse boundary from message');
        }

        return $matches[1];
    }

    /**
     * Set the path to the `AS2Secure.jar` file.
     *
     * @param string $path Path to file.
     * @return $this
     * @throws InvalidPathException
     */
    public function setJarPath($path) {
        $this->jarPath = $path;
        if (!is_file($this->jarPath)) {
            throw new InvalidPathException(
                sprintf('Path to AS2Secure jar file, "%s", does not resolve to a valid location.', $path)
            );
        }
        return $this;
    }

    /**
     * Set the path to the `java` executable.
     *
     * @param string $path Path to `java` executable.
     * @return $this
     * @throws InvalidPathException
     */
    public function setJavaPath($path) {
        $this->javaPath = realpath($path);
        if (!is_file($this->javaPath)) {
            throw new InvalidPathException(
                sprintf('Path to java, "%s", does not resolve to a valid location.', $path)
            );
        }
        return $this;
    }

    /**
     * Set the path to Openssl
     *
     * @param $path
     * @return $this
     * @throws InvalidPathException
     */
    public function setOpensslPath($path) {
        $this->opensslPath = realpath($path);
        if (!is_file($this->opensslPath)) {
            throw new InvalidPathException(
                sprintf('Path to openssl, "%s", does not resolve to a valid location.', $path)
            );
        }
        return $this;
    }

    /**
     * Set the receiving partner for the message. Also sets the $adapter on the given partner to this adapter.
     *
     * @param Partner $partner A PHPAS2\Partner object
     * @return $this
     */
    public function setReceivingPartner(Partner $partner) {
        $this->receivingPartner = $partner;
        $this->receivingPartner->setAdapter($this);

        return $this;
    }

    /**
     * Set the sending partner for this message. Also sets the $adapter on the given partner to this adapter.
     *
     * @param Partner $partner
     * @return $this
     */
    public function setSendingPartner(Partner $partner) {
        $this->sendingPartner = $partner;
        $this->sendingPartner->setAdapter($this);

        return $this;
    }

    /**
     * Sign a message using the PKCS12 bundle.
     *
     * TODO: Determine which encodings are valid, provide list of options
     *
     * @param string $file Path to file.
     * @param bool $useZlib Use zlip compression.
     * @param string $encoding base64, 8bit, 7bit
     * @return bool|string
     * @throws Pkcs12BundleException
     * @throws UnsignedMessageException
     */
    public function sign($file, $useZlib=false) {
        if (!$this->sendingPartner->getSecPkcs12()) {
            throw new Pkcs12BundleException('Missing PKCS12 bundle to sign outgoing messages');
        }

        // $parameters = [];

        if ($useZlib) {
            //$parameters[] = '-compress';
            $file = $this->compress($file);
        }

        $destinationFile = $this->getTempFilename();

        $privateKey = 'file://' . $this->sendingPartner->getPrivateKeyFile();
        if ($this->sendingPartner->getSecPkcs12Password()) {
            $privateKey = [$privateKey, $this->sendingPartner->getSecPkcs12Password()];
        }

        $output = [];
        $result = -1;
        $command = sprintf(
            $this->getOpensslPath() . ' smime -sign -binary -md %s -in %s -out %s -inkey %s -signer %s',
            $this->sendingPartner->getSecSignatureAlgorithm(),
            $file,
            $destinationFile,
            $this->sendingPartner->getPrivateKeyFile(),
            $this->sendingPartner->getPublicCertFile()
        );

        exec($command, $output, $result);
        $result = ($result == 0);
        unset($output);

        /*
         * Convert single Newline to CRLF endings (for MIME)
         */
        $contents = file_get_contents($destinationFile);
        $contents = str_replace(PHPAS2Message::EOL_CR, "", $contents);
        $contents = str_replace(PHPAS2Message::EOL_LF, PHPAS2Message::EOL_CRLF, $contents);
        file_put_contents($destinationFile, $contents);

        /*
        // TODO: Revert to the PHP version once changing the algorithm is allowed with openssl_pkcs7_sign
        $headers = [];

        if ($this->sendingPartner->getExtraCerts() !== null) {
            $result = openssl_pkcs7_sign(
                $file,
                $destinationFile,
                'file://' . $this->sendingPartner->getPublicCertFile(),
                $privateKey,
                $headers,
                PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR,
                $this->sendingPartner->getExtraCertsFile()
            );
        }
        else {
            $result = openssl_pkcs7_sign(
                $file,
                $destinationFile,
                'file://' . $this->sendingPartner->getPublicCertFile(),
                $privateKey,
                $headers,
                PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR
            );
        }
        */

        if (!$result) {
            throw new UnsignedMessageException('Failed to sign message: "' . openssl_error_string() . '"');
        }

        /*
        copy($destinationFile, '/media/mac-share/sandbox/cocoavia-shared/as2-message.signed-og');
        echo $this->sendingPartner->getId() . PHP_EOL;
        exit;
        */

        return $destinationFile;
    }

    /**
     * Verify a message
     *
     * @param string $file Path to file.
     * @return bool|string
     * @throws InvalidMessageException
     * @throws UnverifiedMessageException
     */
    /*
    public function verify($file) {
        $destinationFile = $this->getTempFilename();

        $result = openssl_pkcs7_verify($file, PKCS7_BINARY|PKCS7_DETACHED, $destinationFile);

        if ($result === -1) {
            throw new UnverifiedMessageException(
                'Error while verifying message: "' . openssl_error_string() . '"',
                InvalidMessageException::ERROR_INTEGRITY_CHECK
            );
        }
        else if ($result === false ) {
            throw new InvalidMessageException(
                'Message verification failed.',
                InvalidMessageException::ERROR_INTEGRITY_CHECK
            );
        }

        /*
        $parameters = [];
        if ($this->sendingPartner->getSecPkcs12()) {
            $parameters['-pkcs12'] = $this->sendingPartner->getSecPkcs12File();
            if ($this->sendingPartner->getSecPkcs12Password()) {
                $parameters['-password'] = $this->sendingPartner->getSecPkcs12Pasword();
            }
        }
        else {
            $parameters['-cert'] = $this->sendingPartner->getSecCertificateFile();
        }

        $parameters['-in']  = $file;
        $parameters['-out'] = $destinationFile;
        $parameters[] = '> /dev/null 2&1';

        $this->exec(
            'verify',
            $parameters
        );
        * /

        return $destinationFile;
    }
    */
}