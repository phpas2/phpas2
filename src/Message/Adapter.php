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
use PHPAS2\Exception\InvalidPartnerException;
use PHPAS2\Exception\InvalidPathException;
use PHPAS2\Exception\MessageEncryptionException;
use PHPAS2\Exception\NoFilesProvidedException;
use PHPAS2\Exception\Pkcs12BundleException;
use PHPAS2\Exception\UnknownAuthenticationMethodException;
use PHPAS2\Logger;
use PHPAS2\Partner;

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
        $vendorBin = realpath(
            dirname(dirname(dirname(dirname(dirname(__FILE__))))) . DIRECTORY_SEPARATOR . 'bin'
        );
        $this->setJavaPath('/usr/bin/java');
        $this->setJarPath($vendorBin . DIRECTORY_SEPARATOR . 'AS2Secure.jar');
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
            throw new UnknownAuthenticationMethodException(sprintf('Unknown checksum algorithm "%s"', $algorithm));
        }

        return base64_encode($this->hex2bin($fileContents)) . ', ' . $algorithm;
    }

    /**
     * Compose a new message
     *
     * @param array $files Array of paths to files.
     * @return bool|string
     * @throws NoFilesProvidedException
     */
    public function compose(array $files) {
        if (!is_array($files) || !count($files)) {
            throw new NoFilesProvidedException('At least one file must be provided');
        }

        $parameters = [];
        foreach ($files as $file) {
            $parameters[] = sprintf(
                ' -file %s -mimetype %s -name %s',
                escapeshellarg($file['path']),
                escapeshellarg($file['mimeType']),
                escapeshellarg($file['filename'])
            );
        }

        $destinationFile = $this->getTempFilename();

        $parameters['-out'] = $destinationFile;

        $this->exec('compose', $parameters);

        return $destinationFile;
    }

    /**
     * Compress a file message
     *
     * @param string $file Path to file.
     * @return bool|string
     */
    public function compress($file) {
        $destinationFile = $this->getTempFilename();

        $this->exec(
            'compress',
            [
                '-in'  => $file,
                '-out' => $destinationFile
            ]
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

        $this->exec(
            'decompress',
            [
                '-in'  => $file,
                '-out' => $destinationFile
            ]
        );

        return $destinationFile;
    }

    /**
     * Decrypt an incoming encrypted message.
     *
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
         */
        $contents = file_get_contents($returnValue);
        $contents = str_replace('application/x-pkcs7-mime', 'application/pkcs7-mime', $contents);

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
        $destinationFile = $this->getTempFilename();

        $results = $this->exec('extract', ['-in' => $file, '-out' => $destinationFile], true);

        $files = [];
        foreach ($results as $result) {
            $tmp = explode(';', $result);
            if (count($tmp) <= 1) {
                continue;
            }
            else if (count($tmp) != 3) {
                throw new InvalidDataStructureException('Unexpected data structure while extracting message');
            }

            $file = [
                'path' => trim($tmp[0], '"'),
                'mimeType' => trim($tmp[1], '"'),
                'filename' => trim($tmp[2], '"')
            ];

            $files[] = $file;

            $this->addTempFileForDelete($file['path']);
        }

        return $files;
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
     */
    public function getMessagesDir($path=null) {
        $returnValue = $this->getTopDir() . 'messages' . DIRECTORY_SEPARATOR;
        if ($path !== null) {
            $returnValue .= $path . DIRECTORY_SEPARATOR;
        }
        return $returnValue;
    }

    /**
     * Calculate the MIC Checksum of a file.
     *
     * @param string $file Path to file.
     * @return bool|string
     */
    public function getMicChecksum($file) {
        try {
            $result = $this->exec('checksum', ['-in' => $file, ' 2>/dev/null'], true);
            return $result[0];
        }
        catch (\Exception $e) {
            return false;
        }
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
     * @param string $encoding
     * @return bool|string
     * @throws Pkcs12BundleException
     */
    public function sign($file, $useZlib=false, $encoding='base64') {
        if (!$this->sendingPartner->getSecPkcs12()) {
            throw new Pkcs12BundleException('Missing PKCS12 bundle to sign outgoing messages');
        }

        $parameters = [];

        if ($this->sendingPartner->getSecPkcs12Password()) {
            $parameters['-password'] = $this->sendingPartner->getSecPkcs12Password();
        }
        else {
            $parameters[] = '-nopassword';
        }

        if ($useZlib) {
            $parameters[] = '-compress';
        }

        $pkcs12bundle = $this->sendingPartner->getSecPkcs12File();
        $destinationFile = $this->getTempFilename();

        $parameters['-pkcs12']   = $pkcs12bundle;
        $parameters['-encoding'] = $encoding;
        $parameters['-in']       = $file;
        $parameters['-out']      = $destinationFile;

        $this->exec(
            'sign',
            $parameters
        );

        return $destinationFile;
    }

    /**
     * Verify a message
     *
     * @param string $file Path to file.
     * @return bool|string
     */
    public function verify($file) {
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

        $destinationFile = $this->getTempFilename();

        $parameters['-in']  = $file;
        $parameters['-out'] = $destinationFile;
        $parameters[] = '> /dev/null 2&1';

        $this->exec(
            'verify',
            $parameters
        );

        return $destinationFile;
    }
}