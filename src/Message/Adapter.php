<?php
/**
 * Created by PhpStorm.
 * User: bapat
 * Date: 1/26/2019
 * Time: 12:19 AM
 */

namespace PHPAS2\Message;

use PHPAS2\Exception\NoFilesProvidedException;
use PHPAS2\Exception\UnknownAuthenticationMethodException;
use PHPAS2\Partner;

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
    protected static $tmpFiles=null;

    public function __construct()
    {
        $this->setOpenSSLPath('/usr/bin/openssl');
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
}