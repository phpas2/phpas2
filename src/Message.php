<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

use PHPAS2\Message\AbstractMessage;
use PHPAS2\Message\Adapter;
use PHPAS2\Message\HeaderCollection;
use PHPAS2\Message\MessageDispositionNotification;
use Zend\Mime\Message as MimeMessage;
use Zend\Mime\Mime;
use Zend\Mime\Part;

/**
 * Class Message
 *
 * @package PHPAS2
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Message extends AbstractMessage
{
    /** @var string|null Message MIC checksum */
    protected $micChecksum;
    /** @var bool|string Path to message on filesystem */
    protected $path;

    /**
     * Message constructor.
     *
     * @param null|string|Request|\Horde_Mime_Part $data
     * @param array $params
     */
    public function __construct($data = null, array $params = []) {
        parent::__construct($data, $params);

        if ($data instanceof Request) {
            $this->path = $data->getPath();
        }
        else if ($data instanceof MimeMessage) {
            $this->path = $this->adapter->getTempFilename();
            file_put_contents($this->path, $data->generateMessage());
        }
        else if ($data instanceof \Horde_Mime_Part) {
            $this->path = $this->adapter->getTempFilename();
            file_put_contents($this->path, $data->toString(true));
        }
        else if ($data) {
            if (!array_key_exists('is_file', $params) || $params['is_file']) {
                $this->addFile($data, '', '', true);
            }
            else {
                $this->addFile($data, '', '', false);
            }
        }

        if (array_key_exists('mic', $params)) {
            $this->micChecksum = $params['mic'];
        }
    }

    /**
     * Add file to message.
     *
     * @param string $file The path to a file or the file contents
     * @param string $mimeType Mime-type of the file contents
     * @param string $filename The filename of the file if $file is file contents
     * @param boolean $isFile Whether $file is a path to a file (true) or are file contents (false). Default: true.
     * @param string $encoding The encoding to use for transfer
     * @return $this
     */
    public function addFile($file, $mimeType='', $filename='', $isFile=true, $encoding='base64') {
        if (!$isFile) {
            $tmpFile = $this->adapter->getTempFilename();
            file_put_contents($tmpFile, $file);
            $file = $tmpFile;
        }

        if (!$filename) {
            $filename = basename($file);
        }

        if (!$mimeType) {
            $mimeType = $this->adapter->detectMimeType($file);
        }

        $this->files[] = [
            'path'     => $file,
            'mimeType' => $mimeType,
            'filename' => $filename,
            'encoding' => $encoding
        ];

        return $this;
    }

    /**
     * Decode message and extract parts.
     *
     * @return $this
     */
    public function decode() {
        $this->files = $this->adapter->extract($this->getPath());
        return $this;
    }

    /**
     * Encode the message.
     *
     * @return $this
     * @throws \Exception
     */
    public function encode() {
        if (!($this->getSendingPartner() instanceof Partner)) {
            throw new InvalidPartnerException('Sending partner should be an instance of PHPAS2\Partner.');
        }

        if (!($this->getReceivingPartner() instanceof Partner)) {
            throw new InvalidPartnerException('Receiving partner should be an instance of PHPAS2\Partner');
        }

        $this->setMicChecksum(null);
        $messageId = $this->generateMessageId(AbstractMessage::TYPE_SENDING);
        $this->setMessageId($messageId);

        try {
            $mimePart = new MimeMessage();
            foreach ($this->getFiles() as $file) {
                $part = new Part();
                $part->setType($file['mimeType'])
                    ->setFileName($file['filename'])
                    ->setContent(file_get_contents($file['path']));
                if ($file['encoding']) {
                    $part->setEncoding($file['encoding']);
                }

                $mimePart->addPart($part);
            }

            if (!$mimePart->isMultiPart()) {
                $messageContent = $mimePart->getPartHeaders(0) . Mime::LINEEND . Mime::LINEEND;
                $messageContent .= $mimePart->getPartContent(0);
            }
            else {
                $messageContent = $mimePart->generateMessage();
            }

            $file = $this->adapter->getTempFilename();

            file_put_contents($file, trim($messageContent));
        }
        catch (\Exception $e) {
            $this->logger->log(
                Logger::LEVEL_ERROR,
                $e->getMessage(),
                $this->getMessageId()
            );
            throw $e;
        }

        if ($this->getReceivingPartner()->getSecSignatureAlgorithm() !== Partner::SIGN_NONE) {
            try {
                $file = $this->adapter->sign(
                    $file,
                    $this->getReceivingPartner()->getSendCompress()
                );
                $this->isSigned = true;
                // $this->micChecksum = $this->adapter->getMicChecksum($file);
            }
            catch (\Exception $e) {
                $this->logger->log(Logger::LEVEL_ERROR, $e->getMessage(), $this->getMessageId());
                throw $e;
            }
        }

        if ($this->getReceivingPartner()->getSecEncryptionAlgorithm() !== Partner::CRYPT_NONE) {
            try {
                $file = $this->adapter->encrypt($file);
                $this->isEncrypted = true;
            }
            catch (\Exception $e) {
                $this->logger->log(Logger::LEVEL_ERROR, $e->getMessage(), $this->getMessageId());
                throw $e;
            }
        }

        $this->path = $file;
        // Reinitialize $this->headerCollection
        $this->headerCollection = new HeaderCollection();
        $this->getHeaders()->addHeaders([
            'AS2-From'                    => $this->getSendingPartner()->getId(true),
            'AS2-To'                      => $this->getReceivingPartner()->getId(true),
            'AS2-Version'                 => '1.2',
            'Subject'                     => $this->getSendingPartner()->getSendSubject(),
            'Message-ID'                  => $this->getMessageId(),
            'MIME-Version'                => '1.0',
            'Disposition-Notification-To' => $this->getSendingPartner()->getSendUrl(),
            'Recipient-Address'           => $this->getReceivingPartner()->getSendUrl(),
            'User-Agent'                  => Adapter::getSoftwareName(),
            'Accept-Encoding'             => 'gzip, deflate'
        ]);

        if ($this->getSendingPartner()->getEmail()) {
            $this->getheaders()->addHeader('From', $this->getSendingPartner()->getEmail());
        }

        if ($this->getReceivingPartner()->getMdnSigned()) {
            $this->getHeaders()->addHeader(
                'Disposition-Notification-Options',
                'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha1'
            );
        }

        if ($this->getReceivingPartner()->getMdnRequest() == Partner::MDN_ASYNC) {
            $this->getHeaders()->addHeader(
                'Receipt-Delivery-Option',
                $this->getSendingPartner()->getSendUrl()
            );
        }

        $content = file_get_contents($this->path);
        $this->getHeaders()->addHeadersFromMessage($content);

        /*
         * Strip the S/MIME headers of the content since they're already in the message headers
         */
        $headerSeparator = strpos($content, "\n\n");
        if ($headerSeparator !== false) {
            $content = substr($content, $headerSeparator + 2);
        }

        copy($this->path, '/media/mac-share/sandbox/as2-message.p7m');

        file_put_contents($this->path, trim($content) . "\n");

        return $this;
    }

    /**
     * Generate an MDN for a message.
     *
     * @param null|\Exception $exception
     *
     * @return MessageDispositionNotification
     */
    public function generateMDN(\Exception $exception=null) {
        $mdn = new MessageDispositionNotification($this);

        $messageId = $this->getHeaders()->getHeader('message-id');
        $partner   = $this->getSendingPartner()->getId(true);
        $mic       = $this->getMicChecksum();

        $mdn->setAttribute('Original-Recipient', 'rfc822; ' . $partner)
            ->setAttribute('Final-Recipient', 'rfc822; ' . $partner)
            ->setAttribute('Original-Message-ID', $messageId);

        if ($mic) {
            $mdn->setAttribute('Received-Content-MIC', $mic);
        }

        if ($exception === null) {
            $mdn->setMessage('Successfully received AS2 message ' . $messageId);
            $mdn->setAttribute('Disposition-Type', 'processed');
        }
        else {
            $mdn->setMessage($exception->getMessage());
            $mdn->setAttribute('Disposition-Type', 'failure')
                ->setAttribute('Disposition-Modifier', $exception->getMessage());
        }

        return $mdn;
    }

    /**
     * Get the MIC checksum of the message
     *
     * @return null|string
     */
    public function getMicChecksum() {
        return $this->micChecksum;
    }

    /**
     * Get the destination URL for an outgoing message.
     *
     * @return string
     */
    public function getUrl() {
        return $this->getReceivingPartner()->getSendUrl();
    }

    /**
     * Set the MIC checksum.
     *
     * @param string|null $checksum
     * @return $this
     */
    public function setMicChecksum($checksum) {
        $this->micChecksum = $checksum;
        return $this;
    }
}