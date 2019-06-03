<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2;

use PHPAS2\Message\AbstractMessage;
use PHPAS2\Message\Adapter;
use PHPAS2\Message\HeaderCollection;
use Zend\Mime\Part;
use Zend\Stdlib\Request;

class Message extends AbstractMessage
{
    /** @var string|null Message MIC checksum */
    protected $micChecksum;
    /** @var bool|string Path to message on filesystem */
    protected $path;

    /**
     * Message constructor.
     *
     * @param null|string|Request $data
     * @param array               $params
     */
    public function __construct($data = null, array $params = [])
    {
        parent::__construct($data, $params);
        if ($data instanceof Request) {
            $this->path = $data->getPath();
        } else {
            if ($data instanceof \Zend\Mime\Message) {
                $this->path = $this->adapter->getTempFilename();
                if ($data->isMultiPart()) {
                    file_put_contents($this->path, $data->generateMessage(self::EOL_CRLF));
                } else {
                    $contents = $data->getPartHeaders(0, self::EOL_CRLF) . self::EOL_CRLF;
                    $contents .= $data->getPartContent(0, self::EOL_CRLF);
                    file_put_contents($this->path, $contents);
                }
            } else {
                if ($data) {
                    if (!array_key_exists('is_file', $params) || $params['is_file']) {
                        $this->addFile($data, '', '', true);
                    } else {
                        $this->addFile($data, '', '', false);
                    }
                }
            }
        }
        if (array_key_exists('mic', $params) && $params['mic']) {
            $this->micChecksum = $params['mic'];
        }
    }

    /**
     * Add file to message.
     *
     * @param string  $file     The path to a file or the file contents
     * @param string  $mimeType Mime-type of the file contents
     * @param string  $filename The filename of the file if $file is file contents
     * @param boolean $isFile   Whether $file is a path to a file (true) or are file contents (false). Default: true.
     * @param string  $encoding The encoding to use for transfer
     *
     * @return $this
     */
    public function addFile($file, $mimeType = '', $filename = '', $isFile = true, $encoding = 'base64')
    {
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
            'path' => $file,
            'mimeType' => $mimeType,
            'filename' => $filename,
            'encoding' => $encoding
        ];
        return $this;
    }

    public function decode()
    {
        $this->files = $this->adapter->extract($this->getPath());
        return $this;
    }

    public function encode()
    {
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
            $mimePart = new \Zend\Mime\Message();
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
                $messageContent = $mimePart->getPartHeaders(0, Message::EOL_CRLF) . Message::EOL_CRLF;
                $messageContent .= $mimePart->getPartContent(0, Message::EOL_CRLF);
            } else {
                $messageContent = $mimePart->generateMessage(self::EOL_CRLF);
            }
            $file = $this->adapter->getTempFilename();
            file_put_contents($file, $messageContent);
        } catch (\Exception $e) {
            $this->logger->error(
                $e->getMessage(),
                [],
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
            } catch (\Exception $e) {
                $this->logger->error($e->getMessage(), [], $this->getMessageId());
                throw $e;
            }
        }
        if ($this->getReceivingPartner()->getSecEncryptionAlgorithm() !== Partner::CRYPT_NONE) {
            try {
                $file = $this->adapter->encrypt($file);
                $this->isEncrypted = true;
            } catch (\Exception $e) {
                $this->logger->error($e->getMessage(), [], $this->getMessageId());
                throw $e;
            }
        }
        $this->path = $file;
        // Reinitialize $this->headerCollection
        $this->headerCollection = new HeaderCollection();
        $this->getHeaders()->addHeaders([
            'AS2-From' => $this->getSendingPartner()->getId(true),
            'AS2-To' => $this->getReceivingPartner()->getId(true),
            'AS2-Version' => '1.2',
            'Subject' => $this->getSendingPartner()->getSendSubject(),
            'Message-ID' => $this->getMessageId(),
            'MIME-Version' => '1.0',
            'Disposition-Notification-To' => $this->getSendingPartner()->getSendUrl(),
            'Recipient-Address' => $this->getReceivingPartner()->getSendUrl(),
            'User-Agent' => Adapter::getSoftwareName(),
            'Accept-Encoding' => 'gzip, deflate'
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
        $headerSeparator = strpos($content, Message::EOL_CRLF . Message::EOL_CRLF);
        if ($headerSeparator !== false) {
            $content = substr($content, $headerSeparator + 2);
        }
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
    public function generateMDN(\Exception $exception = null)
    {
        $mdn = new MessageDispositionNotification($this);
        $messageId = $this->getHeaders()->getHeader('message-id');
        $partner = $this->getSendingPartner()->getId(true);
        $mic = $this->getMicChecksum();
        $mdn->setAttribute('Original-Recipient', 'rfc822; ' . $partner)
            ->setAttribute('Final-Recipient', 'rfc822; ' . $partner)
            ->setAttribute('Original-Message-ID', $messageId);
        if ($mic) {
            $mdn->setAttribute('Received-Content-MIC', $mic);
        }
        if ($exception === null) {
            $mdn->setMessage('Successfully received AS2 message ' . $messageId);
            $mdn->setAttribute('Disposition-Type', 'processed');
        } else {
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
    public function getMicChecksum()
    {
        return $this->micChecksum;
    }

    /**
     * Get URL to send message / MDN to
     *
     * @return string
     * @throws Exception\InvalidPartnerException
     */
    public function getUrl()
    {
        return $this->getReceivingPartner()->getSendUrl();
    }

    /**
     * Set the MIC checksum.
     *
     * @param string|null $checksum
     *
     * @return $this
     */
    public function setMicChecksum($checksum)
    {
        $this->micChecksum = $checksum;
        return $this;
    }
}