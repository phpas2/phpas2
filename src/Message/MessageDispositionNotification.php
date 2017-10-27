<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2\Message;

use PHPAS2\Exception\AbstractException;
use PHPAS2\Exception\InvalidMessageException;
use PHPAS2\Exception\MDNFailure;
use PHPAS2\Exception\UnsignedMdnException;
use PHPAS2\Logger;
use PHPAS2\Message;
use PHPAS2\Request;
use PHPAS2\Response;
use Zend\Mime\Message as MimeMessage;
use Zend\Mime\Mime;
use Zend\Mime\Part;

/**
 * Class MessageDispositionNotification
 *
 * @package PHPAS2\Message
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class MessageDispositionNotification extends AbstractMessage
{
    const ACTION_AUTO    = 'automatic-action';
    const ACTION_MANUAL  = 'manual-action';
    const MOD_ERROR      = 'error';
    const MOD_WARN       = 'warning';
    const MODE_AUTO      = 'MDN-sent-automatically';
    const MODE_MANUAL    = 'MDN-sent-manually';
    const TYPE_PROCESSED = 'processed';
    const TYPE_FAILED    = 'failed';

    /** @var HeaderCollection */
    protected $attributes;
    /** @var Message */
    protected $message = '';
    /** @var string */
    protected $url;

    public function __construct($data=null, $params=[]) {
        parent::__construct($data, $params);

        $this->attributes = new HeaderCollection();
        $this->setAttribute('action-mode', self::ACTION_AUTO)
            ->setAttribute('sending-mode', self::MODE_AUTO);

        // TODO: Add AS2Exception type support
        if ($data instanceof AbstractException) {
            $this->setMessage($data->getMessage())
                ->getHeaders()->addHeader('Disposition-Type', $data->getLevelText())
                ->addHeader('Disposition-Modifier', $data->getMessageShort());
        }
        else if ($data instanceof \Exception) {
            $this->setMessage($data->getMessage());
            $this->getheaders()->addHeader('Disposition-Type', 'error')
                ->addHeader('Disposition-Modifier', 'unexpected-processing-error');
        }
        else if ($data instanceof Response) {
            $headers = array_pop($data->getHeaders());
            $this->setSendingPartner($headers['as2-from'])
                ->setReceivingPartner($headers['as2-to'])
                ->setPath($this->adapter->getTempFilename());

            file_put_contents($this->getPath(), $data->getContent());
            file_put_contents('/tmp/message.mdn', $data->getContent());

            $this->decode();

            $this->setMessageId($this->attributes->getHeader('original-message-id'));
            
            $disposition = $this->getAttribute('disposition');
            $matches = [];
            if (preg_match('/failed/Failure:(?<message>.*)/', $disposition, $matches)) {
                throw new MDNFailure($matches['message']);
            }
        }
        else if ($data instanceof Request) {
            $this->setSendingPartner($data->getSendingPartner())
                ->setReceivingPartner($data->getReceivingPartner())
                ->setPath($data->getContents())
                ->setFilename(basename($data->getContents()))
                ->setMimetype('multipart/report');

            if ($this->getSendingPartner()->getMdnSigned() && !$data->getIsSigned()) {
                throw new UnsignedMdnException('Unsigned MDN received but partner is expecting signed MDN');
            }
        }
        else if ($data instanceof Message) {
            $this->setSendingPartner($data->getSendingPartner())
                ->setReceivingPartner($data->getReceivingPartner());
        }
        /*
        else if ($data instanceof \Horde_Mime_Part) {
            $this->setSendingPartner($params['sending_partner'])
                ->setReceivingPartner($params['receiving_partner'])
                ->setPath($this->adapter->getTempFilename());

            file_put_contents($this->getPath(), $data->toString(true));
        }
        */
        else if ($data === null) {
            // To handle error notifications
        }
        else {
            $this->logger->log(
                Logger::LEVEL_ERROR,
                'Unknown message type encountered: "' . gettype($data) . '"',
                $this->attributes->getheader('original-message-id')
            );
            throw new InvalidMessageException(
                'Unexpected message encountered. Expected Request, Response, or Message'
            );
        }
    }

    /**
     * Convert MDN to string
     *
     * @return string
     */
    public function __toString() {
        return (string) $this->getMessage();
    }

    /**
     * Decode incoming MDN
     *
     * @return $this
     */
    public function decode() {
        $boundary = $this->adapter->parseMessageBoundary($this->getPath());
        $message = MimeMessage::createFromMessage(file_get_contents($this->getPath()), $boundary);

        $this->setMessage('');
        $this->attributes = null;

        foreach ($message->getParts() as $num => $part) {
            if (strtolower($part->type) == 'message/disposition-notification') {
                $this->attributes = new HeaderCollection();
                foreach ($part->getHeadersArray() as $header) {
                    $this->attributes->addHeader($header[0], $header[1]);
                }
            }
            else {
                $this->setMessage(trim($part->getContent()));
            }
        }

        return $this;
    }

    /**
     * Encode MDN for sending
     *
     * @param Message $message Message for MDN
     * @return $this
     */
    public function encode(Message $message=null) {
        $container = new MimeMessage();
        $containerHeaders = new HeaderCollection();
        $containerHeaders->addHeader('Content-Type', 'multipart/report; charset=utf-8');
        //$container->setType('multipart/report');

        $textPart = new Part($this->getMessage());
        $textPart->setType(Mime::TYPE_TEXT)
            ->setCharset('utf-8')
            ->setEncoding(Mime::ENCODING_7BIT);

        $container->addPart($textPart);

        $lines = new HeaderCollection();
        $lines->addHeader('Reporting-UA', Adapter::getServerSignature());
        if ($this->getSendingPartner()) {
            $lines->addHeader('Original-Recipient', 'rfc822; ' . $this->getSendingPartner()->getId(true));
            $lines->addHeader('Final-Recipient', 'rfc822; ' . $this->getSendingPartner()->getId(true));
        }
        $lines->addHeader('Original-Message-ID', $this->getAttribute('message-id'));
        $lines->addHeader(
            'Disposition',
            sprintf(
                '%s/%s; %s',
                $this->getAttribute('action-mode'),
                $this->getAttribute('sending-mode'),
                $this->getAttribute('disposition-type')
            )
        );
        if ($this->getAttribute('disposition-type') !== self::TYPE_PROCESSED) {
            $lines->addHeader(
                'Disposition',
                $lines->getHeader('Disposition') . ': ' . $this->getAttribute('disposition-modifier')
            );
        }
        if ($this->getAttribute('received-content-mic')) {
            $lines->addHeader('Received-Content-MIC', $this->getAttribute('received-content-mic'));
        }

        $mdn = new Part($lines->__toString());
        $mdn->setType('message/disposition-notification')
            ->setEncoding(Mime::ENCODING_7BIT);

        $this->setMessageId($this->generateMessageId(Message::TYPE_SENDING));

        $this->getHeaders()->addHeaders([
            'AS2-Version'  => '1.2',
            'Message-ID'   => $this->getMessageId(),
            'Mime-Version' => '1.0',
            'Server'       => Adapter::getServerSignature(),
            'User-Agent'   => Adapter::getServerSignature()
        ]);

        $this->getHeaders()->addHeaders($containerHeaders);

        if ($this->getSendingPartner()) {
            $this->getHeaders()->addHeaders([
                'AS2-From'                    => $this->getSendingPartner()->getId(true),
                'From'                        => $this->getSendingPartner()->getEmail(),
                'Subject'                     => $this->getSendingPartner()->getMdnSubject(),
                // 'Disposition-Notification-To' => $this->getSendingPartner()->getSendUrl()
            ]);
        }

        if ($this->getReceivingPartner()) {
            $this->getHeaders()->addHeaders([
                'AS2-To'            => $this->getReceivingPartner()->getId(true),
                'Recipient-Address' => $this->getReceivingPartner()->getSendUrl()
            ]);
        }

        if ($message) {
            $url = $message->getHeaders()->getHeader('Receipt-Delivery-Option');
            if ($url && $this->getSendingPartner()) {
                $this->setUrl($url);
                $this->headerCollection->addHeader('Recipient-Address', $this->getSendingPartner()->getSendUrl());
            }
        }

        $this->setPath($this->adapter->getTempFilename());

        if ($message && $message->getHeaders()->getHeader('Disposition-Notification-Options')) {
            file_put_contents($this->getPath(), $containerHeaders->__toString() . PHP_EOL . $container->generateMessage());
            $this->setPath($this->adapter->sign($this->getPath()));

            $content = file_get_contents($this->getPath());
            $this->headerCollection->addHeadersFromMessage($content);

            $mimePart = MimeMessage::createFromMessage($content);

            file_put_contents($this->getPath(), $mimePart->getPartContent(0));
        }
        else {
            file_put_contents($this->getPath(), $container->generateMessage());
        }

        return $this;
    }

    /**
     * Get MDN header attribute
     *
     * @param $key
     * @return bool
     */
    public function getAttribute($key) {
        return $this->attributes->getHeader($key);
    }

    /**
     * Get MDN message
     *
     * @return mixed
     */
    public function getMessage() {
        return $this->message;
    }

    /**
     * Get MDN delivery URL
     *
     * @return null|string
     */
    public function getUrl() {
        return $this->url;
    }

    /**
     * Set header attribute value for the MDN
     *
     * @param $key
     * @param $value
     * @return $this
     */
    public function setAttribute($key, $value) {
        $this->attributes->addHeader($key, $value);
        return $this;
    }

    /**
     * Set the message for the MDN
     *
     * @param string $message
     * @return $this
     */
    public function setMessage($message='') {
        $this->message = $message;
        return $this;
    }

    /**
     * Set MDN delivery URL
     *
     * @param $url
     * @return $this
     */
    public function setUrl($url) {
        $this->url = $url;
        return $this;
    }
}