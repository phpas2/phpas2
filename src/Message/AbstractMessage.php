<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2\Message;

use PHPAS2\Exception\InvalidPartnerException;
use PHPAS2\Exception\InvalidPathException;
use PHPAS2\Logger;
use PHPAS2\Partner;
use PHPAS2\Partner\Authentication;

/**
 * Class AbstractMessage
 *
 * @package PHPAS2\Message
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
abstract class AbstractMessage
{
    const TYPE_RECEIVING = 'receiving';
    const TYPE_SENDING   = 'sending';

    /** @var Adapter */
    protected $adapter;
    /** @var Authentication */
    protected $authentication;
    /** @var string */
    protected $filename;
    /** @var array */
    protected $files = [];
    /** @var HeaderCollection */
    protected $headerCollection;
    /** @var boolean */
    protected $isEncrypted;
    /** @var boolean */
    protected $isSigned;
    /** @var Logger */
    protected $logger;
    /** @var string */
    protected $messageId;
    /** @var string */
    protected $mimeType;
    /** @var array|string */
    protected $path;
    /** @var Partner */
    protected $receivingPartner;
    /** @var Partner */
    protected $sendingPartner;

    /**
     * Decode the message
     *
     * @return $this
     */
    abstract public function decode();

    /**
     * Encode the message
     *
     * @return $this
     */
    abstract public function encode();

    /**
     * Retrieve message destination URL.
     *
     * @return string
     */
    abstract function getUrl();

    /**
     * AbstractMessage constructor.
     *
     * @param null|array|string $data
     * @param array $params
     */
    public function __construct($data=null, $params=[]) {
        $this->adapter          = new Adapter();
        $this->authentication   = new Authentication();
        $this->headerCollection = new HeaderCollection();
        $this->logger           = Logger::getInstance();

        if (is_array($data)) {
            $this->path = $data;
        }
        else if (is_string($data)) {
            if (array_key_exists('is_file', $params) && $params['is_file'] === false) {
                $file = $this->adapter->getTempFilename();
                file_put_contents($file, $data);
                $this->setPath($file);
                if (array_key_exists('filename', $params)) {
                    $this->setFilename($params['filename']);
                }
            }
            else {
                $this->setPath($data);
                $this->setFilename(
                    array_key_exists('filename', $params) ? $params['filename'] : basename($this->getPath())
                );
            }
            $this->setMimetype(
                array_key_exists('mimetype', $params) ?
                    $params['mimetype'] : $this->adapter->detectMimeType($this->getFilename())
            );
        }

        if (array_key_exists('receiving_partner', $params) && $params['receiving_partner']) {
            $this->setReceivingPartner($params['receiving_partner']);
            $this->getReceivingPartner()->setAdapter($this->adapter);
        }

        if (array_key_exists('sending_partner', $params) && $params['sending_partner']) {
            $this->setSendingPartner($params['sending_partner']);
            $this->getSendingPartner()->setadapter($this->adapter);
        }
    }

    /**
     * Add file to message.
     *
     * @param string $file Path to file.
     * @return $this
     */
    public function addFile($file) {
        $this->files[] = realpath($file);
        return $this;
    }

    /**
     * Generate a unique message ID per RFC 4130 Section 5 Subsection 3.3.
     *
     * @param string $type
     *
     * @return string
     */
    final public function generateMessageId($type=self::TYPE_SENDING) {
        try {
            switch ($type) {
                case self::TYPE_RECEIVING:
                    $partner = $this->getReceivingPartner();
                    break;

                case self::TYPE_SENDING:
                    $partner = $this->getSendingPartner();
                    break;

                default:
                    throw new InvalidPartnerException('Invalid partner to generate message ID with');
            }
        }
        catch (\Exception $e) {
            $partner = 'unknown';
        }

        $returnValue = sha1(bin2hex(openssl_random_pseudo_bytes(16))) . '@';
        $returnValue .= $partner->getId() . '.' . parse_url($partner->getSendUrl(), PHP_URL_HOST);

        $returnValue = str_replace(' ', '_', $returnValue);
        $returnValue = '<' . substr($returnValue, 0, 255) . '>';

        return $returnValue;
    }

    /**
     * Retrieve adapter for message.
     *
     * @return Adapter
     */
    public function getAdapter() {
        return $this->adapter;
    }

    /**
     * Get authentication object
     *
     * @return Authentication
     */
    public function getAuthentication() {
        return $this->authentication;
    }

    /**
     * Get contents of the message.
     *
     * @return bool|string
     */
    public function getContents() {
        return file_get_contents($this->path);
    }

    /**
     * Get filename of stored message.
     *
     * @return string
     */
    public function getFilename() {
        return $this->filename;
    }

    /**
     * Get list of files.
     *
     * @return array
     */
    public function getFiles() {
        return $this->files;
    }

    /**
     * Get HeaderCollection object with message headers.
     *
     * @return HeaderCollection
     */
    public function getHeaders() {
        return $this->headerCollection;
    }

    /**
     * Get whether or not the message is encrypted.
     *
     * @return bool
     */
    public function getIsEncrypted() {
        return $this->isEncrypted;
    }

    /**
     * Get whether or not the message is signed.
     *
     * @return bool
     */
    public function getIsSigned() {
        return $this->isSigned;
    }

    /**
     * Get the unique message ID.
     *
     * @return string
     */
    public function getMessageId() {
        return $this->messageId;
    }

    /**
     * Get mime-type of message content.
     *
     * @return string
     */
    public function getMimeType() {
        return $this->mimeType;
    }

    /**
     * Get path(s) of file(s) for message.
     *
     * @return array|null|string
     */
    public function getPath() {
        return $this->path;
    }

    /**
     * Get the receiving partner identity.
     *
     * @return Partner
     * @throws InvalidPartnerException
     */
    public function getReceivingPartner() {
        if (!($this->receivingPartner instanceof Partner)) {
            throw new InvalidPartnerException('Receiving partner has not been set, or was not configured properly.');
        }

        return $this->receivingPartner;
    }

    /**
     * Get the sending partner identity.
     *
     * @return Partner
     * @throws InvalidPartnerException
     */
    public function getSendingPartner() {
        if (!($this->sendingPartner instanceof Partner)) {
            throw new InvalidPartnerException('Sending partner has not been set, or was not configured properly.');
        }

        return $this->sendingPartner;
    }

    /**
     * Set the filename.
     *
     * @param string $filename
     * @return $this
     */
    public function setFilename($filename) {
        $this->filename = $filename;
        return $this;
    }

    /**
     * Set the unique message ID.
     *
     * @param string $messageId
     * @return $this
     */
    public function setMessageId($messageId) {
        $this->messageId = $messageId;
        return $this;
    }

    /**
     * Set the mime-type of the message content.
     *
     * @param string $mimeType
     * @return $this
     */
    public function setMimeType($mimeType) {
        $this->mimeType = $mimeType;
        return $this;
    }

    /**
     * Set the path to the message.
     *
     * @param string|array $path
     * @return $this
     */
    public function setPath($path) {
        $this->path = $path;
        return $this;
    }

    /**
     * Set the receiving partner by partner ID, config array or Partner object.
     *
     * @param string|array|Partner $partner The configuration array, partner ID or Partner object.
     * @return $this
     * @throws InvalidPartnerException
     */
    public function setReceivingPartner($partner) {
        if (!($partner instanceof Partner)) {
            $this->receivingPartner = new Partner();
            if (is_array($partner)) {
                $this->receivingPartner->loadFromArray($partner);
            }
            else if (is_string($partner)) {
                $this->receivingPartner->loadFromConfig($partner);
            }
            else {
                throw new InvalidPartnerException('Expected partner config array, ID or Partner object.');
            }
        }
        else {
            $this->receivingPartner = $partner;
        }

        return $this;
    }

    /**
     * Set the sending partner by partner ID, config array or Partner object.
     *
     * @param string|array|Partner $partner The configuration array, partner ID or Partner object.
     * @return $this
     * @throws InvalidPartnerException
     */
    public function setSendingPartner($partner) {
        if (!($partner instanceof Partner)) {
            $this->sendingPartner = new Partner();
            if (is_array($partner)) {
                $this->sendingPartner->loadFromArray($partner);
            }
            else if (is_string($partner)) {
                $this->sendingPartner->loadFromConfig($partner);
            }
            else {
                throw new InvalidPartnerException('Expected partner config array, ID or Partner object.');
            }
        }
        else {
            $this->sendingPartner = $partner;
        }

        return $this;
    }
}