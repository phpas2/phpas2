<?php
/**
 * Copyright © 2019 phpas2-server. All rights reserved.
 */

namespace PHPAS2;

use PHPAS2\Exception\MessageDecryptionException;
use PHPAS2\Exception\MethodNotAvailableException;
use PHPAS2\Exception\Pkcs12BundleException;
use PHPAS2\Exception\UnencryptedMessageException;
use PHPAS2\Exception\UnsignedMessageException;
use PHPAS2\Exception\UnverifiedMessageException;
use PHPAS2\Message\AbstractMessage;
use PHPAS2\Message\HeaderCollection;
use PHPAS2\Message\MessageDispositionNotification;

class Request extends AbstractMessage
{
    /** @var HeaderCollection */
    protected $headerCollection;

    /** @var null|string MIC checksum of request */
    protected $mic = null;

    /**
     * Request constructor.
     *
     * @param array|null|string $content
     * @param array             $headers
     */
    public function __construct($content, $headers)
    {
        if (!($headers instanceof HeaderCollection)) {
            $headerCollection = new HeaderCollection();
            $headerCollection->addHeaders($headers);
            $headers = $headerCollection;
        }
        $mimeType = $headers->getHeader('content-type');
        $mimeTypeSeparator = $pos = strpos($mimeType, ';');
        if ($mimeTypeSeparator !== false) {
            $mimeType = substr($mimeType, 0, $mimeTypeSeparator);
        }

        $params = [
            'sending_partner' => $headers->getHeader('as2-from'),
            'receiving_partner' => $headers->getHeader('as2-to'),
            'mimetype' => $mimeType,
            'is_file' => false
        ];
        parent::__construct($content, $params);
        $this->headerCollection = $headers;
        $messageId = trim($this->getHeaders()->getHeader('message-id'), '<>');
        $this->setMessageId($messageId);
    }

    /**
     * Method not available
     *
     * @throws MethodNotAvailableException
     */
    public function decode()
    {
        throw new MethodNotAvailableException('Method "decode" is not available on a Request message.');
    }

    /**
     * Decrypt received message
     *
     * @return bool|string
     * @throws \Exception
     */
    public function decrypt()
    {
        $returnVal = false;
        $mimeType = $this->getHeaders()->getHeader('Content-Type');
        $position = strpos($mimeType, ';');
        if ($position !== false) {
            $mimeType = trim(substr($mimeType, 0, $position));
        }
        if ($mimeType == 'application/pkcs7-mime' || $mimeType == 'application/x-pkcs7-mime') {
            try {
                $content = $this->getHeaders()->__toString() . HeaderCollection::EOL_CRLF . HeaderCollection::EOL_CRLF;
                $content .= file_get_contents($this->getPath());
                $input = $this->adapter->getTempFilename();
                file_put_contents($input, $content);
                $returnVal = $this->decryptMessage($input);
                $this->setPath($returnVal);
            } catch (\Exception $e) {
                throw $e;
            }
        }
        return $returnVal;
    }

    /**
     * Method not available
     *
     * @throws MethodNotAvailableException
     */
    public function encode()
    {
        throw new MethodNotAvailableException('Method "encode" is not available on a Request message.');
    }

    /**
     * Get aon object from a received message
     *
     * @return MessageDispositionNotification|Message
     */
    public function getObject()
    {
        $message = \Zend\Mime\Message::createFromMessage(file_get_contents($this->getPath()));
        $isMdn = false;
        if ($message->getPartHeadersArray(0)['Content-Type'] == 'multipart/report') {
            $isMdn = true;
        }
        $params = [
            'is_file' => false,
            'mic' => $this->mic,
            'receiving_partner' => $this->getReceivingPartner(),
            'sending_partner' => $this->getSendingPartner()
        ];
        if ($isMdn) {
            $returnVal = new MessageDispositionNotification(null, $params);
        } else {
            $returnVal = new Message($message, $params);
        }
        //$returnVal->getHeaders()->addHeaders($this->getHeaders());
        return $returnVal;
    }

    /**
     * Not Implemented
     *
     * @throws MethodNotAvailableException
     */
    public function getUrl()
    {
        throw new MethodNotAvailableException('Method "getUrl" is not available on a Request message.');
    }

    /**
     * Determine if message is encrypted (according to headers sent)
     *
     * @return bool
     */
    public function isMessageEncrypted()
    {
        $mimeType = $this->getHeaders()->getHeader('Content-Type');
        $position = strpos($mimeType, ';');
        $returnVal = false;
        if ($position !== false) {
            $mimeType = trim(substr($mimeType, 0, $position));
        }
        if ($mimeType == 'application/pkcs7-mime' || $mimeType == 'application/x-pkcs7-mime') {
            $returnVal = true;
        }
        return $returnVal;
    }

    /**
     * Check if current message is signed
     *
     * @return bool
     */
    public function isMessageSigned()
    {
        $boundary = $this->getAdapter()->parseMessageBoundary($this->getPath());
        $message = \Zend\Mime\Message::createFromMessage(file_get_contents($this->getPath()), $boundary);
        $isSigned = false;
        /** @var \Zend\Mime\Part $part */
        foreach ($message->getParts() as $part) {
            $headers = $part->getHeadersArray();
            $contentType = null;
            foreach ($headers as $pair) {
                if (strtolower($pair[0]) == 'content-type') {
                    if (preg_match('/application\/(?:x-)?pkcs7-signature/', $pair[1])) {
                        $isSigned = true;
                        break;
                    }
                }
            }
        }
        return $isSigned;
    }

    /**
     * Process a message via a decrypt / verify signature loop for as many times as there are signatures and
     * encryptions. This is to support high-security messages which are signed, then encrypted, then signed again to
     * prevent message tampering.
     *
     * When done, $this->getPath() will reference the verified original message.
     *
     * @return $this
     */
    public function processMessage()
    {
        do {
            $actedUpon = false;
            // 1. Decrypt message (if encrypted)
            if ($this->isMessageEncrypted()) {
                $this->decryptMessage($this->getPath());
            } else {
                $actedUpon |= true;
            }
            // 2. Verify signature (if signed)
            if ($this->isMessageSigned()) {
                $this->verifyMessageSignature();
            } else {
                $actedUpon |= true;
            }
            // 3. If we did not change the message (no decryption, no verification) we're done
            if (!$actedUpon) {
                break;
            }
        } while (true);
        $this->mic = $this->adapter->calculateMicChecksum($this->getPath(), 'sha1');
        return $this;
    }

    /**
     * Check a message or MDN is signed and encrypted according to partner configuration
     *
     * @param string  $mimeType
     * @param boolean $signed
     * @param boolean $encrypted
     *
     * @throws UnencryptedMessageException
     * @throws UnsignedMdnException
     * @throws UnsignedMessageException
     */
    protected function checkMessageConstruction($mimeType, $signed, $encrypted)
    {
        if (strtolower($mimeType) === 'multipart/report') {
            if (
                $this->getSendingPartner()->getSecSignatureAlgorithm() != Partner::SIGN_NONE &&
                $this->getSendingPartner()->getMdnSigned() &&
                !$signed
            ) {
                throw new UnsignedMessageException('MDN is not signed but partner is configured for signed MDNs');
            }
        } else {
            if (
                $this->getSendingPartner()->getSecEncryptAlgorithm() != Partner::CRYPT_NONE &&
                !$encrypted
            ) {
                throw new UnencryptedMessageException(
                    'Message is not encrypted but partner is configured for encrypted messages'
                );
            }
            if (
                $this->getSendingPartner()->getSecSignatureAlgorithm() != Partner::SIGN_NONE &&
                !$signed
            ) {
                throw new UnsignedMessageException(
                    'Message is not signed but partner is configured for signed messages'
                );
            }
        }
    }

    /**
     * Decrypt an incoming encrypted message.
     *
     * @param string $file Path to file.
     *
     * @throws Pkcs12BundleException
     * @throws MessageDecryptionException
     */
    protected function decryptMessage($file)
    {
        $privateKey = $this->getReceivingPartner()->getPrivateKeyFile();
        if (!$privateKey) {
            throw new Pkcs12BundleException('Unable to extract private key from PKCS12 bundle');
        }
        $privateKey = openssl_pkey_get_private('file://' . $privateKey);
        $cert = openssl_x509_read('file://' . $this->getReceivingPartner()->getPublicCertFile());
        $destinationFile = $this->getAdapter()->getTempFilename();
        $result = openssl_pkcs7_decrypt($file, $destinationFile, $cert, $privateKey);
        if (!$result) {
            throw new MessageDecryptionException(
                'OpenSSL failed to decrypt the message',
                MessageDecryptionException::ERROR_DECRYPTION
            );
        }
        $this->setPath($destinationFile);
    }

    /**
     * Verify the message contents based on the signature
     *
     * @return $this
     * @throws UnverifiedMessageException
     */
    protected function verifyMessageSignature()
    {
        $verifiedFile = $this->getAdapter()->getTempFilename();
        $result = openssl_pkcs7_verify(
            $this->getPath(),
            PKCS7_NOVERIFY | PKCS7_BINARY | PKCS7_NOINTERN,
            '/dev/null',
            [],
            $this->getSendingPartner()->getPublicCertFile(),
            $verifiedFile
        );
        $errorString = '';
        while ($err = openssl_error_string()) {
            $errorString .= $err . Message::EOL_CRLF;
        }
        $errorString = trim($errorString);
        if ($result === false) {
            throw new UnverifiedMessageException(
                'Message was tampered with or signing certificate is invalid:' . Message::EOL_CRLF . $errorString
            );
        } else {
            if ($result !== true) {
                throw new UnverifiedMessageException(
                    'Signed message failed signature check:' . Message::EOL_CRLF . $errorString
                );
            }
        }
        $this->setPath($verifiedFile);
        return $this;
    }
}