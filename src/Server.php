<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

use PHPAS2\Exception\InvalidPartnerException;
use PHPAS2\Message\AbstractMessage;
use PHPAS2\Message\Adapter;
use PHPAS2\Message\HeaderCollection;
use PHPAS2\Exception\InvalidMessageException;
use PHPAS2\Message\MessageDispositionNotification;

/**
 * Class Server
 *
 * @package PHPAS2
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Server
{
    const TYPE_MDN     = 'MDN';
    const TYPE_MESSAGE = 'Message';

    const MESSAGE_DECRYPTED = 'decrypted';
    const MESSAGE_PAYLOAD   = 'payload';
    const MESSAGE_RAW       = 'raw';

    /** @var  Adapter */
    protected $adapter;
    /** @var Logger */
    protected $logger;

    /**
     * Server constructor.
     *
     * @param string $receivingPartnerId Partner ID this server is to act on behalf of.
     * @param Request|null $request AS2 Request object or null to build from incoming POST request.
     * @return AbstractMessage
     */
    public function __construct($receivingPartnerId, $request=null) {
        $this->adapter = new Adapter();
        $this->logger  = Logger::getInstance();

        $receivingPartner = new Partner();
        $receivingPartner->loadFromConfig($receivingPartnerId);

        ob_start();

        $error = null;
        $mdn = null;
        $object = null;

        try {
            if ($request === null) {
                $data = file_get_contents('php://input');
                if (!$data) {
                    throw new InvalidMessageException('An empty AS2 message was received');
                }

                $headers = HeaderCollection::parseHttpRequest();

                if (!$headers->count()) {
                    throw new InvalidMessageException('AS2 message without headers was received');
                }

                if (!$headers->exists('message-id')) {
                    throw new InvalidMessageException('Missing "mesage-id" header');
                }

                if (!$headers->exists('as2-from')) {
                    throw new InvalidMessageException('Missing "as2-from" header');
                }

                if (!$headers->exists('as2-to')) {
                    throw new InvalidMessageException('Missing "as2-to" header');
                }

                $filename = $this->saveMessage($data, $headers);

                $request = new Request($data, $headers);
                if (trim($headers->getHeader('as2-from')) === trim($headers->getHeader('as2-to'))) {
                    $this->logger->log(
                        Logger::LEVEL_WARN,
                        'The AS2-To and AS2-From are identical',
                        $headers->getHeader('message-id')
                    );
                }

                $expectedPartnerId = $receivingPartner->getId();
                if ($headers->getHeader('as2-to') != $expectedPartnerId) {
                    $this->logger->log(
                        Logger::LEVEL_FATAL,
                        'Unknown recipient "' . $headers->getHeader('as2-to') . '"; expected "'
                            . $receivingPartner->getId() . '".',
                        $headers->getHeader('message-id')
                    );
                    throw new InvalidPartnerException('Unknown AS2 recipient');
                }

                $this->logger->log(
                    Logger::LEVEL_INFO,
                    sprintf(
                        'Incoming AS2 message transmission.  Raw message size: %s KB',
                        round(strlen($data)/1024, 2)
                    ),
                    $headers->getHeader('message-id')
                );

                $decrypted = $request->decrypt();
                if ($decrypted) {
                    $content = file_get_contents($decrypted);
                    $this->saveMessage($content, [], $filename.'.decrypted', 'decrypted');
                }
            }
            else if (!($request instanceof Request)) {
                throw new InvalidMessageException('Unexpected error occurred while handling AS2 message: bad format');
            }
            else {
                $headers = $request->getHeaders();
            }

            $object = $request->getObject();
        }
        catch (\Exception $e) {
            $error = $e;
        }

        if ($object instanceof Message || (!is_null($error) && !($object instanceof MessageDispositionNotification))) {
            $objectType = self::TYPE_MESSAGE;
            $this->logger->log(Logger::LEVEL_INFO, 'Incoming transmission is a Message');

            try {
                if (!is_null($error)) {
                    throw $error;
                }

                $object->decode();
                $files = $object->getFiles();
                $this->logger->log(
                    Logger::LEVEL_INFO,
                    sprintf(
                        '%d payload%s found in transmission',
                        count($files),
                        (count($files) == 1 ? '' : 's')
                    )
                );

                foreach ($files as $key => $file) {
                    $content = file_get_contents($file['path']);
                    $this->logger->log(
                        Logger::LEVEL_INFO,
                        sprintf(
                            'Payload #%d : %f KB / "%s"',
                            $key + 1,
                            round(strlen($content) / 1024, 2),
                            $file['filename']
                        )
                    );

                    $this->saveMessage($content, [], $filename . '.payload-' . $key, self::MESSAGE_PAYLOAD);
                }

                $mdn = $object->generateMDN();
                $mdn->encode($object);
            }
            catch (\Exception $e) {
                $mdn = new MessageDispositionNotification();
                $mdn->setMessage($e->getMessage())
                    ->setSendingPartner($headers->getHeader('as2-from'))
                    ->setReceivingPartner($receivingPartner)
                    ->setAttribute('original-message-id', $headers->getHeader('message-id'));
                $mdn->encode();
            }
        }
        else if ($object instanceof MessageDispositionNotification) {
            $objectType = self::TYPE_MDN;
            $this->logger->log(Logger::LEVEL_INFO, 'Incoming transmission is an MDN');
        }
        else {
            $this->logger->log(Logger::LEVEL_ERROR, 'Malformed data');
        }

        try {
            if ($request instanceof Request) {
                $params = [
                    'from'   => $headers->getHeader('as2-from'),
                    'to'     => $headers->getHeader('as2-to'),
                    'status' => '',
                    'data'   => ''
                ];

                if ($error) {
                    $params['status'] = 'ERROR';
                    $params['data']   = [ 'object' => $object, 'error' => $error ];
                }
                else {
                    $params['status'] = 'OK';
                    $params['data']   = [ 'object' => $object, 'error' => null ];
                }

                // TODO: Potentially fire off an event for listeners to react to

                if ($request->getReceivingPartner() instanceof Partner) {
                    // TODO: Call "onReceived" method
                }

                if ($request->getSendingPartner() instanceof Partner) {
                    // TODO: Call "onSent" method
                }
            }
        }
        catch (\Exception $e) {
            $error = $e;
        }

        if (!is_null($error) && $objectType == self::TYPE_MESSAGE) {
            $mdn = new MessageDispositionNotification($e);
            $mdn->setSendingPartner($headers->getHeader('as2-to'))
                ->setReceivingPartner($headers->getHeader('as2-from'))
                ->setAttribute('original-message-id', $headers->getHeader('message-id'))
                ->getHeaders()->addHeader('Original-Message-Id', $headers->getHeader('message-id'))
                ;
            $mdn->encode();
        }

        if (!is_null($mdn)) {
            if (!$headers->getHeader('receipt-delivery-option')) {
                ob_end_clean();

                foreach ($mdn->getHeaders() as $key => $value) {
                    $header = str_replace(array("\r", "\n", "\r\n"), '', $key . ': ' . $value);
                    header($header);
                }

                // TODO: Find a way to return this instead of echoing from here
                echo $mdn->getContents();

                $this->logger->log(Logger::LEVEL_INFO, 'An AS2 MDN has been sent');
            }
            else {
                $this->closeConnectionAndWait(5);

                $client = new Client();
                $result = $client->sendRequest($mdn);
                if ($result['info']['http_code'] == '200') {
                    $this->logger->log(Logger::LEVEL_INFO, 'An AS2 MDN has been sent');
                }
                else {
                    $this->logger->log(
                        Logger::LEVEL_ERROR,
                        sprintf(
                            'An error occurred while sending an MDN: HTTP %s',
                            $result['info']['http_code']
                        )
                    );
                }
            }
        }

        return $request;
    }

    /**
     * Close current HTTP connection and wait to send MDN
     *
     * @param integer $sleep Number of seconds to wait before sending MDN
     */
    protected function closeConnectionAndWait($sleep) {
        ob_end_clean();
        header("Connection: close");
        header("Content-Encoding: none");
        ignore_user_abort(true);
        ob_start();
        $size = ob_get_length();
        header("Content-Length: {$size}");
        ob_end_flush();
        flush();
        ob_end_clean();
        session_write_close();

        sleep($sleep);
    }

    /**
     * Save incoming messages to filesystem.
     *
     * @param string $data
     * @param HeaderCollection $headers
     * @param string $filename
     * @param string $type Values: raw | decrypted | payload
     * @return string
     */
    protected function saveMessage($data, HeaderCollection $headers, $filename='', $type=self::MESSAGE_RAW) {
        $dir = $this->adapter->getMessagesDir('inbox');

        if (!$filename) {
            list($micro, ) = explode(' ', microtime());
            $micro = str_pad(round($micro * 1000), 3, '0');
            $host = ($_SERVER['REMOTE_ADDR'] ? $_SERVER['REMOTE_ADDR'] : 'unknownhost');
            $filename = date('YmdHis') . '-' . $micro . '_' . $host . '.as2';
        }

        switch ($type) {
            case self::MESSAGE_RAW:
                file_put_contents($dir . $filename, $data);
                if ($headers->count()) {
                    file_put_contents($dir . $filename . '.headers', $headers->__toString());
                }
                break;

            case self::MESSAGE_DECRYPTED:
            case self::MESSAGE_PAYLOAD:
                file_put_contents($dir . $filename, $data);
                break;
        }

        return $filename;
    }
}