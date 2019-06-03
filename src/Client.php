<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2;

use PHPAS2\Exception\InvalidMessageException;
use PHPAS2\Message\AbstractMessage;
use PHPAS2\Message\Adapter;
use PHPAS2\Message\MessageDispositionNotification;

class Client
{
    /** @var Request */
    protected $request;

    /** @var Response */
    protected $response;

    public function __construct()
    {
        $this->response = new Response();
    }

    /**
     * Get the response to a request
     *
     * @return Response
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * Send a request to the receiving partner
     *
     * @param AbstractMessage $request
     *
     * @return $this|MessageDispositionNotification
     * @throws InvalidMessageException
     */
    public function sendRequest(AbstractMessage $request)
    {
        if (!($request instanceof AbstractMessage)) {
            throw new InvalidMessageException('Unexpected message type received.  Expected Message or MDN.');
        }

        $this->request = $request;
        $headers = $this->request->getHeaders()->toArray();
        $url = parse_url($this->request->getUrl());
        $port = array_key_exists('port', $url) ? $url['port'] : 80;
        $endpoint = $url['scheme'] . '://' . $url['host'] . $url['path'];

        if (array_key_exists('query', $url) && $url['query']) {
            $endpoint .= '?' . $url['query'];
        }

        if (array_key_exists('fragment', $url) && $url['fragment']) {
            $endpoint .= '#' . $url['fragment'];
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $endpoint,
            CURLOPT_PORT => $port,
            CURLOPT_HEADER => false,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_COOKIE => 'XDEBUG_SESSION=PHPSTORM',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_BINARYTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_FRESH_CONNECT => true,
            CURLOPT_FORBID_REUSE => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $request->getContents(),
            CURLOPT_USERAGENT => Adapter::getServerSignature(),
            CURLOPT_HEADERFUNCTION => [$this->response, 'curlHeaderHandler']
        ]);

        $auth = $request->getAuthentication();
        if ($auth->hasAuthentication()) {
            curl_setopt_array($ch, [
                CURLOPT_HTTPAUTH => $auth->getMethod(),
                CURLOPT_USERPWD => urlencode($auth->getUsername()) . ':' . urlencode($auth->getPassword())
            ]);
        }

        $this->response->handle($ch);
        $this->response->setRequest($request);

        /*
         * Outgoing message and result is a Message Disposition Notification (MDN).
         */
        if (
            $request instanceof Message &&
            $request->getSendingPartner()->getIsLocal() &&
            $request->getSendingPartner()->getMdnRequest() === Partner::MDN_SYNC
        ) {
            return new MessageDispositionNotification(
                $this->getResponse()
            );
        }
        return $this;
    }
}