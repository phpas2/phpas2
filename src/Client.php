<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

use PHPAS2\Exception\InvalidMessageException;
use PHPAS2\Message\AbstractMessage;
use PHPAS2\Message\Adapter;

/**
 * Class Client
 *
 * @package PHPAS2
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Client
{
    protected $request;
    protected $response;

    /**
     * Client constructor.
     *
     *
     */
    public function __construct() {
        $this->response = new Response();
    }

    /**
     * Get the response to a request
     *
     * @return Response
     */
    public function getResponse() {
        return $this->response;
    }

    /**
     * Send a request to the receiving partner
     *
     * @param AbstractMessage $request
     *
     * @return $this
     * @throws InvalidMessageException
     */
    public function sendRequest(AbstractMessage $request) {
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
            CURLOPT_URL            => $endpoint,
            CURLOPT_PORT           => $port,
            CURLOPT_HEADER         => false,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_BINARYTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 10,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_FRESH_CONNECT  => true,
            CURLOPT_FORBID_REUSE   => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $request->getContents(),
            CURLOPT_USERAGENT      => Adapter::getServerSignature(),
            CURLOPT_HEADERFUNCTION => array($this->response, 'curlHeaderHandler')
        ]);

        $auth = $request->getAuthentication();
        if ($auth->hasAuthentication()) {
            curl_setopt_array($ch, [
                CURLOPT_HTTPAUTH => $auth->getMethod(),
                CURLOPT_USERPWD  => urlencode($auth->getUsername()) . ':' . urlencode($auth->getPassword())
            ]);
        }

        $this->response->handle($ch);

        // TODO: Determine if this is necessary here since Outgoing messages don't send MDNs, only incoming messages get an MDN
        /*
        if (
            $request instanceof Message &&
            $request->getReceivingPartner()->getMdnRequest() == Partner::MDN_SYNC
        ) {
            $this->response->sendMDN();
        }
        */

        return $this;
    }
}