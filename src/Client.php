<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

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

    public function __construct() {
        $this->response = new Response();
    }

    public function getResponse() {
        return $this->response;
    }

    public function sendRequest(MessageAbstract $request) {
        if (!($request instanceof MessageAbstract)) {
            throw new InvalidMessageException('Unexpected message type received.  Expected Message or MDN.');
        }

        $this->request = $request;

        $headers = $request->getHeaders()->toArray();

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $request->getUrl(),
            CURLOPT_HEADER         => false,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_BINARYTRANSFER => true,
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

        if (
            $request instanceof MessageAbstract &&
            $request->getReceivingPartner()->getMdnRequest() == Partner::ACKNOWLEDGE_SYNC
        ) {
            $this->response->sendMDN();
        }

        return $this;
    }
}