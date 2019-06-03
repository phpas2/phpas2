<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2;

use PHPAS2\Exception\HttpErrorResponseException;
use PHPAS2\Message\AbstractMessage;

class Response
{
    protected $content;
    protected $error;
    protected $headers = [];
    protected $index = 0;
    protected $info;
    protected $mdnResponse;
    /** @var  Request */
    protected $request;

    /**
     * Get contents of response.
     *
     * @return mixed
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * Capture all headers used during request, including redirects
     *
     * @param $curl
     * @param $header
     *
     * @return int
     */
    public function curlHeaderHandler($curl, $header)
    {
        if (
            !mb_strlen(trim($header)) &&
            isset($this->headers[$this->index]) &&
            $this->headers[$this->index]
        ) {
            $this->index++;
        } else {
            if (strstr($header, ':') !== false) {
                list($name, $val) = explode(':', $header, 2);
                $this->headers[$this->index][trim(strtolower($name))] = trim($val);
            }
        }
        return mb_strlen($header);
    }

    /**
     * Get MDN response
     *
     * @return mixed
     */
    public function getMdnResponse()
    {
        return $this->mdnResponse;
    }

    /**
     * Get error from cURL request
     *
     * @return string|null
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * Get all headers from all redirects
     *
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Get cURL info from last request
     *
     * @return array|null
     */
    public function getInfo()
    {
        return $this->info;
    }

    /**
     * Get the final response of any forwarded or redirected responses
     *
     * @return array
     */
    public function getLastResponse()
    {
        return [
            'headers' => $this->headers[count($this->headers) - 1],
            'content' => $this->content
        ];
    }

    /**
     * Get the original request object.
     *
     * @return Request
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Handle the configured cURL request and build a response object from it
     *
     * @param $ch
     *
     * @return $this
     * @throws HttpErrorResponseException
     */
    public function handle($ch)
    {
        $this->content = curl_exec($ch);
        $this->info = curl_getinfo($ch);
        $this->error = curl_error($ch);
        curl_close($ch);
        if ($this->info['http_code'] != 200) {
            throw new HttpErrorResponseException(
                sprintf('Expected 200 status, received %s instead', $this->info['http_code'])
            );
        }
        if ($this->error) {
            throw new HttpErrorResponseException($this->error);
        }
        return $this;
    }

    /**
     * Send MDN
     */
    public function sendMDN()
    {
        $responseHeaders = $this->getLastResponse()['headers'];
        $this->mdnResponse = new Request($this, $responseHeaders);
        $this->mdnResponse->getObject();
        $this->mdnResponse->decode();
    }

    /**
     * Set the original request object for this response.
     *
     * @param AbstractMessage $request
     *
     * @return $this
     */
    public function setRequest(AbstractMessage $request)
    {
        $this->request = $request;
        return $this;
    }
}