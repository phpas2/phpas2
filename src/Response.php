<?php
/**
 * Copyright 2017 PHPAS2
 *
 * PHP Version ~5.6.5|~7.0.0
 *
 * @author   Brett <bap14@users.noreply.github.com>
 */

namespace PHPAS2;

use PHPAS2\Exception\HttpErrorResponseException;

/**
 * Class Response
 *
 * @package PHPAS2
 * @author   Brett <bap14@users.noreply.github.com>
 * @license  GPL-3.0
 * @link     https://phpas2.github.io/
 */
class Response
{
    protected $as2response;
    protected $content;
    protected $error;
    protected $headers      = [];
    protected $index        = 0;
    protected $info;
    protected $mdnResponse;

    /**
     * Capture all headers used during request, including redirects
     *
     * @param $curl
     * @param $header
     * @return int
     */
    public function curlHeaderHandler($curl, $header) {
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
     * Get response
     *
     * @return mixed
     */
    public function getAs2Response() {
        return $this->as2response;
    }

    /**
     * Get error from cURL request
     *
     * @return string|null
     */
    public function getError() {
        return $this->error;
    }

    /**
     * Get all headers from all redirects
     *
     * @return array
     */
    public function getHeaders() {
        return $this->headers;
    }

    /**
     * Get cURL info from last request
     *
     * @return array|null
     */
    public function getInfo() {
        return $this->info;
    }

    /**
     * Get the final response of any forwarded or redirected responses
     *
     * @return array
     */
    public function getLastResponse() {
        return [
            'headers' => $this->headers[count($this->headers)-1],
            'content' => $this->content
        ];
    }

    /**
     * Handle the configured cURL request and build a response object from it
     *
     * @param $ch
     * @return $this
     * @throws HttpErrorResponseException
     */
    public function handle($ch) {
        $this->content = curl_exec($ch);
        $this->info    = curl_getinfo($ch);
        $this->error   = curl_error($ch);
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
    public function sendMDN() {
        $responseHeaders = $this->as2response->getLastResponse()['headers'];
        $this->as2response = new Request($this, $responseHeaders);
        $this->as2response->getObject();
        $this->as2response->decode();
    }
}