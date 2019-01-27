<?php
/**
 * Copyright © 2019 phpas2-server. All rights reserved.
 */

namespace PHPAS2\Message;

use PHPAS2\Message;

class HeaderCollection implements \ArrayAccess, \Countable, \Iterator
{
    const EOL_CR = "\r";
    const EOL_CRLF = "\r\n";
    const EOL_LF = "\n";

    /** @var array */
    protected $headers = [];

    /** @var array */
    protected $normalizedHeaders = [];

    /** @var int */
    protected $position = 0;

    /**
     * Generate full header block as string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * Generate full header block as string.
     *
     * @param string $glue
     *
     * @return string
     */
    public function toString($glue = self::EOL_CRLF)
    {
        return implode($glue, $this->toArray());
    }

    /**
     * Add header to collection.
     *
     * @param string $name
     * @param string $value
     *
     * @return $this
     */
    public function addHeader($name, $value)
    {
        $this->headers[$name] = $value;
        $this->normalizedHeaders = null;
        return $this;
    }

    /**
     * Add headers to collection.
     *
     * @param array|HeaderCollection $headers Array of headers where the key is the header name and the value is the
     *                                        value of the header.
     *
     * @return $this
     */
    public function addHeaders($headers)
    {
        foreach ($headers as $key => $value) {
            $this->addHeader($key, $value);
        }
        return $this;
    }

    /**
     * Add headers from an AS2 message.
     *
     * @param $message
     *
     * @return $this;
     */
    public function addHeadersFromMessage($message)
    {
        $headers = $this->parseContent($message);
        if ($headers->count()) {
            foreach ($headers as $key => $value) {
                $this->addHeader($key, $value);
            }
        }
        return $this;
    }

    /**
     * Count headers.
     *
     * @return int
     */
    public function count()
    {
        return count($this->headers);
    }

    /**
     * Get current header.
     *
     * @return string|null
     */
    public function current()
    {
        return $this->headers[$this->key()];
    }

    /**
     * Check if header exists.
     *
     * @param string $name
     *
     * @return bool
     */
    public function exists($name)
    {
        return array_key_exists(strtolower($name), $this->getNormalizedHeaders());
    }

    /**
     * Get a header by name.
     *
     * @param string $name
     *
     * @return bool
     */
    public function getHeader($name)
    {
        $tmp = array_change_key_case($this->headers, CASE_LOWER);
        if (array_key_exists(strtolower($name), $tmp)) {
            return $tmp[strtolower($name)];
        }
        return false;
    }

    /**
     * Get headers with names all in one case (lowered).
     *
     * @return array
     */
    public function getNormalizedHeaders()
    {
        if (!$this->normalizedHeaders) {
            $this->normalizedHeaders = array_change_key_case($this->headers);
        }
        return $this->normalizedHeaders;
    }

    /**
     * Get name of current header.
     *
     * @return string
     */
    public function key()
    {
        return array_keys($this->headers)[$this->position];
    }

    /**
     * Move internal pointer to next header.
     *
     * @return $this;
     */
    public function next()
    {
        $this->position++;
        return $this;
    }

    /**
     * Check if offset exists.
     *
     * @param string $offset
     *
     * @return bool
     */
    public function offsetExists($offset)
    {
        return array_key_exists($this->headers, $offset);
    }

    /**
     * Get specific offset.
     *
     * @param string $offset
     *
     * @return string|null
     */
    public function offsetGet($offset)
    {
        if ($this->offsetExists($offset)) {
            return $this->headers[$offset];
        }
        return null;
    }

    /**
     * Set a specific offset value
     *
     * @param string $offset Header name
     * @param string $value  Header value
     *
     * @return $this
     */
    public function offsetSet($offset, $value)
    {
        $this->headers[$offset] = $value;
        return $this;
    }

    /**
     * Remove a specific header.
     *
     * @param string $offset Header name to remove
     *
     * @return $this
     */
    public function offsetUnset($offset)
    {
        if ($this->offsetExists($offset)) {
            unset($this->headers[$offset]);
        }
        return $this;
    }

    /**
     * Parse AS2 message for headers.
     *
     * @param string $content
     *
     * @return HeaderCollection
     */
    public function parseContent($content)
    {
        $returnVal = new HeaderCollection();
        $delimiter = strpos($content, Message::EOL_LF . Message::EOL_LF);
        if ($delimiter === false) {
            $delimiter = strpos($content, Message::EOL_CRLF . Message::EOL_CRLF);
        }
        if ($delimiter !== false) {
            $content = substr($content, 0, $delimiter);
        }
        $content = rtrim($content, "\r\n");
        $headers = [];
        $lines = explode(Message::EOL_LF, $content);
        foreach ($lines as $line) {
            $matches = [];
            if (preg_match('/(.*?):\s*(.*)/', $line, $matches)) {
                $headers[$matches[1]] = trim($matches[2], "\r\n");
                $header = $matches[1];
            } else {
                $headers[$header] .= ' ' . rtrim(trim($line), "\r\n");
            }
        }
        if ($headers) {
            $returnVal->addHeaders($headers);
        }
        /*
        preg_match_all('/(.*?):\s*(.*?\R(\s.*?\R)*)/', $content, $headers);
        if ($headers) {
            foreach ($headers[2] as $key => $value) {
                $headers[2][$key] = trim(str_replace(["\r", "\n"], ' ', $value));
            }
            if (count($headers[1]) && count($headers[1]) == count($headers[2])) {
                $returnVal->addHeaders(array_combine($headers[1], $headers[2]));
            }
        }
        */
        return $returnVal;
    }

    /**
     * Parse the current HTTP request for headers.
     *
     * @return HeaderCollection
     */
    public static function parseHttpRequest()
    {
        $returnVal = new static();
        if (!function_exists('apache_request_headers')) {
            $headers = [
                'Content-Type' => $_SERVER['CONTENT_TYPE'],
                'Content-Length' => $_SERVER['CONTENT_LENGTH']
            ];
            foreach ($_SERVER as $key => $value) {
                if (strpos($key, 'HTTP_') === 0) {
                    $key = str_replace(
                        ' ',
                        '-',
                        ucwords(strtolower(str_replace('_', ' ', substr($key, 5))))
                    );
                    $headers[$key] = trim($value, '"');
                }
            }
            $returnVal->addheaders($headers);
        } else {
            $returnVal->addHeaders(apache_request_headers());
        }
        return $returnVal;
    }

    /**
     * Remove a specific header.
     *
     * @param string $name Header name
     *
     * @return $this
     */
    public function removeHeader($name)
    {
        if (array_key_exists($name, $this->headers)) {
            unset($this->headers[$name]);
            $this->normalizedHeaders = null;
        }
        return $this;
    }

    /**
     * Reset internal pointer to beginning.
     *
     * @return $this
     */
    public function rewind()
    {
        $this->position = 0;
        return $this;
    }

    /**
     * Convert header collection to array.
     *
     * @return array
     */
    public function toArray()
    {
        $returnVal = [];
        foreach ($this->headers as $key => $value) {
            $returnVal[] = $key . ': ' . $value;
        }
        return $returnVal;
    }

    /**
     * Check if current internal position is valid.
     *
     * @return bool
     */
    public function valid()
    {
        return ($this->position >= 0 && $this->position < count($this->headers));
    }
}