<?php

/*
 * This file is part of the Wid'op package.
 *
 * (c) Wid'op <contact@widop.com>
 *
 * For the full copyright and license information, please read the LICENSE
 * file that was distributed with this source code.
 */

namespace Widop\Twitter\OAuth;

use Widop\HttpAdapter\HttpResponse;

/**
 * OAuth response.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthResponse
{
    /** @const string The json format. */
    const FORMAT_JSON = 'json';

    /** @const string The str format. */
    const FORMAT_STR = 'str';

    /** @var \Widop\HttpAdapter\HttpResponse */
    private $httpResponse;

    /** @var string */
    private $format;

    /** @var array */
    private $data;

    /**
     * Creates an OAuth response.
     *
     * @param \Widop\HttpAdapter\HttpResponse $httpResponse The http response.
     *
     * @throws \InvalidArgumentException If the format is not supported.
     */
    public function __construct(HttpResponse $httpResponse, $format = self::FORMAT_JSON)
    {
        $this->httpResponse = $httpResponse;
        $this->format = $format;

        if ($format === self::FORMAT_JSON) {
            $this->data = json_decode($httpResponse->getBody(), true);
        } else if ($format === self::FORMAT_STR) {
            parse_str($httpResponse->getBody(), $this->data);
        } else {
            throw new \InvalidArgumentException(sprintf('The OAuth response format "%s" is not supported.', $format));
        }
    }

    /**
     * Gets the http response.
     *
     * @return \Widop\HttpAdapter\HttpResponse The http response.
     */
    public function getHttpResponse()
    {
        return $this->httpResponse;
    }

    /**
     * Gets the format.
     *
     * @return string The format.
     */
    public function getFormat()
    {
        return $this->format;
    }

    /**
     * Gets the rate limit limit.
     *
     * @return string The rate limit limit.
     */
    public function getRateLimitLimit()
    {
        return $this->httpResponse->getHeader('X-Rate-Limit-Limit');
    }

    /**
     * Gets the rate limit remaining.
     *
     * @return string The rate limit remaining.
     */
    public function getRateLimitRemaining()
    {
        return $this->httpResponse->getHeader('X-Rate-Limit-Remaining');
    }

    /**
     * Gets the rate limit reset.
     *
     * @return string The rate limit reset.
     */
    public function getRateLimitReset()
    {
        return $this->httpResponse->getHeader('X-Rate-Limit-Reset');
    }

    /**
     * Checks if there is data or a specific data.
     *
     * @param string $name The data name.
     *
     * @return boolean TRUE if there is data else FALSE.
     */
    public function hasData($name = null)
    {
        if ($name !== null) {
            return is_array($this->data) && isset($this->data[$name]);
        }

        return !empty($this->data);
    }

    /**
     * Gets the data or a specific data.
     *
     * @param null|string The data name.
     *
     * @return mixed The result.
     */
    public function getData($name = null)
    {
        if ($name !== null) {
            return $this->hasData($name) ? $this->data[$name] : null;
        }

        return $this->data;
    }

    /**
     * Checks if the response is valid.
     *
     * @return boolean TRUE if the response is valid else FALSE.
     */
    public function isValid()
    {
        return !$this->hasData('errors');
    }
}
