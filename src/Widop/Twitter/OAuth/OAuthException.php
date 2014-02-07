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

/**
 * OAuth exception.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthException extends \Exception
{
    /** @var \Widop\Twitter\OAuth\OAuthResponse */
    private $response;

    /**
     * Creates an OAuth exception.
     *
     * @param string                             $message  The message.
     * @param \Widop\Twitter\OAuth\OAuthResponse $response The response.
     */
    public function __construct($message, OAuthResponse $response)
    {
        parent::__construct($message, null, null);

        $this->response = $response;
    }

    /**
     * Gets the response.
     *
     * @return \Widop\Twitter\OAuth\OAuthResponse The response.
     */
    public function getResponse()
    {
        return $this->response;
    }
}
