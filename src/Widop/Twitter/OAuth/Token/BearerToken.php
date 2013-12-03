<?php

/*
 * This file is part of the Wid'op package.
 *
 * (c) Wid'op <contact@widop.com>
 *
 * For the full copyright and license information, please read the LICENSE
 * file that was distributed with this source code.
 */

namespace Widop\Twitter\OAuth\Token;

use Widop\Twitter\OAuth\OAuth;
use Widop\Twitter\OAuth\OAuthRequest;

/**
 * Bearer token.
 *
 * @author Geoffrey Brier <geoffrey.brier@gmail.com>
 */
class BearerToken implements TokenInterface, \Serializable
{
    /** @var string */
    private $value;

    /**
     * Creates a bearer token.
     *
     * @param string $value The application access token.
     */
    public function __construct($value)
    {
        $this->setValue($value);
    }

    /**
     * Gets the access token.
     *
     * @return string The access token.
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Sets the access token.
     *
     * @param string $value The access token.
     */
    public function setValue($value)
    {
        $this->value = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function signRequest(OAuthRequest $request, OAuth $oauth)
    {
        $request->setHeader('Authorization', sprintf('Bearer %s', $this->getValue()));
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize($this->value);
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        $this->value = unserialize($serialized);
    }
}
