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
 * OAuth token.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthToken implements TokenInterface, \Serializable
{
    /** @var string|null */
    private $key;

    /** @var string|null */
    private $secret;

    /**
     * Creates an OAuth token.
     *
     * @param string|null $key    The token key.
     * @param string|null $secret The token secret.
     */
    public function __construct($key = null, $secret = null)
    {
        $this->setKey($key);
        $this->setSecret($secret);
    }

    /**
     * Gets the token key.
     *
     * @return string|null The token key.
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Sets the token key.
     *
     * @param string|null $key The token key.
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * Gets the token secret.
     *
     * @return string|null The token secret.
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Sets the token secret.
     *
     * @param string|null $secret The token secret.
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * {@inheritdoc}
     */
    public function signRequest(OAuthRequest $request, OAuth $oauth)
    {
        $request->setOAuthParameter('oauth_version', $oauth->getVersion());
        $request->setOAuthParameter('oauth_consumer_key', $oauth->getConsumer()->getKey());
        $request->setOAuthParameter('oauth_signature_method', $oauth->getSignature()->getName());

        if ($this->getKey() !== null) {
            $request->setOAuthParameter('oauth_token', $this->getKey());
        }

        $request->setOAuthParameter('oauth_signature', $oauth->getSignature()->generate(
            $request,
            $oauth->getConsumer()->getSecret(),
            $this->getSecret()
        ));

        $authorization = array();

        foreach ($request->getOAuthParameters() as $key => $value) {
            $authorization[] = sprintf('%s="%s"', $key, $value);
        }

        $request->setHeader('Authorization', sprintf('OAuth %s', implode(', ', $authorization)));
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize(array($this->key, $this->secret));
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list($this->key, $this->secret) = unserialize($serialized);
    }
}
