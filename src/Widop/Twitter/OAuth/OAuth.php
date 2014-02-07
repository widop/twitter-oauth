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

use Widop\HttpAdapter\HttpAdapterInterface;
use Widop\Twitter\OAuth\Token\BasicToken;
use Widop\Twitter\OAuth\Token\BearerToken;
use Widop\Twitter\OAuth\Token\OAuthToken;
use Widop\Twitter\OAuth\Token\TokenInterface;
use Widop\Twitter\OAuth\Signature\OAuthSignatureInterface;

/**
 * OAuth.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuth
{
    /** @var \Widop\HttpAdapter\HttpAdapterInterface */
    private $httpAdapter;

    /** @var string */
    private $url;

    /** @var \Widop\Twitter\OAuth\OAuthConsumer */
    private $consumer;

    /** @var \Widop\Twitter\OAuth\Signature\OAuthSignatureInterface */
    private $signature;

    /** @var string */
    private $version;

    /**
     * Creates an OAuth client.
     *
     * @param \Widop\HttpAdapter\HttpAdapterInterface                $httpAdapter The http adapter.
     * @param \Widop\Twitter\OAuth\OAuthConsumer                     $consumer    The OAuth consumer.
     * @param \Widop\Twitter\OAuth\Signature\OAuthSignatureInterface $signature   The OAuth signature.
     * @param string                                                 $url         The OAuth base url.
     * @param string                                                 $version     The OAuth version.
     */
    public function __construct(
        HttpAdapterInterface $httpAdapter,
        OAuthConsumer $consumer,
        OAuthSignatureInterface $signature,
        $url = 'https://api.twitter.com',
        $version = '1.0'
    ) {
        $this->setHttpAdapter($httpAdapter);
        $this->setUrl($url);
        $this->setConsumer($consumer);
        $this->setSignature($signature);
        $this->setVersion($version);
    }

    /**
     * Gets the http adapter.
     *
     * @return \Widop\HttpAdapter\HttpAdapterInterface The http adapter.
     */
    public function getHttpAdapter()
    {
        return $this->httpAdapter;
    }

    /**
     * Sets the http adapter.
     *
     * @param \Widop\HttpAdapter\HttpAdapterInterface $httpAdapter The http adapter.
     */
    public function setHttpAdapter(HttpAdapterInterface $httpAdapter)
    {
        $this->httpAdapter = $httpAdapter;
    }

    /**
     * Gets the OAuth base url.
     *
     * @return string The OAuth base url.
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * Sets the OAuth base url.
     *
     * @param string $url The OAuth base url.
     */
    public function setUrl($url)
    {
        $this->url = $url;
    }

    /**
     * Gets the OAuth consumer.
     *
     * @return \Widop\Twitter\OAuth\OAuthConsumer The OAuth consumer.
     */
    public function getConsumer()
    {
        return $this->consumer;
    }

    /**
     * Sets the OAuth consumer.
     *
     * @param \Widop\Twitter\OAuth\OAuthConsumer $consumer
     */
    public function setConsumer(OAuthConsumer $consumer)
    {
        $this->consumer = $consumer;
    }

    /**
     * Gets the OAuth signature.
     *
     * @return \Widop\Twitter\OAuth\Signature\OAuthSignatureInterface The OAuth signature.
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * Sets the OAuth signature.
     *
     * @param \Widop\Twitter\OAuth\Signature\OAuthSignatureInterface $signature The OAuth signature.
     */
    public function setSignature(OAuthSignatureInterface $signature)
    {
        $this->signature = $signature;
    }

    /**
     * Gets the OAuth version.
     *
     * @return string The OAuth version.
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * Sets the OAuth version.
     *
     * @param string $version The OAuth version.
     */
    public function setVersion($version)
    {
        $this->version = $version;
    }

    /**
     * Gets a request token.
     *
     * @param string $callback The OAuth callback.
     *
     * @return \Widop\Twitter\OAuth\Token\OAuthToken The request token.
     */
    public function getRequestToken($callback = 'oob')
    {
        $request = $this->createRequest('/oauth/request_token', OAuthResponse::FORMAT_STR);
        $request->setOAuthParameter('oauth_callback', $callback);
        $this->signRequest($request, new OAuthToken());

        return $this->createOAuthToken($this->sendRequest($request));
    }

    /**
     * Gets the authorize url.
     *
     * @param \Widop\Twitter\OAuth\Token\OAuthToken $requestToken The request token.
     *
     * @return string The authorize url.
     */
    public function getAuthorizeUrl(OAuthToken $requestToken)
    {
        return sprintf('%s/oauth/authorize?oauth_token=%s', $this->getUrl(), $requestToken->getKey());
    }

    /**
     * Gets the authenticate url.
     *
     * @param \Widop\Twitter\OAuth\Token\OAuthToken $requestToken The request token.
     *
     * @return string The authenticate url.
     */
    public function getAuthenticateUrl(OAuthToken $requestToken)
    {
        return sprintf('%s/oauth/authenticate?oauth_token=%s', $this->getUrl(), $requestToken->getKey());
    }

    /**
     * Gets an access token.
     *
     * @param \Widop\Twitter\OAuth\Token\OAuthToken $requestToken The request token.
     * @param string                                $verifier     The OAuth verifier.
     *
     * @return \Widop\Twitter\OAuth\Token\OAuthToken The access token.
     */
    public function getAccessToken(OAuthToken $requestToken, $verifier)
    {
        $request = $this->createRequest('/oauth/access_token', OAuthResponse::FORMAT_STR);
        $request->setOAuthParameter('oauth_verifier', $verifier);
        $this->signRequest($request, $requestToken);

        return $this->createOAuthToken($this->sendRequest($request));
    }

    /**
     * Gets a bearer token.
     *
     * @param string $grantType The OAuth grant type.
     *
     * @return \Widop\Twitter\OAuth\Token\BearerToken The bearer token.
     */
    public function getBearerToken($grantType = 'client_credentials')
    {
        $request = $this->createRequest('/oauth2/token');
        $request->setPostParameter('grant_type', $grantType);
        $this->signRequest($request, new BasicToken());

        return $this->createBearerToken($this->sendRequest($request));
    }

    /**
     * Invalidates the bearer token.
     *
     * @param \Widop\Twitter\OAuth\BearerToken $token The bearer token.
     *
     * @throws \RuntimeException If the token was not invalidated.
     */
    public function invalidateBearerToken(BearerToken $token)
    {
        $request = $this->createRequest('/oauth2/invalidate_token');
        $request->setPostParameter('access_token', $token->getValue());
        $this->signRequest($request, new BasicToken());

        $response = $this->sendRequest($request);

        if ($token->getValue() !== $response->getData('access_token')) {
            throw new OAuthException('An error occured when invalidating the bearer token.', $response);
        }
    }

    /**
     * Signs a request.
     *
     * @param \Widop\Twitter\OAuth\OAuthRequest   $request The request.
     * @param \Widop\Twitter\OAuth\TokenInterface $token   The token.
     */
    public function signRequest(OAuthRequest $request, TokenInterface $token)
    {
        $token->signRequest($request, $this);
    }

    /**
     * Sends an OAuth request.
     *
     * @param \Widop\Twitter\OAuth\OAuthRequest $request The OAuth request.
     *
     * @throws \RuntimeException If the request method is not supported.
     *
     * @return \Widop\Twitter\OAuth\OAuthResponse The OAuth response.
     */
    public function sendRequest(OAuthRequest $request)
    {
        switch ($request->getMethod()) {
            case OAuthRequest::METHOD_GET:
                $httpResponse = $this->httpAdapter->getContent($request->getUrl(), $request->getHeaders());
                break;

            case OAuthRequest::METHOD_POST:
                $postParameters = array();
                foreach ($request->getPostParameters() as $name => $value) {
                    $postParameters[rawurldecode($name)] = rawurldecode($value);
                }

                $httpResponse = $this->httpAdapter->postContent(
                    $request->getUrl(),
                    $request->getHeaders(),
                    $postParameters,
                    $request->getFileParameters()
                );
                break;

            default:
                throw new \RuntimeException(sprintf(
                    'The request method "%s" is not supported.',
                    $request->getMethod()
                ));
        }

        $response = new OAuthResponse($httpResponse, $request->getResponseFormat());

        if (!$response->isValid()) {
            throw new OAuthException('The http response is not valid.', $response);
        }

        return $response;
    }

    /**
     * Creates an OAuth request.
     *
     * @param string $path           The OAuth path.
     * @param string $responseFormat The response format.
     *
     * @return \Widop\Twitter\OAuth\OAuthRequest The OAuth request.
     */
    private function createRequest($path, $responseFormat = OAuthResponse::FORMAT_JSON)
    {
        $request = new OAuthRequest();
        $request->setBaseUrl($this->getUrl());
        $request->setPath($path);
        $request->setMethod(OAuthRequest::METHOD_POST);
        $request->setResponseFormat($responseFormat);

        return $request;
    }

    /**
     * Creates an oauth token according to an OAuth response.
     *
     * @param \Widop\Twitter\OAuth\OAuthResponse $response The OAuth response.
     *
     * @throws \Widop\Twitter\OAuth\OAuthException If the token cannot be created.
     *
     * @return \Widop\Twitter\OAuth\Token\OAuthToken The OAuth token.
     */
    private function createOAuthToken(OAuthResponse $response)
    {
        if (!$response->hasData('oauth_token') || !$response->hasData('oauth_token_secret')) {
            throw new OAuthException('An error occured when creating the OAuth token.', $response);
        }

        return new OAuthToken($response->getData('oauth_token'), $response->getData('oauth_token_secret'));
    }

    /**
     * Creates a bearer token according to an OAuth response.
     *
     * @param \Widop\Twitter\OAuth\OAuthResponse $response The OAuth response.
     *
     * @throws \Widop\Twitter\OAuth\OAuthException If the token cannot be created.
     *
     * @return \Widop\Twitter\OAuth\Token\BearerToken The Bearer token.
     */
    private function createBearerToken(OAuthResponse $response)
    {
        if (!$response->hasData('token_type') || !$response->hasData('access_token')) {
            throw new OAuthException('An error occured when creating the bearer token.', $response);
        }

        return new BearerToken($response->getData('access_token'));
    }
}
