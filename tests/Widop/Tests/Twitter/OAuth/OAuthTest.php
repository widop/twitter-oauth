<?php

/*
 * This file is part of the Wid'op package.
 *
 * (c) Wid'op <contact@widop.com>
 *
 * For the full copyright and license information, please read the LICENSE
 * file that was distributed with this source code.
 */

namespace Widop\Tests\Twitter\OAuth;

use Widop\Twitter\OAuth\OAuth;
use Widop\Twitter\OAuth\OAuthRequest;
use Widop\Twitter\OAuth\OAuthResponse;
use Widop\Twitter\OAuth\Token\OAuthToken;

/**
 * OAuth test.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\Twitter\OAuth\OAuth */
    private $oauth;

    /** @var \Widop\HttpAdapter\HttpAdapterInterface */
    private $httpAdapter;

    /** @var \Widop\Twitter\OAuth\OAuthConsumer */
    private $consumer;

    /** @var \Widop\Twitter\OAuth\Signature\OAuthSignatureInterface */
    private $signature;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->httpAdapter = $this->getMock('Widop\HttpAdapter\HttpAdapterInterface');

        $this->consumer = $this->getMockBuilder('Widop\Twitter\OAuth\OAuthConsumer')
            ->disableOriginalConstructor()
            ->getMock();

        $this->consumer
            ->expects($this->any())
            ->method('getKey')
            ->will($this->returnValue('consumer_key'));

        $this->consumer
            ->expects($this->any())
            ->method('getSecret')
            ->will($this->returnValue('consumer_secret'));

        $this->signature = $this->getMock('Widop\Twitter\OAuth\Signature\OAuthSignatureInterface');

        $this->signature
            ->expects($this->any())
            ->method('generate')
            ->with(
                $this->isInstanceOf('Widop\Twitter\OAuth\OAuthRequest'),
                $this->equalTo('consumer_secret')
            )
            ->will($this->returnValue('signature'));

        $this->signature
            ->expects($this->any())
            ->method('getName')
            ->will($this->returnValue('signature-name'));

        $this->oauth = new OAuth($this->httpAdapter, $this->consumer, $this->signature);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        unset($this->signature);
        unset($this->consumer);
        unset($this->httpAdapter);
        unset($this->oauth);
    }

    public function testDefaultState()
    {
        $this->assertSame($this->httpAdapter, $this->oauth->getHttpAdapter());
        $this->assertSame($this->consumer, $this->oauth->getConsumer());
        $this->assertSame($this->signature, $this->oauth->getSignature());
        $this->assertSame('https://api.twitter.com', $this->oauth->getUrl());
        $this->assertSame('1.0', $this->oauth->getVersion());
    }

    public function testInitialState()
    {
        $this->oauth = new OAuth($this->httpAdapter, $this->consumer, $this->signature, 'https://my-url.com', '2.0');

        $this->assertSame('https://my-url.com', $this->oauth->getUrl());
        $this->assertSame('2.0', $this->oauth->getVersion());
    }

    public function testHttpAdapter()
    {
        $httpAdapter = $this->getMock('Widop\HttpAdapter\HttpAdapterInterface');
        $this->oauth->setHttpAdapter($httpAdapter);

        $this->assertSame($httpAdapter, $this->oauth->getHttpAdapter());
    }

    public function testConsumer()
    {
        $consumer = $this->getMockBuilder('Widop\Twitter\OAuth\OAuthConsumer')
            ->disableOriginalConstructor()
            ->getMock();

        $this->oauth->setConsumer($consumer);

        $this->assertSame($consumer, $this->oauth->getConsumer());
    }

    public function testSignature()
    {
        $signature = $this->getMock('Widop\Twitter\OAuth\Signature\OAuthSignatureInterface');
        $this->oauth->setSignature($signature);

        $this->assertSame($signature, $this->oauth->getSignature());
    }

    public function testUrl()
    {
        $this->oauth->setUrl('https://my-url.com');

        $this->assertSame('https://my-url.com', $this->oauth->getUrl());
    }

    public function testVersion()
    {
        $this->oauth->setVersion('2.0');

        $this->assertSame('2.0', $this->oauth->getVersion());
    }

    public function testSignRequest()
    {
        $request = $this->getMock('Widop\Twitter\OAuth\OAuthRequest');

        $token = $this->getMockBuilder('Widop\Twitter\OAuth\Token\OAuthToken')
            ->disableOriginalConstructor()
            ->getMock();

        $token
            ->expects($this->once())
            ->method('signRequest')
            ->with($this->identicalTo($request), $this->identicalTo($this->oauth));

        $this->oauth->signRequest($request, $token);
    }

    public function testGetRequestTokenWithoutCallback()
    {
        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('oauth_token=token_key&oauth_token_secret=token_secret'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth/request_token'),
                $this->callback(function($headers) {
                    try {
                        \PHPUnit_Framework_Assert::assertArrayHasKey('Authorization', $headers);
                        \PHPUnit_Framework_Assert::assertRegExp(
                            '#OAuth oauth_callback="oob", oauth_version="1.0", oauth_consumer_key="consumer_key", oauth_signature_method="signature-name", oauth_signature="signature", oauth_nonce="(.*)", oauth_timestamp="(.*)"#',
                            $headers['Authorization']
                        );

                        return true;
                    } catch (\Exception $e) {
                        return false;
                    }
                })
            )
            ->will($this->returnValue($response));

        $token = $this->oauth->getRequestToken();

        $this->assertInstanceOf('Widop\Twitter\OAuth\Token\OAuthToken', $token);
        $this->assertSame('token_key', $token->getKey());
        $this->assertSame('token_secret', $token->getSecret());
    }

    public function testGetRequestTokenWithCallback()
    {
        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('oauth_token=token_key&oauth_token_secret=token_secret'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth/request_token'),
                $this->callback(function($headers) {
                    try {
                        \PHPUnit_Framework_Assert::assertArrayHasKey('Authorization', $headers);
                        \PHPUnit_Framework_Assert::assertRegExp(
                            '#OAuth oauth_callback="http%3A%2F%2Fmy-url.com%2Fcallback", oauth_version="1.0", oauth_consumer_key="consumer_key", oauth_signature_method="signature-name", oauth_signature="signature", oauth_nonce="(.*)", oauth_timestamp="(.*)"#',
                            $headers['Authorization']
                        );

                        return true;
                    } catch (\Exception $e) {
                        return false;
                    }
                })
            )
            ->will($this->returnValue($response));

        $token = $this->oauth->getRequestToken('http://my-url.com/callback');

        $this->assertInstanceOf('Widop\Twitter\OAuth\Token\OAuthToken', $token);
        $this->assertSame('token_key', $token->getKey());
        $this->assertSame('token_secret', $token->getSecret());
    }

    public function testGetAuthorizeUrl()
    {
        $token = $this->getMockBuilder('Widop\Twitter\OAuth\Token\OAuthToken')
            ->disableOriginalConstructor()
            ->getMock();

        $token
            ->expects($this->once())
            ->method('getKey')
            ->will($this->returnValue('token_key'));

        $this->assertSame(
            'https://api.twitter.com/oauth/authorize?oauth_token=token_key',
            $this->oauth->getAuthorizeUrl($token)
        );
    }

    public function testGetAuthenticateUrl()
    {
        $token = $this->getMockBuilder('Widop\Twitter\OAuth\Token\OAuthToken')
            ->disableOriginalConstructor()
            ->getMock();

        $token
            ->expects($this->once())
            ->method('getKey')
            ->will($this->returnValue('token_key'));

        $this->assertSame(
            'https://api.twitter.com/oauth/authenticate?oauth_token=token_key',
            $this->oauth->getAuthenticateUrl($token)
        );
    }

    public function testGetAccessToken()
    {
        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('oauth_token=token_key&oauth_token_secret=token_secret'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth/access_token'),
                $this->callback(function($headers) {
                    try {
                        \PHPUnit_Framework_Assert::assertArrayHasKey('Authorization', $headers);
                        \PHPUnit_Framework_Assert::assertRegExp(
                            '#OAuth oauth_verifier="oauth_verifier", oauth_version="1.0", oauth_consumer_key="consumer_key", oauth_signature_method="signature-name", oauth_token="token_key", oauth_signature="signature", oauth_nonce="(.*)", oauth_timestamp="(.*)"#',
                            $headers['Authorization']
                        );

                        return true;
                    } catch (\Exception $e) {
                        return false;
                    }
                })
            )
            ->will($this->returnValue($response));

        $accessToken = $this->oauth->getAccessToken(new OAuthToken('token_key', 'token_secret'), 'oauth_verifier');

        $this->assertInstanceOf('Widop\Twitter\OAuth\Token\OAuthToken', $accessToken);
        $this->assertSame('token_key', $accessToken->getKey());
        $this->assertSame('token_secret', $accessToken->getSecret());
    }

    /**
     * @expectedException \Widop\Twitter\OAuth\OAuthException
     * @expectedExceptionMessage An error occured when creating the bearer token.
     */
    public function testGetBearerTokenWithInvalidResult()
    {
        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"foo":"bar"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth2/token'),
                $this->equalTo(array('Authorization' => 'Basic Y29uc3VtZXJfa2V5OmNvbnN1bWVyX3NlY3JldA==')),
                $this->equalTo(array('grant_type' => 'oauth_verifier'))
            )
            ->will($this->returnValue($response));

        $this->oauth->getBearerToken('oauth_verifier');
    }

    public function testGetBearerToken()
    {
        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"token_type":"bearer","access_token":"foo"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth2/token'),
                $this->equalTo(array('Authorization' => 'Basic Y29uc3VtZXJfa2V5OmNvbnN1bWVyX3NlY3JldA==')),
                $this->equalTo(array('grant_type' => 'oauth_verifier'))
            )
            ->will($this->returnValue($response));

        $bearerToken = $this->oauth->getBearerToken('oauth_verifier');

        $this->assertInstanceOf('Widop\Twitter\OAuth\Token\BearerToken', $bearerToken);
        $this->assertSame('foo', $bearerToken->getValue());
    }

    public function testInvalidateBearerToken()
    {
        $bearerToken = $this->getMockBuilder('Widop\Twitter\OAuth\Token\BearerToken')
            ->disableOriginalConstructor()
            ->getMock();

        $bearerToken
            ->expects($this->exactly(2))
            ->method('getValue')
            ->will($this->returnValue('token'));

        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"access_token":"token"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth2/invalidate_token'),
                $this->equalTo(array('Authorization' => 'Basic Y29uc3VtZXJfa2V5OmNvbnN1bWVyX3NlY3JldA==')),
                $this->equalTo(array('access_token' => 'token'))
            )
            ->will($this->returnValue($response));

        $this->oauth->invalidateBearerToken($bearerToken);
    }

    /**
     * @expectedException \Widop\Twitter\OAuth\OAuthException
     * @expectedExceptionMessage An error occured when invalidating the bearer token.
     */
    public function testInvalidateBearerTokenWithInvalidResponse()
    {
        $bearerToken = $this->getMockBuilder('Widop\Twitter\OAuth\Token\BearerToken')
            ->disableOriginalConstructor()
            ->getMock();

        $bearerToken
            ->expects($this->any())
            ->method('getValue')
            ->will($this->returnValue('token'));

        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"foo":"bar"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->equalTo('https://api.twitter.com/oauth2/invalidate_token'),
                $this->equalTo(array('Authorization' => 'Basic Y29uc3VtZXJfa2V5OmNvbnN1bWVyX3NlY3JldA==')),
                $this->equalTo(array('access_token' => 'token'))
            )
            ->will($this->returnValue($response));

        $this->oauth->invalidateBearerToken($bearerToken);
    }

    public function testSendRequestWithGetRequest()
    {
        $request = $this->getMock('Widop\Twitter\OAuth\OAuthRequest');
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue(OAuthRequest::METHOD_GET));

        $request
            ->expects($this->once())
            ->method('getUrl')
            ->will($this->returnValue('url'));

        $request
            ->expects($this->once())
            ->method('getHeaders')
            ->will($this->returnValue(array('header' => 'foo')));

        $request
            ->expects($this->once())
            ->method('getResponseFormat')
            ->will($this->returnValue(OAuthResponse::FORMAT_JSON));

        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"foo":"bar"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('getContent')
            ->with($this->identicalTo('url'), $this->identicalTo(array('header' => 'foo')))
            ->will($this->returnValue($response));

        $this->assertSame(array('foo' => 'bar'), $this->oauth->sendRequest($request)->getData());
    }

    public function testSendRequestWithPostRequest()
    {
        $request = $this->getMock('Widop\Twitter\OAuth\OAuthRequest');
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue(OAuthRequest::METHOD_POST));

        $request
            ->expects($this->once())
            ->method('getUrl')
            ->will($this->returnValue('url'));

        $request
            ->expects($this->once())
            ->method('getHeaders')
            ->will($this->returnValue(array('header' => 'foo')));

        $request
            ->expects($this->once())
            ->method('getPostParameters')
            ->will($this->returnValue(array('post' => 'bar')));

        $request
            ->expects($this->once())
            ->method('getFileParameters')
            ->will($this->returnValue(array('file' => 'baz')));

        $request
            ->expects($this->once())
            ->method('getResponseFormat')
            ->will($this->returnValue(OAuthResponse::FORMAT_JSON));

        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"foo":"bar"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->with(
                $this->identicalTo('url'),
                $this->identicalTo(array('header' => 'foo')),
                $this->identicalTo(array('post' => 'bar')),
                $this->identicalTo(array('file' => 'baz'))
            )
            ->will($this->returnValue($response));

        $this->assertSame(array('foo' => 'bar'), $this->oauth->sendRequest($request)->getData());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The request method "DELETE" is not supported.
     */
    public function testSendRequestWithInvalidRequest()
    {
        $request = $this->getMock('Widop\Twitter\OAuth\OAuthRequest');
        $request
            ->expects($this->any())
            ->method('getMethod')
            ->will($this->returnValue('DELETE'));

        $this->oauth->sendRequest($request);
    }

    /**
     * @expectedException \Widop\Twitter\OAuth\OAuthException
     * @expectedExceptionMessage The http response is not valid.
     */
    public function testSendRequestWithErroredRequest()
    {
        $request = $this->getMock('Widop\Twitter\OAuth\OAuthRequest');
        $request
            ->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue(OAuthRequest::METHOD_GET));

        $request
            ->expects($this->once())
            ->method('getUrl')
            ->will($this->returnValue('url'));

        $request
            ->expects($this->once())
            ->method('getHeaders')
            ->will($this->returnValue(array('header' => 'foo')));

        $request
            ->expects($this->once())
            ->method('getResponseFormat')
            ->will($this->returnValue(OAuthResponse::FORMAT_JSON));

        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('{"errors":"foo"}'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('getContent')
            ->with($this->identicalTo('url'), $this->identicalTo(array('header' => 'foo')))
            ->will($this->returnValue($response));

        $this->oauth->sendRequest($request);
    }

    /**
     * @expectedException \Widop\Twitter\OAuth\OAuthException
     * @expectedExceptionMessage An error occured when creating the OAuth token.
     */
    public function testGetRequestTokenError()
    {
        $response = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $response
            ->expects($this->once())
            ->method('getBody')
            ->will($this->returnValue('foo'));

        $this->httpAdapter
            ->expects($this->once())
            ->method('postContent')
            ->will($this->returnValue($response));

        $this->oauth->getRequestToken();
    }
}
