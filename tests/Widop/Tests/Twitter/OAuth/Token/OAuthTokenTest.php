<?php

/*
 * This file is part of the Wid'op package.
 *
 * (c) Wid'op <contact@widop.com>
 *
 * For the full copyright and license information, please read the LICENSE
 * file that was distributed with this source code.
 */

namespace Widop\Tests\Twitter\OAuth\Token;

use Widop\Twitter\OAuth\OAuth;
use Widop\Twitter\OAuth\OAuthRequest;
use Widop\Twitter\OAuth\Token\OAuthToken;

/**
 * OAuth token test.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthTokenTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\Twitter\OAuth\Token\OAuthToken */
    private $token;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->token = new OAuthToken('key', 'secret');
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        unset($this->token);
    }

    public function testDefaultState()
    {
        $this->token = new OAuthToken();

        $this->assertNull($this->token->getKey());
        $this->assertNull($this->token->getSecret());
    }

    public function testInitialState()
    {
        $this->assertInstanceOf('Widop\Twitter\OAuth\Token\TokenInterface', $this->token);
        $this->assertSame('key', $this->token->getKey());
        $this->assertSame('secret', $this->token->getSecret());
    }

    public function testKey()
    {
        $this->token->setKey('foo');

        $this->assertSame('foo', $this->token->getKey());
    }

    public function testSecret()
    {
        $this->token->setSecret('foo');

        $this->assertSame('foo', $this->token->getSecret());
    }

    public function testSignRequestWithoutKey()
    {
        $this->token->setKey(null);

        $oauth = $this->createOAuth();
        $request = new OAuthRequest();

        $this->token->signRequest($request, $oauth);

        $this->assertSame('1.0', $request->getOAuthParameter('oauth_version'));
        $this->assertSame('consumer_key', $request->getOAuthParameter('oauth_consumer_key'));
        $this->assertSame('signature-name', $request->getOAuthParameter('oauth_signature_method'));
        $this->assertSame('signature', $request->getOAuthParameter('oauth_signature'));
        $this->assertFalse($request->hasOAuthParameter('oauth_token'));
        $this->assertTrue($request->hasOAuthParameter('oauth_nonce'));
        $this->assertTrue($request->hasOAuthParameter('oauth_timestamp'));
        $this->assertRegExp(
            '#OAuth oauth_version="1.0", oauth_consumer_key="consumer_key", oauth_signature_method="signature-name", oauth_signature="signature", oauth_nonce="(.*)", oauth_timestamp="(.*)"#',
            $request->getHeader('Authorization')
        );
    }

    public function testSignRequestWithKey()
    {
        $oauth = $this->createOAuth();
        $request = new OAuthRequest();

        $this->token->signRequest($request, $oauth);

        $this->assertSame('1.0', $request->getOAuthParameter('oauth_version'));
        $this->assertSame('consumer_key', $request->getOAuthParameter('oauth_consumer_key'));
        $this->assertSame('signature-name', $request->getOAuthParameter('oauth_signature_method'));
        $this->assertSame('signature', $request->getOAuthParameter('oauth_signature'));
        $this->assertSame('key', $request->getOAuthParameter('oauth_token'));
        $this->assertTrue($request->hasOAuthParameter('oauth_nonce'));
        $this->assertTrue($request->hasOAuthParameter('oauth_timestamp'));
        $this->assertRegExp(
            '#OAuth oauth_version="1.0", oauth_consumer_key="consumer_key", oauth_signature_method="signature-name", oauth_token="key", oauth_signature="signature", oauth_nonce="(.*)", oauth_timestamp="(.*)"#',
            $request->getHeader('Authorization')
        );
    }

    public function testSerialize()
    {
        $token = unserialize(serialize($this->token));

        $this->assertSame($this->token->getKey(), $token->getKey());
        $this->assertSame($this->token->getSecret(), $token->getSecret());
    }

    /**
     * Creates an OAuth client.
     *
     * @return \Widop\Twitter\OAuth\OAuth The OAuth client.
     */
    private function createOAuth()
    {
        $httpAdapter = $this->getMock('Widop\HttpAdapter\HttpAdapterInterface');

        $consumer = $this->getMockBuilder('Widop\Twitter\OAuth\OAuthConsumer')
            ->disableOriginalConstructor()
            ->getMock();

        $consumer
            ->expects($this->any())
            ->method('getKey')
            ->will($this->returnValue('consumer_key'));

        $consumer
            ->expects($this->any())
            ->method('getSecret')
            ->will($this->returnValue('consumer_secret'));

        $signature = $this->getMock('Widop\Twitter\OAuth\Signature\OAuthSignatureInterface');

        $signature
            ->expects($this->any())
            ->method('generate')
            ->with(
                $this->isInstanceOf('Widop\Twitter\OAuth\OAuthRequest'),
                $this->equalTo('consumer_secret')
            )
            ->will($this->returnValue('signature'));

        $signature
            ->expects($this->any())
            ->method('getName')
            ->will($this->returnValue('signature-name'));

        return new OAuth($httpAdapter, $consumer, $signature);
    }
}
