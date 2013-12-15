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
use Widop\Twitter\OAuth\Token\BasicToken;

/**
 * Basic token test.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class BasicTokenTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\Twitter\OAuth\Token\BasicToken */
    private $token;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->token = new BasicToken();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        unset($this->token);
    }

    public function testInitialState()
    {
        $this->assertInstanceOf('Widop\Twitter\OAuth\Token\TokenInterface', $this->token);
    }

    public function testSignRequest()
    {
        $oauth = $this->createOAuth();
        $request = new OAuthRequest();

        $this->token->signRequest($request, $oauth);

        $this->assertSame('Basic Y29uc3VtZXJfa2V5OmNvbnN1bWVyX3NlY3JldA==', $request->getHeader('Authorization'));
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

        return new OAuth($httpAdapter, $consumer, $signature);
    }
}
