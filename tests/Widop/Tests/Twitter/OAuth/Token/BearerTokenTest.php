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

use Widop\Twitter\OAuth\OAuthRequest;
use Widop\Twitter\OAuth\Token\BearerToken;

/**
 * Bearer token test.
 *
 * @author Geoffrey Brier <geoffrey.brier@gmail.com>
 */
class BearerTokenTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\Twitter\OAuth\Token\BearerToken */
    private $token;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->token = new BearerToken('access_token');
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
        $this->assertSame('access_token', $this->token->getValue());
    }

    public function testValue()
    {
        $this->token->setValue('foo');

        $this->assertSame('foo', $this->token->getValue());
    }

    public function testSignRequest()
    {
        $oauth = $this->createOAuth();
        $request = new OAuthRequest();

        $this->token->signRequest($request, $oauth);

        $this->assertSame('Bearer access_token', $request->getHeader('Authorization'));
    }

    public function testSerialize()
    {
        $token = unserialize(serialize($this->token));

        $this->assertSame($this->token->getValue(), $token->getValue());
    }

    /**
     * Creates an OAuth client.
     *
     * @return \Widop\Twitter\OAuth\OAuth The OAuth client.
     */
    private function createOAuth()
    {
        return $this->getMockBuilder('Widop\Twitter\OAuth\OAuth')
            ->disableOriginalConstructor()
            ->getMock();
    }
}
