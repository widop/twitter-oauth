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

use Widop\Twitter\OAuth\OAuthResponse;

/**
 * OAuth response test.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthResponseTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\Twitter\OAuth\OAuthResponse */
    protected $oauthResponse;

    /** @var \Widop\HttpAdapter\HttpResponse */
    protected $httpResponse;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->httpResponse = $this->getMockBuilder('Widop\HttpAdapter\HttpResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $this->httpResponse
            ->expects($this->any())
            ->method('getHeader')
            ->will($this->returnValueMap(array(
                array('X-Rate-Limit-Limit', 'limit'),
                array('X-Rate-Limit-Remaining', 'remaining'),
                array('X-Rate-Limit-Reset', 'reset'),
            )));

        $this->oauthResponse = new OAuthResponse($this->httpResponse);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        unset($this->response);
    }

    public function testHttpResponse()
    {
        $this->assertSame($this->httpResponse, $this->oauthResponse->getHttpResponse());
    }

    public function testRateLimitLimit()
    {
        $this->assertSame('limit', $this->oauthResponse->getRateLimitLimit());
    }

    public function testRateLimitRemaining()
    {
        $this->assertSame('remaining', $this->oauthResponse->getRateLimitRemaining());
    }

    public function testRateLimitReset()
    {
        $this->assertSame('reset', $this->oauthResponse->getRateLimitReset());
    }

    public function testFormat()
    {
        $this->assertSame(OAuthResponse::FORMAT_JSON, $this->oauthResponse->getFormat());
    }

    public function testDataWithoutResult()
    {
        $this->httpResponse
            ->expects($this->any())
            ->method('getBody')
            ->will($this->returnValue('{}'));

        $this->oauthResponse = new OAuthResponse($this->httpResponse);

        $this->assertFalse($this->oauthResponse->hasData());
        $this->assertEmpty($this->oauthResponse->getData());

        $this->assertFalse($this->oauthResponse->hasData('foo'));
        $this->assertNull($this->oauthResponse->getData('foo'));
    }

    public function testDataWithJsonFormat()
    {
        $this->httpResponse
            ->expects($this->any())
            ->method('getBody')
            ->will($this->returnValue('{"foo":"bar"}'));

        $this->oauthResponse = new OAuthResponse($this->httpResponse);

        $this->assertTrue($this->oauthResponse->hasData());
        $this->assertSame(array('foo' => 'bar'), $this->oauthResponse->getData());

        $this->assertTrue($this->oauthResponse->hasData('foo'));
        $this->assertSame('bar', $this->oauthResponse->getData('foo'));
    }

    public function testDataWithStrFormat()
    {
        $this->httpResponse
            ->expects($this->any())
            ->method('getBody')
            ->will($this->returnValue('foo=bar'));

        $this->oauthResponse = new OAuthResponse($this->httpResponse, OAuthResponse::FORMAT_STR);

        $this->assertTrue($this->oauthResponse->hasData());
        $this->assertSame(array('foo' => 'bar'), $this->oauthResponse->getData());

        $this->assertTrue($this->oauthResponse->hasData('foo'));
        $this->assertSame('bar', $this->oauthResponse->getData('foo'));
    }

    public function testIsValidWithValidResponse()
    {
        $this->httpResponse
            ->expects($this->any())
            ->method('getBody')
            ->will($this->returnValue('{"foo":"bar"}'));

        $this->oauthResponse = new OAuthResponse($this->httpResponse);

        $this->assertTrue($this->oauthResponse->isValid());
    }

    public function testIsValidWithInvalidResponse()
    {
        $this->httpResponse
            ->expects($this->any())
            ->method('getBody')
            ->will($this->returnValue('{"errors":"foo"}'));

        $this->oauthResponse = new OAuthResponse($this->httpResponse);

        $this->assertFalse($this->oauthResponse->isValid());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The OAuth response format "foo" is not supported.
     */
    public function testInvalidFormat()
    {
        new OAuthResponse($this->httpResponse, 'foo');
    }
}
