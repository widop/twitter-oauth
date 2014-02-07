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

use Widop\Twitter\OAuth\OAuthException;

/**
 * OAuth exception test.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class OAuthExceptionTest extends \PHPUnit_Framework_TestCase
{
    /** @var \Widop\Twitter\OAuth\OAuthException */
    protected $exception;

    /** @var string */
    protected $message;

    /** @var \Widop\Twitter\OAuth\OAuthResponse */
    protected $response;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->response = $this->getMockBuilder('Widop\Twitter\OAuth\OAuthResponse')
            ->disableOriginalConstructor()
            ->getMock();

        $this->message = 'foo';
        $this->exception = new OAuthException($this->message, $this->response);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        unset($this->response);
        unset($this->message);
        unset($this->exception);
    }

    public function testMessage()
    {
        $this->assertSame($this->message, $this->exception->getMessage());
    }

    public function testResponse()
    {
        $this->assertSame($this->response, $this->exception->getResponse());
    }
}
