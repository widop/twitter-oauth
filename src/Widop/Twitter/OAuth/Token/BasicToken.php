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
 * Basic token.
 *
 * @author GeLo <geloen.eric@gmail.com>
 */
class BasicToken implements TokenInterface
{
    /**
     * {@inheritdoc}
     */
    public function signRequest(OAuthRequest $request, OAuth $oauth)
    {
        $request->setHeader('Authorization', sprintf('Basic %s', base64_encode(
            rawurlencode($oauth->getConsumer()->getKey()).':'.rawurlencode($oauth->getConsumer()->getSecret())
        )));
    }
}
