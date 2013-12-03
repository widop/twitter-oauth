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
 * Token interface.
 *
 * @author Geoffrey Brier <geoffrey.brier@gmail.com>
 */
interface TokenInterface
{
    /**
     * Signs the request.
     *
     * @param \Widop\Twitter\OAuth\OAuthRequest $request The oauth request.
     * @param \Widop\Twitter\OAuth\OAuth        $oauth   The oauth.
     */
    public function signRequest(OAuthRequest $request, OAuth $oauth);
}
