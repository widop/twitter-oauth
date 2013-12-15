# README

[![Build Status](https://secure.travis-ci.org/widop/twitter-oauth.png)](http://travis-ci.org/widop/twitter-oauth)

The Wid'op OAuth library is a modern PHP 5.3+ API allowing you to easily obtain a Twitter access token. For now, it
supports OAuth Web & Application tokens (not xOAuth).

Here a sample for the Web workflow:

``` php
use Widop\HttpAdapter\CurlHttpAdapter;
use Widop\Twitter\OAuth;

// First, instantiate your OAuth client.
$oauth = new OAuth\OAuth(
    new CurlHttpAdapter(),
    new OAuth\OAuthConsumer('consumer_key', 'consumer_secret'),
    new OAuth\Signature\OAuthHmacSha1Signature()
);

// Second, get/cache a "request token" somewhere (here in session)
if (!isset($_SESSION['my_request_session'])) {
    $requestToken = $oauth->getRequestToken('http://my-app.com/twitter-callback.php');
    $_SESSION['my_request_session'] = serialize($requestToken);
} else {
    $requestToken = unserialize($_SESSION['my_request_token']);
}

// Third, redirect the user on twitter for getting permissions
echo '<a href="'.$oauth->getAuthorizeUrl($requestToken).'">Authorize the application</a>';

// Then, get an "access token"
if (isset($_REQUEST['oauth_verifier'])) {
    $accessToken = $oauth->getAccessToken($requestToken, $_REQUEST['oauth_verifier']);

    // Save the access token somewhere for further purpose!
}
```

## Documentation

 1. [Installation](doc/installation.md)
 2. [OAuth](doc/oauth.md)

## Testing

The library is fully unit tested by [PHPUnit](http://www.phpunit.de/) with a code coverage close to **100%**. To
execute the test suite, check the travis [configuration](.travis.yml).

## Contribute

We love contributors! The library is open source, if you'd like to contribute, feel free to propose a PR!

## License

The Wid'op OAuth library is under the MIT license. For the full copyright and license information, please read the
[LICENSE](LICENSE) file that was distributed with this source code.
