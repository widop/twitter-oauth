# OAuth

Since Twitter 1.1, the REST API **requires** an OAuth authentication in order to process requests. Technically, that
means all request needs to wrap an `Authorization` header with the appropriate key/value pairs. To generate this one,
the library needs 4 things: an http adapter, an OAuth consumer, an OAuth signature and an OAuth access token.

## Http Adapter

As the library will issue http requests, we need an http adapter :) Thanks to the `widop/http-adapter`, all the work
is already done! You can find more informations [here](https://github.com/widop/http-adapter).

## OAuth Consumer

The consumer represents a Twitter application. To create one, you can go [here](https://dev.twitter.com/apps).

A consumer is represented by a key & a secret which can be found in your application settings.

``` php
use Widop\Twitter\OAuth\OAuthConsumer;

$consumer = new OAuthConsumer('consumer_key', 'consumer_secret');
```

## OAuth Signature

The signature represents the algorithm applies to the request in order to sign it. The most used is the
`OAuthHmacSha1Signature`.

``` php
use Widop\Twitter\OAuth\Signature\OAuthHmacSha1Signature;

$signature = new OAuthHmacSha1Signature();
```

If you want to learn more, you can read this [documentation](signature.md).

## OAuth Access Token

An access token represents the authorization made between an application and a user account (read, write,
direct messages). This token is required in order to process any requests since Twitter 1.1, so, you need to
generate it.

To retrive an access token, you will need the OAuth client:

``` php
use Widop\Twitter\OAuth\OAuth;

$oauth = new OAuth(
    new CurlHttpAdapter(),
    new OAuthConsumer('consumer_key', 'consumer_secret'),
    new OAuthHmacSha1Signature()
);
```

### Web Workflow

To generate an access token in a web context, you will need to process the
[OAuth 1.0](http://oauth.net/core/1.0/#anchor9) workflow:

![OAuth 1.0 Workflow](http://oauth.net/core/diagram.png)

Basically, it is pretty simple. First of all, we need to get a "request token" with a callback url. Second, send the
user on the authorize/authenticate url with the request token just requested & then, wait for a twitter response on the
callback url in order to generate the final "access token".

So, let's go for requesting a "request token":

``` php
$requestToken = $oauth->getRequestToken('http://my-url.com/twitter-callback');
```

Yeah, that's done! Pretty hard... Now, you need to redirect the user on the authorize url in order to give to our
application some permissions :)

``` php
$url = $oauth->getAuthorizeUrl($requestToken);
```

Making this call will force the user to re-approve the application. If you don't want to, you can use the following
method so that the user will be silently redirected:

``` php
$url = $oauth->getAuthenticateUrl($requestToken);
```

Note: In both case, the user will need to authorize the application if he/she hasn't done it before.

One more time, that was difficult... Now, we wait for the twitter response. Basically, it is much more a request as
twitter will send us an http request to our callback url in order to inform us the request token has been authorized
and ready to be exchanged for an access token. When this request will be received, it will wrap the request token key
previously sent (allowing us to make difference between requests received) & an oauth verifier.

Now, the last step is to get an access token:

``` php
$accessToken = $oauth->getAccessToken($requestToken, $verifier);
```

That's done! You're ready to use the Twitter client!

### Application Workflow

To generate an access token in an application context, you will need to use the
[Client Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.4) of the
[OAuth2 specification](http://tools.ietf.org/html/rfc6749).

![Client Credentials Grant](https://dev.twitter.com/sites/default/files/images_documentation/appauth.png)

Note that Web OAuth access token (OAuth 1.0a) is still required to issue requests on behalf of users (meaning
applications can't do these kinds of requests).

Like in a web context, it is pretty simple (maybe more...). To get an access token (also known as bearer token due to
the technic used), a unique call is needed:

``` php
$bearerToken = $oauth->getBearerToken();
```

You're done! Ready to use your token with the Twitter client!

Additionally, be aware that you can invalidate a bearer token with the following snippet:

``` php
$oauth->invalidateBearerToken($bearerToken);
```

### X-OAuth

Twitter allows you to use the X-OAuth protocol. As it is described [here](https://dev.twitter.com/docs/oauth/xauth), it
is still OAuth but in a different way. For now, it is not supported but if someone is interested, (s)he is welcomed ... :)
