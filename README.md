# ncryptf PHP

[![Packagist Pre Release](https://img.shields.io/packagist/v/ncryptf/ncryptf-php.svg?maxAge=86400?style=flat-square)](https://packagist.org/packages/ncryptf/ncryptf-php)
[![TravisCI](https://img.shields.io/travis/com/ncryptf/ncryptf-php.svg?style=flat-square "TravisCI")](https://travis-ci.com/ncryptf/ncryptf-php)
[![Scrutinizer Code Quality](https://img.shields.io/scrutinizer/g/ncryptf/ncryptf-php.svg?style=flat-square)](https://scrutinizer-ci.com/g/ncryptf/ncryptf-php/)
[![License](https://img.shields.io/badge/license-BSD-orange.svg?style=flat-square "License")](https://github.com/ncryptf/ncryptf-php/blob/master/LICENSE.md)

<center>
    <img src="https://github.com/ncryptf/ncryptf-php/blob/master/logo.png?raw=true" alt="ncryptf logo" width="400px"/>
</center>

A library for facilitating hashed based KDF signature authentication, and end-to-end encrypted communication with compatible API's.

## HMAC+HKDF Authentication

HMAC+HKDF Authentication is an Authentication method that allows ensures the request is not tampered with in transit. This provides resiliance not only against network layer manipulation, but also man-in-the-middle attacks.

At a high level, an HMAC signature is created based upon the raw request body, the HTTP method, the URI (with query parameters, if present), and the current date. In addition to ensuring the request cannot be manipulated in transit, it also ensures that the request is timeboxed, effectively preventing replay attacks.

This library is made available through composer:

```
composer require ncryptf/ncryptf-php
```

Supporting API's will return the following payload containing at minimum the following information.

```json
{
    "access_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "refresh_token": "MA2JX5FXWS57DHW4OIHHQDCJVGS3ZKKFCL7XM4GNOB567I6ER4LQ",
    "ikm": "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=",
    "signing": "7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==",
    "expires_at": 1472678411
}
```

After extracting the elements, we can create signed request by doing the following:

```php
use DateTime;
use ncryptf\Token;
use ncryptf\Authorization;

$date = new DateTime;
$token = new Token(
    $accessToken,
    $refreshToken,
    \base64_decode($ikm), // IKM must be in it's byte form, as oppose to the base64 representation returned by the server
    \base64_decode($signature), // Signature is the same,
    $expiresAt
);

$auth = new Authorization(
    $httpMethod,
    $uri,
    $token,
    new DateTime,
    $payload
);

$header = $auth->getHeader();
```

A trivial full example is shown as follows:

```php
use DateTime;
use ncryptf\Token;
use ncryptf\Authorization;

$date = new DateTime;
$token = new Token(
    '7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA',
    'MA2JX5FXWS57DHW4OIHHQDCJVGS3ZKKFCL7XM4GNOB567I6ER4LQ',
    \base64_decode('bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM='),
    \base64_decode('7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw=='),
    1472678411
);

$auth = new Authorization(
    'POST',
    '/api/v1/test',
    $token,
    new DateTime,
    [
        'foo' => 'bar'
    ]
);

$header = $auth->getHeader();
```

> Note that the `$date` parameter should be pre-offset when calling `new Authorization` to prevent time skewing.

The `$payload` parameter in `Authorization::__construct` should be an JSON serializable array, however a serialized JSON string may be passed.

### Version 2 HMAC Header

The Version 2 HMAC header, for API's that support it can be retrieved by calling:

```php
$header = $auth->getHeader();
```

### Version 1 HMAC Header

For API's using version 1 of the HMAC header, call `new Authorization` with the optional `version` parameter set to `1` for the 6th parameter.

```php
$auth = new Authorization(
    $httpMethod,
    $uri,
    $token,
    new DateTime,
    $payload,
    1
);

$auth->getHeader(),
```

This string can be used in the `Authorization` Header

#### Date Header

The Version 1 HMAC header requires an additional `X-Date` header. The `X-Date` header can be retrieved by calling `authorization.getDateString()`

## Verification

This library can also validate the client generated HMAC. A high level example (psuedocode) is provided below:

```php
use DateTime;
use ncryptf\Authorization;
use ncryptf\Token as NcryptfToken;

public function authenticate($user, $request, $response)
{
    // Extract the parameters from the header string
    $params = Authorization::extractParamsFromHeaderString($request->getHeaders()->get('Authorization'));

    if ($params) {
        // Your API should implement a method to fetch all token data from the access token
        // Typically this is stored in a cache of some kind, such as Redis
        if ($token = $this->getTokenFromAccessToken($params['access_token'])) {
            try {
                // Determine the appropriate date to use, depending upon the version
                $date = new DateTime($params['date'] ?? $request->getHeaders()->get('X-Date'));

                // Construct a new server side Authorization object
                $auth = new Authorization(
                    $request->getHttpMethod(), // GET, POST, PUT... etc
                    $request->getUrl(), // The URI with query parameters
                    $token->getNcryptfToken(), // Your token object should support data extraction to an ncryptf/Token type
                    $date,
                    $request->getRawBody(), // The raw JSON in the request. If you're using encrypted requests, this should be decrypted
                    $params['v'], // The version of the HMAC header to validate
                    \base64_decode($params['salt']) // The salt value from the parameters
                );

                // Verify the HMAC submitted against the newly generated auth object
                if ($auth->verify(\base64_decode($params['hmac']), $auth)) {
                    
                    // Do your login here
                    //
                    //
                }
            } catch (\Exception $e) {
                // Handle exceptions here
            }
        }
    }

   // Handle authentication failures
}
```

## Encrypted Requests & Responses

This library enables clients coding in PHP 7.1+ to establish and trusted encrypted session on top of a TLS layer, while simultaniously (and independently) providing the ability authenticate and identify a client via HMAC+HKDF style authentication.

The rationale for this functionality includes but is not limited to:

1. Necessity for extra layer of security
2. Lack of trust in the network or TLS itself (see https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
3. Need to ensure confidentiality of the Initial Key Material (IKM) provided by the server for HMAC+HKDF authentication
4. Need to ensure confidentiality of user submitted credentials to the API for authentication

The primary reason you may want to establish an encrypted session with the API itself is to ensure confidentiality of the IKM to prevent data leakages over untrusted networks to avoid information being exposed in a Cloudflare like incident (or any man-in-the-middle attack). Encrypted sessions enable you to utilize a service like Cloudflare should a memory leak occur again with confidence that the IKM and other secure data would not be exposed.

### Encrypted Request Body

Payloads can be encrypted as follows:

```php
use ncryptf\Request;
use ncryptf\Utils;
use ncryptf\exceptions\EncryptionFailedException;

try {
    // Generate your request keypair for your local device.
    $keypair = Utils::generateKeypair();
    $signatureKp = Utils::generateSigningKeypair()
    // Create a new request object with your private key
    // and the servers private key
    $request = new Request(
        $privateKeypair->getSecretKey(),
        $signatureKp->getSecretKey
    );

    // Encrypt JSON
    $encryptedRequest = $request->encrypt(
        '{ "foo": "bar" }',
        $remotePublicKey
    );
} catch (EncryptionFailedException $e) {
    // Encrypting the body failed
}
```

> Note that only the v2 encryption is shown here.

> Note that you need to have a pre-bootstrapped public key to encrypt data. For the v1 API, this is typically this is returned by `/api/v1/server/otk`.

### Decrypting Responses

Responses from the server can be decrypted as follows:

```php
use ncryptf\Response;
use ncryptf\exceptions\DecryptionFailedException;
use ncryptf\exceptions\InvalidChecksumException;
use ncryptf\exceptions\InvalidSignatureException;

// Represents the httpResponse
try {
    // Create a new request object with your private key
    // and the servers private key
    $response = new Response(
        \sodium_crypto_box_secretkey($privateKeypair['secret']),
    );

    // Extract the raw body from the response
    $rawBody = \base64_decode($httpResponse->getBody());
    $jsonResponse = $response->decrypt(
        $rawBody,
        $remotePublicKey
    );
} catch (DecryptionFailedException $e) {
    // Decryption failed
} catch (InvalidChecksumException $e) {
    // Request checksum failed
} catch (InvalidSignatureException $e) {
    // Signature verification failed
}
```

### V2 Encrypted Payload

Verison 2 works identical to the version 1 payload, with the exception that all components needed to decrypt the message are bundled within the payload itself, rather than broken out into separate headers. This alleviates developer concerns with needing to manage multiple headers.

The version 2 payload is described as follows. Each component is concatanated together.

| Segment | Length |
|---------|--------|
| 4 byte header `DE259002` in binary format | 4 BYTES |
| Nonce | 24 BYTES |
| The public key associated to the private key | 32 BYTES |
| Encrypted Body | X BYTES + 16 BYTE MAC |
| Signature Public Key | 32 BYTES |
| Signature or raw request body | 64 BYTES |
| Checksum of prior elements concatonated together | 64 BYTES |

## PSR-15 Middleware

### Authentication

Ncryptf supports a PSR-15 middleware via `ncryptf\middleware\AbstractAuthentication`, which simply needs to be extended for token extraction and user retrieval.

```php
use ncryptf\middleware\AbstractAuthentication;

final class Authentication extends AbstractAuthentication
{
    /**
     *  Given an access token, return an `ncryptf\Token` instance.
     */
    protected function getTokenFromAccessToken(string $accessToken) :? Token
    {
        // Search for token in database
        return \ncryptf\Token(...);
    }

    protected function getUserFromToken(Token $token)
    {
        // Convert a token to a user.
        return User::find()
            ->where(['access_token' => $token['access_token']])
            ->one();
    }
}
```

A simple example is shown as follows:

```php
use Authentication;
use Middlewares\Utils\Dispatcher;

$response = Dispatcher::run([
    new Authentication,
    function ($request, $next) {
        // This is your user, do whatever you need to do here.
        $user = $request->getAttribute('ncryptf-user');
        return $next->handle($request);
    }
], $request);
```

### Secure Request Parsing

A PSR-15 middleware is provided to decrypt requests encrypted with `application/vnd.ncryptf+json`. Request decrypting can be performed _independently_ of an authenticated requests and is useful in circumstances where sensative data needs to be transferred, however a HTTP 204, or a non metadata leaking response is returned.

Ideally however, this would always be coupled with an authenticated requests and a corresponding encrypted response.

In order to ensure messages can be decrypted, three components are required:

1. A PSR-16 cache instance where your encryption keys are stored. This guide recommends using a distributed cache, such as Redis or memcache to facilitate long term storage.

2. A `ncryptf\middleware\EncryptionKeyInterface` class that represents a cachable encryption key.

3. Injection of `ncryptf\middleware\RequestParser` at the beginning of your dispatcher, before the request body is acted upon.

```php
use ncryptf\middleware\RequestParser;
use Middlewares\Utils\Dispatcher;

$PSR16CacheInterface = new class implements \Psr\SimpleCache\CacheInterface {};

$response = Dispatcher::run([
    new RequestParser($PSR16CacheInterface),
    function ($request, $next) {
        // This is the plain-text decrypted body
        $decryptedBody = $request->getAttribute('ncryptf-decrypted-body');

        // The parsed body
        $params = $request->getParsedBody();
        return $next->handle($request);
    }
], $request);
```

### Secure Response Formatting

When coupled with an authenticated ncryptf request, `ncryptf\middleware\ResponseFormatter` can format a given response into an `application/vnd.ncryptf+json` response. The formatter currently can only process JSON payloads.

This implementation must be used with an instance of `ncryptf\middleware\AbstractAuthentication`, and is recommended to be used with secure requests processed by `ncryptf\middleware\RequestParser` to ensure full end-to-end encryption of messages.

The `ncryptf\middleware\ResponseFormatter` constructor takes an instance of `Psr\SimpleCache\CacheInterface` to store the newly generate `ncryptf\middleware\EncryptionKeyInterface`, and an instance of `ncryptf\middleware\EncryptionKeyInterface` to construct a new keypair to ensure perfect-forward secrecy.

```php
use Authentication;
use ncryptf\middleware\EncryptionKeyInterface;
use ncryptf\middleware\ResponseFormatter;
use ncryptf\middleware\RequestParser;
use Middlewares\Utils\Dispatcher;

$PSR16CacheInterface = new class implements \Psr\SimpleCache\CacheInterface {};

$response = Dispatcher::run([
    new RequestParser($PSR16CacheInterface),
    new Authentication,
    new ResponseFormatter($PSR16CacheInterface, $EncryptionKeyInterface::class)
    function ($request, $next) {
        return new JsonResponse(['hello' => 'world'])
    }
], $request);
```

> Refer to the `tests` directory for full end-to-end implementation examples.