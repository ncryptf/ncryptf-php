<?php declare(strict_types=1);

namespace ncryptf\Tests;

use DateTime;
use ncryptf\Token;
use ncryptf\Request;
use ncryptf\Response;
use ncryptf\Authorization;
use Middlewares\Utils\Factory;
use WildWolf\Psr16MemoryCache;
use ncryptf\Tests\AbstractTest;
use PHPUnit\Framework\TestCase;

use Middlewares\Utils\Dispatcher;
use ncryptf\Tests\mock\EchoResponse;
use ncryptf\Tests\mock\EncryptionKey;
use ncryptf\Tests\mock\Authentication;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use ncryptf\middleware\JsonRequestParser;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ncryptf\middleware\JsonResponseFormatter;

class RequestResponseTest extends AbstractTest
{
    private $clientKeyPair = [
        'secret' => 'bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=',
        'public' => 'Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU='
    ];

    private $serverKeyPair = [
        'secret' => 'gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=',
        'public' => 'YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8='
    ];

    private $signatureKeyPair = [
        'secret' => '9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==',
        'public' => 'IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE='
    ];

    private $nonce = 'bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut';

    private $expectedCipher = '1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=';
    private $expectedSignature = 'dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==';

    private $expectedv2Cipher = '3iWQAm7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLTo569CkMuhiesfnkGvsDcHR3o2aPL2OVTcmWOTX8AY11odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg4SwqYwa53inoY2+eCPP4Hkp/PKhSOEMFlWV+dlQirn6GGf5RQSsQ7ti/QCvi/BRIhb3ZHiPptZJZIbYwqIpvYu';

    private $payload = <<<JSON
{
    "foo": "bar",
    "test": {
        "true": false,
        "zero": 0.0,
        "a": 1,
        "b": 3.14,
        "nil": null,
        "arr": [
            "a", "b", "c", "d"
        ]
    }
}
JSON;

    public function testv2EncryptDecrypt()
    {
        $request = new Request(
            \base64_decode($this->clientKeyPair['secret']),
            \base64_decode($this->signatureKeyPair['secret'])
        );

        $cipher = $request->encrypt($this->payload, \base64_decode($this->serverKeyPair['public']), 2, \base64_decode($this->nonce));

        $this->assertEquals($this->expectedv2Cipher, \base64_encode($cipher));

        $response = new Response(
            \base64_decode($this->serverKeyPair['secret'])
        );

        $plain = $response->decrypt($cipher);

        $this->assertEquals($this->payload, $plain);
    }

    public function testDecryptEmptyString()
    {
        $request = new Request(
            \base64_decode($this->clientKeyPair['secret']),
            \base64_decode($this->signatureKeyPair['secret'])
        );

        $cipher = $request->encrypt('', \base64_decode($this->serverKeyPair['public']));

        $response = new Response(
            \base64_decode($this->serverKeyPair['secret'])
        );

        $plain = $response->decrypt($cipher);

        $this->assertEquals('', $plain);
    }

    public function testv1EncryptDecrypt()
    {
        $request = new Request(
            \base64_decode($this->clientKeyPair['secret']),
            \base64_decode($this->signatureKeyPair['secret'])
        );

        $cipher = $request->encrypt($this->payload, \base64_decode($this->serverKeyPair['public']), 1, \base64_decode($this->nonce));

        $signature = $request->sign($this->payload);

        $this->assertEquals($this->expectedCipher, \base64_encode($cipher));
        $this->assertEquals($this->expectedSignature, \base64_encode($signature));

        $response = new Response(
            \base64_decode($this->serverKeyPair['secret'])
        );

        $plain = $response->decrypt($cipher, \base64_decode($this->clientKeyPair['public']), \base64_decode($this->nonce));

        $this->assertEquals($this->payload, $plain);

        $this->assertTrue($response->isSignatureValid(
            $this->payload,
            $signature,
            \base64_decode($this->signatureKeyPair['public'])
        ));
    }

    public function testV2EncryptedRequestAndResponse()
    {
        foreach ($this->testCases as $k => $params) {
            $serverKey = EncryptionKey::generate();
            $myKey = EncryptionKey::generate();
            $cache = Psr16MemoryCache::instance();
            $cache->set($serverKey->getHashIdentifier(), \function_exists('igbinary_serialize') ? \igbinary_serialize($serverKey) : \serialize($serverKey));

            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $token = $this->token;

            $response = Dispatcher::run(
                [
                    new JsonRequestParser($cache),
                    new Authentication,
                    function ($request, $next) use ($params) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    },
                    new JsonResponseFormatter($cache, EncryptionKey::class),
                    new EchoResponse,
                ],
                Factory::createServerRequest($params[0], $params[1])
                    ->withHeader('Authorization', $auth->getHeader())
                    ->withHeader('Content-Type', 'application/vnd.ncryptf+json')
                    ->withHeader('Accept', 'application/vnd.ncryptf+json')
                    ->withHeader('X-HashId', $serverKey->getHashIdentifier())
                    ->withHeader('X-PubKey', \base64_encode($myKey->getBoxPublicKey()))
                    ->withBody((function () use ($params, $serverKey, $myKey, $token) {
                        $data = \is_array($params[2]) ? \json_encode($params[2]): $params[2];

                        if (!empty($params[2])) {
                            $request = new Request(
                                $myKey->getBoxSecretKey(),
                                $token->signature
                            );

                            $encryptedData = $request->encrypt(
                                $data,
                                $serverKey->getBoxPublicKey()
                            );
                        }
                        $stream = fopen('php://memory', 'r+');
                        fwrite($stream, empty($params[2]) ? '' : \base64_encode($encryptedData));
                        rewind($stream);
                        return new \Zend\Diactoros\Stream($stream);
                    })())
            );

            $this->assertSame('application/vnd.ncryptf+json', $response->getHeaderLine('Content-Type'));
            $this->assertTrue($response->hasHeader('x-hashid'));

            $r = new Response(
                $myKey->getBoxSecretKey()
            );

            $plaintext = $r->decrypt(
                \base64_decode((string)$response->getBody())
            );

            $this->assertEquals(\is_array($params[2]) ? \json_encode($params[2]) : $params[2], $plaintext);
        }
    }

    public function testUnauthenticatedV2EncryptedRequestAndResponse()
    {
        foreach ($this->testCases as $k => $params) {
            $serverKey = EncryptionKey::generate();
            $myKey = EncryptionKey::generate();
            $cache = Psr16MemoryCache::instance();
            $cache->set($serverKey->getHashIdentifier(), \function_exists('igbinary_serialize') ? \igbinary_serialize($serverKey) : \serialize($serverKey));

            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $token = $this->token;

            $response = Dispatcher::run(
                [
                    new JsonRequestParser($cache),
                    new JsonResponseFormatter($cache, EncryptionKey::class),
                    new EchoResponse,
                ],
                Factory::createServerRequest($params[0], $params[1])
                    ->withHeader('Authorization', $auth->getHeader())
                    ->withHeader('Content-Type', 'application/vnd.ncryptf+json')
                    ->withHeader('Accept', 'application/vnd.ncryptf+json')
                    ->withHeader('X-HashId', $serverKey->getHashIdentifier())
                    ->withHeader('X-PubKey', \base64_encode($myKey->getBoxPublicKey()))
                    ->withBody((function () use ($params, $serverKey, $myKey, $token) {
                        $data = \is_array($params[2]) ? \json_encode($params[2]): $params[2];

                        if (!empty($params[2])) {
                            $request = new Request(
                                $myKey->getBoxSecretKey(),
                                $token->signature
                            );

                            $encryptedData = $request->encrypt(
                                $data,
                                $serverKey->getBoxPublicKey()
                            );
                        }
                        $stream = fopen('php://memory', 'r+');
                        fwrite($stream, empty($params[2]) ? '' : \base64_encode($encryptedData));
                        rewind($stream);
                        return new \Zend\Diactoros\Stream($stream);
                    })())
            );

            $this->assertSame('application/vnd.ncryptf+json', $response->getHeaderLine('Content-Type'));
            $this->assertTrue($response->hasHeader('x-hashid'));

            $r = new Response(
                $myKey->getBoxSecretKey()
            );

            $plaintext = $r->decrypt(
                \base64_decode((string)$response->getBody())
            );

            $this->assertEquals(\is_array($params[2]) ? \json_encode($params[2]) : $params[2], $plaintext);
        }
    }

    public function testV1EncryptedRequestAndResponse()
    {
        foreach ($this->testCases as $k => $params) {
            $serverKey = EncryptionKey::generate();
            $myKey = EncryptionKey::generate();
            $nonce = \random_bytes(24);
            $cache = Psr16MemoryCache::instance();
            $cache->set($serverKey->getHashIdentifier(), \function_exists('igbinary_serialize') ? \igbinary_serialize($serverKey) : \serialize($serverKey));

            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $token = $this->token;
            $response = Dispatcher::run(
                [
                    new JsonRequestParser($cache),
                    new Authentication,
                    function ($request, $next) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    },
                    new JsonResponseFormatter($cache, EncryptionKey::class),
                    new EchoResponse,
                ],
                Factory::createServerRequest($params[0], $params[1])
                    ->withHeader('Authorization', $auth->getHeader())
                    ->withHeader('Content-Type', 'application/vnd.25519+json')
                    ->withHeader('Accept', 'application/vnd.25519+json')
                    ->withHeader('X-HashId', $serverKey->getHashIdentifier())
                    ->withHeader('X-Nonce', \base64_encode($nonce))
                    ->withHeader('X-PubKey', \base64_encode($myKey->getBoxPublicKey()))
                    ->withBody((function () use ($params, $serverKey, $myKey, $nonce, $token) {
                        $data = \is_array($params[2]) ? \json_encode($params[2]): $params[2];

                        $request = new Request(
                            $myKey->getBoxSecretKey(),
                            $token->signature
                        );

                        $encryptedData = $request->encrypt(
                            $data,
                            $serverKey->getBoxPublicKey(),
                            1,
                            $nonce
                        );
                        $stream = fopen('php://memory', 'r+');
                        fwrite($stream, $data === '' ? '' : \base64_encode($encryptedData));
                        rewind($stream);
                        return new \Zend\Diactoros\Stream($stream);
                    })())
            );

            $this->assertSame(200, $response->getStatusCode());
            $this->assertSame('application/vnd.ncryptf+json', $response->getHeaderLine('Content-Type'));
            if ($params[2] !== '') {
                $this->assertTrue($response->hasHeader('x-hashid'));
                $this->assertTrue($response->hasHeader('x-signature'));
                $this->assertTrue($response->hasHeader('x-sigpubkey'));
                $this->assertTrue($response->hasHeader('x-nonce'));
                $this->assertTrue($response->hasHeader('x-pubkey'));
                $this->assertTrue($response->hasHeader('x-public-key-expiration'));
            }

            $r = new Response(
                $myKey->getBoxSecretKey()
            );

            $plaintext = $r->decrypt(
                \base64_decode((string)$response->getBody()),
                \base64_decode($response->getHeaderLine('x-pubkey')),
                \base64_decode($response->getHeaderLine('x-nonce'))
            );

            $this->assertEquals(\is_array($params[2]) ? \json_encode($params[2]) : $params[2], $plaintext);
        }
    }

    public function testPublicKeyExtraction()
    {
        $publicKey = Response::getPublicKeyFromResponse(\base64_decode($this->expectedv2Cipher));
        $this->assertEquals(\base64_decode($this->clientKeyPair['public']), $publicKey);
    }

    public function testVersion()
    {
        $this->assertEquals(1, Response::getVersion(\base64_decode($this->expectedCipher)));
        $this->assertEquals(2, Response::getVersion(\base64_decode($this->expectedv2Cipher)));
    }
}
