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
use ncryptf\middleware\RequestParser;
use ncryptf\Tests\mock\EncryptionKey;
use ncryptf\Tests\mock\Authentication;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use ncryptf\middleware\ResponseFormatter;
use Zend\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ServerRequestInterface;

use Psr\Http\Server\RequestHandlerInterface;
use Lcobucci\ContentNegotiation\Formatter\Json;
use Lcobucci\ContentNegotiation\Formatter\StringCast;

final class AuthenticationTest extends AbstractTest
{
    public function testSuccessfulLogin()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $response = Dispatcher::run(
                [
                    new Authentication,
                    function ($request, $next) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    }
                ],
                Factory::createServerRequest($params[0], $params[1])
                    ->withHeader('Authorization', $auth->getHeader())
                    ->withHeader('Content-Type', 'application/json')
                    ->withHeader('Accept', 'application/json')
                    ->withBody((function () use ($params) {
                        $stream = fopen('php://memory', 'r+');
                        fwrite($stream, \is_array($params[2]) ? \json_encode($params[2]): $params[2]);
                        rewind($stream);
                        return new \Zend\Diactoros\Stream($stream);
                    })())
            );

            $this->assertSame(200, $response->getStatusCode());
        }
    }

    public function testV2EncryptedRequestAndResponse()
    {
        foreach ($this->testCases as $k => $params) {
            $serverKey = EncryptionKey::generate();
            $myKey = EncryptionKey::generate();
            $cache = Psr16MemoryCache::instance();
            $cache->set($serverKey->getHashIdentifier(), $serverKey);

            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $token = $this->token;

            $response = Dispatcher::run(
                [
                    new RequestParser($cache),
                    new Authentication,
                    function ($request, $next) use ($params) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    },
                    new ResponseFormatter(new EncryptionKey),
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
            $cache->set($serverKey->getHashIdentifier(), $serverKey);

            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $token = $this->token;
            $response = Dispatcher::run(
                [
                    new RequestParser($cache),
                    new Authentication,
                    function ($request, $next) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    },
                    new ResponseFormatter(new EncryptionKey),
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

    public function testError()
    {
        $auth = new Authorization('GET', '/api/v1/user/index', $this->token, new DateTime, '{"foo":"bar"}');
        $response = Dispatcher::run(
            [
                new Authentication,
                function ($request, $next) {
                    return new JsonResponse(['foo' => 'bar']);
                }
            ],
            Factory::createServerRequest('GET', '/api/v1/user/index')
                ->withHeader('Authorization', $auth->getHeader())
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Accept', 'application/json')
        );

        $this->assertSame(401, $response->getStatusCode());
    }
}
