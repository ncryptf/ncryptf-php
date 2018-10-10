<?php declare(strict_types=1);

namespace ncryptf\Tests;

use DateTime;
use ncryptf\Authorization;
use ncryptf\Request;
use ncryptf\Token;
use ncryptf\middleware\NcryptfPayload;
use ncryptf\Tests\AbstractTest;
use ncryptf\Tests\mock\Authentication;
use ncryptf\Tests\mock\EncryptionKey;

use PHPUnit\Framework\TestCase;

use Middlewares\JsonPayload;
use Middlewares\Utils\Dispatcher;
use Middlewares\Utils\Factory;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use WildWolf\Psr16MemoryCache;

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

    public function testEncryptedRequestWithPlaintextResponse()
    {
        foreach ($this->testCases as $k => $params) {
            $serverKey = EncryptionKey::generate();
            $myKey = EncryptionKey::generate();
            $cache = Psr16MemoryCache::instance();
            $cache->set($serverKey->getHashIdentifier(), $serverKey);

            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);

            $response = Dispatcher::run(
                [
                    new NcryptfPayload($cache),
                    new Authentication,
                    function ($request, $next) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    }
                ],
                Factory::createServerRequest($params[0], $params[1])
                    ->withHeader('Authorization', $auth->getHeader())
                    ->withHeader('Content-Type', 'application/vnd.ncryptf+json')
                    ->withHeader('Accept', 'application/json')
                    ->withHeader('X-HashId', $serverKey->getHashIdentifier())
                    ->withBody((function () use ($params, $serverKey, $myKey) {
                        $data = \is_array($params[2]) ? \json_encode($params[2]): $params[2];

                        $request = new Request(
                            $myKey->getBoxSecretKey(),
                            $myKey->getSigningSecretKey()
                        );

                        $encryptedData = $request->encrypt(
                            $data,
                            $serverKey->getBoxPublicKey()
                        );
                        $stream = fopen('php://memory', 'r+');
                        fwrite($stream, $data === '' ? '' : \base64_encode($encryptedData));
                        rewind($stream);
                        return new \Zend\Diactoros\Stream($stream);
                    })())
            );

            $this->assertSame(200, $response->getStatusCode());
        }
    }

    public function testError()
    {
        $auth = new Authorization('GET', '/api/v1/user/index', $this->token, new DateTime, '{"foo":"bar"}');
        $response = Dispatcher::run(
            [
                new Authentication
            ],
            Factory::createServerRequest('GET', '/api/v1/user/index')
                ->withHeader('Authorization', $auth->getHeader())
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Accept', 'application/json')
        );

        $this->assertSame(401, $response->getStatusCode());
    }
}
