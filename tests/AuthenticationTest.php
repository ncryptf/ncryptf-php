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
use Zend\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

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
