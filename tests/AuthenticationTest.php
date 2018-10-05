<?php declare(strict_types=1);

namespace ncryptf\Tests;

use DateTime;
use ncryptf\Authorization;
use ncryptf\Token;
use ncryptf\middleware\AbstractAuthentication;
use ncryptf\Tests\AbstractTest;

use PHPUnit\Framework\TestCase;

use Middlewares\Utils\Dispatcher;
use Middlewares\Utils\Factory;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class MockAuthentication extends AbstractAuthentication
{
    protected function getTokenFromAccessToken(string $accessToken) :? Token
    {
        // Return a fixed token
        return new Token(
            'x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J',
            'LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8',
            \base64_decode('f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k='),
            \base64_decode('7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw=='),
            \strtotime('+4 hours')
        );
    }
    
    protected function getUserFromToken(Token $token)
    {
        return [
            'id' => 1
        ];
    }

    protected function getRequestBody(ServerRequestInterface $request) : string
    {
        // Return the raw requestbody
        return $request->getBody()->getContents();
    }
}

final class AuthenticationTest extends AbstractTest
{
    public function testSuccessfulLogin()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2]);
            $response = Dispatcher::run(
                [
                    new MockAuthentication,
                    function ($request, $next) {
                        $this->assertInstanceOf('\ncryptf\Token', $request->getAttribute('ncryptf-token'));
                        $this->assertEquals(true, \is_array($request->getAttribute('ncryptf-user')));
                        return $next->handle($request);
                    }
                ],
                Factory::createServerRequest($params[0], $params[1])
                    ->withHeader('Authorization', $auth->getHeader())
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
                new MockAuthentication
            ],
            Factory::createServerRequest('GET', '/api/v1/user/index')
                ->withHeader('Authorization', $auth->getHeader())
        );

        $this->assertSame(401, $response->getStatusCode());
    }
}
