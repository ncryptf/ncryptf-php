<?php declare(strict_types=1);

namespace ncryptf\Tests\mock;

use Exception;

use Middlewares\Utils\Factory;

use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\ResponseInterface;

use Psr\Http\Server\MiddlewareInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * A simple response middleware that echo's the request back to the user
 */
final class EchoResponse implements MiddlewareInterface
{
    /**
     * Echoes the request back out to the response
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $request->getAttribute('ncryptf-decrypted-body'));
        rewind($stream);
        return Factory::createResponse()
            ->withBody(new \Zend\Diactoros\Stream($stream));
    }
}
