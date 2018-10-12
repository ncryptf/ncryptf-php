<?php declare(strict_types=1);

namespace ncryptf\middleware;

use DateTime;
use Exception;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ncryptf\Authorization;
use ncryptf\Token;

/**
 * PSR-15 Authentication middleware for handling ncryptf Authorization requests
 * Abstract class should be extended and implement `getTokenFromAccessToken` and `getRequestBody`
 */
abstract class AbstractAuthentication implements MiddlewareInterface
{
    use \Middlewares\Utils\Traits\HasResponseFactory;

    // The date header
    const DATE_HEADER = 'X-DATE';

    // The authorization header
    const AUTHORIZATION_HEADER = 'Authorization';

    // The amount of the seconds the request is permitted to differ from the server time
    const DRIFT_TIME_ALLOWANCE = 90;

    /**
     * Process a request
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $params = Authorization::extractParamsFromHeaderString(
            $request->getHeaderLine(self::AUTHORIZATION_HEADER)
        );

        if ($params) {
            if ($token = $this->getTokenFromAccessToken($params['access_token'])) {
                try {
                    $date = new DateTime($params['date'] ?? $request->getHeaderLine(self::DATE_HEADER));

                    $auth = new Authorization(
                        $request->getMethod(),
                        $this->getRequestUri($request),
                        $token,
                        $date,
                        $this->getRequestBody($request),
                        $params['v'],
                        \base64_decode($params['salt'])
                    );

                    if ($auth->verify(\base64_decode($params['hmac']), $auth, static::DRIFT_TIME_ALLOWANCE)) {
                        return $handler->handle(
                            $request->withAttribute('ncryptf-token', $token)
                                ->withAttribute('ncryptf-user', $this->getUserFromToken($token))
                        );
                    }
                } catch (Exception $e) {
                    return $handler->handle($request)
                        ->withStatus(401);
                }
            }
        }

        return $handler->handle($request)
            ->withStatus(401);
    }

    /**
     * Returns the full URI
     * @param ServerRequestInterface $request
     * @return string
     */
    private function getRequestUri(ServerRequestInterface $request) : string
    {
        $uri = $request->getUri()->getPath();
        $query = $request->getUri()->getQuery();

        if (!empty($query)) {
            return $uri . '?' . \urldecode($query);
        }

        return $uri;
    }

    /**
     * Returns the plaintext request body.
     *
     * @param ServerRequestInterface $request
     * @return string
     */
    protected function getRequestBody(ServerRequestInterface $request) : string
    {
        if ($decryptedBody = $request->getAttribute('ncryptf-decrypted-body', false)) {
            return $decryptedBody;
        }

        return $request->getBody()->getContents();
    }

    /**
     * Returns the \ncryptf\Token associated to the given access token.
     * If the access token is not found, `NULL` should be returned
     *
     * @param string $accessToken
     * @return \ncryptf\Token
     */
    abstract protected function getTokenFromAccessToken(string $accessToken) :? Token;

    /**
     * Given a particular token, returns an object, array, or integer representing the user
     *
     * @param \ncryptf\Token $token
     * @return integer|array|object
     */
    abstract protected function getUserFromToken(Token $token);
}
