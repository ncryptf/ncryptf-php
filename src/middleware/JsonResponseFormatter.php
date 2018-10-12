<?php declare(strict_types=1);

namespace ncryptf\middleware;

use Exception;

use ncryptf\Request;

use Psr\SimpleCache\CacheInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\ResponseInterface;

use Psr\Http\Server\MiddlewareInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\SimpleCache\InvalidArgumentException;

use ncryptf\middleware\EncryptionKeyInterface;

final class JsonResponseFormatter implements MiddlewareInterface
{
    const ENCODING_OPTIONS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION;

    /**
     * @var EncryptionKeyInterface $key
     */
    protected $key;

    /**
     * @var CacheInterface $cache
     */
    protected $cache;

    /**
     * @var array $contentType
     */
    protected $contentType = [
        'application/vnd.25519+json',
        'application/vnd.ncryptf+json'
    ];

    /**
     * Constructor
     * @param EncryptionKeyInterface $key
     */
    public function __construct(CacheInterface $cache, EncryptionKeyInterface $key)
    {
        $this->cache = $cache;
        $this->key = $key;
    }

    /**
     * Processes the request
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->checkRequest($request)) {
            $response = $handler->handle($request);
            $version = $request->getAttribute('ncryptf-version');
            $publicKey = $request->getAttribute('ncryptf-request-public-key');
            $token = $request->getAttribute('ncryptf-token');
            
            if ($version === null || $publicKey === null) {
                return $response->withStatus(400, 'Unable to encrypt request.');
            }

            if (!($response instanceof MessageInterface)) {
                throw new Exception('Response does not implement MessageInterface.');
            }

            $stream = $response->getBody();
            $class = $this->key;
            $key = $class::generate();
            
            $this->cache->set($key->getHashIdentifier(), $key);

            $r = new Request(
                $key->getBoxSecretKey(),
                $token === null ? $key->getSignSecretKey() : $token->signature
            );

            $content = $r->encrypt(
                (string)$stream,
                $publicKey,
                $version,
                $version === 2 ? null : \random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES)
            );

            if ($version === 1) {
                $response = $response->withHeader('x-sigpubkey', \base64_encode($token === null ? $key->getSignPublicKey() : $token->getSignaturePublicKey()))
                    ->withHeader('x-signature', \base64_encode($r->sign((string)$stream)))
                    ->withHeader('x-public-key-expiration', $key->getPublicKeyExpiration())
                    ->withHeader('x-nonce', \base64_encode($r->getNonce()))
                    ->withHeader('x-pubkey', \base64_encode($key->getBoxPublicKey()));
            }

            $stream->rewind();
            $stream->write(\base64_encode($content));
            return $response->withBody($stream)
                ->withHeader('Content-Type', 'application/vnd.ncryptf+json')
                ->withHeader('x-hashid', \base64_encode($key->getHashIdentifier()));
        }

        return $handler->handle($request)
            ->withHeader('Content-Type', 'application/vnd.ncryptf+json');
    }

    /**
     * Check whether the request payload need to be processed
     * @param ServerRequestInterface $request
     * @return bool
     */
    private function checkRequest(ServerRequestInterface $request): bool
    {
        $contentType = $request->getHeaderLine('Accept');
        foreach ($this->contentType as $allowedType) {
            if (\stripos($contentType, $allowedType) === 0) {
                return true;
            }
        }
        return false;
    }
}
