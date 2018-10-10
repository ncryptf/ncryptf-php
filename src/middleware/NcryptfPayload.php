<?php declare(strict_types=1);

namespace ncryptf\middleware;

use Exception;

use ncryptf\Response;
use ncryptf\middleware\EncryptionKeyInterface;

use Middlewares\JsonPayload;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class NcryptfPayload extends JsonPayload implements MiddlewareInterface
{
    /**
     * @var array $contentType
     */
    protected $contentType = [
        'application/vnd.25519+json',
        'application/vnd.ncryptf+json'
    ];

    /**
     * @var int $options
     * JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION
     */
    private $options = 1344;

    /**
     * Constructor
     * @param CacheInterface $cache     A PSR-16 CacheInterface
     */
    public function __construct(CacheInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Processes the request
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->checkRequest($request)) {
            try {
                $rawBody = \base64_decode($request->getBody()->getContents());
                if ($rawBody === '') {
                    $request = $request->withParsedBody([]);
                    $request->withAttribute('ncryptf-decrypted-body', '');
                } else {
                    $version = Response::getVersion($rawBody);
                    $key = $this->getEncryptionKey($request);

                    $body = $this->decryptRequest($key, $request, $rawBody, $version);
                    $request = $request->withParsedBody(\json_decode($body, true, $this->options))
                        ->withAttribute('ncryptf-decrypted-body', $body)
                        ->withAttribute('ncryptf-version', $version)
                        ->withAttribute('ncryptf-request-public-key', Response::getPublicKeyFromResponse($rawBody));
                }
            } catch (DecryptionFailedException | InvalidArgumentException | InvalidSignatureException | InvalidChecksumException | Exception $e) {
                return $this->createResponse(400);
            }
        }

        return $handler->handle($request);
    }

    /**
     * Decrypts a request
     * @param EncryptionKeyInterface $key
     * @param ServerRequestInterface $request
     * @param string $rawBody
     * @param int $version
     * @return string|null
     */
    private function decryptRequest(EncryptionKeyInterface $key, ServerRequestInterface $request, string $rawBody, int $version) :? string
    {
        static $response = null;
        static $nonce = null;
        static $publicKey = null;

        $response = new Response(
            $key->getBoxSecretKey()
        );

        if ($version === 1) {
            if (!$request->hasHeader('x-pubkey') || !$equest->hasHeader('x-nonce')) {
                throw new Exception('Missing nonce or public key header. Unable to decrypt response.');
            }

            $publicKey = \base64_decode($request->getHeaderLine('x-pubkey'));
            $nonce = \base64_decode($request->getHeaderLine('x-nonce'));
        }
        $decryptedRequest = $response->decrypt(
            $rawBody,
            $publicKey,
            $nonce
        );

        $hashKey = $request->getHeaderLine('x-hashid');
        if ($key->isEphemeral()) {
            $this->cache->delete($hashKey);
        }

        return $decryptedRequest;
    }

    /**
     * Determines the key from the X-HashId header
     * @param ServerRequestInterface
     * @return EncryptionKeyInterface
     */
    private function getEncryptionKey(ServerRequestInterface $request) : EncryptionKeyInterface
    {
        if (!$request->hasHeader('x-hashid')) {
            throw new Exception('Unable to decrypt request.');
        }

        $hashKey = $request->getHeaderLine('x-hashid');

        try {
            return $this->cache->get($hashKey);
        } catch (InvalidArgumentException $e) {
            throw new Exception('Unable to decrypt request.', null, $e);
        }
    }

    /**
     * Check whether the request payload need to be processed
     */
    private function checkRequest(ServerRequestInterface $request): bool
    {
        $contentType = $request->getHeaderLine('Content-Type');
        foreach ($this->contentType as $allowedType) {
            if (stripos($contentType, $allowedType) === 0) {
                return true;
            }
        }
        return false;
    }
}
