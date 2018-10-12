<?php declare(strict_types=1);

namespace ncryptf\middleware;

use Exception;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use ncryptf\Response;

use ncryptf\Token;
use ncryptf\exceptions\DecryptionFailedException;
use ncryptf\exceptions\InvalidChecksumException;
use ncryptf\exceptions\InvalidSignatureException;

use ncryptf\middleware\EncryptionKeyInterface;

final class JsonRequestParser implements MiddlewareInterface
{
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
                    $request = $request->withParsedBody([])
                        ->withAttribute('ncryptf-decrypted-body', '')
                        ->withAttribute('ncryptf-version', 2)
                        ->withAttribute('ncryptf-request-public-key', \base64_decode($request->getHeaderLine('x-pubkey')));
                } else {
                    $version = Response::getVersion($rawBody);
                    $key = $this->getEncryptionKey($request);

                    $body = $this->decryptRequest($key, $request, $rawBody, $version);

                    // If we're on V2 or greater of the request, and a token is defined, verify that the signature was signed by the user who issued the request
                    if ($version >= 2 && $request->getAttribute('ncryptf-token') instanceof Token) {
                        $token = $request->getAttribute('ncryptf-token');
                        $publicKey = Response::getSigningPublicKeyFromResponse($rawBody);
                        if (\sodium_compare($publicKey, $token->getSignaturePublicKey()) !== 0) {
                            throw new Exception('Signing key mismatch.');
                        }
                    }

                    $request = $request->withParsedBody(\json_decode($body, true))
                        ->withAttribute('ncryptf-decrypted-body', $body)
                        ->withAttribute('ncryptf-version', $version)
                        ->withAttribute('ncryptf-request-public-key', $version === 2 ? Response::getPublicKeyFromResponse($rawBody) : \base64_decode($request->getHeaderLine('x-pubkey')));
                }
            } catch (DecryptionFailedException | InvalidArgumentException | InvalidSignatureException | InvalidChecksumException | Exception $e) {
                return $handler->handle($request)
                        ->withStatus(400);
            }
        }

        // Only attempt to process this request if it is a vnd.25519+json or vnd.ncryptf+json request
        // Otherwise, continue with normal processing
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
            if (!$request->hasHeader('x-pubkey') || !$request->hasHeader('x-nonce')) {
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
            $result = $this->cache->get($hashKey);

            if (!$result) {
                throw new Exception('Unable to extract key from cache.');
            }

            if (\function_exists('igbinary_unserialize')) {
                return \igbinary_unserialize($result);
            }

            return \unserialize($result);
        } catch (InvalidArgumentException $e) {
            throw new Exception('Unable to decrypt request.', null, $e);
        }
    }

    /**
     * Check whether the request payload need to be processed
     * @param ServerRequestInterface $request
     * @return bool
     */
    private function checkRequest(ServerRequestInterface $request): bool
    {
        $contentType = $request->getHeaderLine('Content-Type');
        foreach ($this->contentType as $allowedType) {
            if (\stripos($contentType, $allowedType) === 0) {
                return true;
            }
        }
        return false;
    }
}
