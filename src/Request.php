<?php declare(strict_types=1);

namespace ncryptf;

use ncryptf\Keypair;
use ncryptf\exceptions\EncryptionFailedException;
use InvalidArgumentException;
use SodiumException;

final class Request
{
    /**
     * Sodium CryptoBox Keypair
     *
     * @var Keypair
     */
    private $keypair;

    /**
     * 24 byte nonce
     *
     * @var string
     */
    private $nonce;

    /**
     * Constructor
     *
     * @param string $secretKey The 32 byte secret key
     * @param string $publicKey The 32 byte public keyy
     *
     * @throws InvalidArguementException
     */
    public function __construct(string $secretKey, string $publicKey)
    {
        try {
            $this->keypair = new Keypair(
                $secretKey,
                $publicKey
            );
        } catch (SodiumException $e) {
            throw new InvalidArgumentException($e->getMessage());
        }
    }

    /**
     * Encrypts a request body
     *
     * @param string $request       The raw HTTP request as a string
     * @param string $signatureKey  32 byte signature key
     * @param int    $version       Version to generate, defaults to 2
     * @param string $nonce         Optional nonce. If not provided, a 24 byte nonce will be generated
     * @return string
     *
     * @throws InvalidArguementException
     */
    public function encrypt(string $request, string $signatureKey = null, int $version = 2, string $nonce = null) : string
    {
        $this->nonce = $nonce ?? \random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        if ($version === 2) {
            if ($signatureKey === null || strlen($signatureKey) !== \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                throw new InvalidArgumentException;
            }

            $version = \pack('H*', 'DE259002');
            $body = $this->encryptBody($request, $this->nonce);
            if (!$body) {
                throw new EncryptionFailedException;
            }

            $publicKey = \sodium_crypto_box_publickey_from_secretkey($this->keypair->getSecretKey());
            $sigPubKey = \sodium_crypto_sign_publickey_from_secretkey($signatureKey);
            $payload = $version . $this->nonce . $publicKey . $body . $sigPubKey . $this->sign($request, $signatureKey);
            $checksum = sodium_crypto_generichash($payload, $this->nonce, 64);

            return $payload . $checksum;
        }

        // Version 1 payload is just a single sodium crypto box
        return $this->encryptBody($request, $this->nonce);
    }

    /**
     * Encrypts a request
     *
     * @param string $request   The raw HTTP request as a string
     * @param string $nonce     Optional nonce. If not provided, a 24 byte nonce will be generated
     * @return string
     *
     * @throws InvalidArguementException
     */
    private function encryptBody(string $request, string $nonce) : string
    {
        try {
            return \sodium_crypto_box(
                $request,
                $nonce,
                $this->keypair->getSodiumKeypair()
            );
        } catch (SodiumException $e) {
            throw new InvalidArgumentException($e->getMessage());
        }
    }

    /**
     * Creates a detached signature for the keypair
     *
     * @param string $request
     * @param string $secretKey
     * @return string
     *
     * @throws InvalidArguementException
     */
    public function sign(string $request, string $secretKey) : string
    {
        try {
            return \sodium_crypto_sign_detached(
                $request,
                $secretKey
            );
        } catch (SodiumException $e) {
            throw new InvalidArgumentException($e->getMessage());
        }
    }

    /**
     * Returns the nonce used
     *
     * @return string
     */
    public function getNonce() : string
    {
        return $this->nonce;
    }
}
