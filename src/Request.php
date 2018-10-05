<?php declare(strict_types=1);

namespace ncryptf;

use ncryptf\Keypair;
use ncryptf\exceptions\EncryptionFailedException;
use InvalidArgumentException;
use SodiumException;

final class Request
{
    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $signatureSecretKey;

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
     * @param string $signatureSecretKey The 64 byte public keyy
     *
     * @throws InvalidArgumentException
     */
    public function __construct(string $secretKey, string $signatureSecretKey)
    {
        if (\strlen($secretKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidArgumentException(sprintf("Secret key should be %d bytes.", SODIUM_CRYPTO_BOX_SECRETKEYBYTES));
        }

        $this->secretKey = $secretKey;

        if (\strlen($signatureSecretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidArgumentException(sprintf("Signing key should be %d bytes.", SODIUM_CRYPTO_SIGN_SECRETKEYBYTES));
        }

        $this->signatureSecretKey = $signatureSecretKey;
    }

    /**
     * Encrypts a request body
     *
     * @param string $request           The raw HTTP request as a string
     * @param string $publicKey   32 byte public key
     * @param int    $version           Version to generate, defaults to 2
     * @param string $nonce             Optional nonce. If not provided, a 24 byte nonce will be generated
     * @return string
     *
     * @throws InvalidArgumentException
     */
    public function encrypt(string $request, string $publicKey, int $version = 2, string $nonce = null) : string
    {
        $this->nonce = $nonce ?? \random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        if (\strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(sprintf("Remote public key should be %d bytes.", SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
        }

        if ($version === 2) {
            $version = \pack('H*', 'DE259002');
            $body = $this->encryptBody($request, $publicKey, $this->nonce);
            if (!$body) {
                throw new EncryptionFailedException('An unexpected error occured when encrypting the message.');
            }

            $iPublicKey = \sodium_crypto_box_publickey_from_secretkey($this->secretKey);
            $sigPubKey = \sodium_crypto_sign_publickey_from_secretkey($this->signatureSecretKey);
            $payload = $version . $this->nonce . $iPublicKey . $body . $sigPubKey . $this->sign($request);
            $checksum = sodium_crypto_generichash($payload, $this->nonce, 64);

            return $payload . $checksum;
        }


        // Version 1 payload is just a single sodium crypto box
        return $this->encryptBody($request, $publicKey, $this->nonce);
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
    private function encryptBody(string $request, string $publicKey, string $nonce) : string
    {
        if (\strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(sprintf("Public key should be %d bytes.", SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
        }

        if (\strlen($nonce) !== SODIUM_CRYPTO_BOX_NONCEBYTES) {
            throw new InvalidArgumentException(sprintf("Nonce should be %d bytes.", SODIUM_CRYPTO_BOX_NONCEBYTES));
        }

        try {
            $keypair = new Keypair(
                $this->secretKey,
                $publicKey
            );
            return \sodium_crypto_box(
                $request,
                $nonce,
                $keypair->getSodiumKeypair()
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
    public function sign(string $request) : string
    {
        try {
            return \sodium_crypto_sign_detached(
                $request,
                $this->signatureSecretKey
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
