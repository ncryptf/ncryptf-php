<?php declare(strict_types=1);

namespace ncryptf;

use InvalidArgumentException;
use SodiumException;

class Response
{
    /**
     * Sodium CryptoBox Keypair
     *
     * @var string
     */
    private $keypair;

    /**
     * Constructor
     *
     * @param string $secretKey The 32 byte secret key
     * @param string $publicKey The 32 byte public key
     */
    public function __construct(string $secretKey, string $publicKey)
    {
        try {
            $this->keypair = \sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $secretKey,
                $publicKey
            );
        } catch (SodiumException $e) {
            throw new InvalidArgumentException($e->getMessage());
        }
    }

    /**
     * Decrypts a given response with a nonce
     * This will return the decrypted string of decrypt was successful, and false otherwise
     *
     * @param string $response  The encrypted HTTP response, as a multi-byte string
     * @param string $nonce     The 32 byte nonce
     * @return string|bool
     */
    public function decrypt(string $response, string $nonce)
    {
        try {
            return \sodium_crypto_box_open(
                $response,
                $nonce,
                $this->keypair
            );
        } catch (SodiumException $e) {
            throw new InvalidArgumentException($e->getMessage());
        }
    }

    /**
     * Returns true if the signature validates the response
     *
     * @param string $response  The raw http response, after decoding
     * @param string $signature The raw multi-byte signature
     * @param string $publicKey The signing public key
     * @return bool
     */
    public function isSignatureValid(string $response, string $signature, string $publicKey)
    {
        try {
            return \sodium_crypto_sign_verify_detached(
                $signature,
                $response,
                $publicKey
            );
        } catch (SodiumException $e) {
            throw new InvalidArgumentException($e->getMessage());
        }
    }
}
