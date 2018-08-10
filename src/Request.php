<?php declare(strict_types=1);

namespace ncryptf;

use InvalidArgumentException;
use SodiumException;

class Request
{
    /**
     * Sodium CryptoBox Keypair
     *
     * @var string
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
     * Encrypts a request
     *
     * @param string $request   The raw HTTP request as a string
     * @param string $nonce     Optional nonce. If not provided, a 24 byte nonce will be generated
     * @return string
     */
    public function encrypt(string $request, string $nonce = null)
    {
        $this->nonce = $nonce ?? \random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        try {
            return \sodium_crypto_box(
                $request,
                $this->nonce,
                $this->keypair
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
     */
    public function sign(string $request, string $secretKey)
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
    public function getNonce()
    {
        return $this->nonce;
    }
}
