<?php declare(strict_types=1);

namespace ncryptf;

use InvalidArgumentException;

final class Token
{
    /**
     * The access token
     *
     * @var string
     */
    public $accessToken;

    /**
     * The refresh token
     *
     * @var string
     */
    public $refreshToken;

    /**
     * The 32 byte initial key material
     *
     * @var string
     */
    public $ikm;

    /**
     * The 32 byte signature string
     *
     * @var string
     */
    public $signature;

    /**
     * The token expiration time
     *
     * @var float
     */
    public $expiresAt;

    /**
     * Constructor
     *
     * @param string $accessToken  The access token
     * @param string $refreshToken The refresh token
     * @param string $ikm          32 byte initial key material as a byte array
     * @param string $signature    32 byte signature string as a byte array
     * @param float $expiresAt     The expiration time of the token
     */
    public function __construct(string $accessToken, string $refreshToken, string $ikm, string $signature, float $expiresAt)
    {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;

        if (\strlen($ikm) !== 32) {
            throw new InvalidArgumentException(sprintf("Initial key material should be %d bytes.", 32));
        }

        $this->ikm = $ikm;

        if (\strlen($signature) !== 64) {
            throw new InvalidArgumentException(sprintf("Signature secret key should be %d bytes.", 64));
        }

        $this->signature = $signature;
        $this->expiresAt = $expiresAt;
    }

    /**
     * Extracts the signature public key from the request
     * @return string
     */
    public function getSignaturePublicKey()
    {
        return sodium_crypto_sign_publickey_from_secretkey($this->signature);
    }

    /**
     * Returns true if the token is expired
     *
     * @return boolean
     */
    public function isExpired() : bool
    {
        return \time() > $this->expiresAt;
    }
}
