<?php declare(strict_types=1);

namespace ncryptf;

final class Keypair
{
    /**
     * Secret key
     *
     * @var string
     */
    private $secretKey;

    /**
     * Public Key
     *
     * @var string
     */
    private $publicKey;

    /**
     * Constructor
     *
     * @param string $secret
     * @param string $public
     */
    public function __construct(string $secretKey, string $publicKey)
    {
        $this->secretKey = $secretKey;
        $this->publicKey = $publicKey;
    }

    /**
     * Returns the public key
     *
     * @return string|null
     */
    public function getPublicKey() :? string
    {
        return $this->publicKey;
    }

    /**
     * Returns the secret key
     *
     * @return string|null
     */
    public function getSecretKey() :? string
    {
        return $this->secretKey;
    }

    /**
     * Returns the sodium keypair
     *
     * @return string
     */
    public function getSodiumKeypair()
    {
        return \sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $this->getSecretKey(),
            $this->getPublicKey()
        );
    }
}
