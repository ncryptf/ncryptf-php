<?php declare(strict_types=1);

namespace ncryptf;

final class Keypair
{
    /**
     * Secret key
     *
     * @var string
     */
    private $secret;

    /**
     * Public Key
     *
     * @var string
     */
    private $public;

    /**
     * Constructor
     *
     * @param string $secret
     * @param string $public
     */
    public function __construct(string $secret, string $public)
    {
        $this->secret = $secret;
        $this->public = $public;
    }

    /**
     * Returns the public key
     *
     * @return string|null
     */
    public function getPublicKey() :? string
    {
        return $this->public;
    }

    /**
     * Returns the secret key
     *
     * @return string|null
     */
    public function getSecretKey() :? string
    {
        return $this->secret;
    }
}
