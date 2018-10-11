<?php declare(strict_types=1);

namespace ncryptf\middleware;

use ncryptf\Keypair;

interface EncryptionKeyInterface
{
    /**
     * Returns the hash identifier
     * @return string
     */
    public function getHashIdentifier() : string;

    /**
     * Returns the binary crypto public Key
     * @return string
     */
    public function getBoxPublicKey() : string;

    /**
     * Returns the binary crypto secret key
     * @return string
     */
    public function getBoxSecretKey() : string;

    /**
     * Returns the Sodium KeyPair
     * @return Keypair
     */
    public function getBoxKeyPair() : Keypair;

    /**
     * Returns true if the key is ephemeral
     * @return boolean
     */
    public function isEphemeral() : bool;

    /**
     * Returns the public key expiration time represented as a unix timestamp
     * @return int
     */
    public function getPublicKeyExpiration() : int;

    /**
     * Generates a new EncryptionKeyInterface
     * @return EncryptionKeyInterface
     */
    public static function generate($ephemeral = false) : EncryptionKeyInterface;
}
