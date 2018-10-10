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
     * Returns the signing public key
     * @return string
     */
    public function getSigningPublicKey() : string;

    /**
     * Returns the signing secret key
     * @return string
     */
    public function getSigningSecretKey() : string;

    /**
     * Returns the signing keypair
     * @return string
     */
    public function getSigningKeyPair() : Keypair;

    /**
     * Returns true if the key is ephemeral
     * @return boolean
     */
    public function isEphemeral() : bool;

    /**
     * Generates a new EncryptionKeyInterface
     * @return EncryptionKeyInterface
     */
    public static function generate($ephemeral = false) : EncryptionKeyInterface;
}
