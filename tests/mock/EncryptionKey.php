<?php declare(strict_types=1);

namespace ncryptf\Tests\mock;

use ncryptf\middleware\EncryptionKeyInterface;
use ncryptf\Keypair;
use ncryptf\Utils;

final class EncryptionKey implements EncryptionKeyInterface
{
    private $hashId;
    private $key;
    private $signingKey;

    public function getHashIdentifier() : string
    {
        return $this->hashId;
    }

    public function getBoxPublicKey() : string
    {
        return $this->key->getPublicKey();
    }

    public function getBoxSecretKey() : string
    {
        return $this->key->getSecretKey();
    }

    public function getBoxKeyPair() : Keypair
    {
        return $this->key;
    }

    public function getSigningPublicKey() : string
    {
        return $this->signingKey->getPublicKey();
    }

    public function getSigningSecretKey() : string
    {
        return $this->signingKey->getSecretKey();
    }

    public function getSigningKeyPair() : Keypair
    {
        return $this->signingKey;
    }

    public function isEphemeral() : bool
    {
        return false;
    }

    public static function generate($ephemeral = false) : EncryptionKeyInterface
    {
        $object = new static;
        $object->hashId = \bin2hex(\random_bytes(32));
        $object->key = Utils::generateKeyPair();
        $object->signingKey = Utils::generateSigningKeypair();

        return $object;
    }
}
