<?php declare(strict_types=1);

namespace ncryptf;

use ncryptf\Keypair;
use SodiumException;

final class Utils
{
    /**
     * Securely erases a memory block
     *
     * @param string $data
     * @return boolean
     */
    public static function zero(string $data)
    {
        return \sodium_memzero($data) === null;
    }

    /**
     * Generates a crypto keypair
     *
     * @return \ncryptf\Keypair
     */
    public static function generateKeypair()
    {
        try {
            $keypair = \sodium_crypto_box_keypair();
            return new Keypair(
                \sodium_crypto_box_publickey($keypair),
                \sodium_crypto_box_secretkey($keypair)
            );
        } catch (SodiumException $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     * Generates a signing keypair
     *
     * @return \ncryptf\Keypair
     */
    public static function generateSigningKeypair()
    {
        try {
            $keypair = \sodium_crypto_sign_keypair();
            return new Keypair(
                \sodium_crypto_sign_publickey($keypair),
                \sodium_crypto_sign_secretkey($keypair)
            );
        } catch (SodiumException $e) {
            throw new Exception($e->getMessage());
        }
    }
}
