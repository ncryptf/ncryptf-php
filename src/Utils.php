<?php declare(strict_types=1);

namespace ncryptf;

use SodiumException;

final class Utils
{
    /**
     * Securely erases a memory block
     *
     * @param string $data
     * @return void
     */
    public static function zero(string $data)
    {
        return \sodium_memzero($data);
    }

    /**
     * Generates a crypto keypair
     *
     * @return array
     */
    public static function generateKeypair()
    {
        try {
            $keypair = \sodium_crypto_box_keypair();
            return [
                'public' => \sodium_crypto_box_secretkey($keypair),
                'secret' => \sodium_crypto_box_publickey($keypair)
            ];
        } catch (SodiumException $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     * Generates a signing keypair
     *
     * @return array
     */
    public static function generateSigningKeypair()
    {
        try {
            $keypair = \sodium_crypto_sign_keypair();
            return [
                'public' => \sodium_crypto_sign_secretkey($keypair),
                'secret' => \sodium_crypto_sign_publickey($keypair)
            ];
        } catch (SodiumException $e) {
            throw new Exception($e->getMessage());
        }
    }
}
