<?php declare(strict_types=1);

namespace ncryptf;

use ncryptf\exceptions\InvalidChecksumException;
use ncryptf\exceptions\InvalidSignatureException;
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
     * 
     * @throws InvalidArguementException
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
     * Decrypts a payload using the response and an optional nonce
     * Nonce is not required for v2 type signatures, but is required for v1 signatures
     * 
     * @param string $response  The encrypted HTTP response, as a multi-byte string
     * @param string $nonce     The 32 byte nonce
     * 
     * @throws InvalidArguementException
     */
    public function decrypt(string $response, string $nonce = null) : string
    {
        $version = $this->getVersion($response);
        if ($version === 2) {
            $nonce = \substr($response, 4, 24);
            // Determine the payload size sans the 64 byte checksum at the end
            $payload = \substr($response, 0, \strlen($response) - 64);
            $checksum = \substr($response, -64);

            // Verify the checksum to ensure the headers haven't been tampered with
            if ($checksum !== \sodium_crypto_generichash($payload, $nonce, 64)) {
                throw new InvalidChecksumException;
            }
            
            $publicKey = \substr($response, 28, 32);
            $signature = \substr($payload, -64);
            $payload = \substr($payload, 0, -64);
            $sigPubKey = \substr($payload, -32);
            $payload = \substr($payload, 0, -32);
            $body = \substr($payload, 60, \strlen($payload));

            $decryptedPayload = $this->decrypt($body, $nonce);
            if (!$this->isSignatureValid($decryptedPayload, $signature, $sigPubKey)) {
                throw new InvalidSignatureException;
            }

            return $decryptedPayload;
        }

        if ($nonce === null) {
            throw new InvalidArgumentException('Nonce is required to decrypt v1 requests.');
        }

        return $this->decryptBody($response, $nonce);
    }

    /**
     * Decrypts a given response with a nonce
     * This will return the decrypted string of decrypt was successful, and false otherwise
     *
     * @param string $response  The encrypted HTTP response, as a multi-byte string
     * @param string $nonce     The 32 byte nonce
     * @return string
     * 
     * @throws InvalidArguementException
     */
    private function decryptBody(string $response, string $nonce) : string
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
     * 
     *  @throws InvalidArguementException
     */
    public function isSignatureValid(string $response, string $signature, string $publicKey) : bool
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

    /**
     * Extracts the version from the response
     * 
     * @param string $response  The encrypted http response
     * @return int
     */
    private function getVersion(string $response) : int
    {
        $header = \substr($response, 0, 4);
        if (\strtoupper(\unpack("h*", $header)[1]) === 'DE259002') {
            return 2;
        }

        return 1;
    }
}
