<?php declare(strict_types=1);

namespace ncryptf;

use ncryptf\exceptions\DecryptionFailedException;
use ncryptf\exceptions\InvalidChecksumException;
use ncryptf\exceptions\InvalidSignatureException;
use Exception;
use InvalidArgumentException;
use SodiumException;

class Response
{
    /**
     * Secret key
     *
     * @var string
     */
    private $secretKey;

    /**
     * Constructor
     *
     * @param string $secretKey The 32 byte secret key
     *
     * @throws InvalidArgumentException
     */
    public function __construct(string $secretKey)
    {
        if (\strlen($secretKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidArgumentException(sprintf("Secret key should be %d bytes.", SODIUM_CRYPTO_BOX_SECRETKEYBYTES));
        }

        $this->secretKey = $secretKey;
    }

    /**
     * Decrypts a payload using the response and an optional nonce
     * Nonce is not required for v2 type signatures, but is required for v1 signatures
     *
     * @param string $response  The encrypted HTTP response, as a multi-byte string
     * @param string $publicKey 32 byte optional public key
     * @param string $nonce     The 32 byte nonce, optional
     *
     * @throws InvalidArgumentException
     */
    public function decrypt(string $response, string $publicKey = null, string $nonce = null) : string
    {
        $version = static::getVersion($response);
        if ($version === 2) {
            if (\strlen($response) < 236) {
                throw new DecryptionFailedException(sprintf("Message is %d bytes, however 236+ were expected", \strlen($response)));
            }

            $nonce = \substr($response, 4, 24);

            // Determine the payload size sans the 64 byte checksum at the end
            $payload = \substr($response, 0, \strlen($response) - 64);
            $checksum = \substr($response, -64);

            // Verify the checksum to ensure the headers haven't been tampered with
            if ($checksum !== \sodium_crypto_generichash($payload, $nonce, 64)) {
                throw new InvalidChecksumException("Calculated checksum differs from the checksum associated with the message.");
            }
            
            $publicKey = \substr($response, 28, 32);
            $signature = \substr($payload, -64);
            $payload = \substr($payload, 0, -64);
            $sigPubKey = \substr($payload, -32);
            $payload = \substr($payload, 0, -32);
            $body = \substr($payload, 60, \strlen($payload));

            $decryptedPayload = $this->decryptBody($body, $publicKey, $nonce);
            if (!$decryptedPayload) {
                throw new DecryptionFailedException('An unexpected error occurred when decrypting the message.');
            }

            if (!$this->isSignatureValid($decryptedPayload, $signature, $sigPubKey)) {
                throw new InvalidSignatureException('The message signature is not valid.');
            }

            return $decryptedPayload;
        }

        if ($nonce === null) {
            throw new InvalidArgumentException('Nonce is required to decrypt v1 requests.');
        }

        if (\strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(sprintf("Public key should be %d bytes.", SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
        }
        
        return $this->decryptBody($response, $publicKey, $nonce);
    }

    /**
     * Decrypts a given response with a nonce
     * This will return the decrypted string of decrypt was successful, and false otherwise
     *
     * @param string $response  The encrypted HTTP response, as a multi-byte string
     * @param string $publicKey 32 byte public key
     * @param string $nonce     The 32 byte nonce
     * @return string
     *
     * @throws InvalidArgumentException
     */
    private function decryptBody(string $response, string $publicKey, string $nonce) : string
    {
        try {
            if (\strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
                throw new InvalidArgumentException(sprintf("Public key should be %d bytes.", SODIUM_CRYPTO_BOX_PUBLICKEYBYTES));
            }

            if (\strlen($response) < SODIUM_CRYPTO_BOX_MACBYTES) {
                throw new DecryptionFailedException("Minimum message length not met.");
            }

            $keypair = new Keypair(
                $this->secretKey,
                $publicKey
            );

            if ($result = \sodium_crypto_box_open(
                $response,
                $nonce,
                $keypair->getSodiumKeypair()
            )) {
                return $result;
            }
            
            throw new DecryptionFailedException;
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
     * @throws InvalidArgumentException
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
     * Extracts the public key from a v2 response
     *
     * @param string $response
     * @return string
     */
    public static function getPublicKeyFromResponse(string $response) : string
    {
        $version = static::getVersion($response);
        if ($version === 2) {
            if (\strlen($response) < 236) {
                throw new InvalidArgumentException;
            }
            
            return \substr($response, 28, 32);
        }

        throw new InvalidArgumentException('The response provided is not suitable for public key extraction.');
    }

    /**
     * Extracts the signature public key from a v2 response
     *
     * @param string $response
     * @return string
     */
    public static function getSignaturePublicKeyFromResponse(string $response) : string
    {
        $version = static::getVersion($response);
        if ($version === 2) {
            if (\strlen($response) < 236) {
                throw new InvalidArgumentException;
            }
            
            $payload = \substr($response, 0, \strlen($response) - 64);
            return  \substr($payload, -32);
        }

        throw new InvalidArgumentException('The response provided is not suitable for public key extraction.');
    }

    /**
     * Extracts the version from the response
     *
     * @param string $response  The encrypted http response
     * @return int
     */
    public static function getVersion(string $response) : int
    {
        if (\strlen($response) < 16) {
            throw new DecryptionFailedException("Message length is too short to determine version.");
        }

        $header = \substr($response, 0, 4);
        if (\strtoupper(\bin2hex($header)) === 'DE259002') {
            return 2;
        }

        return 1;
    }
}
