<?php declare(strict_types=1);

namespace ncryptf;

use DateTime;

final class Signature
{
    /**
     * Constructs a new signature
     *
     * @param string       $httpMethod The HTTP method
     * @param string       $uri        The full URI with query string parameters
     * @param string       $salt       32 byte salt
     * @param DateTime     $date       The datetime object
     * @param array|string $payload    An array containing the data to sign
     * @param int          $version    The signature version to generate
     */
    public static function derive(
        string $httpMethod,
        string $uri,
        string $salt,
        DateTime $date,
        $payload = [],
        int $version = 2
    ) {
        $httpMethod = \strtoupper($httpMethod);
        $data = self::serializePayload($payload);
        $hash = self::getSignatureHash($data, $salt, $version);
        $time = $date->format(\DateTime::RFC1123);
        $b64Salt = \base64_encode($salt);

        return "{$hash}\n{$httpMethod}+{$uri}\n{$time}\n{$b64Salt}";
    }

    /**
     * Serializes the payload for signing
     *
     * @param array|string $payload
     * @return string
     */
    private static function serializePayload($payload = [])
    {
        // If the payload is already JSON, return it
        if (\is_string($payload)) {
            return $payload;
        }

        $data = '';

        if (!empty($payload)) {
            $data = \json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        }

        return $data;
    }

    /**
     * Returns the signature hash
     *
     * @param string  $data
     * @param string  $salt
     * @param integer $version
     * @return string
     */
    private static function getSignatureHash(string $data, string $salt, int $version = 2)
    {
        if ($version === 2) {
            return \base64_encode(\sodium_crypto_generichash($data, $salt, 64));
        }

        // Version 1 signature hash should be returned as a fallback
        return \hash('sha256', $data);
    }
}
