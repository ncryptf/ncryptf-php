<?php declare(strict_types=1);

namespace ncryptf;

use DateTime;
use ncryptf\Signature;
use ncryptf\Token;

class Authorization
{
    /**
     * The HMAC info parameter. Overwrite this class and redeclare to change.
     */
    const AUTH_INFO = 'HMAC|AuthenticationKey';

    /**
     * The HMAC algorithm. Overwrite this class and redeclare to change.
     */
    const HMAC_ALGO = 'sha256';

    /**
     * Token object containing the access token and initial key material
     *
     * @var Token
     */
    private $token;

    /**
     * 32 byte salt array
     *
     * @var string
     */
    private $salt;

    /**
     * RFC1123 representation of the date
     *
     * @var string
     */
    private $date;

    /**
     * The generated signature
     *
     * @var string
     */
    private $signature;

    /**
     * 32 byte HMAC
     *
     * @var string
     */
    private $hmac;

    /**
     * The header version to generate
     *
     * @var integer
     */
    private $version = 2;

    /**
     * Calculates the authorization header information
     *
     * @param string $httpMethod    The HTTP method
     * @param string $uri           The full URI with query string parameters
     * @param Token $token          A token object containing the ikm, access token, and other authentication attributes
     * @param DateTime $date        The date
     * @param array|string $payload Array representation of the payload
     * @param integer $version      The authorization version, by default this is 2
     * @param string $salt          An optional fixed salt value
     */
    public function __construct(string $httpMethod, string $uri, Token $token, DateTime $date, $payload = '', int $version = 2, string $salt = null)
    {
        $httpMethod = \strtoupper($httpMethod);
        if ($salt === null) {
            $this->salt = \random_bytes(32);
        } else {
            $this->salt = $salt;
        }
        $this->signature = Signature::derive($httpMethod, $uri, $this->salt, $date, $payload, $version);

        $hkdf = hash_hkdf(static::HMAC_ALGO, $token->ikm, 0, static::AUTH_INFO, $this->salt);

        $this->hmac = \hash_hmac('sha256', $this->signature, \bin2hex($hkdf), true);
        $this->version = $version;
        $this->date = $date->format(\DateTime::RFC1123);
        $this->token = $token;
    }

    /**
     * Generates the versions HMAC header
     *
     * @return string
     */
    public function getHeader()
    {
        $salt = \base64_encode($this->salt);
        $hmac = \base64_encode($this->hmac);

        if ($this->version === 2) {
            $data = \base64_encode(\json_encode([
                'access_token' => $this->token->accessToken,
                'date' => $this->date,
                'hmac' => $hmac,
                'salt' => $salt,
                'v' => 2
            ]));

            return "HMAC {$data}";
        }
        
        // The version 1 HMAC is returned by default
        return "HMAC {$this->token->accessToken},{$hmac},{$salt}";
    }
}
