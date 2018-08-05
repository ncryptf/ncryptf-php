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
        $this->salt = $salt ?? \random_bytes(32);
        $this->signature = Signature::derive($httpMethod, $uri, $this->salt, $date, $payload, $version);

        $hkdf = hash_hkdf(static::HMAC_ALGO, $token->ikm, 0, static::AUTH_INFO, $this->salt);

        $this->hmac = \hash_hmac('sha256', $this->signature, \bin2hex($hkdf), true);
        $this->version = $version;
        $this->date = $date->format(\DateTime::RFC1123);
        $this->token = $token;
    }

    /**
     * Extracts the HMAC parameters from a header string
     *
     * @param string $hmacHeader
     * @return array|boolean
     */
    public static function extractParamsFromHeaderString(string $hmacHeader = null)
    {
        if ($hmacHeader !== null && preg_match('/^HMAC\s+(.*?)$/', $hmacHeader, $matches)) {
            if (\strpos($matches[1], ',') !== false) {
                $params = explode(',', trim($matches[1][1]));

                if (count($params) !== 3) {
                    return false;
                }

                return [
                    'access_token' => $params[0],
                    'hmac' => $params[1],
                    'salt' => $params[2],
                    'v' => 1,
                    'date' => null,
                ];
            } else {
                $params = \json_decode(\base64_decode($matches[1]), true);

                if (!isset($params['v']) ||
                    !isset($params['access_token']) ||
                    !isset($params['hmac']) ||
                    !isset($params['salt']) ||
                    !isset($params['v']) ||
                    !isset($params['date'])
                ) {
                    return false;
                }

                return $params;
            }
        }

        return false;
    }

    /**
     * Returns the signature string
     *
     * @return string
     */
    public function getSignatureString()
    {
        return $this->signature;
    }

    /**
     * Returns the generated HMAC
     *
     * @return string
     */
    public function getHMAC()
    {
        return $this->hmac;
    }

    /**
     * Returns an RFC1123 formatted date
     *
     * @return string
     */
    public function getDate()
    {
        return $this->date;
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

    /**
     * Validates a provided HMAC against an auth object and a date
     *
     * @param string $hmac
     * @param self $auth
     * @param integer $driftAllowance
     * @return boolean
     */
    public function verify(string $hmac, self $auth, int $driftAllowance = 90)
    {
        $drift = $this->getTimeDrift($auth->getDate());
        if ($drift && $drift >= $driftAllowance) {
            return false;
        }

        if (\hash_equals($hmac, $auth->getHMAC())) {
            return true;
        }

        return false;
    }

    /**
     * Calculates the time difference between now and the provided date
     *
     * @param string $date
     * @return int|boolean
     */
    private function getTimeDrift(string $date)
    {
        $now = new \DateTime();
        $now->format(\DateTime::RFC1123);

        try {
            $realDate = new DateTime($date);
        } catch (\Exception $e) {
            return false;
        }

        return \abs($now->getTimestamp() - $realDate->getTimestamp());
    }
}
