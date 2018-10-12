<?php declare(strict_types=1);

namespace ncryptf\Tests;

use Curl\Curl;
use DateTime;
use PHPUnit\Framework\TestCase;
use ncryptf\Request;
use ncryptf\Response;
use ncryptf\Token;
use ncryptf\Utils;

/**
 * This class demonstrates a practical end-to-end implementation via cURL
 * Implementation may be inferred from this implementation, and is broken out into the following stages:
 * 1. Create a \ncryptf\Keypair instance
 * 2. Bootstrap an encrypted session by sending an unauthenticated requests to the ephemeral key endpoint with the following headers:
 *  - Accept: application/vnd.ncryptf+json
 *  - Content-Type: application/vnd.ncryptf+json
 *  - X-PubKey: <base64_encoded_$key->getPublicKey()>
 * 3. Decrypt the V2 response from the server. This contains a single use ephemeral key we can use to encrypt future requests in the payload.
 *    The servers public key is embedded in the response, and can be extracted by `Response::getPublicKeyFromResponse($response);`
 * 4. Perform an authenticated request using the clients secret key, and the servers public key.
 *
 *
 * Implementation Details
 * - The server WILL always advertise at minimum the following 2 headers:
 *      - X-HashId: A string used to represent the identifier to use to select which key to use.
 *      - X-Public-Key-Expiration: A unix timestamp representing the time at which the key will expire. This is used to determine if rekeying is required.
 * - The server WILL always generate a new keypair for each request. You may continue to use existing keys until they expire.
 * - To achieve perfect-forward-secrecy, it is advised to rekey the client key on each request. The server does not store the shared secret for prior requests.
 * - The client SHOULD keep a record of public keys offered by the server, along with their expiration time.
 * - The client SHOULD always use the most recent key offered by the server.
 * - If the client does not have any active keys, it should bootstrap a new session by calling the ephemeral key endpoint to retrieve a new public key from the server.
 */
final class IntegrationTest extends TestCase
{
    /**
     * This is the URL provided by the `NCRYPTF_TEST_API` environment variable
     * @var string $url
     */
    private $url;

    /**
     * A Keypair object
     * @var \ncryptf\Keypair $key
     */
    private $key;

    /**
     * Setup our test suite by checking the `NCRYPTF_TEST_API` environment variable, and creating a Keypair
     * @return void
     */
    public function setup()
    {
        if (($url = getenv('NCRYPTF_TEST_API')) === false) {
            $this->markTestSkipped('NCRYPTF_TEST_API environment variable not set. Unable to proceed.');
            $this->assertTrue(false);
            return;
        }

        $this->key = Utils::generateKeypair();
        $this->url = $url;
        $this->assertTrue(true);
    }

    /**
     * Tests the bootstrap process with an encrypted response
     * @return array
     */
    public function testEphemeralKeyBootstrap()
    {
        $curl = new Curl;

        // Set the appropriate headers
        $curl->setHeader('Content-Type', 'application/vnd.ncryptf+json');
        $curl->setHeader('Accept', 'application/vnd.ncryptf+json');

        // Tell the server what our PublicKey is
        $curl->setHeader('x-pubkey', \base64_encode($this->key->getPublicKey()));
        $curl->get("{$this->url}/ek");

        if ($curl->error) {
            $this->assertTrue(false, $curl->errorCode . ': ' . $curl->errorMessage);
            return;
        }

        $response = new Response($this->key->getSecretKey());

        try {
            $message = \json_decode(
                $response->decrypt(
                    \base64_decode($curl->response)
                ),
                true
            );

            $this->assertNotEmpty($message);
            $this->assertArrayHasKey('public', $message);
            $this->assertArrayHasKey('signature', $message);
            $this->assertArrayHasKey('hash-id', $message);

            return [
                'key' => Response::getPublicKeyFromResponse(\base64_decode($curl->response)),
                'hash-id' => $curl->responseHeaders['x-hashid'],
                'expiration' => $curl->responseHeaders['x-public-key-expiration'],
                'message' => $message
            ];
        } catch (\Exception $e) {
            $this->assertTrue(false, $e->getMessage());
        }
    }

    /**
     * This requests illustrates making an unauthenticated encrypted request and receiving an encrypted response
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    public function testUnauthenticatedEncryptedRequest(array $stack)
    {
        $curl = new Curl;

        // Set the appropriate headers
        $curl->setHeader('Content-Type', 'application/vnd.ncryptf+json');
        $curl->setHeader('Accept', 'application/vnd.ncryptf+json');

        // Tell the server what key we want to use
        $curl->setHeader('X-HashId', $stack['hash-id']);
        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        // $curl->setHeader('x-pubkey', \base64_encode($this->key->getPublicKey()));
        
        $request = new Request(
            $this->key->getSecretKey(),
            // Because our request is unauthenticated, this signature doesn't mean anything, so we can just generate a random one.
            Utils::generateSigningKeypair()->getSecretKey()
        );
        
        // Encrypt our JSON payload using the public key provided by the server from our ephemeral key request
        $payload = \json_encode(['hello' => 'world'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        $encryptedPayload = \base64_encode($request->encrypt(
            $payload,
            $stack['key']
        ));

        $curl->post("{$this->url}/echo", $encryptedPayload);

        if ($curl->error) {
            $this->assertTrue(false, $curl->errorCode . ': ' . $curl->errorMessage);
            return;
        }
        
        $response = new Response($this->key->getSecretKey());

        try {
            $message = $response->decrypt(
                \base64_decode($curl->response)
            );

            // The echo request will return the same payload back to us.
            $this->assertSame($payload, $message);
        } catch (\Exception $e) {
            $this->assertTrue(false, $e->getMessage());
        }
    }
}
