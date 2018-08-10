<?php declare(strict_types=1);

namespace ncryptf\Tests;

use ncryptf\Request;
use ncryptf\Response;
use PHPUnit\Framework\TestCase;

class RequestResponseTest extends TestCase
{
    private $clientKeyPair = [
        'secret' => 'bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=',
        'public' => 'Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU='
    ];

    private $serverKeyPair = [
        'secret' => 'gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=',
        'public' => 'YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8='
    ];

    private $signatureKeyPair = [
        'secret' => '9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==',
        'public' => 'IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE='
    ];
    
    private $nonce = 'bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut';

    public function testEncryptDecrypt()
    {
        $payload = <<<JSON
{
    "foo": "bar",
    "test": {
        "true": false,
        "a": 1,
        "b": 3.14,
        "nil": null,
        "arr": [
            "a", "b", "c", "d"
        ]
    }
}
JSON;

        $request = new Request(
            \base64_decode($this->clientKeyPair['secret']),
            \base64_decode($this->serverKeyPair['public'])
        );

        $cipher = $request->encrypt($payload, \base64_decode($this->nonce));

        $signature = $request->sign($payload, \base64_decode($this->signatureKeyPair['secret']));

        $response = new Response(
            \base64_decode($this->serverKeyPair['secret']),
            \base64_decode($this->clientKeyPair['public'])
        );

        $plain = $response->decrypt($cipher, \base64_decode($this->nonce));

        $this->assertEquals($payload, $plain);

        $this->assertTrue($response->isSignatureValid(
            $payload,
            $signature,
            \base64_decode($this->signatureKeyPair['public'])
        ));
    }
}
