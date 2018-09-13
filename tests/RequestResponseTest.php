<?php declare(strict_types=1);

namespace ncryptf\Tests;

use ncryptf\Request;
use ncryptf\Response;
use ncryptf\Tests\AbstractTest;

class RequestResponseTest extends AbstractTest
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

    private $expectedCipher = '1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=';
    private $expectedSignature = 'dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==';

    private $expectedv2Cipher = '7VIJIG7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLWFO+F9jqh7oy1Qx/cIBB7HA+Xsoiz73LoEVGRukdwQf1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg41/K6NkVYeH5RWFt9WNQ6+8d/qvQ/odHD9pJq86ejU8SldDGDqAfwMmdQh9AHUJIbtxlOg9cNUWCNYX8wQ9qbz';
    public function testv2EncryptDecrypt()
    {
        $payload = <<<JSON
{
    "foo": "bar",
    "test": {
        "true": false,
        "zero": 0.0,
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

        $cipher = $request->encrypt($payload, \base64_decode($this->signatureKeyPair['secret']), \base64_decode($this->nonce));

        $this->assertEquals($this->expectedv2Cipher, \base64_encode($cipher));
        
        $response = new Response(
            \base64_decode($this->serverKeyPair['secret']),
            \base64_decode($this->clientKeyPair['public'])
        );

        $plain = $response->decrypt($cipher);

        $this->assertEquals($payload, $plain);
    }

    public function testv1EncryptDecrypt()
    {
        $payload = <<<JSON
{
    "foo": "bar",
    "test": {
        "true": false,
        "zero": 0.0,
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

        $cipher = $request->encrypt($payload, null, \base64_decode($this->nonce), 1);

        $signature = $request->sign($payload, \base64_decode($this->signatureKeyPair['secret']));
        
        $this->assertEquals($this->expectedCipher, \base64_encode($cipher));
        $this->assertEquals($this->expectedSignature, \base64_encode($signature));

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
