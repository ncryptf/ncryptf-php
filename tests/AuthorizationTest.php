<?php declare(strict_types=1);

namespace ncryptf\Tests;

use DateTime;
use ncryptf\Tests\AbstractTest;
use ncryptf\Authorization;

final class AuthorizationTests extends AbstractTest
{
    public function testV1HMAC()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, $this->date, $params[2], 1, $this->salt);

            $this->assertEquals($auth->getHeader(), $this->v1HMACHeaders[$k]);
            $hmac = \explode(',', $this->v1HMACHeaders[$k])[1];
            $this->assertEquals($auth->verify($hmac, $auth, 90), false);
        }
    }

    public function testV2HMAC()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, $this->date, $params[2], 2, $this->salt);

            $this->assertEquals($auth->getHeader(), $this->v2HMACHeaders[$k]);
            $hmac = \json_decode(\base64_decode(\str_replace('HMAC ', '', $this->v2HMACHeaders[$k])), true)['hmac'];
            $this->assertEquals($auth->verify($hmac, $auth, 90), false);
        }
    }

    public function testVerify()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2], 1, $this->salt);

            $this->assertEquals($auth->verify($auth->getHMAC(), $auth, 90), true);

            $auth2 = new Authorization($params[0], $params[1], $this->token, new DateTime, $params[2], 2, $this->salt);

            $this->assertEquals($auth2->verify($auth2->getHMAC(), $auth2, 90), true);
        }
    }
}
