<?php declare(strict_types=1);

namespace ncryptf\Tests;

use ncryptf\Tests\AbstractTest;
use ncryptf\Authorization;

final class AuthorizationTests extends AbstractTest
{
    public function testV1HMAC()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, $this->date, $params[2], 1, $this->salt);

            $this->assertEquals($auth->getHeader(), $this->v1HMACHeaders[$k]);
        }
    }

    public function testV2HMAC()
    {
        foreach ($this->testCases as $k => $params) {
            $auth = new Authorization($params[0], $params[1], $this->token, $this->date, $params[2], 2, $this->salt);

            $this->assertEquals($auth->getHeader(), $this->v2HMACHeaders[$k]);
        }
    }
}
