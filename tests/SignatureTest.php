<?php declare(strict_types=1);

namespace ncryptf\Tests;

use ncryptf\Tests\AbstractTest;
use ncryptf\Signature;

final class SignatureTest extends AbstractTest
{
    public function testV1Signatures()
    {
        foreach ($this->testCases as $k => $params) {
            $signature = Signature::derive($params[0], $params[1], $this->salt, $this->date, $params[2], 1);

            $hash = \explode("\n", $signature)[0];
            $this->assertEquals($hash, $this->v1SignatureResults[$k]);
        }
    }

    public function testV2Signatures()
    {
        foreach ($this->testCases as $k => $params) {
            $signature = Signature::derive($params[0], $params[1], $this->salt, $this->date, $params[2]);

            $hash = \explode("\n", $signature)[0];
            $this->assertEquals($hash, $this->v2SignatureResults[$k]);
        }
    }
}
