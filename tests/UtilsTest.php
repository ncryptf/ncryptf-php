<?php declare(strict_types=1);

namespace ncryptf\Tests;

use ncryptf\Utils;
use PHPUnit\Framework\TestCase;

class UtilsTest extends TestCase
{
    public function testKeypairGeneration()
    {
        $keypair = Utils::generateKeypair();
        $this->assertEquals(32, \strlen($keypair['public']));
        $this->assertEquals(32, \strlen($keypair['secret']));
    }

    public function testSigningKeypairGeneration()
    {
        $keypair = Utils::generateSigningKeypair();
        $this->assertEquals(64, \strlen($keypair['public']));
        $this->assertEquals(32, \strlen($keypair['secret']));
    }

    public function testZero()
    {
        $data = \random_bytes(32);
        $zero = Utils::zero($data);
        $this->assertEquals($zero, null);
    }
}
