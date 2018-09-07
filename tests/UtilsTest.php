<?php declare(strict_types=1);

namespace ncryptf\Tests;

use ncryptf\Utils;
use ncryptf\Keypair;
use PHPUnit\Framework\TestCase;

class UtilsTest extends TestCase
{
    public function testKeypairGeneration()
    {
        $keypair = Utils::generateKeypair();
        $this->assertEquals(\get_class($keypair), 'ncryptf\Keypair');
        $this->assertEquals(32, \strlen($keypair->getPublicKey()));
        $this->assertEquals(32, \strlen($keypair->getSecretKey()));
    }

    public function testSigningKeypairGeneration()
    {
        $keypair = Utils::generateSigningKeypair();
        $this->assertEquals(\get_class($keypair), 'ncryptf\Keypair');
        $this->assertEquals(64, \strlen($keypair->getPublicKey()));
        $this->assertEquals(32, \strlen($keypair->getSecretKey()));
    }

    public function testZero()
    {
        $data = \random_bytes(32);
        $zero = Utils::zero($data);
        $this->assertEquals($zero, true);
        $this->assertEquals($data, NULL);
    }
}
