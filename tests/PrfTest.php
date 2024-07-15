<?php

namespace PHPTLS\Tests;

use PHPTLS\Tls\Prf;
use PHPUnit\Framework\TestCase;

class PrfTest extends TestCase
{
    public function testCreateMasterSecret()
    {
        $len = 48;
        $secret = '0101010101';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '0201010101010101010102020202020202020202030303030303030303030404';
        $result = Prf::createMasterSecret(hex2bin($secret), hex2bin($clientRandom), hex2bin($serverRandom));
        $this->assertEquals($len, strlen($result));
    }

    public function testCreateKeyBlock()
    {
        $secret = '0101010101';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '0201010101010101010102020202020202020202030303030303030303030404';
        $result = Prf::createKeyBlock(hex2bin($secret), hex2bin($clientRandom), hex2bin($serverRandom));
        $this->assertEquals(16, strlen($result['ClientWriteKey']));
        $this->assertEquals(16, strlen($result['ServerWriteKey']));
        $this->assertEquals(4, strlen($result['ClientWriteIV']));
        $this->assertEquals(4, strlen($result['ServerWriteIV']));
    }
}
