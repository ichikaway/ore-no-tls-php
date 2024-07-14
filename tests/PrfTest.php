<?php

namespace PHPTLS\Tests;

use PHPTLS\Tls\Prf;
use PHPUnit\Framework\TestCase;

class PrfTest extends TestCase
{
    public function testCreateHash()
    {
        $len = 48;
        $secret = '0101010101';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '0201010101010101010102020202020202020202030303030303030303030404';
        $label = 'master secret';
        $result = Prf::createMasterSecret($len, hex2bin($secret), $label, hex2bin($clientRandom), hex2bin($serverRandom));
        $this->assertEquals($len, strlen($result));
    }
}
