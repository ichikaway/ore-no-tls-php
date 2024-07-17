<?php

namespace PHPTLS\Tests;

use PHPTLS\Tls\Prf;
use PHPUnit\Framework\TestCase;

class PrfTest extends TestCase
{
    public function testCreateMasterSecret()
    {
        //test case from https://tls12.xargs.org/#client-encryption-keys-calculation
        $masterSecret = '916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c';
        $len = 48;
        $secret = 'df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624';
        ### client random from Client Hello
        $clientRandom = '0001020304050607'.
                        '08090a0b0c0d0e0f'.
                        '1011121314151617'.
                        '18191a1b1c1d1e1f';

        ### server random from Server Hello
        $serverRandom  = '7071727374757677'.
                         '78797a7b7c7d7e7f'.
                         '8081828384858687'.
                         '88898a8b8c8d8e8f';

        $result = Prf::createMasterSecret(hex2bin($secret), hex2bin($clientRandom), hex2bin($serverRandom));
        $this->assertEquals($len, strlen($result));
        $this->assertEquals(hex2bin($masterSecret), $result);
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
