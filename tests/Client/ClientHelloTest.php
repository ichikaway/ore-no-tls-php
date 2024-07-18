<?php

namespace PHPTLS\Tests\Client;

use PHPTLS\Tls\Client\ClientHello;
use PHPUnit\Framework\TestCase;

class ClientHelloTest extends TestCase
{

    public function test_createClientHello()
    {
        $expect = "160303002d0100002903030101010101010101010102020202020202020202030303030303030303030404000002009c0100";
        $ClientHello = new ClientHello();
        $result = $ClientHello->createClientHello();
        $this->assertEquals($expect, bin2hex($result));
    }

    public function test_tlsMessageTrait()
    {
        //レコードヘッダを取り除いた値
        $expect = "0100002903030101010101010101010102020202020202020202030303030303030303030404000002009c0100";
        $ClientHello = new ClientHello();
        $ClientHello->createClientHello();
        $this->assertEquals($expect, $ClientHello->getTlsPayload());
    }

    public function test_tlsMessageTrait_hased()
    {
        //Client Helloメッセージをsha256ハッシュした値
        $expect = "b5ade2178d9f73e898a36f79b6e5096f2ea40c950f6fdf37809c7fbc826d5657";
        $ClientHello = new ClientHello();
        $ClientHello->createClientHello();
        $this->assertEquals(32, strlen($ClientHello->getMessageHashed()));
        $this->assertEquals($expect, bin2hex($ClientHello->getMessageHashed()));
    }
}
