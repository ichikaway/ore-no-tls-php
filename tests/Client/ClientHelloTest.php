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
        $this->assertEquals($expect, bin2hex($ClientHello->getTlsPayload()));
    }
}
