<?php

namespace PHPTLS\Tests\Client;

use PHPTLS\Tls\Client\ClientHello;
use PHPUnit\Framework\TestCase;

class ClientHelloTest extends TestCase
{

    public function test_createClientHello()
    {
        $expect = "160303004d01000049030301010101010101010101020202020202020202020303030303030303030304042002010101010101010101020202020202020202020303030303030303030304040002009c0100";
        $ClientHello = new ClientHello();
        $result = $ClientHello->createClientHello();
        $this->assertEquals($expect, bin2hex($result));
    }

    public function test_tlsMessageTrait()
    {
        //レコードヘッダを取り除いた値
        $expect = "01000049030301010101010101010101020202020202020202020303030303030303030304042002010101010101010101020202020202020202020303030303030303030304040002009c0100";
        $ClientHello = new ClientHello();
        $ClientHello->createClientHello();
        $this->assertEquals($expect, $ClientHello->getTlsPayload());
    }
}
