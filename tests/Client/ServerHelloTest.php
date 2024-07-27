<?php

namespace PHPTLS\Tests\Client;

use PHPTLS\Tls\Client\ServerHello;
use PHPUnit\Framework\TestCase;

class ServerHelloTest extends TestCase
{
    private function getTestDataString()
    {
        $data =
            //ServerHello
            '160303004a0200004603034016c02bfc25c39437c523f7b9cda73d7ecc0fd1309b8c9aafd884f4a45591552075654b2e5fff2ad6517ab57acc7a977a985e3e802723350a3798daf9d11de108009c00';
        return hex2bin($data);
    }

    public function test_getRandom()
    {
        $expect =
            '4016c02bfc25c39437c523f7b9cda73d' .
            '7ecc0fd1309b8c9aafd884f4a4559155';

        $ServerHello = new ServerHello($this->getTestDataString());
        $result = $ServerHello->getServerRandom();
        $this->assertEquals($expect, bin2hex($result));
    }
}
