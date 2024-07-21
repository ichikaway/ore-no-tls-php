<?php

namespace PHPTLS\Tests;

use PHPTLS\Tls\Crypt;
use PHPUnit\Framework\TestCase;

class CryptTest extends TestCase
{

    public function testCreateKeyBlock()
    {
        $secret = '0101010101';
        $text = openssl_random_pseudo_bytes(16);
        $iv = hex2bin('01020304');
        $add = hex2bin('010203040506');
        list($encrypted, $ivAdd, $tag) = Crypt::encryptAesGcm($text, $secret, $iv, $add);
        $this->assertEquals(16, strlen($encrypted));
        $this->assertEquals(16, strlen($tag));
    }
}
