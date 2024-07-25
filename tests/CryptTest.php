<?php

namespace PHPTLS\Tests;

use PHPTLS\Tls\Client\Sequence;
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
        $seq = (new Sequence())->getSequenceNumberBin();
        list($encrypted, $nonce, $tag) = Crypt::encryptAesGcm($text, $secret, $iv, $add, $seq);
        $this->assertEquals($seq, $nonce);
        $this->assertEquals(16, strlen($encrypted));
        $this->assertEquals(16, strlen($tag));
    }
}
