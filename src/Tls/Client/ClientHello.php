<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ClientHello
{
    private string $clientHelloHexData;

    private string $clientRandomHex;

    public function createClientHello(): string
    {
        $clientHello =
            '16' .  // Content Type: Handshake
            '0303' .  // Version: TLS 1.2
            Util::decToHexWithLen(77, 2) . //'004D' .  // Length 77 byte
            '01' .  // Handshake Type: ClientHello
            Util::decToHexWithLen(73, 3) . //'000049' .  // Length  73 byte
            '0303' .  // Version: TLS 1.2
            $this->createRandomByteHex() .  // Random 32byte
            '20' .  // Session ID Length
            $this->createSessionByteHex() .  // SessionID 32byte
            '0002' .  // Cipher Suites Length
            //'1301' .  // Cipher Suites (AES_128_GCM_SHA256)
            '009c' .  // Cipher Suites (RSA_WITH_AES_128_GCM_SHA256
            '01' .  // Compression Methods Length
            '00'  // Compression Method: null
        ;
        $this->clientHelloHexData = $clientHello;
        return hex2bin($clientHello);
    }

    private function createRandomByteHex(): string
    {
        $data = '0101010101010101010102020202020202020202030303030303030303030404';   // Random 32byte (本来はランダムデータを入れる)
        $this->clientRandomHex = $data;
        return $data;
    }

    private function createSessionByteHex(): string
    {
        $data = '0201010101010101010102020202020202020202030303030303030303030404';  // SessionID 32byte (本来はランダムデータを入れる)
        return $data;
    }

    public function getClientHelloRandomHex(): string
    {
        return $this->clientRandomHex;
    }

    public function getClientHelloHexData(): string
    {
        return $this->clientHelloHexData;
    }
}