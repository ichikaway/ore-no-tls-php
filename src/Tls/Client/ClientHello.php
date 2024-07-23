<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ClientHello
{
    use TlsMessageTrait;

    private string $clientRandomHex;

    public function createClientHello(): string
    {

        $clientHello =
            '01' .  // Handshake Type: ClientHello
            Util::decToHexWithLen(41, 3) .
            '0303' .  // Version: TLS 1.2
            $this->createRandomByteHex() .  // Random 32byte
            '00' .  // Session ID Length
            //$this->createSessionByteHex() .  // SessionID 32byte
            '0002' .  // Cipher Suites Length
            '009c' .  // Cipher Suites (RSA_WITH_AES_128_GCM_SHA256 //golang tls
            //'c013' . //0xC013 (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) //Illustrate TLS1.2 site
            //'0035' . //CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 }; kanatoko-san
            '01' .  // Compression Methods Length
            '00'  // Compression Method: null
        ;
        $len = strlen(hex2bin($clientHello));

        $clientHelloAll =
            '16' .  // Content Type: Handshake
            '0303' .  // Version: TLS 1.2
            Util::decToHexWithLen($len, 2) .
            $clientHello
            ;
        $this->dataHex = $clientHelloAll;

        return hex2bin($clientHelloAll);
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

    public function getClientHelloRandom(): string
    {
        return hex2bin($this->clientRandomHex);
    }
}
