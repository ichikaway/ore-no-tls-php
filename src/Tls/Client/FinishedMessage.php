<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Prf;

class FinishedMessage
{
    private MasterSecret $MasterSecret;

    private string $clientHello;
    private string $serverHello;
    private string $certificate;
    private string $serverHelloDone;
    private string $clientKeyExchange;

    private string $handshakeMessage; //bin

    /**
     * @param MasterSecret $MasterSecret
     * @param string $clientHelloHex
     * @param string $serverHelloHex
     * @param string $certificateHex
     * @param string $serverHelloDoneHex
     * @param string $clientKeyExchangeHex
     */
    public function __construct(
        MasterSecret $MasterSecret,
        string $clientHelloHex,
        string $serverHelloHex,
        string $certificateHex,
        string $serverHelloDoneHex,
        string $clientKeyExchangeHex
    ) {
        $this->MasterSecret = $MasterSecret;
        $this->clientHello = hex2bin($clientHelloHex);
        $this->serverHello = hex2bin($serverHelloHex);
        $this->certificate = hex2bin($certificateHex);
        $this->serverHelloDone = hex2bin($serverHelloDoneHex);
        $this->clientKeyExchange = hex2bin($clientKeyExchangeHex);
    }

    public function createHandshakeMessage(): string
    {
        //14 - handshake message type 0x14 (finished)
        //00 00 0c - 0xC (12) bytes of handshake finished follows
        //$header = hex2bin('160303' . '10' .'14' . '00000c');
        $header = hex2bin('14' . '00000c');
        $this->handshakeMessage = $header . $this->createVerifyData();
        return $this->handshakeMessage;
    }

    /**
     * これまでやり取りしたHandshakeメッセージ(ClientHello, ServerHello, Certificate, ServerHelloDone, ClientKeyExchange)
     * を渡して12byteのverify_dataを作成
     */
    public function createVerifyData(): string
    {
        $masterSecret = $this->MasterSecret->getMasterSecret();
        $label = 'client finished';
        $handshakeMessages = $this->clientHello . $this->serverHello .
            $this->certificate . $this->serverHelloDone . $this->clientKeyExchange;
        $seed = $label . $handshakeMessages;
        $len = 12; //12byte
        return Prf::pHash($len, $masterSecret, $seed);
    }
}
