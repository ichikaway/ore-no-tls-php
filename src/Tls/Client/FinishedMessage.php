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
     * @param string $clientHello
     * @param string $serverHello
     * @param string $certificate
     * @param string $serverHelloDone
     * @param string $clientKeyExchange
     */
    public function __construct(
        MasterSecret $MasterSecret,
        string $clientHello,
        string $serverHello,
        string $certificate,
        string $serverHelloDone,
        string $clientKeyExchange
    ) {
        $this->MasterSecret      = $MasterSecret;
        $this->clientHello       = $clientHello;
        $this->serverHello       = $serverHello;
        $this->certificate       = $certificate;
        $this->serverHelloDone   = $serverHelloDone;
        $this->clientKeyExchange = $clientKeyExchange;
    }


    public function createHandshakeMessage(): string
    {
        //14 - handshake message type 0x14 (finished)
        //00 00 0c - 0xC (12) bytes of handshake finished follows
        $header = hex2bin('160303' . '10' .'14' . '00000c');
        //$header = hex2bin('14' . '00000c');
        $this->handshakeMessage = $header . $this->createVerifyData();
        return $this->handshakeMessage;
    }

    /**
     * これまでやり取りしたHandshakeメッセージ(ClientHello, ServerHello, Certificate, ServerHelloDone, ClientKeyExchange)
     * をsha256でハッシュしたバイナリデータを渡して12byteのverify_dataを作成
     */
    public function createVerifyData(): string
    {
        $masterSecret = $this->MasterSecret->getMasterSecret();
        $label = 'client finished';
        $handshakeMessages = $this->clientHello . $this->serverHello .
            $this->certificate . $this->serverHelloDone . $this->clientKeyExchange;
        $seed = $label . hash('sha256', $handshakeMessages, true);
        $len = 12; //12byte
        return Prf::pHash($len, $masterSecret, $seed);
    }
}
