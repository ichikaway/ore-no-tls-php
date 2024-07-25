<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Crypt;
use PHPTLS\Tls\Prf;
use PHPTLS\Tls\Util;

class FinishedMessage
{
    private MasterSecret $MasterSecret;

    private Sequence $Sequence;

    private string $clientHelloMessage;
    private string $serverHelloMessage;
    private string $certificateMessage;
    private string $serverHelloDoneMessage;
    private string $clientKeyExchangeMessage;

    private string $handshakeMessage; //bin

    /**
     * @param MasterSecret $MasterSecret
     * @param Sequence $Sequence
     * @param string $clientHelloMessage
     * @param string $serverHelloMessage
     * @param string $certificateMessage
     * @param string $serverHelloDoneMessage
     * @param string $clientKeyExchangeMessage
     */
    public function __construct(
        MasterSecret $MasterSecret,
        Sequence $Sequence,
        string $clientHelloMessage,
        string $serverHelloMessage,
        string $certificateMessage,
        string $serverHelloDoneMessage,
        string $clientKeyExchangeMessage
    ) {
        $this->MasterSecret             = $MasterSecret;
        $this->Sequence                 = $Sequence;
        $this->clientHelloMessage       = $clientHelloMessage;
        $this->serverHelloMessage       = $serverHelloMessage;
        $this->certificateMessage       = $certificateMessage;
        $this->serverHelloDoneMessage   = $serverHelloDoneMessage;
        $this->clientKeyExchangeMessage = $clientKeyExchangeMessage;
    }


    public function createHandshakeMessage(): string
    {
        // 暗号化する対象のハンドシェイクメッセージを作成
        $verifyData = $this->createVerifyData();
        $verifyDataLen = Util::decToHexWithLen(strlen($verifyData), 3);
        $handshakeHeader = hex2bin('14' . $verifyDataLen);
        $this->handshakeMessage = $handshakeHeader . $verifyData;

        // AEAD(認証付き暗号)の暗号化のためのAADを作成する
        //暗号化前のコンテンツの長さを入れる
        $contentLen = Util::decToHexWithLen(strlen($this->handshakeMessage), 2);
        $recordHeader = hex2bin('160303' . $contentLen);
        $seq = $this->Sequence->getSequenceNumberBin();
        $AAD = $seq . $recordHeader;
        //var_dump(bin2hex($AAD));

        $key = $this->MasterSecret->getClientKey();
        $iv = $this->MasterSecret->getClientIV();
        list($encrypt, $nonce, $tag) = Crypt::encryptAesGcm($this->handshakeMessage, $key, $iv, $AAD, $seq);

        //var_dump(bin2hex($encrypt));
        //var_dump(bin2hex($tag));

        // 暗号化したデータのLengthを取得
        // レコードヘッダーを作って暗号化したデータを入れる
        //$len = Util::decToHexWithLen(strlen($iv.$encrypt.$tag), 2);
        //$data = hex2bin('160303' . $len) . $iv.$encrypt.$tag;
        //$head = hex2bin('0000000000000000');
        //$output = $head.$nonce.$encrypt.$tag;
        //$output = $head.$encrypt.$tag;
        //$output = $encrypt.$tag;
        $output = $nonce.$encrypt.$tag;
        /*
        var_dump(strlen($output));
        var_dump(strlen($head));
        var_dump(strlen($nonce));
        var_dump(strlen($encrypt));
        var_dump(strlen($tag));
        */

        $len = Util::decToHexWithLen(strlen($output), 2);
        //var_dump($len);
        $data = hex2bin('160303' . $len) . $output;
        return $data;
    }

    /**
     * これまでやり取りしたHandshakeメッセージ(ClientHello, ServerHello, Certificate, ServerHelloDone, ClientKeyExchange)
     * をsha256でハッシュしたバイナリデータを渡して12byteのverify_dataを作成
     */
    public function createVerifyData(): string
    {
        $masterSecret = $this->MasterSecret->getMasterSecret();
        $label = 'client finished';
        $handshakeMessages =
            $this->clientHelloMessage .
            $this->serverHelloMessage .
            $this->certificateMessage .
            $this->serverHelloDoneMessage .
            $this->clientKeyExchangeMessage
        ;
        $seed = $label . hash('sha256', $handshakeMessages, true);
        $len = 12; //12byte
        return Prf::pHash($len, $masterSecret, $seed);
    }
}
