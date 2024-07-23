<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Crypt;
use PHPTLS\Tls\Prf;
use PHPTLS\Tls\Util;

class FinishedMessage
{
    private MasterSecret $MasterSecret;

    private string $clientHelloMessage;
    private string $serverHelloMessage;
    private string $certificateMessage;
    private string $serverHelloDoneMessage;
    private string $clientKeyExchangeMessage;

    private string $handshakeMessage; //bin

    /**
     * @param MasterSecret $MasterSecret
     * @param string $clientHelloMessage
     * @param string $serverHelloMessage
     * @param string $certificateMessage
     * @param string $serverHelloDoneMessage
     * @param string $clientKeyExchangeMessage
     */
    public function __construct(
        MasterSecret $MasterSecret,
        string $clientHelloMessage,
        string $serverHelloMessage,
        string $certificateMessage,
        string $serverHelloDoneMessage,
        string $clientKeyExchangeMessage
    ) {
        $this->MasterSecret             = $MasterSecret;
        $this->clientHelloMessage       = $clientHelloMessage;
        $this->serverHelloMessage       = $serverHelloMessage;
        $this->certificateMessage       = $certificateMessage;
        $this->serverHelloDoneMessage   = $serverHelloDoneMessage;
        $this->clientKeyExchangeMessage = $clientKeyExchangeMessage;
    }


    public function createHandshakeMessage(): string
    {
        // verify dataは長さ12バイトのため、lengthは 00000c 固定
        //14 - handshake message type 0x14 (finished)
        //00 00 0c - 0xC (12) bytes of handshake finished follows
        ///$header = hex2bin('14' . '00000c');
        //$this->handshakeMessage = $header . $this->createVerifyData();

        $recordHeader = hex2bin('1603030028');

        $seq = hex2bin('0000000000000000');
        $add = hex2bin('14' . '00000c');
        //$add = hex2bin('0000000000000000'.'14' . '00000c');
        $this->handshakeMessage = $add . $this->createVerifyData();

        //todo
        // handshameMessageを暗号化
        $key = $this->MasterSecret->getClientKey();
        $iv = $this->MasterSecret->getClientIV();
        list($encrypt, $nonce, $tag) = Crypt::encryptAesGcm($this->handshakeMessage, $key, $iv, $seq.$recordHeader);
        /*
var_dump(strlen($nonce));
var_dump(bin2hex($nonce));
        var_dump(strlen($encrypt));
        var_dump(bin2hex($encrypt));
*/
        var_dump(bin2hex($encrypt));
        var_dump(bin2hex($tag));
        // 暗号化したデータのLengthを取得
        // レコードヘッダーを作って暗号化したデータを入れる
        //$len = Util::decToHexWithLen(strlen($iv.$encrypt.$tag), 2);
        //$data = hex2bin('160303' . $len) . $iv.$encrypt.$tag;
        //$output = $nonce.$encrypt.$tag;
        $head = hex2bin('0000000000000000');
        //$output = $head.$nonce.$encrypt.$tag;
        //$output = $head.$encrypt.$tag;
        $output = $encrypt.$tag;
        /*
        var_dump(strlen($output));
        var_dump(strlen($head));
        var_dump(strlen($nonce));
        var_dump(strlen($encrypt));
        var_dump(strlen($tag));
        */

        $len = Util::decToHexWithLen(strlen($output), 2);
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
