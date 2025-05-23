<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Crypt;
use PHPTLS\Tls\Util;

class ApplicationData
{
    private MasterSecret $MasterSecret;
    private Sequence $Sequence;

    //TLSレコードヘッダの先頭からのContentTypeとLengthまでのデータ長
    private const RecordHeaderOffset = 5;

    /**
     * @param MasterSecret $MasterSecret
     * @param Sequence $Sequence
     */
    public function __construct(MasterSecret $MasterSecret, Sequence $Sequence)
    {
        $this->MasterSecret = $MasterSecret;
        $this->Sequence     = $Sequence;
    }


    /**
     * @param string $contentBin
     * @return string bin
     */
    public function encrypt(string $contentBin): string
    {
        $this->Sequence->incrementSequenceNumber();

        //今回暗号化するのはアプリケーションコンテンツのデータのみで、TLSのヘッダ情報は暗号化に含めない
        //$contentBinLen = Util::decToHexWithLen(strlen($contentBin), 3);
        //$header = hex2bin("170303" . $contentBinLen);
        //$message = $header . $contentBin;
        $message = $contentBin;

        // ADDデータ作成
        // additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length;
        // AADに入れてハッシュ値で改ざんチェック用にする
        //こちらはTLSヘッダの情報と暗号化前のアプリケーションコンテンツのlengthを一緒にする
        $contentLen  = strlen($contentBin);
        $AAD = $this->createAdditionalData($contentLen);
        $seq = $this->Sequence->getSequenceNumberBin();
        //var_dump(bin2hex($AAD));

        $key = $this->MasterSecret->getClientKey();
        $iv = $this->MasterSecret->getClientIV();
        list($encrypt, $nonce, $tag) = Crypt::encryptAesGcm($message, $key, $iv, $AAD, $seq);

        // TLSのボディには、nonce + 暗号化データ + tagを連携したものを入れる
        $output = $nonce.$encrypt.$tag;

        $len = Util::decToHexWithLen(strlen($output), 2);
        $data = hex2bin('170303' . $len) . $output;
        return $data;
    }

    public function decrypt(string $tlsRecord): string
    {
        $key = $this->MasterSecret->getServerKey();
        $iv = $this->MasterSecret->getServerIV();

        //受信したTLSレコードは、nonce(8byte) + 暗号データ(data + tag(16byte))となっているため、
        // nonceと暗号データを切り出す
        $ivExplicit = $this->getIvExplicit($tlsRecord);
        $encryptedData = $this->getEncryptedContent($tlsRecord);

        //nonceは、サーバ側のIVとレスポンスについてた8byteを連結したもの
        $nonce = $iv . $ivExplicit;

        //暗号データからAADを作成
        //暗号データは、暗号データ + tag(16byte)
        //暗号データサイズは、暗号データからタグのサイズ16byteを引いた長さ、
        $contentLen = strlen($encryptedData) - 16; //tagの16byteを除いた長さ
        $AAD = $this->createAdditionalData($contentLen);

        //var_dump(hexdec($tlsLen));
        //var_dump(bin2hex($ivExplicit));
        //var_dump(bin2hex($encryptedData));

        //var_dump(bin2hex($AAD));

        $data = Crypt::decryptAesGcm($encryptedData, $key, $nonce, $AAD);
        //var_dump($data);
        return $data;
    }

    /**
     * コンテンツの長さを元に AEADの additional dataを返す
     * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length;
     *
     * @param int $contentLen
     * @return string bin
     */
    public function createAdditionalData(int $contentLen): string
    {
        //var_dump($contentLen);
        $recordHeader = hex2bin('170303' . Util::decToHexWithLen($contentLen, 2));
        //var_dump(bin2hex($recordHeader));
        //$this->Sequence->incrementSequenceNumber();
        $seq = $this->Sequence->getSequenceNumberBin();
        $AAD = $seq . $recordHeader;
        return $AAD;
    }

    /**
     * TCPで受信したTLSレコードのデータを渡して、nonceのexplicitの8バイトを切り出す
     *
     * @param string $tlsRecord bin
     * @return string bin
     */
    public function getIvExplicit(string $tlsRecord): string
    {
        $tlsLen = bin2hex(substr($tlsRecord, 3, 2));
        $content = substr($tlsRecord, self::RecordHeaderOffset, hexdec($tlsLen));
        return substr($content, 0, 8); //先頭8バイトまで
    }

    /**
     * TCPで受信したTLSレコードのデータを渡して、暗号化されたコンテンツデータを切り出して返す
     *
     * @param string $tlsRecord bin
     * @return string bin
     */
    public function getEncryptedContent(string $tlsRecord): string
    {
        // ApplicationDataと一緒にAlert(close)のデータもくる場合があるため、
        // tlsレコードのlengthにセットされている長さだけ切り出す
        $tlsLen = bin2hex(substr($tlsRecord, 3, 2));
        $content = substr($tlsRecord, self::RecordHeaderOffset, hexdec($tlsLen));
        return substr($content, 8); //8バイト以降
    }
}
