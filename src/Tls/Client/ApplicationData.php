<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Crypt;
use PHPTLS\Tls\Util;

class ApplicationData
{
    private MasterSecret $MasterSecret;
    private Sequence $Sequence;

    //TLSレコードヘッダの先頭からのContentTypeとLengthまでのデータ長
    private const int RecordHeaderOffset = 5;

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

        // AADに入れてハッシュ値で改ざんチェックようにするため、こちらはTLSヘッダの情報とアプリケーションコンテンツの情報を一緒にする
        $contentLen = Util::decToHexWithLen(strlen($contentBin), 2);
        $recordHeader = hex2bin('170303' . $contentLen);
        $seq = $this->Sequence->getSequenceNumberBin();
        $AAD = $seq . $recordHeader;
        //var_dump(bin2hex($AAD));

        $key = $this->MasterSecret->getClientKey();
        $iv = $this->MasterSecret->getClientIV();
        list($encrypt, $nonce, $tag) = Crypt::encryptAesGcm($message, $key, $iv, $AAD, $seq);

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

        //var_dump(bin2hex($ivExplicit));
        //var_dump(bin2hex($encryptedData));

        $data = Crypt::decryptAesGcm($encryptedData, $key, $nonce);
        var_dump($data);
        return '';
    }

    public function getIvExplicit(string $contentBin): string
    {
        $content = substr($contentBin, self::RecordHeaderOffsetOfContentTypeAndLength);
        return substr($content, 0, 8); //先頭8バイトまで
    }

    public function getEncryptedContent(string $contentBin): string
    {
        $content = substr($contentBin, self::RecordHeaderOffsetOfContentTypeAndLength);
        return substr($content, 8); //8バイト以降
    }
}