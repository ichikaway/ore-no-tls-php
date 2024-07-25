<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Crypt;
use PHPTLS\Tls\Util;

class ApplicationData
{
    private MasterSecret $MasterSecret;
    private Sequence $Sequence;

    /**
     * @param MasterSecret $MasterSecret
     * @param Sequence $Sequence
     */
    public function __construct(MasterSecret $MasterSecret, Sequence $Sequence)
    {
        $this->MasterSecret = $MasterSecret;
        $this->Sequence     = $Sequence;
    }


    public function encrypt(string $contentBin)
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
}
