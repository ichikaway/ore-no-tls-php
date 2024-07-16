<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

trait TlsMessageTrait
{
    private string $dataHex;
    /**
     * レコードヘッダを除いたTLSメッセージを抽出する
     *
     * @return string hex
     */
    public function getTlsPayload(): string
    {
        if (is_null($this->dataHex)) {
            throw new \Exception('No data hex set.');
        }
        if (!ctype_xdigit($this->dataHex)) {
            throw new \Exception('Not hex data.');
        }
        $data = $this->dataHex;
        $offset = 5; //TLSレコードヘッダはtype(1byte), version(2byte), length(2byte)の合計5バイト
        $len = strlen(hex2bin($data)) - $offset;
        return Util::getHexDataWithLen($data, $offset, $len); //レコードヘッダを除いたデータを切り出し
    }
}
