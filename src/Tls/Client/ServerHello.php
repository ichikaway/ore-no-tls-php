<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ServerHello
{

    //TLSレコードヘッダの先頭からのContentTypeとLengthとTLSバージョンまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndTlsVerAndLen = 5;

    // TLSレコードヘッダの後にあるペイロードの先頭からハンドシェイクタイプとペイロードの長さ、TLSバージョンまでのデータ長
    private const int PayloadLengthOfHandshaketypeAndLengthAndVersion = 6;

    private readonly string $data; //hex
    public function __construct(string $data)
    {
        $this->data = $data;
    }

    /**
     * 32バイトのServerHelloランダムの値をHexで返す
     *
     * @return string hex
     */
    public function getServerRandomHex(): string
    {
        $offset = self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen + self::PayloadLengthOfHandshaketypeAndLengthAndVersion;
        $randomByte = 32;
        return Util::getHexDataWithLen($this->data, $offset, $randomByte);
    }
}
