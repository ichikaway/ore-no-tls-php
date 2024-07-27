<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ServerHello
{
    use TlsMessageTrait;

    //TLSレコードヘッダの先頭からのContentTypeとLengthとTLSバージョンまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndTlsVerAndLen = 5;

    // TLSレコードヘッダの後にあるペイロードの先頭からハンドシェイクタイプとペイロードの長さ、TLSバージョンまでのデータ長
    private const int PayloadLengthOfHandshaketypeAndLengthAndVersion = 6;

    public function __construct(string $data)
    {
        $this->data = $data;
    }

    /**
     * 32バイトのServerHelloランダムの値をbinで返す
     *
     * @return string bin
     */
    public function getServerRandom(): string
    {
        $offset = self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen + self::PayloadLengthOfHandshaketypeAndLengthAndVersion;
        $randomByte = 32;
        return substr($this->data, $offset, $randomByte);
    }
}
