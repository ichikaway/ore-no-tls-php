<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ParseServerHello {
    /**
     * @var string
     */
    public readonly string $data; //hex

    public readonly ServerHello $serverHello;
    public readonly ServerCertificate $certificate;
    public readonly ServerHelloDone $serverHelloDone;

    //TLSレコードヘッダの先頭からのContentTypeとLengthまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndLength = 3;

    //TLSレコードヘッダの先頭からのContentTypeとLengthとTLSバージョンまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndTlsVerAndLen = self::RecordHeaderOffsetOfContentTypeAndLength + 2;

    public function __construct(string $data)
    {
        $this->data = $data;
        $parsedData = $this->parse();
        $this->serverHello = new ServerHello($parsedData['ServerHello']);
        $this->certificate = new ServerCertificate($parsedData['Certificate']);
        $this->serverHelloDone = new ServerHelloDone($parsedData['ServerHelloDone']);
    }

    /**
     * ServerHello、Certificate、ServerHelloDoneのデータが一度に来るためそれを分ける
     * 各データはLengthの値があるため、それをもとにTLSパケット分だけデータを切り出していく
     *
     * @param string $data
     * @return array
     */
    public function parse(): array
    {
        //受信データの先頭から3バイト目にあるTLSパケットのLengthを取得。Lengthは2バイト長。
        $serverHelloLen = hexdec(Util::getHexDataWithLen($this->data, self::RecordHeaderOffsetOfContentTypeAndLength, 2));
        // 最初のServerHelloのTLSパケットの全体の長さを計算
        $serverHelloAllLen = $serverHelloLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
        // 受信データの先頭からTLSパケットの長さだけデータ切り出し。16進数のデータ
        $serverHelloHex = Util::getHexDataWithLen($this->data, 0, $serverHelloAllLen);

        // Certificateのデータ切り出し。Certificateのデータが始まるのは、ServerHelloのデータの後になる
        $certificateOffset = $serverHelloAllLen;
        $certificateLen = hexdec(Util::getHexDataWithLen($this->data, $certificateOffset + self::RecordHeaderOffsetOfContentTypeAndLength, 2));
        $certificateAllLen = $certificateLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
        $certificateHex = Util::getHexDataWithLen($this->data, $certificateOffset, $certificateAllLen);

        // ServerHelloDoneのデータ切り出し。Certificateのデータの後に続くデータを切り出し
        $serverHelloDoneOffset = $serverHelloAllLen + $certificateAllLen;
        $serverHelloDoneLen = hexdec(Util::getHexDataWithLen($this->data, $serverHelloDoneOffset + self::RecordHeaderOffsetOfContentTypeAndLength, 2));
        $serverHelloDoneAllLen = $serverHelloDoneLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
        $serverHelloDoneHex = Util::getHexDataWithLen($this->data, $serverHelloDoneOffset, $serverHelloDoneAllLen);

        return [
            'ServerHello' => $serverHelloHex,
            'Certificate' => $certificateHex,
            'ServerHelloDone' => $serverHelloDoneHex,
        ];
    }

}