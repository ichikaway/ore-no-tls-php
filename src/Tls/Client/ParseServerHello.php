<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ParseServerHello
{
    /**
     * @var string
     */
    public readonly string $data; //bin

    public readonly ServerHello $serverHello; //bin
    public readonly ServerCertificate $certificate; //bin
    public readonly ServerHelloDone $serverHelloDone; //bin

    //TLSレコードヘッダの先頭からのContentTypeとLengthまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndLength = 3;

    //TLSレコードヘッダの先頭からのContentTypeとLengthとTLSバージョンまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndTlsVerAndLen = self::RecordHeaderOffsetOfContentTypeAndLength + 2;

    public function __construct(string $data)
    {
        $this->data = $data; //bin
        $parsedData = $this->parse();
        $this->serverHello = new ServerHello($parsedData['ServerHello']);
        $this->certificate = new ServerCertificate($parsedData['Certificate']);
        $this->serverHelloDone = new ServerHelloDone($parsedData['ServerHelloDone']);
    }

    /**
     * ServerHello、Certificate、ServerHelloDoneのデータが一度に来るためそれを分ける
     * 各データはLengthの値があるため、それをもとにTLSパケット分だけデータを切り出していく
     *
     * @param  string $data
     * @return array
     */
    public function parse(): array
    {
        //受信データの先頭から3バイト目にあるTLSパケットのLengthを取得。Lengthは2バイト長。
        $serverHelloLen = Util::getTlsLengthFromByte($this->data);
        // 最初のServerHelloのTLSパケットの全体の長さを計算
        $serverHelloAllLen = $serverHelloLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
        // 受信データの先頭からTLSパケットの長さだけデータ切り出し。16進数のデータ
        $serverHelloBin = substr($this->data, 0, $serverHelloAllLen);

        // Certificateのデータ切り出し。Certificateのデータが始まるのは、ServerHelloのデータの後になる
        $certificateOffset = $serverHelloAllLen;
        $certificateLen = Util::getTlsLengthFromByte($this->data, $certificateOffset + self::RecordHeaderOffsetOfContentTypeAndLength);
        $certificateAllLen = $certificateLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
        $certificateBin = substr($this->data, $certificateOffset, $certificateAllLen);

        // ServerHelloDoneのデータ切り出し。Certificateのデータの後に続くデータを切り出し
        $serverHelloDoneOffset = $serverHelloAllLen + $certificateAllLen;
        $serverHelloDoneLen = Util::getTlsLengthFromByte($this->data, $serverHelloDoneOffset + self::RecordHeaderOffsetOfContentTypeAndLength);
        $serverHelloDoneAllLen = $serverHelloDoneLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
        $serverHelloDoneBin = substr($this->data, $serverHelloDoneOffset, $serverHelloDoneAllLen);

        return [
            'ServerHello' => $serverHelloBin,
            'Certificate' => $certificateBin,
            'ServerHelloDone' => $serverHelloDoneBin,
        ];
    }
}
