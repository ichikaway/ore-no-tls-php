<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\TlsRecord;
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
        $records = TlsRecord::getTlsRecords($this->data);

        return [
            'ServerHello' => $records[0],
            'Certificate' => $records[1],
            'ServerHelloDone' => $records[2],
        ];
    }
}
