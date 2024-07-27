<?php

namespace PHPTLS\Tls\Client;

trait TlsMessageTrait
{
    private readonly string $data;
    /**
     * レコードヘッダを除いたTLSメッセージを抽出する
     *
     * @return string bin
     */
    public function getTlsPayload(): string
    {
        if (is_null($this->data)) {
            throw new \Exception('No data hex set.');
        }
        if (ctype_xdigit($this->data)) {
            throw new \Exception('forbid hex data.');
        }
        $data = $this->data;
        $offset = 5; //TLSレコードヘッダはtype(1byte), version(2byte), length(2byte)の合計5バイト
        $len = strlen($data) - $offset;
        return substr($data, $offset, $len);
    }
}
