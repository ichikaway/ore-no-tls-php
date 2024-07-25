<?php

namespace PHPTLS\Tls\Client;

class Sequence
{
    private int $seq = 0;

    public function incrementSequenceNumber(): int
    {
        $this->seq = $this->seq + 1;
        return $this->seq;
    }

    public function getSequenceNumberBin(): string
    {
        // 整数を8バイトのバイナリデータに変換
        return pack('J', $this->seq);
    }
}
