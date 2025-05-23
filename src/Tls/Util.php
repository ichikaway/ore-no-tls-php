<?php
namespace PHPTLS\Tls;

final class Util
{

    /**
     * TLSのバイト列から、TLSヘッダのlengthをintで返す
     *
     * @param string $byte
     * @param int $offset
     * @param int $len
     * @return int
     */
    static function getTlsLengthFromByte(string $byte, int $offset = 3, int $len = 2): int
    {
        $data = substr($byte, $offset, $len);
        $hex = bin2hex($data);
        return hexdec($hex);
    }

    /**
     * 10進数の数字を与えると16進数で返す。byteLengthで指定した桁数でパディングする。
     * 例えば decimal=77, byteLength=2 を入れると '004D' が返る
     *
     * @param  int $decimal
     * @param  int $byteLength
     * @return string
     */
    static function decToHexWithLen(int $decimal, int $byteLength): string
    {
        $hexadecimal = dechex($decimal); // 16進数に変換
        $hexadecimal = strtoupper($hexadecimal); // 大文字に変換
        $hexLen = $byteLength * 2; //1byteあたり16進表現で2桁となるため調整
        return str_pad($hexadecimal, $hexLen, '0', STR_PAD_LEFT); //指定桁になるように左側を0で埋める
    }

    /**
     * x.509のbinaryデータを渡すとPEM形式の文字列で返す
     *
     * @param  string $data bin
     * @return string
     */
    static function binToPem(string $data): string
    {
        $base64 = base64_encode($data);
        // 1行64バイトで改行が必要
        $pem = chunk_split($base64, 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n" . $pem. "-----END CERTIFICATE-----";
    }
}
