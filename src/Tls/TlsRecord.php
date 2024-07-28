<?php

namespace PHPTLS\Tls;

class TlsRecord
{
    //TLSレコードヘッダの先頭からのContentTypeとLengthまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndLength = 3;

    //TLSレコードヘッダの先頭からのContentTypeとLengthとTLSバージョンまでのデータ長
    private const int RecordHeaderOffsetOfContentTypeAndTlsVerAndLen = self::RecordHeaderOffsetOfContentTypeAndLength + 2;


    /**
     * 受信したデータがTLSレコードとしてすべて揃っているかチェックする
     * 1回のパケットで複数のTLSレコードが入っている場合も考慮
     * 複数回のパケットでTLSデータを受信する可能性があるため、TLSレコードヘッダのLengthを見てデータを切り出し
     * そのデータサイズがヘッダのLengthと同じであれば十分な状態、
     * Lengthより実際のデータのサイズが小さい場合は不十分で追加でsocket readが必要
     *
     * @param string $data
     * @return bool
     * @throws \Exception
     */
    public static function isEnoughData(string $data): bool
    {
        $records = self::getTlsRecords($data);
        foreach ($records as $record) {
            $tlsRecordLen = Util::getTlsLengthFromByte($record, self::RecordHeaderOffsetOfContentTypeAndLength);
            $tlsRecordAllLen = $tlsRecordLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
            if (strlen($record) !== $tlsRecordAllLen) {
                return false;
            }
        }
        return true;
    }

    /**
     * 受信データからTLSレコードを抽出して配列で返す
     * 複数のTLSレコードが含まれている場合にも対応
     *
     * @param string $data
     * @return array<string>
     * @throws \Exception
     */
    public static function getTlsRecords(string $data): array
    {
        if (strlen($data) === 0) {
            throw new \Exception('TLS data is empty');
        }
        $offset = 0;
        $records = [];
        for ($i = 0; $i < 10; $i++) {
            $tlsRecordLen = Util::getTlsLengthFromByte($data, $offset + self::RecordHeaderOffsetOfContentTypeAndLength);
            $tlsRecordAllLen = $tlsRecordLen + self::RecordHeaderOffsetOfContentTypeAndTlsVerAndLen;
            $tlsRecordData = substr($data, $offset, $tlsRecordAllLen);
            if (strlen($tlsRecordData) === 0) {
                break;
            }
            $records[] = $tlsRecordData;
            $offset = $offset + $tlsRecordAllLen;
        }
        return $records;
    }
}
