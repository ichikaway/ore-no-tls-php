<?php

namespace PHPTLS\Tls\Client;

class ChangeCipherSpec
{
    private static string $versionHex = '0303'; //TLS1.2

    private static string $handShakeHex = '14'; // Change Cipher Spec

    /**
     * @return string bin
     */
    public static function createChangeCipherSpec(): string
    {
        $data =
            self::$handShakeHex .
            self::$versionHex .
            '0001' . //length
            '01' ; //1 byte
        return hex2bin($data);
    }
}
