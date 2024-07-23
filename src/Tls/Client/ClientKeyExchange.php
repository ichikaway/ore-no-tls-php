<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ClientKeyExchange
{
    use TlsMessageTrait;

    private string $versionHex = '0303'; //TLS1.2
    private string $secretRandomHex = '01010101010101010101020202020202020202020303030303030303030304040404040404040404050505050505'; //46byte

    private ServerCertificate $serverCertificate;

    // pre master secret(暗号化済み)のデータ(bin)
    private string $preMasterSecret;

    public function __construct(ServerCertificate $serverCertificate)
    {
        $this->serverCertificate = $serverCertificate;
    }

    /**
     * pre master secretを生成して返す。
     *
     * @return string  bin 公開鍵で暗号化されたpre master secretのバイナリ
     * @throws \Exception
     */
    public function createPreMasterSecret(): string
    {
        /**
         * struct {
         * ProtocolVersion client_version;
         * opaque random[46];
         * } PreMasterSecret;
         */
        $this->secretRandomHex = bin2hex(openssl_random_pseudo_bytes(46));
        //$this->secretRandomHex = bin2hex(pack('x46')); //46byteの0x00を埋める
        $this->preMasterSecret = hex2bin($this->versionHex . $this->secretRandomHex);
        $encryptedSecret = $this->serverCertificate->encryptWithPubKey($this->preMasterSecret);
        //var_dump(bin2hex($this->preMasterSecret));
        //var_dump(bin2hex($encryptedSecret));
        return $encryptedSecret;
    }

    /**
     * @return string bin
     */
    public function getPreMasterSecret()
    {
        return $this->preMasterSecret;
    }

    /**
     * Client Key Exchange のペイロードを作成する(hex)
     *
     * @return string
     * @throws \Exception
     */
    public function createClientKeyExchangeDataHex(): string
    {
        $encryptedPreMasterSecret = $this->createPreMasterSecret();
        $lengthOfPreMasterSecret = strlen($encryptedPreMasterSecret);
        /**
         * Implementation note: Public-key-encrypted data is represented as an opaque
         * vector <0..2^16-1> (see Section 4.7).
         * Thus, the RSA-encrypted PreMasterSecret in a ClientKeyExchange is preceded by two length bytes.
         * These bytes are redundant in the case of RSA because the EncryptedPreMasterSecret is the only data
         * in the ClientKeyExchange and its length can therefore be unambiguously determined.
         * The SSLv3 specification was not clear about the encoding of public-key-encrypted data,
         * and therefore many SSLv3 implementations do not include the length bytes -- they encode
         * the RSA-encrypted data directly in the ClientKeyExchange message
         *
         * 長さのデータは2つあるため注意
         * content type(1byte) + length(3byte) + length(2byte) + encrypted data
         */
        $handShakeExchange =
            '10' . //Content Type : Client Key Exchange
            Util::decToHexWithLen($lengthOfPreMasterSecret + 2, 3) .
            Util::decToHexWithLen($lengthOfPreMasterSecret, 2) .
            bin2hex($encryptedPreMasterSecret);

        $lengthOfHandShakeExchange = strlen(hex2bin($handShakeExchange));

        $clientKeyExchange =
            '16' .  // Content Type: Handshake
            '0303' .  // Version: TLS 1.2
            Util::decToHexWithLen($lengthOfHandShakeExchange, 2) .
            $handShakeExchange
        ;
        $this->dataHex = $clientKeyExchange;
        return $clientKeyExchange;
    }
}
