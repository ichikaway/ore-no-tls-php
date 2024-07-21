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
        $this->preMasterSecret = hex2bin($this->versionHex . $this->secretRandomHex);
        $encryptedSecret = $this->serverCertificate->encryptWithPubKey($this->preMasterSecret);
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
        $preMasterSecret = $this->createPreMasterSecret();
        $lengthOfPreMasterSecret = strlen($preMasterSecret);
        $handShakeExchange =
            '10' . //Content Type : Client Key Exchange
            Util::decToHexWithLen($lengthOfPreMasterSecret, 3) .
            bin2hex($preMasterSecret);

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
