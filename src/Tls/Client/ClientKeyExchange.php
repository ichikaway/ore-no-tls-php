<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ClientKeyExchange
{
    use TlsMessageTrait;

    private string $versionHex = '0303'; //TLS1.2
    private string $secretRandomHex = '01010101010101010101020202020202020202020303030303030303030304040404040404040404050505050505'; //46byte

    private ServerCertificate $serverCertificate;

    // pre master secret(暗号化済み)のデータ(hex)
    private string $preMasterSecretHex;

    public function __construct(ServerCertificate $serverCertificate)
    {
        $this->serverCertificate = $serverCertificate;
    }

    /**
     * pre master secretを生成して返す。 hex
     *
     * @return string hex
     * @throws \Exception
     */
    public function createPreMasterSecretHex(): string
    {
        $secret = hex2bin($this->versionHex . $this->secretRandomHex);
        $this->preMasterSecretHex = bin2hex($this->serverCertificate->encryptWithPubKey($secret));
        return $this->preMasterSecretHex;
    }

    /**
     * Client Key Exchange のペイロードを作成する(hex)
     *
     * @return string
     * @throws \Exception
     */
    public function createClientKeyExchangeDataHex(): string
    {
        $preMasterSecretHex = $this->createPreMasterSecretHex();
        $lengthOfPreMasterSecret = strlen(hex2bin($preMasterSecretHex));
        $handShakeExchange =
            '10' . //Content Type : Client Key Exchange
            Util::decToHexWithLen($lengthOfPreMasterSecret, 3) .
            $preMasterSecretHex;

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
