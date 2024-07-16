<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Prf;

class MasterSecret
{
    private string $clientRandomBin;
    private string $serverRandomBin;

    private string $preMasterSecretBin;
    private string $masterSecretBin;
    private array $keyBlock;

    public function __construct(string $clientRandomBin, string $serverRandomBin)
    {
        if (ctype_xdigit($clientRandomBin) || ctype_xdigit($serverRandomBin)) {
            throw new \InvalidArgumentException('Invalid Client/Server Random. hex data provided.');
        }
        $this->clientRandomBin = $clientRandomBin;
        $this->serverRandomBin = $serverRandomBin;
        $this->createMasterSecret();
        $this->createKeyBlock();
    }

    public function createKeyBlock()
    {
        $this->keyBlock = Prf::createKeyBlock($this->masterSecretBin, $this->clientRandomBin, $this->serverRandomBin);
    }

    public function createMasterSecret()
    {
        $secret = $this->createPreMasterSecretBin();
        $this->masterSecretBin = Prf::createMasterSecret($secret, $this->clientRandomBin, $this->serverRandomBin);
    }

    private function createPreMasterSecretBin(): string
    {
        $data = '010101010101010101010202020202020202020203030303030303030303040404040404040404040505050505050505';   // Random 48byte (本来はランダムデータを入れる)
        $this->preMasterSecretBin = hex2bin($data);
        return $this->preMasterSecretBin;
    }
}
