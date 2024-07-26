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

    public function __construct(string $preMasterSecretBin, string $clientRandomBin, string $serverRandomBin)
    {
        if (ctype_xdigit($clientRandomBin) || ctype_xdigit($serverRandomBin)) {
            throw new \InvalidArgumentException('Invalid Client/Server Random. hex data provided.');
        }
        $this->preMasterSecretBin = $preMasterSecretBin;
        $this->clientRandomBin = $clientRandomBin;
        $this->serverRandomBin = $serverRandomBin;
        $this->createMasterSecret();
        $this->createKeyBlock();
    }

    public function getMasterSecret()
    {
        return $this->masterSecretBin;
    }

    public function getClientKey(): string
    {
        return $this->keyBlock['ClientWriteKey'];
    }
    public function getClientIV(): string
    {
        return $this->keyBlock['ClientWriteIV'];
    }

    public function getServerKey(): string
    {
        return $this->keyBlock['ServerWriteKey'];
    }
    public function getServerIV(): string
    {
        return $this->keyBlock['ServerWriteIV'];
    }

    public function createKeyBlock()
    {
        $this->keyBlock = Prf::createKeyBlock($this->masterSecretBin, $this->clientRandomBin, $this->serverRandomBin);
        //$this->keyBlock = Prf::createKeyBlockForCBC($this->masterSecretBin, $this->clientRandomBin, $this->serverRandomBin);
    }

    public function createMasterSecret()
    {
        $this->masterSecretBin = Prf::createMasterSecret($this->preMasterSecretBin, $this->clientRandomBin, $this->serverRandomBin);
    }
}
