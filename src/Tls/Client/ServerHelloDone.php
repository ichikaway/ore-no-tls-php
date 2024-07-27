<?php

namespace PHPTLS\Tls\Client;

class ServerHelloDone
{
    use TlsMessageTrait;

    public function __construct(string $data)
    {
        $this->data = $data;
    }
}
