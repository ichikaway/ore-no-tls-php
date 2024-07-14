<?php

namespace PHPTLS\Tls\Client;

class ServerHelloDone
{
    private readonly string $data; //hex
    public function __construct(string $data)
    {
        $this->data = $data;
    }
}
