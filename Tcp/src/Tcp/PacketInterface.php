<?php

namespace TCPIPHP\Tcp;

interface PacketInterface
{
    public function createPacket(int $seqNum, int $ackNum, int $flag, string $data): string;

    public function send($socket, string $data);

    public function recv($socket, string &$buf);
}
