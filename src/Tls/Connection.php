<?php

namespace PHPTLS\Tls;

use Socket;

class Connection
{
    private Socket $socket;

    private string $host;
    private string $ip;
    private int $port;

    /**
     * @param $host
     */
    public function __construct(string $host, ?int $port = null)
    {
        $this->ip = gethostbyname($host);
        $this->port = ($port === null) ? 443 : $port;
        $this->host = $host;
    }

    public function connect(): void
    {
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        try {
            if ($socket === false) {
                //echo "Socket creation failed: " . socket_strerror(socket_last_error()) . "\n";
                throw new \Exception("Socket creation failed: " . socket_strerror(socket_last_error()));
            }

            $result = socket_connect($socket, $this->ip, $this->port);
            if ($result === false) {
                //echo "Socket connect failed: " . socket_strerror(socket_last_error($socket)) . "\n";
                throw new \Exception("Socket connect failed". socket_strerror(socket_last_error($socket)) . "\n");
            }
            $this->socket = $socket;
        } catch (\Exception $e) {
            socket_close($socket);
            throw $e;
        }
        echo "\nConnected to {$this->host}({$this->ip}):{$this->port}\n\n";
    }

    public function read(): string
    {
        $recvAllData = null;
        $size = 8000;
        do {
            if ($recvAllData !== null) {
                // readのループが回っているか判断できるようにするecho
                echo "  socket read again. \n";
            }
            $recv = socket_read($this->socket, $size);
            $recvAllData .= $recv;
        } while (strlen($recv) === $size);
        return $recvAllData;
    }

    public function write(string $data): int
    {
        $result = socket_write($this->socket, $data, strlen($data));
        if ($result === false) {
            throw new \Exception('Socket write failed.' . socket_strerror(socket_last_error($this->socket)));
        }
        return $result;
    }

    public function close(): void
    {
        socket_close($this->socket);
    }
}
