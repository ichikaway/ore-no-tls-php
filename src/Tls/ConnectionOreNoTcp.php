<?php

namespace PHPTLS\Tls;
use TCPIPHP\Tcp\PhpTcp;

use Socket;

class ConnectionOreNoTcp
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

            // ソケットオプションでタイムアウトを設定
            socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, [
                'sec' => 5, //5秒でタイムアウト
                'usec' => 0,
            ]);

            $this->socket = $socket;
        } catch (\Exception $e) {
            socket_close($socket);
            throw $e;
        }
        echo "\nConnected to {$this->host}({$this->ip}):{$this->port}\n\n";
    }

    /**
     * TLSデータが分割されて受信する場合にも対応したreadメソッド
     * readの受信サイズ以上のデータの場合は複数回のreadを行う。
     * TLSレコードが複数のパケットに分割されて受信する場合があるため、TLSレコード長と実際のデータサイズのチェックを行い、
     * 必要であれば追加でsocket readする
     *
     * @return string
     * @throws \Exception
     */
    public function read(): string
    {
        $dataAll = null;
        for ($i = 0; $i < 5; $i++) {
            $dataAll .= $this->readData();
            if (TlsRecord::isEnoughData($dataAll)) {
                break;
            } else {
                echo "TLS Data is not enough. socket_read again: {$i}\n";
            }
        }

        return $dataAll;
    }


    private function readData(): string
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
