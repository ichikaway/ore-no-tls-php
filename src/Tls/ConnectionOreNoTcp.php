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

    private string $srcIp;

    private PhpTcp $PhpTcp;

    /**
     * @param $host
     */
    public function __construct(string $host, int $port = 443, string $srcIp = '')
    {
        $this->ip = gethostbyname($host);
        $this->port = $port;
        $this->host = $host;
        $this->srcIp = $srcIp;
    }

    public function connect(): void
    {
        $this->PhpTcp = new PhpTcp($this->srcIp);

        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        try {
            $result = $this->PhpTcp->connect($this->ip, $this->port);
            if ($result === false) {
                //echo "Socket connect failed: " . socket_strerror(socket_last_error($socket)) . "\n";
                throw new \Exception("Socket connect failed". socket_strerror(socket_last_error($socket)) . "\n");
            }

        } catch (\Exception $e) {
            $this->PhpTcp->close();
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
            $dataAll .= $this->PhpTcp->read();
            if (TlsRecord::isEnoughData($dataAll)) {
                break;
            } else {
                echo "TLS Data is not enough. socket_read again: {$i}\n";
            }
        }

        return $dataAll;
    }


    public function write(string $data): void
    {
        $this->PhpTcp->write($data);
    }

    public function close(): void
    {
        $this->PhpTcp->close();
    }
}
