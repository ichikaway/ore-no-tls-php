<?php
namespace TCPIPHP\Tcp;

class PhpTcp
{
    private string $srcIp;

    private string $dstIp;
    private int $port;

    private TcpController $TcpController;

    /**
     * @param string $srcIp
     */
    public function __construct(string $srcIp)
    {
        $this->srcIp = $srcIp;
    }


    public function connect(string $dstIp, int $dstPort): bool
    {
        //do 3 way handshake
        $socket = socket_create(AF_INET, SOCK_RAW, SOL_TCP);
        if ($socket === false) {
            var_dump("ソケットの作成に失敗しました: " . socket_strerror(socket_last_error()));
            return false;
        }
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);

        $this->TcpController= new TcpController($socket, $this->srcIp, $dstIp, $dstPort);
        $this->TcpController->handshake();
        return true;
    }

    public function read()
    {
        //read data and return ack
        $data = $this->TcpController->receive();
        return $data;
    }

    public function write(string $data): false|int
    {
        // write data and recv ack
        return $this->TcpController->send($data);
    }

    public function close()
    {
        // fin
        $this->TcpController->fin();
    }
}