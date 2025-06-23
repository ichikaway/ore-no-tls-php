<?php
namespace TCPIPHP\Tcp;

class PhpTcp
{
    private string $srcIp;

    private string $dstIp;
    private int $port;

    private bool $withMyIpPacket;

    private TcpController $TcpController;

    /**
     * @param string $srcIp
     */
    public function __construct(string $srcIp, bool $withMyIpPacket = false)
    {
        $this->srcIp = $srcIp;
        $this->withMyIpPacket = $withMyIpPacket;
    }


    public function connect(string $dstIp, int $dstPort)
    {
        //do 3 way handshake
        $socket = socket_create(AF_INET, SOCK_RAW, SOL_TCP);
        if ($socket === false) {
            die("ソケットの作成に失敗しました: " . socket_strerror(socket_last_error()));
        }
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);

        $this->TcpController= new TcpController($socket, $this->srcIp, $dstIp, $dstPort, $this->withMyIpPacket);
        $this->TcpController->handshake();

        //socket_close($socket);
    }

    public function read()
    {
        //read data and return ack
        $data = $this->TcpController->receive();
        return $data;
    }

    public function write(string $data)
    {
        // write data and recv ack
        $this->TcpController->send($data);
    }

    public function close()
    {
        // fin
        $this->TcpController->fin();
    }
}
