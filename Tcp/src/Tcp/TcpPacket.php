<?php
namespace TCPIPHP\Tcp;

class TcpPacket implements PacketInterface
{
    private string $srcIp;
    private int $srcPort;

    private string $dstIp;
    private int $dstPort;


    /**
     * @param string $srcIp
     * @param string $dstIp
     * @param int $port
     */
    public function __construct(string $srcIp, int $srcPort, string $dstIp, int $dstPort)
    {
        $this->srcIp = $srcIp;
        $this->dstIp = $dstIp;
        $this->srcPort = $srcPort;
        $this->dstPort = $dstPort;
    }

    public function createPacket(int $seqNum, int $ackNum, int $flag, string $data): string
    {

        $tcp_header = pack('n', $this->srcPort);  // 送信元ポート
        $tcp_header .= pack('n', $this->dstPort);  // 送信先ポート
        $tcp_header .= pack('N', $seqNum);  // シーケンス番号
        $tcp_header .= pack('N', $ackNum);  // 確認応答番号 (ACKなし)
        $tcp_header .= pack('C', 5 << 4);  // ヘッダー長 20byte固定にしておく
        $tcp_header .= pack('C', $flag);  // フラグ
        $tcp_header .= pack('n', 65535);  // ウィンドウサイズ
        $tcp_header .= pack('n', 0);  // チェックサム (後で計算)
        $tcp_header .= pack('n', 0);  // 緊急ポインタ

        // 疑似ヘッダー (TCPチェックサム計算用)
        $src_ip_bin = inet_pton($this->srcIp);
        $dst_ip_bin = inet_pton($this->dstIp);

        $protocol = 6;  // TCP

        // 疑似ヘッダー (TCPチェックサム計算用)
        $pseudo_header = $src_ip_bin . $dst_ip_bin . pack('C', 0) . pack('C', $protocol) . pack('n', strlen($tcp_header) + strlen($data));
        $tcp_checksum  = TcpUtil::checksum($pseudo_header . $tcp_header . $data);

        // チェックサムを設定
        $tcp_header = substr_replace($tcp_header, pack('n', $tcp_checksum), 16, 2);
        return $tcp_header . $data;
    }

    public function send($socket, string $data)
    {
        return socket_sendto($socket, $data, strlen($data), 0, $this->dstIp, $this->dstPort);
    }

    public function recv($socket, string &$buf)
    {
        return @socket_recv($socket, $buf, 65535, 0);
    }
}
