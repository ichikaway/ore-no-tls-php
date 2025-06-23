<?php
namespace TCPIPHP\Tcp;

class TcpIpPacket implements PacketInterface
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
    public function __construct($socket, string $srcIp, int $srcPort, string $dstIp, int $dstPort)
    {
        $this->srcIp = $srcIp;
        $this->dstIp = $dstIp;
        $this->srcPort = $srcPort;
        $this->dstPort = $dstPort;

        $this->setIpHdrInclude($socket);
    }

    private function setIpHdrInclude($socket)
    {
        $IP_HDRINCL = 3;
        socket_set_option($socket, IPPROTO_IP,$IP_HDRINCL, 1);
        return $socket;
    }

    public function createPacket(int $seqNum, int $ackNum, int $flag, string $data): string
    {
        $ipPacket = $this->createIpPacket();
        $tcpPacket = $this->createTcpPacket($seqNum, $ackNum, $flag, $data);
        return $ipPacket . $tcpPacket;
    }

    public function createIpPacket()
    {
        // IPヘッダーの作成
        $ip_ver        = 4;
        $ip_header_len = 5;
        $tos           = 0;
        $total_length  = 20 + 20;  // IPヘッダー(20バイト) + TCPヘッダー(20バイト)
        //$ip_id         = rand(0, 65535);
        $ip_id         = 12345;
        $frag_offset   = 0;
        $ttl           = 64;
        $protocol      = 6;  // TCP
        $ip_checksum   = 0;
        $src_ip_bin    = inet_pton($this->srcIp);
        $dst_ip_bin    = inet_pton($this->dstIp);

        // IPヘッダー (20バイト)
        $ip_header = pack('C', ($ip_ver << 4) + $ip_header_len);  // バージョン(4ビット) + ヘッダー長(4ビット)
        $ip_header .= pack('C', $tos);  // サービスタイプ
        $ip_header .= pack('n', $total_length);  // 全長
        $ip_header .= pack('n', $ip_id);  // 識別子
        $ip_header .= pack('n', $frag_offset);  // フラグメントオフセット
        $ip_header .= pack('C', $ttl);  // TTL
        $ip_header .= pack('C', $protocol);  // プロトコル (TCP)
        $ip_header .= pack('n', $ip_checksum);  // チェックサム (後で計算)
        $ip_header .= $src_ip_bin;  // 送信元IPアドレス
        $ip_header .= $dst_ip_bin;  // 送信先IPアドレス

        // チェックサムを計算し、IPヘッダーに差し替える
        $ip_checksum  = TcpUtil::checksum($ip_header);
        $ip_header = substr_replace($ip_header, pack('n', $ip_checksum), 10, 2);
        return $ip_header;
    }

    public function createTcpPacket(int $seqNum, int $ackNum, int $flag, string $data): string
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
