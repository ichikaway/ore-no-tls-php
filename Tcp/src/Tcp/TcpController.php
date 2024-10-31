<?php
namespace TCPIPHP\Tcp;

class TcpController
{
    private string $srcIp;
    private int $srcPort;

    private string $dstIp;
    private int $dstPort;

    private $socket;

    private int $seqNum;
    private int $ackNum;

    private int $finCount = 0;

    private TcpPacket $TcpPacket;

    /**
     * @param string $srcIp
     * @param string $dstIp
     * @param int $dstPort
     */
    public function __construct($socket, string $srcIp, string $dstIp, int $dstPort)
    {
        $this->socket = $socket;
        $this->srcIp = $srcIp;
        $this->dstIp = $dstIp;
        $this->dstPort = $dstPort;

        $this->srcPort = rand(60000, 60100);
        $this->seqNum = rand(2000001000, 2000003000);  // シーケンス番号をランダムに設定

        $this->TcpPacket = new TcpPacket($this->srcIp, $this->srcPort, $this->dstIp, $this->dstPort);
    }

    public function close()
    {
        socket_close($this->socket);
    }
    public function handshake()
    {
        // syn packet
        $synFlag = TcpUtil::createFlagByte(syn: 1);
        $packet = $this->TcpPacket->createTcpPacket(seqNum:$this->seqNum, ackNum: 0,flag: $synFlag,data: '');
        $result = socket_sendto($this->socket, $packet, strlen($packet), 0, $this->dstIp, $this->dstPort);
        var_dump($result);
        // パケットの受信
        echo "SYNパケット送信。SYN-ACK待機中...\n";
        $this->receive();

    }

    public function send(string $data): false|int
    {
        echo "PSH 送信...\n";
        $flag = TcpUtil::createFlagByte(psh: 1, ack: 1);
        $packet = $this->TcpPacket->createTcpPacket(seqNum:$this->seqNum, ackNum: $this->ackNum, flag: $flag, data: $data);
        var_dump("send packet: " . bin2hex($packet));
        $result = socket_sendto($this->socket, $packet, strlen($packet), 0, $this->dstIp, $this->dstPort);
        //var_dump($result);
        // パケットの受信
        echo "PSH後の受信...\n";
        $this->receive();
        return $result;
    }

    public function fin()
    {
        echo "FIN/ACK 送信...\n";
        $flag = TcpUtil::createFlagByte(fin: 1, ack: 1);
        $packet = $this->TcpPacket->createTcpPacket(seqNum:$this->seqNum, ackNum: $this->ackNum, flag: $flag, data: '');
        var_dump("send fin/ack packet: " . bin2hex($packet));
        $result = socket_sendto($this->socket, $packet, strlen($packet), 0, $this->dstIp, $this->dstPort);
        //var_dump($result);
        // パケットの受信
        echo "FIN/ACK後の受信...\n";
        $this->receive();
        // FIN/ACKでACKを返した後、サーバからFIN/ACKが来るためもう一度receiveしてACKを返す
        var_dump("finCount: " . $this->finCount);
        $this->receive();
    }


    public function receive()
    {
        $dataBuf = '';

        while (true) {
            echo "\n ===== start receive =====\n";
            $buf  = '';
            $from = '';
            $port = 0;

            // 受信バッファサイズを定義
            if (@socket_recvfrom($this->socket, $buf, 65535, 0, $from, $port) === false) {
                echo "タイムアウト: TCPパケットを受信できませんでした。\n";
                return $dataBuf;
            }

            var_dump("recvfrom buf: " . bin2hex($buf) . "\n");

            // 受信データがIPパケットとして正しいか確認
            $ip_header_length = (ord($buf[0]) & 0x0F) * 4;  // IPヘッダーの長さを取得
            $tcp_header_start = $ip_header_length;  // TCPヘッダーの開始位置

            // TCPヘッダーを解析
            $tcp_segment = substr($buf, $tcp_header_start, 20);  // TCPヘッダー部分だけ抜き出す
            $tcp_flags   = ord($tcp_segment[13]);  // TCPヘッダー内の13バイト目がフラグ

            var_dump("Flag: 0x" . dechex($tcp_flags) . " , " . $tcp_flags);
            //var_dump(bin2hex($tcp_segment));

            $peerSrcPort = unpack('nint', substr($tcp_segment, 0, 2))['int'];
            $peerDstPort = unpack('nint', substr($tcp_segment, 2, 4))['int'];

            //受信パケットだけ受け付ける
            // 相手からの受信パケットは、こちらから送信したportと逆になっているためそれをチェック
            if ($peerSrcPort !== $this->dstPort  || $peerDstPort !== $this->srcPort) {
                echo "src/dst port mismatch\n";
                var_dump("  peerSrcPort: " . $peerSrcPort . ", dst port: " . $this->dstPort);
                var_dump("  peerDstPort: " . $peerDstPort . ", src port: " . $this->srcPort);
                continue;
            }

            $recvSeqNum = unpack('Nint', substr($tcp_segment, 4, 4))['int'];
            $recvAckNum = unpack('Nint', substr($tcp_segment, 8, 4))['int'];

            //データ受信処理のため、ackで返す確認応答番号は相手から送信されてきたシーケンス番号となるためackNumにrecvSeqNumをセット
            $this->ackNum = $recvSeqNum;

            // SYN-ACKのフラグは、SYN (0x02) と ACK (0x10) の両方がセットされている必要がある
            if (($tcp_flags & 0x12) == 0x12) {
                $flagName = 'SYN-ACK';
                echo "{$flagName}パケットを受信しました！\n";
                $this->seqNum++;
                $this->ackNum++;
                if (intval($recvAckNum) === $this->seqNum) {
                    echo "{$flagName}パケットack num: $recvAckNum\n";
                }

                $flag = TcpUtil::createFlagByte(ack: 1);
                $packet = $this->TcpPacket->createTcpPacket(seqNum:$this->seqNum, ackNum: $this->ackNum,flag: $flag, data: '');
                $result = socket_sendto($this->socket, $packet, strlen($packet), 0, $this->dstIp, $this->dstPort);
                break;
            }

            // FIN-ACKフラグは、 FIN(0x01) と ACK(0x10)
            if (($tcp_flags & 0x11) == 0x11) {
                $flagName = 'FIN-ACK';
                echo "{$flagName}パケットを受信しました！\n";

                $tcp_header_size = (ord($tcp_segment[12]) >> 4) * 4;
                var_dump("header size: ". $tcp_header_size);
                $data = substr($buf, $tcp_header_start + $tcp_header_size);
                //var_dump("data: ". $data);

                var_dump("recvSeqNum: ". $recvSeqNum);
                var_dump("recvAckNum: ". $recvAckNum);

                $dataLen = strlen($data);
                var_dump("data len: " . $dataLen);

                //fin-ackの場合は、データが付与されている場合があるため、データがある場合はデータサイズを足す
                //それ以外は確認応答番号を1つ足す
                if ($dataLen > 0) {
                    // サーバからデータ受信しそのAckを返す時は、受け取ったシーケンス番号に対してさらに受け取ったデータサイズを足す
                    $this->ackNum += $dataLen;
                } else {
                    $this->ackNum++;
                }
                var_dump("this->ackNum: " . $this->ackNum);

                $flag = TcpUtil::createFlagByte(ack: 1);
                $packet = $this->TcpPacket->createTcpPacket(seqNum:$this->seqNum, ackNum: $this->ackNum,flag: $flag, data: '');
                $result = socket_sendto($this->socket, $packet, strlen($packet), 0, $this->dstIp, $this->dstPort);

                $this->finCount++;

                $dataBuf .= $data;
                return $dataBuf;
            }

            // サーバからデータが送信されるpush(0x08)を受信する処理を作成
            if (($tcp_flags & 0x08) == 0x08) {
                echo "PSHパケットを受信しました！\n";

                $tcp_header_size = (ord($tcp_segment[12]) >> 4) * 4;
                var_dump("header size: ". $tcp_header_size);
                $data = substr($buf, $tcp_header_start + $tcp_header_size);
                //var_dump("data: ". $data);

                var_dump("recvSeqNum: ". $recvSeqNum);
                var_dump("recvAckNum: ". $recvAckNum);

                $dataLen = strlen($data);
                var_dump("data len: " . $dataLen);
                if ($dataLen > 0) {
                    // サーバからデータ受信しそのAckを返す時は、受け取ったシーケンス番号に対してさらに受け取ったデータサイズを足す
                    $this->ackNum += $dataLen;
                    var_dump("this->ackNum: " . $this->ackNum);
                }

                $flag = TcpUtil::createFlagByte(ack: 1);
                $packet = $this->TcpPacket->createTcpPacket(seqNum:$this->seqNum, ackNum: $this->ackNum,flag: $flag, data: '');
                $result = socket_sendto($this->socket, $packet, strlen($packet), 0, $this->dstIp, $this->dstPort);
                $dataBuf .= $data;
                continue;
            }


            // Ack (0x10)のみ
            if ($tcp_flags == 0x10) {
                echo "ACKパケットを受信しました！\n";

                //var_dump(ord($tcp_segment[12]));
                //var_dump(ord($tcp_segment[12]) >> 4);
                $tcp_header_size = (ord($tcp_segment[12]) >> 4) * 4;
                var_dump("header size: ". $tcp_header_size);
                $data = substr($buf, $tcp_header_start + $tcp_header_size);

                var_dump("data: ". $data);

                var_dump("recvSeqNum: ". $recvSeqNum);
                var_dump("recvAckNum: ". $recvAckNum);

                // ackの Ack Numにこちらから送信したシーケンス番号+送信データ量の値が帰るため、次の送信のシーケンス番号でそれを使う
                $this->seqNum = $recvAckNum;
                var_dump("SeqNum: " . $this->seqNum);
                break;
            }

        }

        return null;
    }
}