<?php
namespace TCPIPHP\Tcp;

class TcpUtil
{
    public static function checksum(string $data): string
    {
        $sum = 0;
        $len = strlen($data);

        for ($i = 0; $i < $len; $i += 2) {
            $word = ord($data[$i]) << 8;
            if ($i + 1 < $len) {
                $word += ord($data[$i + 1]);
            }
            $sum += $word;
        }

        while ($sum >> 16) {
            $sum = ($sum & 0xFFFF) + ($sum >> 16);
        }

        return ~($sum & 0xFFFF);
    }

    public static function createFlagByte(int $syn = 0, int $ack = 0, int $fin = 0, int $rst = 0, int $psh = 0): int
    {
        $urg = 0;
        $tcp_flags = ($fin) | ($syn << 1) | ($rst << 2) | ($psh << 3) | ($ack << 4) | ($urg << 5);
        return $tcp_flags;
    }
}
