<?php
use TCPIPHP\Tcp\PhpTcp;

require 'vendor/autoload.php';

if ($argc < 4) {
    fwrite(STDERR, "Error: php TcpSample.php srcIp dstIp dstPort\n");
    exit(1);
}

$srcIpArg = $argv[1];
$dstIpArg = $argv[2];
$dstPortArg = $argv[3];

$PhpTcp = new PhpTcp($srcIpArg);
$PhpTcp->connect($dstIpArg, $dstPortArg);

$data = 'GET / HTTP/1.0' . "\r\nHost: vaddy.net" . "\r\n\r\n" ;
$PhpTcp->write($data);

$recvData = $PhpTcp->read();
var_dump($recvData);



$PhpTcp->close();

/*
$recvData = $PhpTcp->read();
var_dump($recvData);
$recvData = $PhpTcp->read();
var_dump($recvData);
*/