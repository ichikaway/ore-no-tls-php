<?php
namespace PHPTLS;

use PHPTLS\Tls\Client\ClientHello;
use PHPTLS\Tls\Client\ParseServerHello;

require 'vendor/autoload.php';

if ($argc < 2) {
    fwrite(STDERR, "Error: No argument provided.\n");
    exit(1);
}
$hostIp = $argv[1];
//echo "First argument: $firstArgument\n";

#$host = '127.0.0.1';
$port = 443;


$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if ($socket === false) {
    echo "Socket creation failed: " . socket_strerror(socket_last_error()) . "\n";
    exit;
}

$result = socket_connect($socket, $hostIp, $port);
if ($result === false) {
    echo "Socket connect failed: " . socket_strerror(socket_last_error($socket)) . "\n";
    socket_close($socket);
    exit;
}

$ClientHelloObj = new ClientHello();
$clientHello = $ClientHelloObj->createClientHello();


// ソケットに`ClientHello`パケットを送信
socket_write($socket, $clientHello, strlen($clientHello));

// サーバーからの応答を読み取る
$response = socket_read($socket, 8000);

$recvServerHello = new ParseServerHello(bin2hex($response));

$serverCert = $recvServerHello->certificate->getServerPubKeyFromCert();
$keyData = openssl_pkey_get_details($serverCert);

var_dump($keyData['key']);

// ソケットを閉じる
socket_close($socket);



?>