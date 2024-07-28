<?php
namespace PHPTLS;

use PHPTLS\Tls\Client\ApplicationData;
use PHPTLS\Tls\Client\ChangeCipherSpec;
use PHPTLS\Tls\Client\ClientHello;
use PHPTLS\Tls\Client\ClientKeyExchange;
use PHPTLS\Tls\Client\FinishedMessage;
use PHPTLS\Tls\Client\MasterSecret;
use PHPTLS\Tls\Client\ParseServerHello;
use PHPTLS\Tls\Client\Sequence;
use PHPTLS\Tls\Connection;

require 'vendor/autoload.php';

if ($argc < 2) {
    fwrite(STDERR, "Error: No argument provided.\n");
    exit(1);
}
$host = $argv[1];
$port = 443;

$Socket = new Connection($host, $port);
$Socket->connect();


$ClientHelloObj = new ClientHello();
$clientHello = $ClientHelloObj->createClientHello();


// ソケットに`ClientHello`パケットを送信
$Socket->write($clientHello);

// サーバーからの応答を読み取る
$response = $Socket->read();

$recvServerHello = new ParseServerHello($response);
/*
// データが足りない場合は追加データをreadする
if (strlen($recvServerHello->serverHelloDone->getTlsPayload()) == 0) {
    echo "server hello done is null\n";
    $response2 = $Socket->read();
    //var_dump(bin2hex($response));
    //var_dump(bin2hex($response2));
    $response = $response . $response2;
    $recvServerHello = new ParseServerHello($response);
}
*/

//echo "server hello response all:\n" . bin2hex($response) . PHP_EOL;
//    echo "serverHello:\n" . bin2hex($recvServerHello->serverHello->getTlsPayload()). PHP_EOL;
//    echo "serverCertificate:\n" . bin2hex($recvServerHello->certificate->getTlsPayload()). PHP_EOL;
//    echo "serverHelloDone:\n" . bin2hex($recvServerHello->serverHelloDone->getTlsPayload()). PHP_EOL;

//$serverCert = $recvServerHello->certificate->getServerPubKeyFromCert();
//$keyData = openssl_pkey_get_details($serverCert);
// var_dump($keyData['key']);

// Client Key Exchangeデータ作成
$ClientKeyExchange = new ClientKeyExchange($recvServerHello->certificate);
$clientKeyExchangeData = $ClientKeyExchange->createClientKeyExchangeData();

// ClientCipherSpecデータ作成
$changeCipher = ChangeCipherSpec::createChangeCipherSpec();

// Finishedデータ作成
$preMasterSecret = $ClientKeyExchange->getPreMasterSecret();
$clientRandom = $ClientHelloObj->getClientHelloRandom();
$serverRandom = $recvServerHello->serverHello->getServerRandom();
$MasterSecret = new MasterSecret($preMasterSecret, $clientRandom, $serverRandom);
$Sequence = new Sequence();

//echo "create Master Secret\n";
//echo bin2hex($preMasterSecret) . PHP_EOL;
//echo bin2hex($clientRandom) . PHP_EOL;
//echo bin2hex($serverRandom) . PHP_EOL;
//echo "finish create Master Secret\n\n";

$FinishedObj = new FinishedMessage(
    $MasterSecret,
    $Sequence,
    $ClientHelloObj->getTlsPayload(),
    $recvServerHello->serverHello->getTlsPayload(),
    $recvServerHello->certificate->getTlsPayload(),
    $recvServerHello->serverHelloDone->getTlsPayload(),
    $ClientKeyExchange->getTlsPayload()
);

//handshake messageを暗号化してfinishメッセージの形式にする
$finishedMessage = $FinishedObj->createHandshakeMessage();

//Client key exchange, Change cipher spec, Finishedのデータを一つにまとめて送信
$sendData = $clientKeyExchangeData . $changeCipher. $finishedMessage;

$Socket->write($sendData);

$response = $Socket->read();
echo "received server finish: " . bin2hex($response) . PHP_EOL;


//-------------ここから実際のHTTPプロトコルの通信を行う----------------------
$httpGetReq = "GET / HTTP/1.1\r\n\r\n";

$ApplicationData = new ApplicationData($MasterSecret, $Sequence);

$sendData = $ApplicationData->encrypt($httpGetReq);
//echo "request data:\n" . bin2hex($httpGetReq).PHP_EOL;
//echo "sendData:\n" . bin2hex($sendData).PHP_EOL;

$Socket->write($sendData);

$response = $Socket->read();

echo "received GET response: " . bin2hex($response) . PHP_EOL;
echo "\n\n";
$html = $ApplicationData->decrypt($response);

echo $httpGetReq ;
var_dump($html);

//echo "decrypt html hex:\n" . bin2hex($html);

$Socket->close();
