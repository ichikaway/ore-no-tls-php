<?php

namespace PHPTLS\Tests\Client;

use PHPTLS\Tls\Client\FinishedMessage;
use PHPTLS\Tls\Client\MasterSecret;
use PHPTLS\Tls\Client\Sequence;
use PHPUnit\Framework\TestCase;

class FinishedMessageTest extends TestCase
{

    public function getTlsPayload(): array
    {
        $result = [
            'clientHello' => '0100002903030101010101010101010102020202020202020202030303030303030303030404000002009c0100',
            'serverHello' => '020000460303677b91f952ccfc2fef1eda157077ab13e564f805b26a5166a4c2b58626fad25e204deb8e103a8c1fbee437307864305eefc48d9ae9650b39d1ff889e952befd261009c00',
            'certificate' => '0b000add000ada000646308206423082052aa003020102020c5659f5c44004d7574df96c68300d06092a864886f70d01010b0500304c310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d73613122302006035504031319416c70686153534c204341202d20534841323536202d204734301e170d3233303833303038333330385a170d3234303933303038333330375a30163114301206035504030c0b2a2e76616464792e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100d730582c120df024fdbf07917e9fb44b338b99e3984eb4ef4b420d267252fab8fb52f4aec5cc987d1391515b1f14814b23811e19172b879f1e8c030f9223f50b8a69a64693fd0185f9a866612817713af838b5c4146ba315c517933bf6e2ffaa8895590e124bee451017a88534c71363ddb6b3927b00f4854475cc082d36dc1e6d0867b2b6d9b5aed4af48ec8156fa6ad1d5f8f8c720fd9ada7b0ecdce1ac8628038f78c5aa07cd3fe33705070c46a40e9232f875ea27d72210750bdb6273b1e159f296c448b382ad37f7f4f8943df8e3a4657967d880e0f0ea3d663832814e0cf26bf59b265338109023342fd199143dc56a6a2f2bdd116118ca3aa705fa8170203010001a382035830820354300e0603551d0f0101ff0404030205a0300c0603551d130101ff0402300030819306082b06010505070101048186308183304606082b06010505073002863a687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f616c70686173736c636173686132353667342e637274303906082b06010505073001862d687474703a2f2f6f6373702e676c6f62616c7369676e2e636f6d2f616c70686173736c6361736861323536673430570603551d200450304e3008060667810c0102013042060a2b06010401a0320a01033034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f30410603551d1f043a30383036a034a0328630687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f616c70686173736c636173686132353667342e63726c30210603551d11041a3018820b2a2e76616464792e6e6574820976616464792e6e6574301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680144fcbaca8c2efabdd836f6bbfce983d5c58257615301d0603551d0e04160414299c829e37e27e2fdc5c70c64b59933033e3e5943082017e060a2b06010401d6790204020482016e0482016a0168007500eecdd064d5db1acec55cb79db4cd13a23287467cbcecdec351485946711fb59b0000018a45933749000004030046304402206b8911189322ebf4ae99f297fa4c1ec1602c0fdae68f838a53b5e44c1192006b022019be9767f09e644b12d7fbaedf3c6d48045593d3a211941c89e4337993e2893300770048b0e36bdaa647340fe56a02fa9d30eb1c5201cb56dd2c81d9bbbfab39d884730000018a459337590000040300483046022100bcfef20664bc471832c0463cd841b6554f1179aa7a4d81a03417606bd6c4ada4022100b8272131e78e6f7fa527a66023c0e96d36eb87e719b58fa5b75f1f2dc283da55007600dab6bf6b3fb5b6229f9bc2bb5c6be87091716cbb51848534bda43d3048d7fbab0000018a4593377a000004030047304502210083e32347fc83f1ceec102eff909c64e0a6de5415eef01068f9e7e83f150c6eef02201796df9cf04162d3113fdc427db4c955621ced527ab5296936363b2c415fb044300d06092a864886f70d01010b0500038201010075398c7494d93aa674574094a67be43a8fd86b408a984193c526f532e009413f6d87df156f5b7e21b16dc8f2ce39cc4d284aed44c931188eb76ff81213cc3984722229e8f98de7684992d8bac0e2aca2ec1baeec7705dbc28a006472a1dc3ae975b13b788206e6afcb90583944da7f7826cd035f1959e8d4cacb0e46ea4cc0101c729824d1b026895f48879506dc2b5c1ac42db87999b4dd53ac958a0679573b2b131b367605144febddbea77a18d606d1dc09f4dcb4e77f3e732751fd136e1d70282f1ccc6dcbd1b684a2aa622a9473f2c6182bb90d6856d57cda695becf4a7596c8c369679f6e86a17b2c466b4c3349853e7c858d5a500d64b7f559fc4333800048e3082048a30820372a00302010202107d4d42a92b431d7e6453e7c19a8d5877300d06092a864886f70d01010b05003057310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d73613110300e060355040b1307526f6f74204341311b301906035504031312476c6f62616c5369676e20526f6f74204341301e170d3232313031323033343934335a170d3237313031323030303030305a304c310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d73613122302006035504031319416c70686153534c204341202d20534841323536202d20473430820122300d06092a864886f70d01010105000382010f003082010a0282010100ad2429956615883f33870378cfd50c24b83153f3ff83226c99952b7ce54a59c2aec6d12a9dfa7f202e51c8672a5091a7795644fb38b53e308efc942ecb570c69535f44c656962faec0372586f171f1dc0245428661b836ef51e373450c90b3a5d2e7037ab83945d017f502d094416ac618b198c320b5c53af382b14aa444ac21732a9255064ec87c8bb0ca66145455f82b3cb25491b6cb52b2d8e36f8a4428b07d2bc19680b93e00d89e3de8319d5a4dedd67e4de5d48e03dd129a2783d4d6a1d784724e81ed9b8c620697a32c68137e041dacafa127c57d319cc21b7b0da821f385a0baace3bbe1fc61f824dd2aaa5d960477c33d50e6ddbf8643163a37f2d70203010001a382015b30820157300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030106082b0601050507030230120603551d130101ff040830060101ff020100301d0603551d0e041604144fcbaca8c2efabdd836f6bbfce983d5c58257615301f0603551d23041830168014607b661a450d97ca89502f7d04cd34a8fffcfd4b307a06082b06010505070101046e306c302d06082b060105050730018621687474703a2f2f6f6373702e676c6f62616c7369676e2e636f6d2f726f6f747231303b06082b06010505073002862f687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f726f6f742d72312e63727430330603551d1f042c302a3028a026a0248622687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f726f6f742e63726c30210603551d20041a30183008060667810c010201300c060a2b06010401a0320a0103300d06092a864886f70d01010b050003820101001a25f673648840a95907a743ba153f5161bd15ff2d64ddcd7a5d326a7f4842e710986839efb7eba13476df2d58683e7b301c0cf78660f9a9f379c054b783a638bb36abbc95d07cf86fc1e94f4607c8b60c3200a92b0512f70c6d66f9819dbf0e644d7227c68bd14a02e16edb0c9fb78b380c7c332f6089db38cc95438cdd1684d5cc6e3acf8e9ba3020fd1bbbe7900b52882fce39f1cef74d9fe322366b8f0afa029a01fde52121578dddf6a70436d4ba4cdee7881b275a27ed7fcfc9eff82ed2513e5b1e8cfb718536ecb52f8759f65923670bafd0c054a83fa80d29ae0f38efe83b5df18e1acb44727fd3870a31b4402ed2564243da709f12255841d91ec12',
            'serverHelloDone' => '0e000000',
            'clientKeyExchange' => '1000010201009a738226ab02b326551095bed94a46f3a9f6a31c41c2fd38138f6317c46bdd1f7725b6801c625f00f539baf20e9f861c442f9738b92b64e667ef22613ca95d85d95703ce9518aaeaa140fe13f31d9265b11f61b393e94914d08eb890d3031cfbdc137daa1184d72c6fdbb78c44f12618d8bb31da6d0a14c6b1623a0247f61e6ccbcec5ae52a4e4ac644932a9734491aa1eef3e2b6d064ae9ef3242815d058bf5f782f886348836ba193ac8a7f4c8959a90ba5e0dde9dfc36ec97ca99464a3e3c1c4ca7efea899b02b4ae2ca6b31e5b93119ef598827c91f2cc644e552b6cc589add59bd98f270ae98ef4e951b804f6c2db97aa1e227b2aeea24a155cf14d0418',
        ];
        return $result;
    }

    public function test_createVerifyData()
    {
        $preMasterSecret = '03030c0fd6fc3d0f6b413571836add039882282320d597d06993f307bb993303d947b1cfc5767dbab1e2e39877d8cd04';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '677b91f952ccfc2fef1eda157077ab13e564f805b26a5166a4c2b58626fad25e';

        $MasterSecret = new MasterSecret(
            hex2bin($preMasterSecret),
            hex2bin($clientRandom),
            hex2bin($serverRandom)
        );
        $Sequence = new Sequence();
        $payload = $this->getTlsPayload();

        $FinishedObj = new FinishedMessage(
            $MasterSecret,
            $Sequence,
            hex2bin($payload['clientHello']),
            hex2bin($payload['serverHello']),
            hex2bin($payload['certificate']),
            hex2bin($payload['serverHelloDone']),
            hex2bin($payload['clientKeyExchange']),
        );

        $result = $FinishedObj->createVerifyData();

        // AES-GCM 前提。他の暗号を利用すると値が変わるため注意
        $expect = '47fa24a59701388edf5baa50';

        $this->assertEquals($expect, bin2hex($result));
    }

    public function test_createHandshakeMessage()
    {
        $preMasterSecret = '03030c0fd6fc3d0f6b413571836add039882282320d597d06993f307bb993303d947b1cfc5767dbab1e2e39877d8cd04';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '677b91f952ccfc2fef1eda157077ab13e564f805b26a5166a4c2b58626fad25e';

        $MasterSecret = new MasterSecret(
            hex2bin($preMasterSecret),
            hex2bin($clientRandom),
            hex2bin($serverRandom)
        );
        $Sequence = new Sequence();
        $payload = $this->getTlsPayload();

        $FinishedObj = new FinishedMessage(
            $MasterSecret,
            $Sequence,
            hex2bin($payload['clientHello']),
            hex2bin($payload['serverHello']),
            hex2bin($payload['certificate']),
            hex2bin($payload['serverHelloDone']),
            hex2bin($payload['clientKeyExchange']),
        );

        $result = $FinishedObj->createHandshakeMessage();

        // AES-GCM 前提。他の暗号を利用すると値が変わるため注意
        $expect = '160303002800000000000000003f4b2e4b81cb29c2388ce18b068920832ab1ca77d4eeaf85d2187726a704d2f1';

        $this->assertEquals($expect, bin2hex($result), 'Client FinishedのTLSデータチェック');
    }
}
