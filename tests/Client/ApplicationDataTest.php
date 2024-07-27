<?php

namespace PHPTLS\Tests\Client;

use PHPTLS\Tls\Client\ApplicationData;
use PHPTLS\Tls\Client\FinishedMessage;
use PHPTLS\Tls\Client\MasterSecret;
use PHPTLS\Tls\Client\Sequence;
use PHPUnit\Framework\TestCase;

class ApplicationDataTest extends TestCase
{

    public function test_encrypt()
    {
        $preMasterSecret = '030337673debad720d46040bcd25e35c7277a1983f1d79805809193255c469ec41268fb37635bcef4e61f40b628442de';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '290caeeff9550c0cb33eaf5d1936ca5285baa4beaf096f070c37c558914d08d6';

        $MasterSecret = new MasterSecret(
            hex2bin($preMasterSecret),
            hex2bin($clientRandom),
            hex2bin($serverRandom)
        );
        $Sequence = new Sequence();

        $httpGetReq = "GET / HTTP/1.1\r\n\r\n";
        $ApplicationData = new ApplicationData($MasterSecret, $Sequence);
        $result = $ApplicationData->encrypt($httpGetReq);

        // AES-GCM 前提。他の暗号を利用すると値が変わるため注意
        $expect = '170303002a00000000000000012907f06cf66804ae8eebd4a0d4de4f41256228fdef4438173aa687e1f23f511d2d51';

        $this->assertEquals($expect, bin2hex($result));
    }

    public function test_decrypt()
    {
        $preMasterSecret = '030337673debad720d46040bcd25e35c7277a1983f1d79805809193255c469ec41268fb37635bcef4e61f40b628442de';
        $clientRandom = '0101010101010101010102020202020202020202030303030303030303030404';
        $serverRandom = '290caeeff9550c0cb33eaf5d1936ca5285baa4beaf096f070c37c558914d08d6';

        $receivedData = '17030301a01389e5a9eaf0717fb38f644907e75850140c5d179d406b4139d7047d7c63d297c028f73e022a2772fc6955e666cf472c11b9f93721815ca5c1e69503f9345c2459cd73755ad1a238411f1d8bf731d1e4fba03a72f75ca82dfdbd3d90d833f936fb75c627aa5ecfb3ea1f7b856bfe5027c35d0b59aecf4bedba8cc1cba4ee6ce36e4e181c3e4b57aebe24d7209979ac8165096bd1a93f446f247084cf58b187ca8be247497ef631c91b47c6ec7f4e99d6c09702baeaa5c1a22e0b3b85246e63bd21ab810ec9d18cd9b615c8ca27ab031b7bad2c0e70c2a1c281fd2088b8ae5e0495d2be3fa52a6d20fb5dd727368712abf27b38fcbbbed45f2ebf755871081042d4727a704d6a16824b45c1f989465b9723e10a726535a078a03bc6d1868f8662c5fe16a92360a21ecdefe28b5ee6b127804b390d8a2b2f611ce952e4997deacce3f4c95bbb19864969da1a5e366869c8ee987a44a2420a7a1de00f319d5026bff77781254ac80890d53739a17d6f3e846e63170bba70581e09c0458343e661c9f7b5fdf210596e3b639efda882ee58b039103bc50bf5cad59ff52c607134d628150303001a1389e5a9eaf07180cffdbc82f74057f97b7559a1574e2cbd60a0';

        $MasterSecret = new MasterSecret(
            hex2bin($preMasterSecret),
            hex2bin($clientRandom),
            hex2bin($serverRandom)
        );
        $Sequence = new Sequence();

        // sequenceの値をカウントアップさせておく。
        // decryptの処理でアカウントアップ後のsequenceを使うため
        // sequenceのカウントアップはencrypt側で送信メッセージ作成の際にされる。そのためメッセージ受信のテストでは手動でカウントアップ。
        $Sequence->incrementSequenceNumber();

        $ApplicationData = new ApplicationData($MasterSecret, $Sequence);

        $result = $ApplicationData->decrypt(hex2bin($receivedData));

        // AES-GCM 前提。他の暗号を利用すると値が変わるため注意
        $expect = '485454502f312e31203430302042616420526571756573740d0a446174653a205361742c203237204a756c20323032342030383a30383a343020474d540d0a5365727665723a204170616368650d0a436f6e74656e742d4c656e6774683a203232360d0a436f6e6e656374696f6e3a20636c6f73650d0a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d69736f2d383835392d310d0a0d0a3c21444f43545950452048544d4c205055424c494320222d2f2f494554462f2f4454442048544d4c20322e302f2f454e223e0a3c68746d6c3e3c686561643e0a3c7469746c653e3430302042616420526571756573743c2f7469746c653e0a3c2f686561643e3c626f64793e0a3c68313e42616420526571756573743c2f68313e0a3c703e596f75722062726f777365722073656e7420612072657175657374207468617420746869732073657276657220636f756c64206e6f7420756e6465727374616e642e3c6272202f3e0a3c2f703e0a3c2f626f64793e3c2f68746d6c3e0a';

        $this->assertEquals($expect, bin2hex($result));
    }
}
