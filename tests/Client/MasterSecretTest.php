<?php

namespace PHPTLS\Tests\Client;

use PHPTLS\Tls\Client\MasterSecret;
use PHPUnit\Framework\TestCase;

class MasterSecretTest extends TestCase
{

    public function test_createMasterSecret()
    {
        // AES-GCM のmaster secret。他の暗号を利用すると値が変わるため注意
        $expect = '3a9445f8902993b0deab6cf05953ec5bb75123444c216c475fdf766a9818f371b76b71cfa373330233d8734c19bc6a62';

        $MasterSecret = new MasterSecret('masterSecret', 'clientRandom', 'serverRandom');
        $result = $MasterSecret->getMasterSecret();
        $this->assertEquals($expect, bin2hex($result));
    }
    public function test_createMasterSecretKeyBlock()
    {
        // AES-GCM のmaster secretを前提にしたテスト。他の暗号を利用すると値が変わるため注意

        $MasterSecret = new MasterSecret('masterSecret', 'clientRandom', 'serverRandom');

        $expect = '5baea9524285067379f93760a35d4517';
        $result = $MasterSecret->getClientKey();
        $this->assertEquals($expect, bin2hex($result));

        $expect = '47a19d53';
        $result = $MasterSecret->getClientIV();
        $this->assertEquals($expect, bin2hex($result));

        $expect = 'b50a5c479b1e896774548cccf823dd33';
        $result = $MasterSecret->getServerKey();
        $this->assertEquals($expect, bin2hex($result));

        $expect = 'c181c9c1';
        $result = $MasterSecret->getServerIV();
        $this->assertEquals($expect, bin2hex($result));
    }
}
