<?php

namespace PHPTLS\Tls\Client;

use PHPTLS\Tls\Util;

class ServerCertificate
{
    private readonly string $data; //hex
    public function __construct(string $data)
    {
        $this->data = $data;
    }

    /**
     * Certificatesの中にある最初の証明書をhexで返す
     * 最初の証明書が該当サーバの証明書、中間証明書はその後に続く
     * @return string
     */
    public function getPrimaryCert(): string
    {
        //12バイト目からの３バイトで最初の証明書のLengthがわかる
        $offset = 12;
        $byte = 3;
        $length = hexdec(Util::getHexDataWithLen($this->data, $offset, $byte));
        $certOffset = $offset + $byte;

        return Util::getHexDataWithLen($this->data, $certOffset, $length);
    }

    /**
     * 証明書のバイナリデータをPEM形式にしてOpensslのクラスに読み込み、
     * 処理できる形にする
     *
     * @return \OpenSSLCertificate
     * @throws \Exception
     */
    public function getCertData(): \OpenSSLCertificate
    {
        $data = $this->getPrimaryCert();
        $x509 = openssl_x509_read(Util::hexToPem($data));
        if ($x509 === false) {
            throw new \Exception('Unable to read X509 data');
        }
        return $x509;
    }

    /**
     * 証明書から公開鍵のデータを取得する
     *
     * @return \OpenSSLAsymmetricKey
     * @throws \Exception
     */
    public function getServerPubKeyFromCert(): \OpenSSLAsymmetricKey
    {
        $x509 = $this->getCertData();
        $key = openssl_pkey_get_public($x509);
        if ($key === false) {
            throw new \Exception('Unable to read X509 public key data');
        }
        return $key;
    }

    /**
     * バイナリデータを渡すと、サーバから取得済みの公開鍵で暗号化し、その結果をバイナリで返す
     * 引数にhexデータを渡すと例外を出す
     *
     * @param string $data binary
     * @return string
     * @throws \Exception
     */
    public function encryptWithPubKey(string $data): string
    {
        $encrypted_data = '';
        $openSSLAsymmetricKey = $this->getServerPubKeyFromCert();

        if (ctype_xdigit($data)) {
            throw new \Exception('forbid hex data.');
        }

        $result =  openssl_public_encrypt(
            $data,
            $encrypted_data,
            $openSSLAsymmetricKey
            //OPENSSL_SSLV23_PADDING
        );
        if ($result === false) {
            throw new \Exception('Unable to encrypt data with Public Key');
        }
        return $encrypted_data;
    }
}