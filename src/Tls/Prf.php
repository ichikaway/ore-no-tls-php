<?php
namespace PHPTLS\Tls;

final class Prf
{

    /**
     * マスターシークレットを作成
     *
     * @param  string $secret       bin
     * @param  string $clientRandom bin
     * @param  string $serverRandom bin
     * @return string bin
     * @throws \Exception
     */
    public static function createMasterSecret(string $secret, string $clientRandom, string $serverRandom): string
    {
        if (ctype_xdigit($clientRandom) || ctype_xdigit($serverRandom) || ctype_xdigit($secret)) {
            throw new \Exception('Forbid hex data in createHash()');
        }
        $seed = 'master secret' . $clientRandom . $serverRandom;
        $len = 48; //master secretを作る時は48byte固定
        return self::pHash($len, $secret, $seed);
    }

    /**
     * @param string $secret bin
     * @param string $clientRandom bin
     * @param string $serverRandom bin
     * @return array <string, string> bin
     * @throws \Exception
     */
    public static function createKeyBlock(string $secret, string $clientRandom, string $serverRandom): array
    {
        if (ctype_xdigit($clientRandom) || ctype_xdigit($serverRandom) || ctype_xdigit($secret)) {
            throw new \Exception('Forbid hex data in createHash()');
        }
        $seed = 'key expansion' . $serverRandom. $clientRandom; //key expansionはserver random, client randomの順に繋げる
        $len = 40; //key blockは40byte固定
        $hashed = self::pHash($len, $secret, $seed);
        return [
            "ClientWriteKey" => substr($hashed, 0, 16),
            "ServerWriteKey" => substr($hashed, 16, 16),
            "ClientWriteIV"  => substr($hashed, 32, 4),
            "ServerWriteIV"  => substr($hashed, 36, 4),
        ];
    }

    /**
     * HMAC作成
     *
     * @param  int    $len
     * @param  string $secret bin
     * @param  string $seed   bin
     * @return string bin
     * @throws \Exception
     */
    public static function pHash(int $len, string $secret, string $seed): string
    {
        if (ctype_xdigit($seed)  || ctype_xdigit($secret)) {
            throw new \Exception('Forbid hex data in createHash()');
        }
        $hashed = hash_hkdf('sha256', $secret, $len, 'sha56', $seed);
        if ($hashed === false) {
            throw new \Exception('can not create hmac.');
        }
        return $hashed;
    }
}
