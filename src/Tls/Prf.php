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
        // RFC5246 8.1. Computing the Master Secret 参照
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
        // RFC5246 8.1. 6.3. Key Calculation 参照
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
    public static function createKeyBlockForCBC(string $secret, string $clientRandom, string $serverRandom): array
    {
        if (ctype_xdigit($clientRandom) || ctype_xdigit($serverRandom) || ctype_xdigit($secret)) {
            throw new \Exception('Forbid hex data in createHash()');
        }
        // RFC5246 8.1. 6.3. Key Calculation 参照
        $seed = 'key expansion' . $serverRandom. $clientRandom; //key expansionはserver random, client randomの順に繋げる
        $len = 104; //key blockは48byte固定
        $hashed = self::pHash($len, $secret, $seed);
        return [
            "ClientMac" => substr($hashed, 0, 20),
            "ServerMac" => substr($hashed, 20, 20),
            "ClientWriteKey" => substr($hashed, 40, 16),
            "ServerWriteKey" => substr($hashed, 56, 16),
            "ClientWriteIV"  => substr($hashed, 72, 16),
            "ServerWriteIV"  => substr($hashed, 88, 16),
        ];
    }

    /**
     * HMAC作成
     *
     * seed = "master secret" + client_random + server_random
     * a0 = seed
     * a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
     * a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
     * p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 + seed)
     * p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 + seed)
     * MasterSecret = p1[all 32 bytes] + p2[first 16 bytes]
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
        //hash_hkdfはhmac 256とは異なる値を出力するため利用しない
        //$hashed = hash_hkdf('sha256', $secret, $len, 'sha256', $seed);

        // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ..
        $a = hash_hmac('sha256', $seed, $secret, true);
        $result = '';
        while (strlen($result) < $len) {
            $hashed = hash_hmac('sha256', $a . $seed, $secret, true);
            if ($hashed === false) {
                throw new \Exception('can not create hmac.');
            }
            $result .= $hashed;
            //次のハッシュに利用する$aは、seedを入れないハッシュ値
            $a = hash_hmac('sha256', $a, $secret, true);
        }
        $hashed = substr($result, 0, $len);
        return $hashed;
    }
}
