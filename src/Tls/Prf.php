<?php
namespace PHPTLS\Tls;

final class Prf
{

    /**
     * マスターシークレットを作成
     *
     * @param  int    $len
     * @param  string $secret       bin
     * @param  string $clientRandom bin
     * @param  string $serverRandom bin
     * @return string bin
     * @throws \Exception
     */
    public static function createMasterSecret(int $len, string $secret, string $clientRandom, string $serverRandom): string
    {
        if (ctype_xdigit($clientRandom) || ctype_xdigit($serverRandom) || ctype_xdigit($secret)) {
            throw new \Exception('Forbid hex data in createHash()');
        }
        $seed = 'master secret' . $clientRandom . $serverRandom;
        return self::pHash($len, $secret, $seed);
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
