<?php

namespace PHPTLS\Tls;

class Crypt
{
    public static function encryptAesGcm(string $plaintext, string $key, string $iv, string $add)
    {
        $cipher = "aes-128-gcm";
        if (in_array($cipher, openssl_get_cipher_methods())) {
            $ivLen = openssl_cipher_iv_length($cipher);
            if (strlen($iv) < $ivLen) {
                //var_dump(bin2hex($iv));

                /**
                 * AES-GCMの場合はIVはマスターシークレットの4バイトと、ランダムなiv Explicit(nonce) 8byteの連結文字
                 * RFC5288
                 * struct {
                 *   opaque salt[4];
                 *   opaque nonce_explicit[8];
                 * } GCMNonce;
                 */
                /**
                 * RFC5116 3.2章にnonceは固定値とカウンター値の例があるため、
                 * 完全にランダムな値にするよりは、カウンターに使える値にしておく。まずは0で埋める。
                 */
                //$ivExplicit = openssl_random_pseudo_bytes($ivLen - strlen($iv));
                $ivExplicit = str_repeat("\x00", $ivLen - strlen($iv));
                $iv = $iv . $ivExplicit;
                //var_dump(bin2hex($iv));
            }
            //$ivAdd = '0000000000000000';
            //$iv = $iv . hex2bin($ivAdd);

            //var_dump(bin2hex($key));
            //var_dump(bin2hex($iv));

            $ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, $add);
            //$ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv, $tag, $add);
            //$ciphertext = openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv);
            //var_dump("-------chpertext-------");
            //var_dump(bin2hex($ciphertext));
            //var_dump($tag);
            return [$ciphertext, $ivExplicit ,$tag];
        }
    }
}
