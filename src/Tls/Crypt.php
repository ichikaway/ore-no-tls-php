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
                ///$ivAdd = openssl_random_pseudo_bytes($ivLen - strlen($iv));
                //$ivImplicit = '0101010101010101';
                $ivImplicit = '0000000000000000';
                $ivAdd = hex2bin($ivImplicit);
                $iv = $iv . $ivAdd;
                //var_dump(bin2hex($iv));
            }
            //$ivAdd = '0000000000000000';
            //$iv = $iv . hex2bin($ivAdd);

            //var_dump(bin2hex($key));
            //var_dump(bin2hex($iv));

            //$ciphertext = openssl_encrypt($plaintext, $cipher, $key, 0, $iv, $tag, $add);
            //$ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, $add);
            $ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv, $tag, $add);
            //$ciphertext = openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv);
            //var_dump("-------chpertext-------");
            //var_dump(bin2hex($ciphertext));
            //var_dump($tag);
            return [$ciphertext, $ivAdd ,$tag];
            //return [$ciphertext, hex2bin($ivAdd), $tag];
        }
    }
}
