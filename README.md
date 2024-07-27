# Ore no TLS PHP

TLS1.2を学習するためにPHPでTLSクライアントを実装する。  
ClientHelloを送信して、暗号化されたコンテンツを複合し、HTMLを表示するまでがゴール。  

## 暗号化/ハッシュで利用したPHP関数

- hash_hmac()
  - TLS1.2のpHash関数の実装で利用
  - メモ: TLS1.3の場合は独自でpHashが不要でhash_hkdf()というPHP関数が利用できる
- openssl_random_pseudo_bytes()
  - Client key exchangeの secret random の値生成
- openssl_x509_read()
  - 証明書のデータを解析
- openssl_pkey_get_public()
  - 証明書からRSAの公開鍵を抽出
- openssl_public_encrypt()
  - RSA公開鍵を使って暗号化
- openssl_get_cipher_methods()
  - 暗号化で使えるアルゴリズム一覧を取得。利用する暗号化方式がこの一覧にあるかチェックするため。
- openssl_cipher_iv_length()
  - 暗号化方式によってIVの長さが異なるため、利用する暗号用のIVの長さを取得
- openssl_encrypt()
  - 共通鍵を使った暗号化。今回はAEAD方式のGCM。
- openssl_decrypt()
  - 共通鍵を使った復号。今回はAEAD方式のGCM。

## 参考文献

- [golangで作るTLS1.2プロトコル](https://zenn.dev/satoken/articles/golang-tls1_2)
  - これを読めばTLS1.2のクライアントツールは実装できる非常にありがたい資料
- [RFC5246 TLS1.2](https://tex2e.github.io/rfc-translater/html/rfc5246.html)
  - TLS1.2のRFC。必読
- [RFC 5116 - An Interface and Algorithms for Authenticated Encryption](https://tex2e.github.io/rfc-translater/html/rfc5116.html)
  - nonceの作り方などが書いてある
- [Plan 9におけるTLSの実装](https://blog.lufia.org/entry/2021/02/10/113000)
  - この記事を読んで、AES-GCMの実装がうまくいった。
- [RFC 5288 - AES Galois Counter Mode (GCM) Cipher Suites for TLS](https://tex2e.github.io/rfc-translater/html/rfc5288.html)
  - あまり役に立ってない
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tex2e.github.io/rfc-translater/html/rfc5869.html)
  - あまり役に立ってない
- [TLS1.2 Handshake Video](https://www.youtube.com/watch?v=ZkL10eoG1PY)
  - マスターシークレットの鍵がどう使われるのかまで解説しているYoutubeビデオ
- [SSL/TLS session negotiation](https://www.infraexpert.com/study/security28.html)
  - ハンドシェイクの流れがざっと分かる
- [The Illustrated TLS 1.2 Connection](https://tls12.xargs.org/)
  - TLS1.2のデータの流れがバイト単位で書いてある。めっちゃ使える。
- [TLS 1.3 開発日記 その17 AEAD](https://kazu-yamamoto.hatenablog.jp/entry/20170426/1493186127)
  - TLS1.2のAEADのAADについて書いてある
- https://wiki.osdev.org/TLS_Handshake
- [TLS Alert Protocol](https://www.gnutls.org/manual/html_node/The-TLS-Alert-Protocol.html)
- [TLS nonce　クラウドフレアの記事](https://blog.cloudflare.com/tls-nonce-nse)
- Q&Aサイト
  - [What does the TLS 1.2 client finished message contain?](https://crypto.stackexchange.com/questions/34754/what-does-the-tls-1-2-client-finished-message-contain)
  - [decrypt TLS 1.2 AES-GCM packet](https://stackoverflow.com/questions/28198379/decrypt-tls-1-2-aes-gcm-packet)
  - 