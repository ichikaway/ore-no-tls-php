# Ore no TLS PHP

TLS1.2を学習するためにPHPでTLSクライアントを実装する。  
ClientHelloを送信して、暗号化されたコンテンツを複合し、HTMLを表示するまでがゴール。  

## 参考文献

- [golangで作るTLS1.2プロトコル](https://zenn.dev/satoken/articles/golang-tls1_2)
  - これを読めばTLS1.2のクライアントツールは実装できる非常にありがたい資料
- [RFC5246 TLS1.2](https://tex2e.github.io/rfc-translater/html/rfc5246.html)
- [TLS1.2 Handshake Video](https://www.youtube.com/watch?v=ZkL10eoG1PY)
  - マスターシークレットの鍵がどう使われるのかまで解説しているYoutubeビデオ
- [SSL/TLS session negotiation](https://www.infraexpert.com/study/security28.html)
  - ハンドシェイクの流れがざっと分かる
- https://tls12.xargs.org/
  - TLS1.2のデータの流れがバイト単位で書いてある。めっちゃ使える。
- https://wiki.osdev.org/TLS_Handshake