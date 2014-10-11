Zend Framework OpenId Patch
===========================

Zend Framework (v1.x系) Open ID ライブラリーの Google ＆ Mixi 対応

> ※作った当時はZF1の時代でした。

 経緯
-----
よく知られていることですが、Zend FrameworkのOpenIdクラス群はGoogleやMixiなどのXRI/Yadis環境のOpenId認証には対応できません。

普通は、[Open ID Library](http://www.janrain.com/openid-enabled)を使うようなのですが、これがどうも分かりずらい。

ワーニングがでまくるしうまく動作しません。みんな一発で動いているなんてすごいですね。  
それで、中のコードを読んで対応しようとするのですが、どーもコードが汚い。

いい加減いやになり、Zend FrameworkのほうをGoogleに対応させる事にしました。

最初は[Akeem Philbertさんのページ](http://ak33m.com/?p=71)のパッチを当てて動いて感動したのですが、どうもGoogleだけでは物足りなくてもうひとつ動かない代表格のMixiにも対応させて見ました。

その結果Akeem Philbertさんのコードが跡形もなくなってしまったのですが、一応改変版です。


実装内容
-------
対応方法は・・・

- Yadisもどき
 - x-xrds-locationヘッダーに反応します。
 - metaタグのx-xrds-locationに反応します。 

- XRIもどき
 - content-type: application/xrds+xmlに反応してXRDSを認識します
 - x-xrds-locationされたらXRDSを取りに行きます。

- OpenID 2.0のauth request対応
 - identifier_selectに対応します。

- Mixiパッチ
 - OpenID 2.0でも、HMAC-SHA1を許しました。

- AX対応
 - Googleに加えて、Yahoo.co.jp、Yahoo.com、Mixi.jpにも対応しました。

・・・といったところです。


動作確認済みサービス
-----------------
一応、見た目上は動いているサーバーは以下のとおり。

- https://www.google.com/accounts/o8/id
- https://me.yahoo.co.jp
- https://me.yahoo.com/
- http://www.yahoo.co.jp
- http://mixi.jp

そしてOpenID 1.xへ悪影響はないかと調べたかったのですが、はてなサーバで試したところ動いているようです。

- http://www.hatena.ne.jp/ユーザーID

使い方
-----
phpのパスの通ったところに展開してください。  
使い方は、サンプルコードもつけてあるので、Zend Frameworkが分かる人ならすぐ分かります。  
これらは、Zend Frameworkのマニュアルに載っているサンプルを動かすものです。  

- openid_form.php
- openid_request_handler.php
- openid_verify_response.php

これはAXで属性を取ってくるサンプルを動かすものです。

- test_consumer_ax.php

良かったら使ってみてください。

Copyright and License
----------------------
See [LICENSE](LICENSE)
