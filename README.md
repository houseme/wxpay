# WxPay


### Installation

Use [Composer](https://getcomposer.org/)

```json
"require": {
    "houseme/wxpay": "~1.0.0"
}
```

微信支付 PHP SDK
---

对[微信支付开发者文档](https://pay.weixin.qq.com/wiki/doc/api/index.html)中给出的API进行了封装。

`WXPay\WXPay`类下提供了对应的方法：

|方法名 | 说明 |
|--------|--------|
|microPay| 刷卡支付 |
|unifiedOrder | 统一下单|
|orderQuery | 查询订单 |
|reverse | 撤销订单 |
|closeOrder|关闭订单|
|refund|申请退款|
|refundQuery|查询退款|
|downloadBill|下载对账单|
|report|交易保障|
|shortUrl|转换短链接|
|authCodeToOpenid|授权码查询openid|

* 参数为关联数组，返回类型也是关联数组。
* 方法内部会将参数会转换成含有`appid、mch_id`、`nonce_str`、`sign_type`和`sign`的XML；
* 默认使用MD5进行签名；
* 通过HTTPS请求得到返回数据后会对其做必要的处理（例如验证签名，签名错误则抛出异常）。
* 对于downloadBill，无论是否成功都返回Map，且都含有`return_code`和`return_msg`。若成功，其中`return_code`为SUCCESS，`data`对应对账单数据。暂不支持下载压缩格式的对账单。

## 安装

```
$ composer require "houseme/wxpay:1.0.10" -vvv
```
php必须启用curl，并在php.ini中配置`curl.cainfo`的值`rootca.pem`的绝对路径。

## 示例

接口的使用方法是一致的，例如统一下单：

```php
require __DIR__.'/vendor/autoload.php';
use WXPay\WXPay;
use WXPay\WXPayConstants;
use WXPay\WXPayUtil;

$wxpay = new WXPay(
        'wx888888888',  // appid
        '22222222',     // mch id
        '123456781234567812345678',  // key
        '/path/to/apiclient_cert.pem',
        '/path/to/apiclient_key.pem',
        6000);  // 超时时间，毫秒
$resp = $wxpay->orderQuery(array(
                  'out_trade_no' => '201610265257070987061763',
                  'total_fee' => 1,
                  'body' => '腾讯充值中心-QQ会员充值',
                  'spbill_create_ip' => '123.12.12.123',
                  'trade_type' => 'NATIVE',
                  'notify_url' => 'https://www.example.com/wxpay/notify'
              ));
var_dump($resp);
```


### 关于签名
默认使用MD5签名。查询订单示例：
```php
require __DIR__.'/vendor/autoload.php';
use WXPay\WXPay;
use WXPay\WXPayConstants;
use WXPay\WXPayUtil;

$wxpay = new WXPay(
        'wx888888888',  // appid
        '22222222',     // mch id
        '123456781234567812345678',  // key
        '/path/to/apiclient_cert.pem',
        '/path/to/apiclient_key.pem',
        6000);  // 超时时间，毫秒
$resp = $wxpay->orderQuery(array('out_trade_no' => '201610265257070987061763'));
var_dump($resp);
```

使用HMAC-SHA256做签名查询订单：
```php
$wxpay = new WXPay(
        'wx888888888',  // appid
        '22222222',     // mch id
        '123456781234567812345678',  // key
        '/path/to/apiclient_cert.pem',
        '/path/to/apiclient_key.pem',
        6000,  // 超时时间，毫秒
        WXPayConstants::SIGN_TYPE_HMACSHA256);  
$resp = $wxpay->orderQuery(array('out_trade_no' => '201610265257070987061763'));
var_dump($resp);
```

### 沙箱环境
查询订单示例：
```php
$useSandbox = true;

$wxpay = new WXPay(
       'wx888888888',  // appid
       '22222222',     // mch id
       '123456781234567812345678',  // 沙箱环境key
       '/path/to/apiclient_cert.pem',
       '/path/to/apiclient_key.pem',
       6000,  // 超时时间，毫秒
       WXPayConstants::SIGN_TYPE_MD5,
       $useSandbox);

var_dump( $wxpay->orderQuery(array('out_trade_no' => '201610265257070987061763')) );
```

### 其他
若需要生成请求的XML数据，可以这样：
```php
$data = array(
    'bill_date' => '20140603',
    'bill_type' => 'ALL',
    'tar_type' => 'GZIP'
);
$wxpay = new WXPay(
        'wx888888888',  // appid
        '22222222',     // mch id
        '123456781234567812345678',  // key
        '/path/to/apiclient_cert.pem',
        '/path/to/apiclient_key.pem',
        6000);  // 超时时间，毫秒
$data = $wxpay->fillRequestData($data); // 会添加appid、mch_id、sign_type、sign、nonce_str
var_dump($data);
echo "\n";
echo \WXPay\WXPayUtil::array2xml($data);
```

收到支付结果通知时，需要验证签名，可以这样做：
```php
$wxpay = new WXPay(
    'wx888888888',  // appid
    '22222222',     // mch id
    "123456781234567812345678",  // key
    '/path/to/apiclient_cert.pem',
    '/path/to/apiclient_key.pem',
    6000);

$xml = "<xml> 
    ......
    <sign>9A0A8659F005D6984697E2CA0A9CF3B7</sign> 
    </xml>";
$data = WXPayUtil::xml2array($xml);
// $data必须有sign字段，也就是return_code必须为SUCCESS。否则返回false
var_dump($wxpay->isPayResultNotifySignatureValid($data));  // 布尔类型，标识签名是否正确
```
