<?php
/**
 * Created by PhpStorm.
 * Project: WxPayAPI
 * Author: houseme houseme@outlook.com
 * Time: 2017/3/29 09:36
 * FileName: WxPay.php
 * Chinese:
 */

namespace WeChatPay;
class WxPay
{
    /**
     *
     * 网页授权接口微信服务器返回的数据，返回样例如下
     * {
     *  "access_token":"ACCESS_TOKEN",
     *  "expires_in":7200,
     *  "refresh_token":"REFRESH_TOKEN",
     *  "openid":"OPENID",
     *  "scope":"SCOPE",
     *  "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL"
     * }
     * 其中access_token可用于获取共享收货地址
     * openid是微信支付jsapi支付接口必须的参数
     *
     * @var array
     */
    public $data = null;
    private $curl_timeout = 0;
    private static $wxPayConfig = null;

    /**
     * WxPayConfig constructor.
     *
     * @param $appId
     * @param $mchId
     * @param $key
     * @param $appSecret
     * @param $sslCertPath
     * @param $sslKeyPath
     */
    public function __construct($appId, $mchId, $key, $appSecret, $sslCertPath, $sslKeyPath)
    {
        if (self::$wxPayConfig === null) {
            self::$wxPayConfig = new WxPayConfig($appId, $mchId, $key, $appSecret, $sslCertPath, $sslKeyPath);
        }
    }

    /**
     * @return WxPayConfig
     */
    public static function getWxPayConfig()
    {
        return self::$wxPayConfig;
    }

    /**
     * @param WxPayConfig $wxPayConfig
     */
    public static function setWxPayConfig($wxPayConfig)
    {
        self::$wxPayConfig = $wxPayConfig;
    }


    /**
     *
     * 通过跳转获取用户的openid，跳转流程如下：
     * 1、设置自己需要调回的url及其其他参数，跳转到微信服务器https://open.weixin.qq.com/connect/oauth2/authorize
     * 2、微信服务处理完成之后会跳转回用户redirect_uri地址，此时会带上一些参数，如：code
     *
     * @return string $openid
     */
    public function GetOpenid()
    {
        //通过code获得openid
        if (!isset($_GET['code'])) {
            //触发微信返回code码
            //$baseUrl = urlencode('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . $_SERVER['QUERY_STRING']);
            $http_type = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')) ? 'https://' : 'http://';
            $baseUrl = urlencode($http_type . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . $_SERVER['QUERY_STRING']);
            $url = $this->createOauthUrlForCode($baseUrl);
            Header("Location: $url");
            exit();
        } else {
            //获取code码，以获取openid
            $code = $_GET['code'];
            return $this->getOpenidFromMp($code);
        }
    }

    /**
     *
     * 获取jsapi支付的参数
     * json数据，可直接填入js函数作为参数
     *
     * @param array $UnifiedOrderResult 统一支付接口返回的数据
     *
     * @return false|string
     * @throws WxPayException
     */
    public function getJsApiParameters($UnifiedOrderResult)
    {
        if (!array_key_exists('appid', $UnifiedOrderResult) || !array_key_exists('prepay_id', $UnifiedOrderResult) || $UnifiedOrderResult['prepay_id'] == '') {
            throw new WxPayException('参数错误');
        }
        $jsapi = new WxPayJsApiPay();
        $jsapi->setAppId($UnifiedOrderResult['appid']);
        $jsapi->setTimeStamp('$timeStamp');
        $jsapi->setNonceStr(WxPayApi::getNonceStr());
        $jsapi->setPackage('prepay_id=' . $UnifiedOrderResult['prepay_id']);
        $jsapi->setSignType('MD5');
        $jsapi->setPaySign($jsapi->makeSign());
        return json_encode($jsapi->getValues());
    }

    /**
     *
     * 通过code从工作平台获取openid机器access_token
     *
     * @param string $code 微信跳转回来带上的code
     *
     * @return string
     */
    public function getOpenidFromMp($code)
    {
        $url = $this->createOauthUrlForOpenid($code);
        //初始化curl
        $ch = curl_init();
        //设置超时
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->curl_timeout);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (WxPayConfig::getCurlProxyHost() !== '0.0.0.0' && WxPayConfig::getCurlProxyPort() !== 0) {
            curl_setopt($ch, CURLOPT_PROXY, WxPayConfig::getCurlProxyHost());
            curl_setopt($ch, CURLOPT_PROXYPORT, WxPayConfig::getCurlProxyPort());
        }
        //运行curl，结果以jason形式返回
        $res = curl_exec($ch);
        curl_close($ch);
        //取出openid
        $data = json_decode($res, true);
        $this->data = $data;
        return $data['openid'];
    }

    /**
     *
     * 拼接签名字符串
     *
     * @param array $urlObj
     * 返回已经拼接好的字符串
     *
     * @return string
     */
    private function toUrlParams($urlObj)
    {
        $buff = '';
        foreach ($urlObj as $k => $v) {
            if ($k !== 'sign') {
                $buff .= $k . '=' . $v . '&';
            }
        }

        $buff = trim($buff, '&');

        return $buff;
    }

    /**
     *
     * 获取地址js参数
     * 获取共享收货地址js函数需要的参数，json格式可以直接做参数使用
     *
     * @return string
     */
    public function getEditAddressParameters()
    {
        $http_type = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')) ? 'https://' : 'http://';
        $getData = $this->data;
        $data = [];
        $data['appid'] = WxPayConfig::getAppId();
        $data['url'] = $http_type . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $data['timestamp'] = time();
        $data['noncestr'] = '1234568';
        $data['accesstoken'] = $getData['access_token'];
        ksort($data);
        $params = $this->toUrlParams($data);
        $addrSign = sha1($params);

        $afterData = [
            'addrSign'  => $addrSign,
            'signType'  => 'sha1',
            'scope'     => 'jsapi_address',
            'appId'     => WxPayConfig::getAppId(),
            'timeStamp' => $data['timestamp'],
            'nonceStr'  => $data['noncestr'],
        ];
        return json_encode($afterData);
    }

    /**
     *
     * 构造获取code的url连接
     *
     * @param string $redirectUrl 微信服务器回跳的url，需要url编码
     *                            返回构造好的url
     *
     * @return
     */
    private function createOauthUrlForCode($redirectUrl)
    {
        $urlObj['appid'] = WxPayConfig::getAppId();
        $urlObj['redirect_uri'] = '$redirectUrl';
        $urlObj['response_type'] = 'code';
        $urlObj['scope'] = 'snsapi_base';
        $urlObj['state'] = 'STATE' . '#wechat_redirect';
        $bizString = $this->toUrlParams($urlObj);

        return 'https://open.weixin.qq.com/connect/oauth2/authorize?' . $bizString;
    }

    /**
     *
     * 构造获取open和access_toke的url地址 返回请求的url
     *
     * @param string $code ，微信跳转带回的code
     *
     * @return string
     */
    private function createOauthUrlForOpenid($code)
    {
        $urlObj['appid'] = WxPayConfig::getAppId();
        $urlObj['secret'] = WxPayConfig::getAppSecret();
        $urlObj['code'] = $code;
        $urlObj['grant_type'] = 'authorization_code';
        $bizString = $this->toUrlParams($urlObj);

        return 'https://api.weixin.qq.com/sns/oauth2/access_token?' . $bizString;
    }

    /**
     *
     * 提交刷卡支付，并且确认结果，接口比较慢
     *
     * @param WxPayMicroPay $microPayInput
     * 返回查询接口的结果
     *
     * @return bool|int
     * @throws WxpayException
     */
    public function pay($microPayInput)
    {
        //①、提交被扫支付
        $result = WxPayApi::micropay($microPayInput, 5);
        //如果返回成功
        if (!array_key_exists('return_code', $result) || !array_key_exists('out_trade_no', $result) || !array_key_exists('result_code', $result)) {
            echo '接口调用失败,请确认是否输入是否有误！';
            throw new WxPayException('接口调用失败！');
        }
        //签名验证
        $out_trade_no = $microPayInput->getOutTradeNo();
        //②、接口调用成功，明确返回调用失败
        if ($result['return_code'] == 'SUCCESS' && $result['result_code'] == 'FAIL' && $result['err_code'] != 'USERPAYING' && $result['err_code'] != 'SYSTEMERROR') {
            return false;
        }

        //③、确认支付是否成功
        $queryTimes = 10;
        while ($queryTimes > 0) {
            $successResult = 0;
            $queryResult = $this->query($out_trade_no, $successResult);
            //如果需要等待1s后继续
            if ($successResult === 2) {
                sleep(2);
                continue;
            } elseif ($successResult === 1) {//查询成功
                return $queryResult;
            } else {//订单交易失败
                return false;
            }
        }

        //④、次确认失败，则撤销订单
        if (!$this->cancel($out_trade_no)) {
            throw new WxpayException('撤销单失败！');
        }

        return false;
    }

    /**
     *
     * 查询订单情况
     * 成功时返回，其他抛异常 0 订单不成功，1表示订单成功，2表示继续等待
     *
     * @param string $out_trade_no 商户订单号
     * @param int    $succCode     查询订单结果
     *
     * @return bool| int
     * @throws WxPayException
     */
    public function query($out_trade_no, &$succCode)
    {
        $queryOrderInput = new WxPayOrderQuery();
        $queryOrderInput->setOutTradeNo($out_trade_no);
        $result = WxPayApi::orderQuery($queryOrderInput);

        if ($result['return_code'] == 'SUCCESS' && $result['result_code'] == 'SUCCESS') {
            //支付成功
            if ($result['trade_state'] == 'SUCCESS') {
                $succCode = 1;

                return $result;
            }//用户支付中
            else if ($result['trade_state'] == 'USERPAYING') {
                $succCode = 2;

                return false;
            }
        }

        //如果返回错误码为“此交易订单号不存在”则直接认定失败
        if ($result['err_code'] == 'ORDERNOTEXIST') {
            $succCode = 0;
        } else {
            //如果是系统错误，则后续继续
            $succCode = 2;
        }

        return false;
    }

    /**
     *
     * 撤销订单，如果失败会重复调用10次
     *
     * @param string $out_trade_no
     * @param int    $depth
     *
     * @return bool
     * @throws WxPayException
     */
    public function cancel($out_trade_no, $depth = 0)
    {
        if ($depth > 10) {
            return false;
        }

        $closeOrder = new WxPayReverse();
        $closeOrder->setOutTradeNo($out_trade_no);
        $result = WxPayApi::reverse($closeOrder);

        //接口调用失败
        if ($result['return_code'] != 'SUCCESS') {
            return false;
        }

        //如果结果为success且不需要重新调用撤销，则表示撤销成功
        if ($result['result_code'] != 'SUCCESS' && $result['recall'] == 'N') {
            return true;
        } else if ($result['recall'] == 'Y') {
            return $this->cancel($out_trade_no, ++$depth);
        }

        return false;
    }

    /**
     *
     * 生成扫描支付URL,模式一
     *
     * @param $productId
     *
     * @return string
     * @throws WxPayException
     */
    public function getPrePayUrl($productId)
    {
        $biz = new WxPayBizPayUrl();
        $biz->setProductId($productId);
        $values = WxpayApi::bizPayUrl($biz);
        return 'weixin://wxpay/bizpayurl?' . $this->toUrlParams($values);
    }

    /**
     *
     * 生成直接支付url，支付url有效期为2小时,模式二
     * 成功时返回，其他抛异常
     *
     * @param WxPayUnifiedOrder $input
     *
     * @return array
     * @throws WxPayException
     */
    public function getPayUrl($input)
    {
        if ($input->getTradeType() == 'NATIVE') {
            return WxPayApi::unifiedOrder($input);
        }
    }
}