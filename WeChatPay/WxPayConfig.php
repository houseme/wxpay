<?php
/**
 * Created by PhpStorm.
 * Project: WxPayAPI
 * Author: houseme houseme@outlook.com
 * Time: 2017/3/29 17:34
 * FileName: WxPayConfig.class.php
 * Chinese:
 */


namespace WeChatPay;

/**
 * 	配置账号信息
 */
class WxPayConfig{
    //=======【基本信息设置】=====================================
    //
    /**
     * TODO: 修改这里配置为您自己申请的商户信息
     * 微信公众号信息配置
     *
     * APPID：绑定支付的APPID（必须配置，开户邮件中可查看）
     *
     * MCHID：商户号（必须配置，开户邮件中可查看）
     *
     * KEY：商户支付密钥，参考开户邮件设置（必须配置，登录商户平台自行设置）
     * 设置地址：https://pay.weixin.qq.com/index.php/account/api_cert
     *
     * APPSECRET：公众帐号secert（仅JSAPI支付的时候需要配置， 登录公众平台，进入开发者中心可设置），
     * 获取地址：https://mp.weixin.qq.com/advanced/advanced?action=dev&t=advanced/dev&token=2005451881&lang=zh_CN
     * @var string
     */
//    const APPID = 'wx426b3015555a46be';
//    const MCHID = '1900009851';
//    const KEY = '8934e7d15453e97507ef794cf7b0519d';
//    const APPSECRET = '7813490da6f1265e4901ffb80afaa36f';
    
    //=======【证书路径设置】=====================================
    /**
     * TODO：设置商户证书路径
     * 证书路径,注意应该填写绝对路径（仅退款、撤销订单时需要，可登录商户平台下载，
     * API证书下载地址：https://pay.weixin.qq.com/index.php/account/api_cert，下载之前需要安装商户操作证书）
     * @var path
     */
//    const SSLCERT_PATH = '../cert/apiclient_cert.pem';
//    const SSLKEY_PATH = '../cert/apiclient_key.pem';
    
    //=======【curl代理设置】===================================
    /**
     * TODO：这里设置代理机器，只有需要代理的时候才设置，不需要代理，请设置为0.0.0.0和0
     * 本例程通过curl使用HTTP POST方法，此处可修改代理服务器，
     * 默认CURL_PROXY_HOST=0.0.0.0和CURL_PROXY_PORT=0，此时不开启代理（如有需要才设置）
     * @var unknown_type
     */
//    const CURL_PROXY_HOST = "0.0.0.0";//"10.152.18.220";
//    const CURL_PROXY_PORT = 0;//8080;
    
    //=======【上报信息配置】===================================
    /**
     * TODO：接口调用上报等级，默认紧错误上报（注意：上报超时间为【1s】，上报无论成败【永不抛出异常】，
     * 不会影响接口调用流程），开启上报之后，方便微信监控请求调用的质量，建议至少
     * 开启错误上报。
     * 上报等级，0.关闭上报; 1.仅错误出错上报; 2.全量上报
     * @var int
     */
//    const REPORT_LEVENL = 1;
    
    private static $appId;
    private static $mchId;
    private static $key;
    private static $appSecret;
    
    private static $sslCertPath;
    private static $sslKeyPath;
    
    private static $curlProxyHost = '0.0.0.0';
    private static $curlProxyPort = 0;
    
    private static $reportLevel = 1;
    
    private static $notifyUrl= '';

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
    public function __construct($appId,$mchId,$key,$appSecret,$sslCertPath,$sslKeyPath){
        self::setAppId($appId);
        self::setMchId($mchId);
        self::setAppSecret($appSecret);
        self::setSslCertPath($sslCertPath);
        self::setSslKeyPath($sslKeyPath);
    }
    
    
    /**
     * @return mixed
     */
    public static function getAppId(){
        return self::$appId;
    }
    
    /**
     * @param mixed $appId
     */
    public static function setAppId($appId){
        self::$appId = $appId;
    }
    
    /**
     * @return mixed
     */
    public static function getMchId(){
        return self::$mchId;
    }
    
    /**
     * @param mixed $mchId
     */
    public static function setMchId($mchId){
        self::$mchId = $mchId;
    }
    
    /**
     * @return mixed
     */
    public static function getKey(){
        return self::$key;
    }
    
    /**
     * @param mixed $key
     */
    public static function setKey($key){
        self::$key = $key;
    }
    
    /**
     * @return mixed
     */
    public static function getAppSecret(){
        return self::$appSecret;
    }
    
    /**
     * @param mixed $appSecret
     */
    public static function setAppSecret($appSecret){
        self::$appSecret = $appSecret;
    }
    
    /**
     * @return mixed
     */
    public static function getSslCertPath(){
        return self::$sslCertPath;
    }
    
    /**
     * @param mixed $sslCertPath
     */
    public static function setSslCertPath($sslCertPath){
        self::$sslCertPath = $sslCertPath;
    }
    
    /**
     * @return mixed
     */
    public static function getSslKeyPath(){
        return self::$sslKeyPath;
    }
    
    /**
     * @param mixed $sslKeyPath
     */
    public static function setSslKeyPath($sslKeyPath){
        self::$sslKeyPath = $sslKeyPath;
    }
    
    /**
     * @return string
     */
    public static function getCurlProxyHost(){
        return self::$curlProxyHost;
    }
    
    /**
     * @param string $curlProxyHost
     */
    public static function setCurlProxyHost($curlProxyHost){
        self::$curlProxyHost = $curlProxyHost;
    }
    
    /**
     * @return int
     */
    public static function getCurlProxyPort(){
        return self::$curlProxyPort;
    }
    
    /**
     * @param int $curlProxyPort
     */
    public static function setCurlProxyPort($curlProxyPort){
        self::$curlProxyPort = $curlProxyPort;
    }
    
    /**
     * @return int
     */
    public static function getReportLevel(){
        return self::$reportLevel;
    }
    
    /**
     * @param int $reportLevel
     */
    public static function setReportLevel($reportLevel){
        self::$reportLevel = $reportLevel;
    }
    
    /**
     * @return mixed
     */
    public static function getNotifyUrl(){
        return self::$notifyUrl;
    }
    
    /**
     * @param mixed $notifyUrl
     */
    public static function setNotifyUrl($notifyUrl){
        self::$notifyUrl = $notifyUrl;
    }
    
}