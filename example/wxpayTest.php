<?php

namespace houseme\wxpaytest;
/**
 * Created by PhpStorm.
 * Project: WxPayAPI
 * Author: houseme houseme@outlook.com
 * Time: 2017/3/30 08:56
 * FileName: wxpayTest.php
 * Chinese:
 */
//use houseme\wxpay\WxPayConfig as WxPayConfig;

use Wechat\WxPay;

//use houseme\wxpay\WxPayConfig;

//include "../src/WxPayConfig.class.php";
//include "../src/WxPay.php";
include_once "../autoload.php";
$appId       = '1';
$mchId       = '2';
$key         = '3';
$appSecret   = '4';
$sslCertPath = '111/32.txt';
$sslKeyPath  = '123';
//$wxPayConfig = new WxPayConfig($appId, $mchId, $key, $appSecret, $sslCertPath, $sslKeyPath);
$wxPay       = new WxPay($appId, $mchId, $key, $appSecret, $sslCertPath, $sslKeyPath);
$wxPayConfig = WxPay::getWxPayConfig();
var_dump($wxPayConfig::getAppId());

$wxPayConfig::setAppId(123);
//
var_dump($wxPayConfig::getAppId());
//
//var_dump($wxPayConfig::getCurlProxyHost());
//
////var_dump($_SERVER);
//var_dump($wxPayConfig::setCurlProxyHost('116.255.212.73'));

//var_dump($wxPayConfig::getCurlProxyHost());

//$wxPay = new wxpay($appId, $mchId, $key, $appSecret, $sslCertPath, $sslKeyPath);