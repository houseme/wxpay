<?php
/**
 * Created by PhpStorm.
 * Project: WxPayAPI
 * Author: houseme houseme@outlook.com
 * Time: 2017/3/29 17:06
 * FileName: WxPayException.class.php
 * Chinese:
 */


namespace WeChatPay;

use Exception;

/**
 *
 * 微信支付API异常类
 *
 * @author widyhu
 *
 */
class WxPayException extends Exception {
    public function errorMessage()
    {
        return $this->getMessage();
    }
}