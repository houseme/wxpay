<?php
/**
 * Created by PhpStorm.
 * Project: WxPayAPI
 * Author: houseme houseme@outlook.com
 * Time: 2017/3/29 11:37
 * FileName: WxPayNotifyReply.class.php
 * Chinese:
 */


namespace houseme\wxpay;

/**
 *
 * 回调基础类
 * @author widyhu
 *
 */
class WxPayNotifyReply extends WxPayDataBase{
    /**
     *
     * 设置错误码 FAIL 或者 SUCCESS
     * @param string
     */
    public function SetReturn_code($return_code)
    {
        $this->values['return_code'] = $return_code;
    }
    
    /**
     *
     * 获取错误码 FAIL 或者 SUCCESS
     * @return string $return_code
     */
    public function GetReturn_code()
    {
        return $this->values['return_code'];
    }
    
    /**
     *
     * 设置错误信息
     * @param string $return_code
     */
    public function SetReturn_msg($return_msg)
    {
        $this->values['return_msg'] = $return_msg;
    }
    
    /**
     *
     * 获取错误信息
     * @return string
     */
    public function GetReturn_msg()
    {
        return $this->values['return_msg'];
    }
    
    /**
     *
     * 设置返回参数
     * @param string $key
     * @param string $value
     */
    public function SetData($key, $value)
    {
        $this->values[$key] = $value;
    }
}