<?php
/**
 * Created by PhpStorm.
 * Project: WxPayAPI
 * Author: houseme houseme@outlook.com
 * Time: 2017/3/29 17:05
 * FileName: WxPayNotify.class.php
 * Chinese:
 */


namespace WeChatPay;


class WxPayNotify extends WxPayNotifyReply
{
    /**
     *
     * 回调入口
     *
     * @param bool $needSign 是否需要签名输出
     *
     * @throws WxPayException
     */
    final public function handle($needSign = true)
    {
        $msg = 'OK';
        //当返回false的时候，表示notify中调用NotifyCallBack回调失败获取签名校验失败，此时直接回复失败
        $result = WxpayApi::notify([$this, 'notifyCallBack'], $msg);
        if ($result == false) {
            $this->setReturnCode('FAIL');
            $this->setReturnMsg($msg);
            $this->replyNotify(false);
            return;
        } else {
            //该分支在成功回调到NotifyCallBack方法，处理完成之后流程
            $this->setReturnCode('SUCCESS');
            $this->setReturnMsg('OK');
        }
        $this->replyNotify($needSign);
    }

    /**
     *
     * 回调方法入口，子类可重写该方法
     * 注意：
     * 1、微信回调超时时间为2s，建议用户使用异步处理流程，确认成功之后立刻回复微信服务器
     * 2、微信服务器在调用失败或者接到回包为非确认包的时候，会发起重试，需确保你的回调是可以重入
     * true回调出来完成不需要继续回调，false回调处理未完成需要继续回调
     *
     * @param array  $data 回调解释出的参数
     * @param string $msg  如果回调处理失败，可以将错误信息输出到该方法
     *
     * @return bool
     */
    public function notifyProcess($data, &$msg)
    {
        //TODO 用户基础该类之后需要重写该方法，成功的时候返回true，失败返回false
        return true;
    }

    /**
     *
     * notify回调方法，该方法中需要赋值需要输出的参数,不可重写
     * true回调出来完成不需要继续回调，false回调处理未完成需要继续回调
     *
     * @param array $data
     *
     * @return bool
     */
    final public function notifyCallBack($data)
    {
        $msg = 'OK';
        $result = $this->notifyProcess($data, $msg);

        if ($result == true) {
            $this->setReturnCode('SUCCESS');
            $this->setReturnMsg('OK');
        } else {
            $this->setReturnCode('FAIL');
            $this->setReturnMsg($msg);
        }

        return $result;
    }

    /**
     *
     * 回复通知
     *
     * @param bool $needSign 是否需要签名输出
     *
     * @param bool $returnCode
     *
     * @throws WxPayException
     */
    private function replyNotify($needSign = true, $returnCode = false)
    {
        //如果需要签名
        if ($needSign == true && $this->getReturnCode($returnCode) == 'SUCCESS') {
            $this->SetSign();
        }
        WxpayApi::replyNotify($this->toXml());
    }
}