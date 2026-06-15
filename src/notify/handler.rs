//! 通知处理器模块
//!
//! 提供处理微信支付回调通知的功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Verifier;
use crate::config::NotifyConfig;
use crate::crypto::Aes256GcmCipher;
use crate::error::{WxPayError, WxPayResult};

/// 通知请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyRequest {
    /// 通知 ID
    pub id: String,

    /// 通知创建时间
    pub create_time: String,

    /// 通知类型
    #[serde(rename = "type")]
    pub notify_type: String,

    /// 通知数据
    pub resource: NotifyResource,
}

/// 通知资源
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyResource {
    /// 加密算法
    pub algorithm: String,

    /// 密文
    pub ciphertext: String,

    /// 附加数据
    pub associated_data: Option<String>,

    /// 随机串
    pub nonce: String,
}

/// 支付通知数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentNotifyData {
    /// 应用 ID
    pub appid: String,

    /// 商户号
    pub mchid: String,

    /// 商户订单号
    pub out_trade_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 交易类型
    pub trade_type: String,

    /// 交易状态
    pub trade_state: String,

    /// 交易状态描述
    pub trade_state_desc: String,

    /// 付款银行
    pub bank_type: String,

    /// 附加数据
    pub attach: Option<String>,

    /// 支付完成时间
    pub success_time: String,

    /// 支付者
    pub payer: Option<NotifyPayer>,

    /// 订单金额
    pub amount: Option<NotifyAmount>,
}

/// 通知支付者
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyPayer {
    /// 用户标识
    pub openid: String,
}

/// 通知金额
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyAmount {
    /// 总金额
    pub total: u64,

    /// 用户支付金额
    pub payer_total: Option<u64>,

    /// 货币类型
    pub currency: String,

    /// 用户支付币种
    pub payer_currency: Option<String>,
}

/// 退款通知数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundNotifyData {
    /// 商户号
    pub mchid: String,

    /// 商户订单号
    pub out_trade_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户退款单号
    pub out_refund_no: String,

    /// 微信退款单号
    pub refund_id: String,

    /// 退款状态
    pub refund_status: String,

    /// 退款成功时间
    pub success_time: Option<String>,

    /// 退款金额
    pub amount: Option<RefundNotifyAmount>,
}

/// 退款通知金额
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundNotifyAmount {
    /// 退款金额
    pub total: u64,

    /// 退款金额
    pub refund: u64,

    /// 用户支付金额
    pub payer_total: u64,

    /// 用户退款金额
    pub payer_refund: u64,
}

/// 通知处理器
///
/// 用于处理微信支付回调通知。
///
/// # 示例
///
/// ```rust,no_run
/// use std::sync::Arc;
///
/// use wxpay_rs::{
///     auth::{Sha256RsaVerifier, Verifier},
///     config::NotifyConfig,
///     notify::NotifyHandler,
/// };
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = NotifyConfig {
///         api_v3_key: "abcdefghijklmnopqrstuvwxyz123456".to_string(),
///         cert_serial_number: "CERT123456".to_string(),
///         platform_certificate: vec![],
///     };
///     let verifier = Sha256RsaVerifier::new(vec![b"dummy certificate".to_vec()])?;
///     let verifier: Arc<dyn Verifier> = Arc::new(verifier);
///     let handler = NotifyHandler::new(config, verifier)?;
///
///     let _ = handler;
///     Ok(())
/// }
/// ```
pub struct NotifyHandler {
    /// 通知配置
    config: NotifyConfig,

    /// 验签器
    verifier: Arc<dyn Verifier>,

    /// AES 加密器
    cipher: Aes256GcmCipher,
}

impl NotifyHandler {
    /// 创建新的通知处理器
    pub fn new(config: NotifyConfig, verifier: Arc<dyn Verifier>) -> WxPayResult<Self> {
        let cipher = Aes256GcmCipher::new(&config.api_v3_key)?;
        Ok(Self {
            config,
            verifier,
            cipher,
        })
    }

    /// 处理支付通知
    pub async fn handle_payment_notify(
        &self,
        request: &NotifyRequest,
    ) -> WxPayResult<PaymentNotifyData> {
        // 验证通知类型
        if request.notify_type != "TRANSACTION.SUCCESS" {
            return Err(WxPayError::InvalidNotifyType(request.notify_type.clone()));
        }

        // 解密通知数据
        let data = self.decrypt_notify_data(request)?;

        // 解析支付数据
        let payment_data: PaymentNotifyData = serde_json::from_str(&data)?;

        Ok(payment_data)
    }

    /// 处理退款通知
    pub async fn handle_refund_notify(
        &self,
        request: &NotifyRequest,
    ) -> WxPayResult<RefundNotifyData> {
        // 验证通知类型
        if request.notify_type != "REFUND.SUCCESS" {
            return Err(WxPayError::InvalidNotifyType(request.notify_type.clone()));
        }

        // 解密通知数据
        let data = self.decrypt_notify_data(request)?;

        // 解析退款数据
        let refund_data: RefundNotifyData = serde_json::from_str(&data)?;

        Ok(refund_data)
    }

    /// 解密通知数据
    fn decrypt_notify_data(&self, request: &NotifyRequest) -> WxPayResult<String> {
        let resource = &request.resource;

        match resource.algorithm.as_str() {
            "AEAD_AES_256_GCM" => {
                let associated_data = resource.associated_data.as_deref().unwrap_or("");
                self.cipher.decrypt_notification(
                    &resource.nonce,
                    &resource.ciphertext,
                    associated_data,
                )
            }
            _ => Err(WxPayError::DecryptionError(format!(
                "不支持的加密算法: {}",
                resource.algorithm
            ))),
        }
    }

    /// 验证通知签名
    pub async fn verify_notify_signature(
        &self,
        timestamp: &str,
        nonce: &str,
        body: &str,
        signature: &str,
    ) -> WxPayResult<bool> {
        // 构建验签消息
        let message = format!("{}\n{}\n{}\n", timestamp, nonce, body);

        // 验证签名
        self.verifier.verify(&message, signature).await
    }

    /// 验证通知时间戳
    pub fn verify_timestamp(&self, timestamp: &str, tolerance_seconds: i64) -> WxPayResult<bool> {
        let timestamp: i64 = timestamp
            .parse()
            .map_err(|e| WxPayError::InvalidNotifyFormat(format!("无效的时间戳: {}", e)))?;

        Ok(crate::utils::timestamp::is_timestamp_valid(
            timestamp,
            tolerance_seconds,
        ))
    }
}

impl std::fmt::Debug for NotifyHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyHandler")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_request_deserialization() {
        let json = r#"{
            "id": "EV-2018022511223320873",
            "create_time": "2015-05-20T13:29:35+08:00",
            "type": "TRANSACTION.SUCCESS",
            "resource": {
                "algorithm": "AEAD_AES_256_GCM",
                "ciphertext": "...",
                "associated_data": "transaction",
                "nonce": "..."
            }
        }"#;

        let request: NotifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.id, "EV-2018022511223320873");
        assert_eq!(request.notify_type, "TRANSACTION.SUCCESS");
        assert_eq!(request.resource.algorithm, "AEAD_AES_256_GCM");
    }

    #[test]
    fn test_payment_notify_data_deserialization() {
        let json = r#"{
            "appid": "wx88888888",
            "mchid": "1900000109",
            "out_trade_no": "test_trade_no",
            "transaction_id": "1217752501201407033233368018",
            "trade_type": "JSAPI",
            "trade_state": "SUCCESS",
            "trade_state_desc": "支付成功",
            "bank_type": "CMB_CREDIT",
            "success_time": "2018-06-08T10:34:56+08:00"
        }"#;

        let data: PaymentNotifyData = serde_json::from_str(json).unwrap();
        assert_eq!(data.trade_state, "SUCCESS");
        assert_eq!(data.transaction_id, "1217752501201407033233368018");
    }
}
