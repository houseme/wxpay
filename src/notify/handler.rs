//! 通知处理器模块
//!
//! 提供处理微信支付回调通知的功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Verifier;
use crate::config::NotifyConfig;
use crate::crypto::Aes256GcmCipher;
use crate::error::{WxPayError, WxPayResult};

/// 回调签名所需的四个原始 HTTP 头；每一项都必须存在且非空。
#[derive(Clone, Copy)]
pub struct NotifyHeaders<'a> {
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub serial: &'a str,
    pub signature: &'a str,
}

/// 已通过时间窗口检查及平台验签的通知。
///
/// 只能由 [`NotifyHandler::verify_and_parse`] 创建。验签不代替数据库中的
/// 订单核对、通知去重或业务状态变更事务。
#[derive(Debug, Clone)]
pub struct VerifiedNotifyRequest(NotifyRequest);

impl VerifiedNotifyRequest {
    /// 只读访问已验签的通知元数据。
    pub fn request(&self) -> &NotifyRequest {
        &self.0
    }
}

/// 从本地订单读取的支付期望值；金额为订单总金额，不是优惠后的实付金额。
#[derive(Debug, Clone, Copy)]
pub struct PaymentExpectation<'a> {
    pub appid: &'a str,
    pub mchid: &'a str,
    pub out_trade_no: &'a str,
    pub total: u64,
    pub currency: &'a str,
}

/// 从本地退款单及原订单读取的期望值。
#[derive(Debug, Clone, Copy)]
pub struct RefundExpectation<'a> {
    pub mchid: &'a str,
    pub out_trade_no: &'a str,
    pub out_refund_no: &'a str,
    pub total: u64,
    pub refund: u64,
}

/// 通知请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyRequest {
    /// 通知 ID
    pub id: String,

    /// 通知创建时间
    pub create_time: String,

    /// 通知类型
    #[serde(rename = "event_type", alias = "type")]
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

impl PaymentNotifyData {
    /// 核对本地订单的商户、应用、订单号、总金额和币种。
    ///
    /// 调用方必须在订单状态事务中调用，并落实重复通知的幂等处理。
    pub fn validate_order(&self, expected: PaymentExpectation<'_>) -> WxPayResult<()> {
        let amount = self
            .amount
            .as_ref()
            .ok_or_else(|| WxPayError::InvalidNotifyFormat("支付通知缺少 amount".to_string()))?;
        if expected.appid.is_empty()
            || expected.mchid.is_empty()
            || expected.out_trade_no.is_empty()
            || expected.total == 0
            || expected.currency.is_empty()
            || self.appid != expected.appid
            || self.mchid != expected.mchid
            || self.out_trade_no != expected.out_trade_no
            || self.trade_state != "SUCCESS"
            || self.transaction_id.is_empty()
            || amount.total != expected.total
            || amount.currency != expected.currency
            || amount.payer_total.is_some_and(|paid| paid > amount.total)
        {
            return Err(WxPayError::BusinessError(
                "支付通知与本地订单不匹配".to_string(),
            ));
        }
        Ok(())
    }
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

impl RefundNotifyData {
    /// 核对本地退款单；退款成功、异常和关闭均需由业务层分别处理。
    pub fn validate_order(&self, expected: RefundExpectation<'_>) -> WxPayResult<()> {
        let amount = self
            .amount
            .as_ref()
            .ok_or_else(|| WxPayError::InvalidNotifyFormat("退款通知缺少 amount".to_string()))?;
        if expected.mchid.is_empty()
            || expected.out_trade_no.is_empty()
            || expected.out_refund_no.is_empty()
            || expected.refund == 0
            || expected.refund > expected.total
            || self.mchid != expected.mchid
            || self.out_trade_no != expected.out_trade_no
            || self.out_refund_no != expected.out_refund_no
            || self.refund_id.is_empty()
            || self.transaction_id.is_empty()
            || !matches!(
                self.refund_status.as_str(),
                "SUCCESS" | "ABNORMAL" | "CLOSED"
            )
            || amount.total != expected.total
            || amount.refund != expected.refund
            || amount.payer_total > amount.total
            || amount.payer_refund > amount.refund
            || amount.payer_refund > amount.payer_total
        {
            return Err(WxPayError::BusinessError(
                "退款通知与本地退款单不匹配".to_string(),
            ));
        }
        Ok(())
    }
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
#[derive(Clone)]
pub struct NotifyHandler {
    /// 通知配置
    config: Arc<NotifyConfig>,

    /// 验签器
    verifier: Arc<dyn Verifier>,

    /// AES 加密器
    cipher: Arc<Aes256GcmCipher>,
}

impl NotifyHandler {
    /// 创建新的通知处理器
    pub fn new(config: NotifyConfig, verifier: Arc<dyn Verifier>) -> WxPayResult<Self> {
        let cipher = Aes256GcmCipher::new(&config.api_v3_key)?;
        Ok(Self {
            config: Arc::new(config),
            verifier,
            cipher: Arc::new(cipher),
        })
    }

    /// 按原始请求体验签，检查前后 300 秒的时间窗口，然后解析通知。
    ///
    /// `body` 必须是 HTTP 收到的完整原始字节，不能重新序列化 JSON。
    /// 四个签名头都必填；使用 `serial` 指定的平台证书或公钥验签。
    /// 这限制旧报文重放，窗口内的重复通知仍需由业务数据库进行幂等处理。
    pub async fn verify_and_parse(
        &self,
        headers: NotifyHeaders<'_>,
        body: &[u8],
    ) -> WxPayResult<VerifiedNotifyRequest> {
        for (name, value) in [
            ("Wechatpay-Timestamp", headers.timestamp),
            ("Wechatpay-Nonce", headers.nonce),
            ("Wechatpay-Serial", headers.serial),
            ("Wechatpay-Signature", headers.signature),
        ] {
            if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(WxPayError::InvalidNotifyFormat(format!(
                    "缺失或无效的 {name}"
                )));
            }
        }
        if !headers.timestamp.bytes().all(|byte| byte.is_ascii_digit())
            || !self.verify_timestamp(headers.timestamp, 300)?
        {
            return Err(WxPayError::NotifySignatureVerificationFailed);
        }
        let body = std::str::from_utf8(body)
            .map_err(|_| WxPayError::InvalidNotifyFormat("通知必须是 UTF-8 JSON".to_string()))?;
        let message = format!("{}\n{}\n{}\n", headers.timestamp, headers.nonce, body);
        if !self
            .verifier
            .verify_with_serial(&message, headers.signature, headers.serial)
            .await?
        {
            return Err(WxPayError::NotifySignatureVerificationFailed);
        }
        let request = super::parser::NotifyParser::parse(body)?;
        if request.id.is_empty()
            || request.create_time.is_empty()
            || request.notify_type.is_empty()
            || request.resource.ciphertext.is_empty()
            || request.resource.nonce.is_empty()
            || request.resource.algorithm != "AEAD_AES_256_GCM"
        {
            return Err(WxPayError::InvalidNotifyFormat(
                "通知字段缺失或加密算法不受支持".to_string(),
            ));
        }
        Ok(VerifiedNotifyRequest(request))
    }

    /// 解密已验签的支付通知并检查事件状态；随后必须核对本地订单并持久化接收结果。
    pub async fn handle_verified_payment_notify(
        &self,
        request: &VerifiedNotifyRequest,
    ) -> WxPayResult<PaymentNotifyData> {
        let data = self.handle_payment_notify(request.request()).await?;
        if data.trade_state != "SUCCESS" || data.amount.is_none() {
            return Err(WxPayError::InvalidNotifyFormat(
                "支付事件状态或金额无效".to_string(),
            ));
        }
        Ok(data)
    }

    /// 解密已验签的退款通知，并确认事件类型与解密后的退款状态一致。
    pub async fn handle_verified_refund_notify(
        &self,
        request: &VerifiedNotifyRequest,
    ) -> WxPayResult<RefundNotifyData> {
        let data = self.handle_refund_notify(request.request()).await?;
        if request.request().notify_type.strip_prefix("REFUND.")
            != Some(data.refund_status.as_str())
            || data.amount.is_none()
        {
            return Err(WxPayError::InvalidNotifyFormat(
                "退款事件状态或金额无效".to_string(),
            ));
        }
        Ok(data)
    }

    /// 解密、解析支付通知（底层入口，不执行验签或防重放检查）。
    ///
    /// HTTP 回调请先调用 [`Self::verify_and_parse`]，再调用
    /// [`Self::handle_verified_payment_notify`]。业务幂等和订单核对由调用方负责。
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

    /// 解密、解析退款通知（底层入口，不执行验签或防重放检查）。
    ///
    /// HTTP 回调请使用 [`Self::verify_and_parse`] 和 [`Self::handle_verified_refund_notify`]。
    pub async fn handle_refund_notify(
        &self,
        request: &NotifyRequest,
    ) -> WxPayResult<RefundNotifyData> {
        // 验证通知类型
        if !matches!(
            request.notify_type.as_str(),
            "REFUND.SUCCESS" | "REFUND.ABNORMAL" | "REFUND.CLOSED"
        ) {
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

    /// 仅验证通知签名（底层兼容入口，不校验时间窗口，也不按 serial 选择公钥）。
    ///
    /// HTTP 回调应使用 [`Self::verify_and_parse`]，并传入未经重新序列化的原始请求体。
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
    use crate::auth::Sha256RsaVerifier;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use base64::Engine;
    use std::sync::Arc;

    const API_V3_KEY: &str = "abcdefghijklmnopqrstuvwxyz123456";

    fn test_handler() -> NotifyHandler {
        // verifier 仅用于满足构造签名，验签逻辑由专门测试覆盖；这里传一个真实 DER 解析会失败，
        // 因此用一个最小可用的“空证书列表” verifier（Sha256RsaVerifier::new(vec![]) 可成功构造）。
        let verifier: Arc<dyn Verifier> = Arc::new(Sha256RsaVerifier::new(vec![]).unwrap());
        let config = NotifyConfig {
            api_v3_key: API_V3_KEY.to_string(),
            cert_serial_number: "CERT123456".to_string(),
            platform_certificate: vec![],
        };
        NotifyHandler::new(config, verifier).unwrap()
    }

    /// 用真实 AES-256-GCM 加密一段支付通知明文，返回可被 NotifyRequest 引用的字段值。
    fn encrypt_resource(plaintext: &str, associated_data: &str, nonce: &str) -> (String, String) {
        let cipher = Aes256Gcm::new_from_slice(API_V3_KEY.as_bytes()).unwrap();
        let nonce_bytes: [u8; 12] = nonce.as_bytes().try_into().unwrap();
        let nonce_value = Nonce::from(nonce_bytes);
        let ct = cipher
            .encrypt(
                &nonce_value,
                aes_gcm::aead::Payload {
                    msg: plaintext.as_bytes(),
                    aad: associated_data.as_bytes(),
                },
            )
            .unwrap();
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ct);
        // 返回原始 nonce 字符串（与微信通知一致，明文 nonce）。
        (ciphertext_b64, nonce.to_string())
    }

    fn make_request(
        notify_type: &str,
        algorithm: &str,
        ciphertext: &str,
        nonce: &str,
        associated_data: &str,
    ) -> NotifyRequest {
        NotifyRequest {
            id: "EV-TEST".to_string(),
            create_time: "2024-01-01T00:00:00+08:00".to_string(),
            notify_type: notify_type.to_string(),
            resource: NotifyResource {
                algorithm: algorithm.to_string(),
                ciphertext: ciphertext.to_string(),
                associated_data: Some(associated_data.to_string()),
                nonce: nonce.to_string(),
            },
        }
    }

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

    #[tokio::test]
    async fn test_handle_payment_notify_decrypts_and_parses() {
        let handler = test_handler();

        let plaintext = r#"{
            "appid": "wx88888888",
            "mchid": "1900000109",
            "out_trade_no": "out_20240101",
            "transaction_id": "4200000001",
            "trade_type": "JSAPI",
            "trade_state": "SUCCESS",
            "trade_state_desc": "支付成功",
            "bank_type": "CMB_CREDIT",
            "success_time": "2024-01-01T00:00:00+08:00"
        }"#;
        let nonce = "nonce1234567"; // 12 字节
        let (ciphertext, nonce) = encrypt_resource(plaintext, "transaction", nonce);

        let request = make_request(
            "TRANSACTION.SUCCESS",
            "AEAD_AES_256_GCM",
            &ciphertext,
            &nonce,
            "transaction",
        );
        let data = handler.handle_payment_notify(&request).await.unwrap();

        assert_eq!(data.out_trade_no, "out_20240101");
        assert_eq!(data.transaction_id, "4200000001");
        assert_eq!(data.trade_state, "SUCCESS");
    }

    #[tokio::test]
    async fn test_handle_refund_notify_decrypts_and_parses() {
        let handler = test_handler();

        let plaintext = r#"{
            "mchid": "1900000109",
            "out_trade_no": "out_20240101",
            "transaction_id": "4200000001",
            "out_refund_no": "refund_001",
            "refund_id": "5000000038",
            "refund_status": "SUCCESS"
        }"#;
        let nonce = "refundnonce1"; // 12 字节
        let (ciphertext, nonce) = encrypt_resource(plaintext, "refund", nonce);

        let request = make_request(
            "REFUND.SUCCESS",
            "AEAD_AES_256_GCM",
            &ciphertext,
            &nonce,
            "refund",
        );
        let data = handler.handle_refund_notify(&request).await.unwrap();

        assert_eq!(data.out_refund_no, "refund_001");
        assert_eq!(data.refund_id, "5000000038");
        assert_eq!(data.refund_status, "SUCCESS");
    }

    #[tokio::test]
    async fn test_handle_payment_notify_rejects_wrong_type() {
        let handler = test_handler();
        let request = make_request(
            "REFUND.SUCCESS",
            "AEAD_AES_256_GCM",
            "x",
            "n",
            "transaction",
        );
        let err = handler.handle_payment_notify(&request).await.unwrap_err();
        assert!(matches!(err, WxPayError::InvalidNotifyType(_)));
    }

    #[tokio::test]
    async fn test_handle_notify_rejects_unsupported_algorithm() {
        let handler = test_handler();
        let request = make_request("TRANSACTION.SUCCESS", "RSA-OAEP", "x", "n", "transaction");
        let err = handler.handle_payment_notify(&request).await.unwrap_err();
        assert!(matches!(err, WxPayError::DecryptionError(_)));
    }

    #[tokio::test]
    async fn test_handle_payment_notify_rejects_tampered_ciphertext() {
        let handler = test_handler();
        let nonce = "nonce1234567";
        let (ciphertext, nonce) = encrypt_resource("{}", "transaction", nonce);

        // 篡改密文：base64 解码后翻转首字节再重新编码，保证 base64 仍合法但 GCM 认证失败。
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&ciphertext)
            .unwrap();
        bytes[0] ^= 0xff;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let request = make_request(
            "TRANSACTION.SUCCESS",
            "AEAD_AES_256_GCM",
            &tampered,
            &nonce,
            "transaction",
        );
        let err = handler.handle_payment_notify(&request).await.unwrap_err();
        assert!(matches!(err, WxPayError::DecryptionError(_)));
    }

    #[tokio::test]
    async fn test_verify_notify_signature_delegates_to_verifier() {
        // 空 verifier 的 verify 会返回错误；这里仅验证签名校验入口正确委托给 verifier。
        let handler = test_handler();
        let result = handler
            .verify_notify_signature("ts", "nonce", "body", "sig")
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_timestamp_validity() {
        let handler = test_handler();
        let now = crate::utils::timestamp::get_timestamp();

        // 当前时间戳在 300s 容差内有效。
        let valid = handler.verify_timestamp(&now.to_string(), 300).unwrap();
        assert!(valid);

        // 远古时间戳无效。
        let invalid = handler.verify_timestamp("0", 300).unwrap();
        assert!(!invalid);

        // 非法时间戳字符串应报错。
        let bad = handler.verify_timestamp("not-a-number", 300);
        assert!(bad.is_err());
    }

    #[test]
    fn test_new_rejects_invalid_api_v3_key() {
        let verifier: Arc<dyn Verifier> = Arc::new(Sha256RsaVerifier::new(vec![]).unwrap());
        let config = NotifyConfig {
            api_v3_key: "too-short".to_string(),
            cert_serial_number: "CERT".to_string(),
            platform_certificate: vec![],
        };
        let result = NotifyHandler::new(config, verifier);
        assert!(matches!(result, Err(WxPayError::InvalidKey(_))));
    }
}
