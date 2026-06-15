//! APP 支付服务模块
//!
//! 提供微信支付 APP 支付功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::services::payments::jsapi::{Amount, JsapiRequest};

/// APP 支付请求
#[derive(Debug, Clone, Serialize)]
pub struct AppRequest {
    /// 应用 ID
    pub appid: String,

    /// 商户号
    pub mchid: String,

    /// 商品描述
    pub description: String,

    /// 商户订单号
    pub out_trade_no: String,

    /// 订单金额
    pub amount: Option<Amount>,

    /// 通知地址
    pub notify_url: Option<String>,
}

/// APP 支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct AppResponse {
    /// 预支付交易会话标识
    pub prepay_id: String,
}

/// APP 支付参数
///
/// 用于客户端调用微信支付 SDK 时的参数。
#[derive(Debug, Clone, Serialize)]
pub struct AppPayParams {
    /// 应用 ID
    pub appid: String,

    /// 商户号
    pub partnerid: String,

    /// 预支付交易会话标识
    pub prepayid: String,

    /// 扩展字段
    pub package: String,

    /// 随机字符串
    pub noncestr: String,

    /// 时间戳
    pub timestamp: String,

    /// 签名
    pub sign: String,
}

/// APP 支付服务
///
/// 提供微信支付 APP 支付的创建、查询等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::services::AppService;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = AppService::new(config, http_client, signer);
///
/// let request = AppRequest {
///     appid: "wx88888888".to_string(),
///     mchid: "1900000109".to_string(),
///     description: "测试商品".to_string(),
///     out_trade_no: "test_trade_no_123".to_string(),
///     amount: Some(Amount {
///         total: 100,
///         currency: Some("CNY".to_string()),
///     }),
///     notify_url: None,
/// };
///
/// let response = tokio::runtime::Runtime::new()?.block_on(service.create_order(&request))?;
/// # Ok(())
/// # }
/// ```
pub struct AppService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl AppService {
    /// 创建新的 APP 服务
    pub fn new(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self {
            config,
            http_client,
            signer,
        }
    }

    /// 创建 APP 订单
    pub async fn create_order(&self, request: &AppRequest) -> WxPayResult<AppResponse> {
        let url = format!("{}/v3/pay/transactions/app", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/pay/transactions/app\n{}\n{}\n{}\n", timestamp, nonce, body);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        // 构建请求头
        let authorization = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}"#,
            self.config.merchant_id, nonce, timestamp, self.config.cert_serial_number, signature
        );

        let headers = vec![
            ("Authorization".to_string(), authorization),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "wxpay-rs/0.1.0".to_string()),
        ];

        // 发送请求
        let response = self.http_client.post(&url, headers, &body).await?;

        // 检查响应状态
        if !response.is_success() {
            let error: serde_json::Value = serde_json::from_str(&response.body)?;
            let code = error.get("code").and_then(|c| c.as_str()).unwrap_or("UNKNOWN");
            let message = error.get("message").and_then(|m| m.as_str()).unwrap_or("未知错误");
            return Err(WxPayError::api(code, message));
        }

        // 解析响应
        let app_response: AppResponse = serde_json::from_str(&response.body)?;

        Ok(app_response)
    }

    /// 生成 APP 支付参数
    ///
    /// # 参数
    ///
    /// * `prepay_id` - 预支付交易会话标识
    ///
    /// # 返回
    ///
    /// 返回 APP 支付参数
    pub async fn generate_pay_params(&self, prepay_id: &str) -> WxPayResult<AppPayParams> {
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();

        // 构建签名消息
        let message = format!("{}\n{}\n{}\nprepay_id={}\n", self.config.app_id, timestamp, nonce, prepay_id);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        Ok(AppPayParams {
            appid: self.config.app_id.clone(),
            partnerid: self.config.merchant_id.clone(),
            prepayid: prepay_id.to_string(),
            package: "Sign=WXPay".to_string(),
            noncestr: nonce,
            timestamp: timestamp.to_string(),
            sign: signature,
        })
    }
}

impl std::fmt::Debug for AppService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_request_serialization() {
        let request = AppRequest {
            appid: "wx88888888".to_string(),
            mchid: "1900000109".to_string(),
            description: "测试商品".to_string(),
            out_trade_no: "test_trade_no_123".to_string(),
            amount: Some(Amount {
                total: 100,
                currency: Some("CNY".to_string()),
            }),
            notify_url: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wx88888888"));
        assert!(json.contains("1900000109"));
    }

    #[test]
    fn test_app_response_deserialization() {
        let json = r#"{"prepay_id":"wx201410272009395522657a690ac89ed300"}"#;
        let response: AppResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.prepay_id, "wx201410272009395522657a690ac89ed300");
    }
}
