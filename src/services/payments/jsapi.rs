//! JSAPI 支付服务模块
//!
//! 提供微信支付 JSAPI 支付功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::transport::{ServiceTransport, TransportObserver};

/// JSAPI 支付请求
#[derive(Debug, Clone, Serialize)]
pub struct JsapiRequest {
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

    /// 支付者信息
    pub payer: Option<Payer>,

    /// 通知地址
    pub notify_url: Option<String>,
}

/// 订单金额
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Amount {
    /// 总金额（分）
    pub total: u64,

    /// 货币类型
    pub currency: Option<String>,
}

/// 支付者信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payer {
    /// 用户标识
    pub openid: String,
}

/// JSAPI 支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct JsapiResponse {
    /// 预支付交易会话标识
    pub prepay_id: String,
}

/// JSAPI 支付参数
///
/// 用于前端调用 wx.chooseWXpay 时的参数。
#[derive(Debug, Clone, Serialize)]
pub struct JsapiPayParams {
    /// 时间戳
    pub timestamp: String,

    /// 随机字符串
    pub nonce_str: String,

    /// 预支付交易会话标识
    pub prepay_id: String,

    /// 签名
    pub sign_type: String,

    /// 签名
    pub pay_sign: String,
}

/// JSAPI 支付服务
///
/// 提供微信支付 JSAPI 支付的创建、查询等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use std::sync::Arc;
///
/// use wxpay_rs::{
///     auth::{Signer, Sha256RsaSigner},
///     config::WxPayConfig,
///     http::ReqwestHttpClient,
///     services::JsapiService,
/// };
/// use wxpay_rs::services::payments::jsapi::{Amount, Payer};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = WxPayConfig::builder()
///         .app_id("wx88888888")
///         .merchant_id("1900000109")
///         .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
///         .private_key_from_file("path/to/private_key.pem")
///         .cert_serial_number("CERT123456")
///         .build()?;
///     let http_client = Arc::new(ReqwestHttpClient::builder().build()?);
///     let signer: Arc<dyn Signer> = Arc::new(Sha256RsaSigner::new(
///         "1900000109",
///         b"PRIVATE KEY",
///         "CERT123456",
///     )?);
///     let service = JsapiService::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::payments::jsapi::JsapiRequest {
///         appid: "wx88888888".to_string(),
///         mchid: "1900000109".to_string(),
///         description: "测试商品".to_string(),
///         out_trade_no: "test_trade_no_123".to_string(),
///         amount: Some(Amount {
///             total: 100,
///             currency: Some("CNY".to_string()),
///         }),
///         payer: Some(Payer {
///             openid: "test_openid".to_string(),
///         }),
///         notify_url: None,
///     };
///     let response = service.create_order(&request).await?;
///     let _ = response;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct JsapiService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl JsapiService {
    /// 创建新的 JSAPI 服务
    ///
    /// # 参数
    ///
    /// * `config` - 配置
    /// * `http_client` - HTTP 客户端
    /// * `signer` - 签名器
    ///
    /// # 返回
    ///
    /// 返回 JSAPI 服务实例
    pub fn new(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self::new_with_observer(config.clone(), http_client.clone(), signer.clone(), None)
    }

    pub fn new_with_observer(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> Self {
        Self {
            config: config.clone(),
            http_client: http_client.clone(),
            signer: signer.clone(),
            transport: ServiceTransport::new_with_observer(
                config,
                http_client,
                signer,
                transport_observer,
            ),
        }
    }

    /// 创建 JSAPI 订单
    ///
    /// # 参数
    ///
    /// * `request` - JSAPI 请求
    ///
    /// # 返回
    ///
    /// 返回 JSAPI 响应
    pub async fn create_order(&self, request: &JsapiRequest) -> WxPayResult<JsapiResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/pay/transactions/jsapi",
                Some(&body),
                "payments.jsapi.create_order",
            )
            .await
    }

    /// 预下单（兼容文档风格）
    pub async fn prepay(&self, request: &JsapiRequest) -> WxPayResult<JsapiResponse> {
        self.create_order(request).await
    }

    /// 兼容 README 中的 build_pay_params 名称
    pub async fn build_pay_params(&self, prepay_id: &str) -> WxPayResult<JsapiPayParams> {
        self.generate_pay_params(prepay_id).await
    }

    /// 生成 JSAPI 支付参数
    ///
    /// # 参数
    ///
    /// * `prepay_id` - 预支付交易会话标识
    ///
    /// # 返回
    ///
    /// 返回 JSAPI 支付参数
    pub async fn generate_pay_params(&self, prepay_id: &str) -> WxPayResult<JsapiPayParams> {
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();

        // 构建签名消息
        let message = format!("{}\n{}\nprepay_id={}\n", timestamp, nonce, prepay_id);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        Ok(JsapiPayParams {
            timestamp: timestamp.to_string(),
            nonce_str: nonce,
            prepay_id: prepay_id.to_string(),
            sign_type: "RSA".to_string(),
            pay_sign: signature,
        })
    }
}

impl std::fmt::Debug for JsapiService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsapiService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsapi_request_serialization() {
        let request = JsapiRequest {
            appid: "wx88888888".to_string(),
            mchid: "1900000109".to_string(),
            description: "测试商品".to_string(),
            out_trade_no: "test_trade_no_123".to_string(),
            amount: Some(Amount {
                total: 100,
                currency: Some("CNY".to_string()),
            }),
            payer: Some(Payer {
                openid: "test_openid".to_string(),
            }),
            notify_url: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wx88888888"));
        assert!(json.contains("1900000109"));
        assert!(json.contains("测试商品"));
    }

    #[test]
    fn test_jsapi_response_deserialization() {
        let json = r#"{"prepay_id":"wx201410272009395522657a690ac89ed300"}"#;
        let response: JsapiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.prepay_id, "wx201410272009395522657a690ac89ed300");
    }
}
