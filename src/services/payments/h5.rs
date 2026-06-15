//! H5 支付服务模块
//!
//! 提供微信支付 H5 支付功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::payments::jsapi::Amount;
use crate::services::transport::{ServiceTransport, TransportObserver};

/// H5 支付请求
#[derive(Debug, Clone, Serialize)]
pub struct H5Request {
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

    /// 场景信息
    pub scene_info: Option<SceneInfo>,
}

/// 场景信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SceneInfo {
    /// 用户终端 IP
    pub payer_client_ip: Option<String>,

    /// 商户端设备号
    pub device_id: Option<String>,

    /// H5 场景信息
    pub h5_info: Option<H5Info>,
}

/// H5 场景信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H5Info {
    /// 场景类型
    pub r#type: String,
}

/// H5 支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct H5Response {
    /// 支付跳转链接
    pub h5_url: String,
}

/// H5 支付服务
///
/// 提供微信支付 H5 支付的创建、查询等功能。
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
///     services::H5Service,
/// };
/// use wxpay_rs::services::payments::jsapi::Amount;
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
///     let service = H5Service::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::payments::h5::H5Request {
///         appid: "wx88888888".to_string(),
///         mchid: "1900000109".to_string(),
///         description: "测试商品".to_string(),
///         out_trade_no: "test_trade_no_123".to_string(),
///         amount: Some(Amount {
///             total: 100,
///             currency: Some("CNY".to_string()),
///         }),
///         notify_url: None,
///         scene_info: None,
///     };
///     let response = service.create_order(&request).await?;
///     let _ = response;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct H5Service {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl H5Service {
    /// 创建新的 H5 服务
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

    /// 创建 H5 订单
    pub async fn create_order(&self, request: &H5Request) -> WxPayResult<H5Response> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/pay/transactions/h5",
                Some(&body),
                "payments.h5.create_order",
            )
            .await
    }

    /// 预下单（兼容文档风格）
    pub async fn prepay(&self, request: &H5Request) -> WxPayResult<H5Response> {
        self.create_order(request).await
    }
}

impl std::fmt::Debug for H5Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H5Service").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h5_request_serialization() {
        let request = H5Request {
            appid: "wx88888888".to_string(),
            mchid: "1900000109".to_string(),
            description: "测试商品".to_string(),
            out_trade_no: "test_trade_no_123".to_string(),
            amount: Some(Amount {
                total: 100,
                currency: Some("CNY".to_string()),
            }),
            notify_url: None,
            scene_info: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wx88888888"));
        assert!(json.contains("1900000109"));
    }

    #[test]
    fn test_h5_response_deserialization() {
        let json = r#"{"h5_url":"https://wx.tenpay.com/cgi-bin/mmpayweb-bin/checkmweb?prepay_id=wx201410272009395522657a690ac89ed300"}"#;
        let response: H5Response = serde_json::from_str(json).unwrap();
        assert!(response.h5_url.starts_with("https://wx.tenpay.com"));
    }
}
