//! 分账服务模块
//!
//! 提供微信支付分账功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::transport::{ServiceTransport, TransportObserver};

/// 分账请求
#[derive(Debug, Clone, Serialize)]
pub struct ProfitSharingRequest {
    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 分账接收方列表
    pub receivers: Vec<Receiver>,

    /// 分账说明
    pub description: String,
}

/// 查询分账结果请求
#[derive(Debug, Clone, Serialize)]
pub struct QueryProfitSharingRequest {
    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户分账单号
    pub out_order_no: String,
}

/// 分账接收方
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receiver {
    /// 接收方类型
    #[serde(rename = "type")]
    pub receiver_type: String,

    /// 接收方账号
    pub account: String,

    /// 分账金额（分）
    pub amount: u64,

    /// 分账描述
    pub description: String,

    /// 接收方名称
    pub name: Option<String>,
}

/// 添加分账接收方请求
#[derive(Debug, Clone, Serialize)]
pub struct AddProfitSharingReceiverRequest {
    /// 子商户号（服务商模式可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_mchid: Option<String>,

    /// 应用 ID
    pub appid: String,

    /// 子商户应用 ID（服务商模式可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_appid: Option<String>,

    /// 接收方类型
    #[serde(rename = "type")]
    pub receiver_type: String,

    /// 接收方账号
    pub account: String,

    /// 接收方名称（个人收款方时必填）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// 与分账方的关系类型
    #[serde(rename = "relation_type")]
    pub relation_type: String,

    /// 自定义关系（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_relation: Option<String>,
}

/// 删除分账接收方请求
#[derive(Debug, Clone, Serialize)]
pub struct DeleteProfitSharingReceiverRequest {
    /// 应用 ID
    pub appid: String,

    /// 接收方类型
    #[serde(rename = "type")]
    pub receiver_type: String,

    /// 接收方账号
    pub account: String,

    /// 子商户号（服务商模式可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_mchid: Option<String>,

    /// 子商户应用 ID（服务商模式可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_appid: Option<String>,
}

/// 分账响应
#[derive(Debug, Clone, Deserialize)]
pub struct ProfitSharingResponse {
    /// 微信分账单号
    pub order_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 分账单状态
    pub status: String,
}

/// 分账接收方响应（添加/删除）
#[derive(Debug, Clone, Deserialize)]
pub struct ProfitSharingReceiverResponse {
    /// 子商户号（服务商模式返回）
    pub sub_mchid: Option<String>,

    /// 应用 ID
    pub appid: Option<String>,

    /// 子商户应用 ID（服务商模式返回）
    pub sub_appid: Option<String>,

    /// 接收方类型
    #[serde(rename = "type")]
    pub receiver_type: Option<String>,

    /// 接收方账号
    pub account: Option<String>,

    /// 接收方姓名
    pub name: Option<String>,

    /// 与分账方的关系类型
    #[serde(rename = "relation_type")]
    pub relation_type: Option<String>,

    /// 自定义关系
    pub custom_relation: Option<String>,
}

/// 分账完结请求
#[derive(Debug, Clone, Serialize)]
pub struct ProfitSharingFinishRequest {
    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 分账完结描述
    pub description: String,
}

/// 分账完结响应
#[derive(Debug, Clone, Deserialize)]
pub struct ProfitSharingFinishResponse {
    /// 微信分账单号
    pub order_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 分账单状态
    pub status: String,
}

/// 分账服务
///
/// 提供微信支付分账的创建、查询、完结等功能。
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
///     services::ProfitSharingService,
/// };
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
///     let service = ProfitSharingService::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::ProfitSharingRequest {
///         transaction_id: "1217752501201407033233368018".to_string(),
///         out_order_no: "P20150806125346".to_string(),
///         receivers: vec![wxpay_rs::services::Receiver {
///             receiver_type: "MERCHANT_ID".to_string(),
///             account: "1900000109".to_string(),
///             amount: 100,
///             description: "分账".to_string(),
///             name: None,
///         }],
///         description: "分账".to_string(),
///     };
///     let response = service.create_profit_sharing(&request).await?;
///     let _ = response;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct ProfitSharingService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl ProfitSharingService {
    /// 创建新的分账服务
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

    /// 创建分账
    pub async fn create_profit_sharing(
        &self,
        request: &ProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/profitsharing/orders",
                Some(&body),
                "profit_sharing.create_profit_sharing",
            )
            .await
    }

    /// 创建分账（文档风格）
    pub async fn create(&self, request: &ProfitSharingRequest) -> WxPayResult<ProfitSharingResponse> {
        self.create_profit_sharing(request).await
    }

    /// 创建分账单（兼容 `wechatpay-go` 风格）
    pub async fn create_order(&self, request: &ProfitSharingRequest) -> WxPayResult<ProfitSharingResponse> {
        self.create_profit_sharing(request).await
    }

    /// 添加分账接收方
    pub async fn add_receiver(
        &self,
        request: &AddProfitSharingReceiverRequest,
    ) -> WxPayResult<ProfitSharingReceiverResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/profitsharing/receivers/add",
                Some(&body),
                "profit_sharing.add_receiver",
            )
            .await
    }

    /// 删除分账接收方
    pub async fn delete_receiver(
        &self,
        request: &DeleteProfitSharingReceiverRequest,
    ) -> WxPayResult<ProfitSharingReceiverResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/profitsharing/receivers/delete",
                Some(&body),
                "profit_sharing.delete_receiver",
            )
            .await
    }

    /// 查询分账
    pub async fn query_profit_sharing(
        &self,
        transaction_id: &str,
        out_order_no: &str,
    ) -> WxPayResult<ProfitSharingResponse> {
        let path = format!(
            "/v3/profitsharing/orders/{}?transaction_id={}",
            out_order_no, transaction_id
        );

        self.transport
            .request(HttpMethod::Get, &path, None, "profit_sharing.query_profit_sharing")
            .await
    }

    /// 查询分账（文档风格）
    pub async fn query(
        &self,
        request: &QueryProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        self.query_profit_sharing(&request.transaction_id, &request.out_order_no)
            .await
    }

    /// 查询分账单（兼容 `wechatpay-go` 风格）
    pub async fn query_order(
        &self,
        request: &QueryProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        self.query_profit_sharing(&request.transaction_id, &request.out_order_no)
            .await
    }

    /// 完成分账
    pub async fn finish_profit_sharing(
        &self,
        request: &ProfitSharingFinishRequest,
    ) -> WxPayResult<ProfitSharingFinishResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/profitsharing/finish",
                Some(&body),
                "profit_sharing.finish_profit_sharing",
            )
            .await
    }

    /// 完成分账（文档风格）
    pub async fn finish(&self, request: &ProfitSharingFinishRequest) -> WxPayResult<ProfitSharingFinishResponse> {
        self.finish_profit_sharing(request).await
    }

    /// 完成分账单（兼容 `wechatpay-go` 风格）
    pub async fn finish_order(
        &self,
        request: &ProfitSharingFinishRequest,
    ) -> WxPayResult<ProfitSharingFinishResponse> {
        self.finish_profit_sharing(request).await
    }
}

impl std::fmt::Debug for ProfitSharingService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfitSharingService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profit_sharing_request_serialization() {
        let request = ProfitSharingRequest {
            transaction_id: "1217752501201407033233368018".to_string(),
            out_order_no: "P20150806125346".to_string(),
            receivers: vec![Receiver {
                receiver_type: "MERCHANT_ID".to_string(),
                account: "1900000109".to_string(),
                amount: 100,
                description: "分账".to_string(),
                name: None,
            }],
            description: "分账".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("1217752501201407033233368018"));
        assert!(json.contains("P20150806125346"));
    }

    #[test]
    fn test_profit_sharing_response_deserialization() {
        let json = r#"{
            "order_id": "6110000071100999991182020050700019480101",
            "out_order_no": "P20150806125346",
            "transaction_id": "1217752501201407033233368018",
            "status": "FINISHED"
        }"#;
        let response: ProfitSharingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "FINISHED");
        assert_eq!(response.order_id, "6110000071100999991182020050700019480101");
    }
}
