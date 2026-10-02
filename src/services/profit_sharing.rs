//! 分账服务模块
//!
//! 提供微信支付分账功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

    /// Legacy description retained for source compatibility; API uses each receiver description.
    #[serde(skip_serializing)]
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

    /// Plaintext name; encrypted by the service using the selected platform key.
    #[serde(skip_serializing_if = "Option::is_none")]
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

    /// Plaintext merchant full name (required for MERCHANT_ID), optional for PERSONAL_OPENID.
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

    /// 分账单状态（FINISHED 只表示处理完毕，需检查每个接收方的 result）。
    pub state: String,

    /// 每个接收方的分账结果。
    pub receivers: Vec<ProfitSharingReceiverResult>,
}

/// Individual outcome; a FINISHED order can contain CLOSED receivers.
#[derive(Debug, Clone, Deserialize)]
pub struct ProfitSharingReceiverResult {
    /// Receiver type.
    #[serde(rename = "type")]
    pub receiver_type: String,
    /// Receiver account.
    pub account: String,
    /// Amount in cents.
    pub amount: u64,
    /// Description supplied when creating the order.
    pub description: String,
    /// PENDING, SUCCESS or CLOSED.
    pub result: String,
    /// Failure reason for CLOSED receivers.
    pub fail_reason: Option<String>,
    /// Time the individual transfer was created.
    pub create_time: Option<String>,
    /// Completion time if available.
    pub finish_time: Option<String>,
    /// WeChat transfer detail identifier.
    pub detail_id: Option<String>,
}

/// Options for creating an ordinary-merchant profit-sharing order.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProfitSharingOptions {
    /// AppID for PERSONAL_OPENID receivers; defaults to the client configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    /// Release the remaining funds and prohibit subsequent splits when true.
    /// Defaults to false so calling create does not implicitly finish an order.
    pub unfreeze_unsplit: bool,
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

    /// 分账单状态（FINISHED 只表示处理完毕，需检查每个接收方的 result）。
    pub state: String,

    /// 每个接收方的分账结果。
    pub receivers: Vec<ProfitSharingReceiverResult>,
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
///             receiver_type: "PERSONAL_OPENID".to_string(),
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
    pub(crate) fn from_transport(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        transport: ServiceTransport,
    ) -> Self {
        Self {
            config,
            http_client,
            signer,
            transport,
        }
    }

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
        self.create_profit_sharing_with_options(request, &ProfitSharingOptions::default())
            .await
    }

    /// Create a split with explicit AppID and remaining-funds behavior.
    /// Receiver names must be plaintext; this method encrypts them once per request.
    pub async fn create_profit_sharing_with_options(
        &self,
        request: &ProfitSharingRequest,
        options: &ProfitSharingOptions,
    ) -> WxPayResult<ProfitSharingResponse> {
        super::require_identifier(&request.transaction_id, "transaction_id")?;
        super::require_identifier(&request.out_order_no, "out_order_no")?;
        if request.receivers.is_empty() || request.receivers.len() > 50 {
            return Err(crate::error::WxPayError::invalid_parameter(
                "profit sharing requires 1 to 50 receivers",
            ));
        }
        for receiver in &request.receivers {
            validate_receiver(
                &receiver.receiver_type,
                &receiver.account,
                receiver.name.as_deref(),
            )?;
            super::require_text(&receiver.description, "receiver.description")?;
            if receiver.amount == 0 || receiver.description.len() > 80 {
                return Err(crate::error::WxPayError::invalid_parameter(
                    "receiver amount must be positive and description at most 80 bytes",
                ));
            }
        }
        let appid = options.appid.as_deref().unwrap_or(&self.config.app_id);
        super::require_text(appid, "appid")?;
        let mut encrypted = std::borrow::Cow::Borrowed(request);
        let serial = if request.receivers.iter().any(|r| r.name.is_some()) {
            let mut names: Vec<_> = encrypted
                .to_mut()
                .receivers
                .iter_mut()
                .filter_map(|r| r.name.as_mut())
                .collect();
            self.transport.encrypt_sensitive_fields(&mut names).await?
        } else {
            None
        };
        #[derive(Serialize)]
        struct Body<'a> {
            #[serde(flatten)]
            request: &'a ProfitSharingRequest,
            appid: &'a str,
            unfreeze_unsplit: bool,
        }
        let body = serde_json::to_string(&Body {
            request: encrypted.as_ref(),
            appid,
            unfreeze_unsplit: options.unfreeze_unsplit,
        })?;
        self.transport
            .request_with_headers(
                HttpMethod::Post,
                "/v3/profitsharing/orders",
                Some(&body),
                "profit_sharing.create_profit_sharing",
                serial
                    .into_iter()
                    .map(|serial| ("Wechatpay-Serial".into(), serial))
                    .collect(),
            )
            .await
    }

    /// 创建分账（文档风格）
    pub async fn create(
        &self,
        request: &ProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        self.create_profit_sharing(request).await
    }

    /// 创建分账单（兼容 `wechatpay-go` 风格）
    pub async fn create_order(
        &self,
        request: &ProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        self.create_profit_sharing(request).await
    }

    /// 添加分账接收方
    pub async fn add_receiver(
        &self,
        request: &AddProfitSharingReceiverRequest,
    ) -> WxPayResult<ProfitSharingReceiverResponse> {
        super::require_text(&request.appid, "appid")?;
        validate_receiver(
            &request.receiver_type,
            &request.account,
            request.name.as_deref(),
        )?;
        super::require_text(&request.relation_type, "relation_type")?;
        if request.relation_type == "CUSTOM" {
            super::require_text(
                request.custom_relation.as_deref().unwrap_or(""),
                "custom_relation",
            )?;
        }
        let mut encrypted = request.clone();
        let mut names: Vec<_> = encrypted.name.iter_mut().collect();
        let serial = self.transport.encrypt_sensitive_fields(&mut names).await?;
        let body = serde_json::to_string(&encrypted)?;
        self.transport
            .request_with_headers(
                HttpMethod::Post,
                "/v3/profitsharing/receivers/add",
                Some(&body),
                "profit_sharing.add_receiver",
                serial
                    .into_iter()
                    .map(|serial| ("Wechatpay-Serial".into(), serial))
                    .collect(),
            )
            .await
    }

    /// 删除分账接收方
    pub async fn delete_receiver(
        &self,
        request: &DeleteProfitSharingReceiverRequest,
    ) -> WxPayResult<ProfitSharingReceiverResponse> {
        super::require_text(&request.appid, "appid")?;
        super::require_text(&request.account, "account")?;
        super::require_text(&request.receiver_type, "type")?;
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
        super::require_identifier(transaction_id, "transaction_id")?;
        super::require_identifier(out_order_no, "out_order_no")?;
        let path = format!(
            "/v3/profitsharing/orders/{}?transaction_id={}",
            super::encode_component(out_order_no),
            super::encode_component(transaction_id)
        );

        self.transport
            .request(
                HttpMethod::Get,
                &path,
                None,
                "profit_sharing.query_profit_sharing",
            )
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
        super::require_identifier(&request.transaction_id, "transaction_id")?;
        super::require_identifier(&request.out_order_no, "out_order_no")?;
        super::require_text(&request.description, "description")?;
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/profitsharing/orders/unfreeze",
                Some(&body),
                "profit_sharing.finish_profit_sharing",
            )
            .await
    }

    /// 完成分账（文档风格）
    pub async fn finish(
        &self,
        request: &ProfitSharingFinishRequest,
    ) -> WxPayResult<ProfitSharingFinishResponse> {
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

fn validate_receiver(receiver_type: &str, account: &str, name: Option<&str>) -> WxPayResult<()> {
    super::require_text(account, "receiver.account")?;
    if !matches!(receiver_type, "MERCHANT_ID" | "PERSONAL_OPENID") {
        return Err(crate::error::WxPayError::invalid_parameter(
            "unsupported profit sharing receiver type",
        ));
    }
    if receiver_type == "MERCHANT_ID" && name.is_none() {
        return Err(crate::error::WxPayError::invalid_parameter(
            "MERCHANT_ID receiver requires its plaintext name",
        ));
    }
    if let Some(name) = name {
        super::require_text(name, "receiver.name")?;
    }
    Ok(())
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
            "state": "FINISHED",
            "receivers": []
        }"#;
        let response: ProfitSharingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.state, "FINISHED");
        assert_eq!(
            response.order_id,
            "6110000071100999991182020050700019480101"
        );
    }

    #[test]
    fn test_go_style_profit_sharing_alias_signatures_exist() {
        let _ = ProfitSharingService::create_order;
        let _ = ProfitSharingService::query_order;
        let _ = ProfitSharingService::finish_order;
    }
}
