//! 转账服务模块
//!
//! 提供存量商家转账到零钱（批量转账）功能；不包含新版用户确认收款接口。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::transport::{ServiceTransport, TransportObserver};

/// 转账请求
#[derive(Debug, Clone, Serialize)]
pub struct TransferRequest {
    /// 商户号
    pub appid: String,

    /// 商户订单号
    pub out_batch_no: String,

    /// 批次名称
    pub batch_name: String,

    /// 批次备注
    pub batch_remark: String,

    /// 转账明细
    pub transfer_detail_list: Vec<TransferDetail>,

    /// 转账总金额（分）
    pub total_amount: u64,

    /// 转账总笔数
    pub total_num: u64,
}

/// 转账明细
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDetail {
    /// 商户明细 ID
    pub out_detail_no: String,

    /// 转账金额（分）
    pub transfer_amount: u64,

    /// 转账备注
    pub transfer_remark: String,

    /// 用户标识
    pub openid: String,

    /// Plaintext recipient name. The service encrypts this field automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
}

/// 转账响应
#[derive(Debug, Clone, Deserialize)]
pub struct TransferResponse {
    /// 微信批次单号
    pub batch_id: String,

    /// 商户批次单号
    pub out_batch_no: String,

    /// Optional status in the creation response; acceptance is not payment success.
    pub batch_status: Option<String>,

    /// Time this batch was accepted.
    pub create_time: String,
}

/// Batch query response uses a nested transfer_batch object.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryTransferBatchResponse {
    /// Current batch totals and status.
    pub transfer_batch: TransferBatch,
    /// Requested detail page when available.
    #[serde(default)]
    pub transfer_detail_list: Vec<TransferDetailResult>,
}

/// Batch summary returned by a query.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferBatch {
    /// Merchant batch number.
    pub out_batch_no: String,
    /// WeChat batch number.
    pub batch_id: String,
    /// Current batch processing state.
    pub batch_status: String,
    /// Total requested amount in cents.
    pub total_amount: u64,
    /// Total requested transfers.
    pub total_num: u64,
    /// Successful transfer amount so far, when reported.
    pub success_amount: Option<u64>,
    /// Successful transfer count so far, when reported.
    pub success_num: Option<u64>,
    /// Failed transfer amount so far, when reported.
    pub fail_amount: Option<u64>,
    /// Failed transfer count so far, when reported.
    pub fail_num: Option<u64>,
    /// Reason a batch was closed.
    pub close_reason: Option<String>,
}

/// Compact transfer detail returned by a batch query.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferDetailResult {
    /// Merchant detail number.
    pub out_detail_no: String,
    /// WeChat detail number.
    pub detail_id: String,
    /// Current detail processing state.
    pub detail_status: String,
}

/// Optional batch query pagination. Defaults to querying only the summary.
#[derive(Debug, Clone, Default)]
pub struct TransferQueryOptions {
    /// Whether to include transfer details.
    pub need_query_detail: bool,
    /// Starting detail offset.
    pub offset: Option<u64>,
    /// Page size from 20 to 100.
    pub limit: Option<u64>,
    /// ALL, SUCCESS, FAIL, or WAIT_PAY.
    pub detail_status: Option<String>,
}

impl TransferQueryOptions {
    fn query_string(&self) -> WxPayResult<String> {
        if self.limit.is_some_and(|n| !(20..=100).contains(&n)) {
            return Err(crate::error::WxPayError::invalid_parameter(
                "transfer query limit must be between 20 and 100",
            ));
        }
        if self
            .detail_status
            .as_deref()
            .is_some_and(|s| !matches!(s, "ALL" | "SUCCESS" | "FAIL" | "WAIT_PAY"))
        {
            return Err(crate::error::WxPayError::invalid_parameter(
                "unsupported transfer detail_status",
            ));
        }
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair(
            "need_query_detail",
            if self.need_query_detail {
                "true"
            } else {
                "false"
            },
        );
        if let Some(offset) = self.offset {
            query.append_pair("offset", &offset.to_string());
        }
        if let Some(limit) = self.limit {
            query.append_pair("limit", &limit.to_string());
        }
        if let Some(status) = &self.detail_status {
            query.append_pair("detail_status", status);
        }
        Ok(query.finish())
    }
}

impl TransferRequest {
    /// Validate batch totals and reject duplicate detail identifiers before sending.
    pub fn validate(&self) -> WxPayResult<()> {
        use crate::error::WxPayError;
        for (value, field) in [
            (&self.appid, "appid"),
            (&self.out_batch_no, "out_batch_no"),
            (&self.batch_name, "batch_name"),
            (&self.batch_remark, "batch_remark"),
        ] {
            super::require_text(value, field)?;
        }
        if self.transfer_detail_list.is_empty()
            || self.transfer_detail_list.len() > 3000
            || self.total_num != self.transfer_detail_list.len() as u64
        {
            return Err(WxPayError::invalid_parameter(
                "batch must contain 1 to 3000 details and total_num must match",
            ));
        }
        let all_named = self.transfer_detail_list[0].user_name.is_some();
        let mut total = 0_u64;
        let mut ids = std::collections::HashSet::new();
        for detail in &self.transfer_detail_list {
            super::require_text(&detail.out_detail_no, "out_detail_no")?;
            super::require_text(&detail.openid, "openid")?;
            super::require_text(&detail.transfer_remark, "transfer_remark")?;
            if detail.transfer_amount == 0 || !ids.insert(&detail.out_detail_no) {
                return Err(WxPayError::invalid_parameter(
                    "transfer amount must be positive and detail numbers unique",
                ));
            }
            if detail.user_name.is_some() != all_named
                || (detail.transfer_amount < 30 && detail.user_name.is_some())
                || (detail.transfer_amount >= 200_000 && detail.user_name.is_none())
            {
                return Err(WxPayError::invalid_parameter(
                    "recipient names must be consistent within a batch, omitted below 30 cents, and provided from 200000 cents",
                ));
            }
            if let Some(name) = &detail.user_name {
                super::require_text(name, "user_name")?;
            }
            total = total
                .checked_add(detail.transfer_amount)
                .ok_or_else(|| WxPayError::invalid_parameter("transfer total overflow"))?;
        }
        if total != self.total_amount {
            return Err(WxPayError::invalid_parameter(
                "total_amount must equal sum of detail amounts",
            ));
        }
        Ok(())
    }
}

/// 查询转账批次请求
#[derive(Debug, Clone, Serialize)]
pub struct QueryTransferBatchRequest {
    /// 商户批次单号
    pub out_batch_no: String,
}

/// 转账服务
///
/// 提供微信支付转账的创建、查询等功能。
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
///     services::TransferService,
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
///     let service = TransferService::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::transfer::TransferRequest {
///         appid: "wx88888888".to_string(),
///         out_batch_no: "batch_001".to_string(),
///         batch_name: "测试转账".to_string(),
///         batch_remark: "测试".to_string(),
///         transfer_detail_list: vec![wxpay_rs::services::transfer::TransferDetail {
///             out_detail_no: "detail_001".to_string(),
///             transfer_amount: 100,
///             transfer_remark: "转账".to_string(),
///             openid: "test_openid".to_string(),
///             user_name: None,
///         }],
///         total_amount: 100,
///         total_num: 1,
///     };
///     let response = service.create_transfer(&request).await?;
///     let _ = response;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct TransferService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl TransferService {
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

    /// 创建新的转账服务
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

    /// 创建转账
    pub async fn create_transfer(
        &self,
        request: &TransferRequest,
    ) -> WxPayResult<TransferResponse> {
        request.validate()?;
        let mut encrypted = std::borrow::Cow::Borrowed(request);
        let serial = if request
            .transfer_detail_list
            .iter()
            .any(|d| d.user_name.is_some())
        {
            let mut names: Vec<_> = encrypted
                .to_mut()
                .transfer_detail_list
                .iter_mut()
                .filter_map(|d| d.user_name.as_mut())
                .collect();
            self.transport.encrypt_sensitive_fields(&mut names).await?
        } else {
            None
        };
        let body = serde_json::to_string(encrypted.as_ref())?;

        self.transport
            .request_with_headers(
                HttpMethod::Post,
                "/v3/transfer/batches",
                Some(&body),
                "transfer.create_transfer",
                serial
                    .into_iter()
                    .map(|serial| ("Wechatpay-Serial".into(), serial))
                    .collect(),
            )
            .await
    }

    /// 发起批量转账（文档风格）
    pub async fn create(&self, request: &TransferRequest) -> WxPayResult<TransferResponse> {
        self.create_transfer(request).await
    }

    /// 发起批量转账（兼容 `wechatpay-go` 风格）
    pub async fn initiate_batch_transfer(
        &self,
        request: &TransferRequest,
    ) -> WxPayResult<TransferResponse> {
        self.create_transfer(request).await
    }

    /// Query by WeChat batch ID, returning only the batch summary by default.
    pub async fn query_transfer_batch(
        &self,
        batch_id: &str,
    ) -> WxPayResult<QueryTransferBatchResponse> {
        self.query_transfer_batch_with_options(batch_id, &TransferQueryOptions::default())
            .await
    }

    /// Query by WeChat batch ID with explicit detail pagination.
    pub async fn query_transfer_batch_with_options(
        &self,
        batch_id: &str,
        options: &TransferQueryOptions,
    ) -> WxPayResult<QueryTransferBatchResponse> {
        super::require_identifier(batch_id, "batch_id")?;
        let path = format!(
            "/v3/transfer/batches/batch-id/{}?{}",
            super::encode_component(batch_id),
            options.query_string()?
        );
        self.transport
            .request(
                HttpMethod::Get,
                &path,
                None,
                "transfer.query_transfer_batch",
            )
            .await
    }

    /// Query by merchant batch number.
    pub async fn query_batch(
        &self,
        request: &QueryTransferBatchRequest,
    ) -> WxPayResult<QueryTransferBatchResponse> {
        self.get_transfer_batch_by_out_batch_no(&request.out_batch_no)
            .await
    }

    /// Alias for querying a merchant batch number.
    pub async fn query(
        &self,
        request: &QueryTransferBatchRequest,
    ) -> WxPayResult<QueryTransferBatchResponse> {
        self.query_batch(request).await
    }

    /// Query by merchant batch number, returning only the summary by default.
    pub async fn get_transfer_batch_by_out_batch_no(
        &self,
        out_batch_no: &str,
    ) -> WxPayResult<QueryTransferBatchResponse> {
        self.get_transfer_batch_by_out_batch_no_with_options(
            out_batch_no,
            &TransferQueryOptions::default(),
        )
        .await
    }

    /// Query by merchant batch number with explicit detail pagination.
    pub async fn get_transfer_batch_by_out_batch_no_with_options(
        &self,
        out_batch_no: &str,
        options: &TransferQueryOptions,
    ) -> WxPayResult<QueryTransferBatchResponse> {
        super::require_identifier(out_batch_no, "out_batch_no")?;
        let path = format!(
            "/v3/transfer/batches/out-batch-no/{}?{}",
            super::encode_component(out_batch_no),
            options.query_string()?
        );
        self.transport
            .request(
                HttpMethod::Get,
                &path,
                None,
                "transfer.get_transfer_batch_by_out_batch_no",
            )
            .await
    }
}

impl std::fmt::Debug for TransferService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_request_serialization() {
        let request = TransferRequest {
            appid: "wx88888888".to_string(),
            out_batch_no: "batch_001".to_string(),
            batch_name: "测试转账".to_string(),
            batch_remark: "测试".to_string(),
            transfer_detail_list: vec![TransferDetail {
                out_detail_no: "detail_001".to_string(),
                transfer_amount: 100,
                transfer_remark: "转账".to_string(),
                openid: "test_openid".to_string(),
                user_name: None,
            }],
            total_amount: 100,
            total_num: 1,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("batch_001"));
        assert!(json.contains("测试转账"));
    }

    #[test]
    fn test_transfer_response_deserialization() {
        let json = r#"{
            "batch_id": "1030000071100999991182020050700019480101",
            "out_batch_no": "batch_001",
            "create_time": "2026-10-02T12:00:00+08:00"
        }"#;
        let response: TransferResponse = serde_json::from_str(json).unwrap();
        assert!(response.batch_status.is_none());
        assert_eq!(
            response.batch_id,
            "1030000071100999991182020050700019480101"
        );
    }

    #[test]
    fn test_go_style_transfer_alias_signatures_exist() {
        let _ = TransferService::initiate_batch_transfer;
        let _ = TransferService::get_transfer_batch_by_out_batch_no;
    }
}
