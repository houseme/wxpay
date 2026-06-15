//! 转账服务模块
//!
//! 提供微信支付转账功能。

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

    /// 用户名
    pub user_name: Option<String>,
}

/// 转账响应
#[derive(Debug, Clone, Deserialize)]
pub struct TransferResponse {
    /// 微信批次单号
    pub batch_id: String,

    /// 商户批次单号
    pub out_batch_no: String,

    /// 批次状态
    pub batch_status: String,
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
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/transfer/batches",
                Some(&body),
                "transfer.create_transfer",
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

    /// 查询转账批次
    pub async fn query_transfer_batch(&self, batch_id: &str) -> WxPayResult<TransferResponse> {
        let path = format!("/v3/transfer/batches/{}", batch_id);
        self.transport
            .request(
                HttpMethod::Get,
                &path,
                None,
                "transfer.query_transfer_batch",
            )
            .await
    }

    /// 查询转账批次（文档风格）
    pub async fn query_batch(
        &self,
        request: &QueryTransferBatchRequest,
    ) -> WxPayResult<TransferResponse> {
        self.query_transfer_batch(&request.out_batch_no).await
    }

    /// 查询转账（文档/API 表格简化命名）
    pub async fn query(
        &self,
        request: &QueryTransferBatchRequest,
    ) -> WxPayResult<TransferResponse> {
        self.query_batch(request).await
    }

    /// 按商户批次单号查询转账批次（兼容 `wechatpay-go` 风格）
    pub async fn get_transfer_batch_by_out_batch_no(
        &self,
        out_batch_no: &str,
    ) -> WxPayResult<TransferResponse> {
        self.query_transfer_batch(out_batch_no).await
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
            "batch_status": "ACCEPT"
        }"#;
        let response: TransferResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.batch_status, "ACCEPT");
        assert_eq!(
            response.batch_id,
            "1030000071100999991182020050700019480101"
        );
    }
}
