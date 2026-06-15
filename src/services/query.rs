//! 订单查询服务模块
//!
//! 提供微信支付订单查询功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::transport::{ServiceTransport, TransportObserver};

/// 订单查询过滤参数（文档风格：复杂条件查询）
#[derive(Debug, Clone, Serialize)]
pub struct QueryFilter {
    /// 微信支付订单号（二选一）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,

    /// 商户订单号（二选一）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_trade_no: Option<String>,

    /// 商户号（可选，默认使用配置中的 merchant_id）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mchid: Option<String>,
}

/// 订单查询 - 微信支付订单号请求
#[derive(Debug, Clone, Serialize)]
pub struct QueryByTransactionIdRequest {
    /// 微信支付订单号
    pub transaction_id: String,
    /// 直连商户号
    pub mchid: String,
}

/// 订单查询 - 商户订单号请求
#[derive(Debug, Clone, Serialize)]
pub struct QueryByOutTradeNoRequest {
    /// 商户订单号
    pub out_trade_no: String,
    /// 直连商户号
    pub mchid: String,
}

/// 关闭订单请求
#[derive(Debug, Clone, Serialize)]
pub struct CloseOrderRequest {
    /// 商户号
    pub mchid: String,
}

/// 关闭订单响应
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CloseOrderResponse {}

/// 交易信息
#[derive(Debug, Clone, Deserialize)]
pub struct Transaction {
    /// 应用 ID
    pub appid: String,
    /// 商户号
    pub mchid: String,
    /// 商户订单号
    pub out_trade_no: Option<String>,
    /// 微信支付订单号
    pub transaction_id: String,
    /// 交易状态
    pub trade_state: String,
    /// 交易类型
    #[serde(rename = "trade_type")]
    pub trade_type: Option<String>,
    /// 交易状态说明
    #[serde(rename = "trade_state_desc")]
    pub trade_state_desc: Option<String>,
    /// 订单金额
    pub amount: Option<QueryAmount>,
}

/// 金额信息
#[derive(Debug, Clone, Deserialize)]
pub struct QueryAmount {
    /// 订单金额（分）
    pub total: u64,
    /// 货币类型
    pub currency: Option<String>,
    /// 用户实际支付金额（分）
    #[serde(rename = "payer_total")]
    pub payer_total: Option<u64>,
}

/// 订单查询服务
#[allow(dead_code)]
pub struct QueryService {
    /// 配置
    config: Arc<WxPayConfig>,
    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,
    /// 签名器
    signer: Arc<dyn Signer>,
    /// 统一请求执行器
    transport: ServiceTransport,
}

impl QueryService {
    /// 创建新的查询服务
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

    /// 通过微信支付订单号查询（兼容文档风格）
    pub async fn by_transaction_id(&self, transaction_id: &str) -> WxPayResult<Transaction> {
        let request = QueryByTransactionIdRequest {
            transaction_id: transaction_id.to_string(),
            mchid: self.config.merchant_id.clone(),
        };
        self.by_transaction_id_request(&request).await
    }

    /// 通过微信支付订单号查询（兼容文档中的 request 参数）
    pub async fn by_transaction_id_request(
        &self,
        request: &QueryByTransactionIdRequest,
    ) -> WxPayResult<Transaction> {
        self.by_transaction_id_with_request(request).await
    }

    /// 通过微信支付订单号查询（兼容 `wechatpay-go` 风格）
    pub async fn query_order_by_id(&self, transaction_id: &str) -> WxPayResult<Transaction> {
        self.by_transaction_id(transaction_id).await
    }

    async fn by_transaction_id_with_request(
        &self,
        request: &QueryByTransactionIdRequest,
    ) -> WxPayResult<Transaction> {
        let path = format!(
            "/v3/pay/transactions/id/{}?mchid={}",
            request.transaction_id, request.mchid
        );

        self.transport
            .request(HttpMethod::Get, &path, None, "query.by_transaction_id")
            .await
    }

    /// 通过商户订单号查询（兼容文档风格）
    pub async fn by_out_trade_no(&self, out_trade_no: &str) -> WxPayResult<Transaction> {
        let request = QueryByOutTradeNoRequest {
            out_trade_no: out_trade_no.to_string(),
            mchid: self.config.merchant_id.clone(),
        };
        self.by_out_trade_no_request(&request).await
    }

    /// 通过商户订单号查询（结构体参数）
    pub async fn by_out_trade_no_request(
        &self,
        request: &QueryByOutTradeNoRequest,
    ) -> WxPayResult<Transaction> {
        self.by_out_trade_no_with_request(request).await
    }

    /// 通过商户订单号查询（兼容 `wechatpay-go` 风格）
    pub async fn query_order_by_out_trade_no(
        &self,
        out_trade_no: &str,
    ) -> WxPayResult<Transaction> {
        self.by_out_trade_no(out_trade_no).await
    }

    async fn by_out_trade_no_with_request(
        &self,
        request: &QueryByOutTradeNoRequest,
    ) -> WxPayResult<Transaction> {
        let path = format!(
            "/v3/pay/transactions/out-trade-no/{}?mchid={}",
            request.out_trade_no, request.mchid
        );

        self.transport
            .request(HttpMethod::Get, &path, None, "query.by_out_trade_no")
            .await
    }

    /// 复杂条件查询（当前实现支持 transaction_id / out_trade_no 二选一透传）
    pub async fn by_filter(&self, filter: &QueryFilter) -> WxPayResult<Transaction> {
        let transaction_id = filter.transaction_id.as_deref();
        let out_trade_no = filter.out_trade_no.as_deref();
        let mchid = filter
            .mchid
            .clone()
            .unwrap_or_else(|| self.config.merchant_id.clone());
        match (transaction_id, out_trade_no) {
            (Some(transaction_id), _) => {
                let request = QueryByTransactionIdRequest {
                    transaction_id: transaction_id.to_string(),
                    mchid,
                };
                self.by_transaction_id_request(&request).await
            }
            (None, Some(out_trade_no)) => {
                let request = QueryByOutTradeNoRequest {
                    out_trade_no: out_trade_no.to_string(),
                    mchid,
                };
                self.by_out_trade_no_request(&request).await
            }
            _ => Err(crate::error::WxPayError::invalid_parameter(
                "by_filter 需要提供 transaction_id 或 out_trade_no",
            )),
        }
    }

    /// 关闭订单
    pub async fn close(&self, out_trade_no: &str) -> WxPayResult<CloseOrderResponse> {
        let request = CloseOrderRequest {
            mchid: self.config.merchant_id.clone(),
        };
        self.close_with_request(out_trade_no, &request).await
    }

    /// 关闭订单（兼容文档中的 request 参数）
    pub async fn close_with_request(
        &self,
        out_trade_no: &str,
        request: &CloseOrderRequest,
    ) -> WxPayResult<CloseOrderResponse> {
        let path = format!("/v3/pay/transactions/out-trade-no/{}/close", out_trade_no);
        let body = serde_json::to_string(request)?;

        self.transport
            .request_default(HttpMethod::Post, &path, Some(&body), "query.close")
            .await
    }
}

impl std::fmt::Debug for QueryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_by_transaction_id_request_serialization() {
        let request = QueryByTransactionIdRequest {
            transaction_id: "4200000001".to_string(),
            mchid: "1900000109".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("4200000001"));
        assert!(json.contains("1900000109"));
    }

    #[test]
    fn test_query_by_out_trade_no_request_serialization() {
        let request = QueryByOutTradeNoRequest {
            out_trade_no: "out_trade_no_001".to_string(),
            mchid: "1900000109".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("out_trade_no_001"));
        assert!(json.contains("1900000109"));
    }

    #[test]
    fn test_go_style_query_alias_signatures_exist() {
        let _ = QueryService::query_order_by_id;
        let _ = QueryService::query_order_by_out_trade_no;
    }
}
