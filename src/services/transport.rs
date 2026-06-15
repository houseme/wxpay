use std::sync::Arc;
use std::time::Instant;

use serde::de::DeserializeOwned;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::{WxPayAlertLevel, WxPayError, WxPayErrorKind, WxPayResult};
use crate::http::client::HttpResponse;
use crate::http::{HttpClient, HttpMethod, RequestBuilder, ResponseHandler};

/// 统一服务请求执行器
#[derive(Debug)]
pub struct TransportEvent {
    /// 操作标识
    pub operation: String,
    /// HTTP 方法
    pub method: String,
    /// 请求路径
    pub path: String,
    /// HTTP 状态码
    pub status: u16,
    /// 请求 ID
    pub request_id: String,
    /// 请求耗时（毫秒）
    pub elapsed_ms: u128,
    /// 商户号
    pub merchant_id: String,
    /// 应用 ID
    pub app_id: String,
    /// 是否成功
    pub is_success: bool,
    /// 微信 API 错误码
    pub error_code: Option<String>,
    /// 错误分类
    pub error_kind: Option<WxPayErrorKind>,
    /// 告警级别
    pub alert_level: WxPayAlertLevel,
    /// 告警策略
    pub alert_policy: String,
    /// 是否建议重试
    pub should_retry: bool,
    /// 是否鉴权/签名类错误
    pub is_auth_error: bool,
}

struct TransportErrorContext<'a> {
    operation: &'a str,
    method: &'a str,
    path: &'a str,
    status: u16,
    request_id: &'a str,
    elapsed_ms: u128,
    error: &'a WxPayError,
}

impl TransportEvent {
    fn success(
        operation: &str,
        method: &str,
        path: &str,
        config: &WxPayConfig,
        status: u16,
        request_id: &str,
        elapsed_ms: u128,
    ) -> Self {
        Self {
            operation: operation.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            status,
            request_id: request_id.to_string(),
            elapsed_ms,
            merchant_id: config.merchant_id.clone(),
            app_id: config.app_id.clone(),
            is_success: true,
            error_code: None,
            error_kind: None,
            alert_level: WxPayAlertLevel::Low,
            alert_policy: "success".to_string(),
            should_retry: false,
            is_auth_error: false,
        }
    }

    fn error(config: &WxPayConfig, context: TransportErrorContext<'_>) -> Self {
        Self {
            operation: context.operation.to_string(),
            method: context.method.to_string(),
            path: context.path.to_string(),
            status: context.status,
            request_id: context.request_id.to_string(),
            elapsed_ms: context.elapsed_ms,
            merchant_id: config.merchant_id.clone(),
            app_id: config.app_id.clone(),
            is_success: false,
            error_code: context.error.api_code().map(str::to_string),
            error_kind: context.error.api_kind(),
            alert_level: context.error.alert_level(),
            alert_policy: context.error.alert_policy().to_string(),
            should_retry: context.error.should_retry(),
            is_auth_error: context.error.is_auth_error(),
        }
    }

    /// 错误分类字符串（用于日志/告警标签）
    pub fn error_kind_label(&self) -> &'static str {
        self.error_kind
            .map(|kind| kind.as_str())
            .unwrap_or("non_api")
    }

    /// 统一告警路由键（告警系统规则直接引用）
    pub fn alert_key(&self) -> String {
        format!("{}.{}", self.alert_level.as_str(), self.alert_policy)
    }

    /// 是否建议立即触发告警（用于结构化日志策略）
    pub fn should_alert(&self) -> bool {
        matches!(
            self.alert_level,
            WxPayAlertLevel::High | WxPayAlertLevel::Critical
        ) || self.should_retry
    }
}

/// 传输观测回调
pub trait TransportObserver: Send + Sync {
    /// 请求成功回调（可用于指标计数/延迟统计）
    fn on_success(&self, _event: &TransportEvent) {}

    /// 请求失败回调（可用于告警/链路打点）
    fn on_error(&self, _event: &TransportEvent, _error: &WxPayError) {}
}

#[derive(Debug)]
pub struct NoopTransportObserver;

impl TransportObserver for NoopTransportObserver {}

pub struct ServiceTransport {
    config: Arc<WxPayConfig>,
    http_client: Arc<dyn HttpClient>,
    signer: Arc<dyn Signer>,
    transport_observer: Option<Arc<dyn TransportObserver>>,
}

impl std::fmt::Debug for ServiceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTransport")
            .field("transport_observer", &self.transport_observer.is_some())
            .finish()
    }
}

impl ServiceTransport {
    /// 创建执行器
    pub fn new(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self::new_with_observer(config, http_client, signer, None)
    }

    /// 创建执行器（携带观测回调）
    pub fn new_with_observer(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> Self {
        Self {
            config,
            http_client,
            signer,
            transport_observer,
        }
    }

    fn build_headers(
        &self,
        request: &crate::http::request::WxPayRequest,
        method: HttpMethod,
        signature: &str,
    ) -> Vec<(String, String)> {
        let mut headers = request.headers_vec();

        let authorization = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}""#,
            self.config.merchant_id,
            request.nonce,
            request.timestamp,
            self.config.cert_serial_number,
            signature
        );

        headers.push(("Authorization".to_string(), authorization));
        headers.push(("Accept".to_string(), "application/json".to_string()));
        headers.push(("User-Agent".to_string(), "wxpay-rs/0.1.0".to_string()));

        if matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
        ) {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }

        headers
    }

    async fn send(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
    ) -> WxPayResult<HttpResponse> {
        let mut request =
            RequestBuilder::new(method, path).timestamp(crate::utils::timestamp::get_timestamp());
        if let Some(body) = body {
            request = request.body(body);
        }

        let request = request.nonce(crate::utils::nonce::generate_nonce()).build();
        let signature = self.signer.sign(&request.sign_message()).await?;
        let headers = self.build_headers(&request, method, &signature);
        let url = request.full_url(self.config.base_url());

        let started_at = Instant::now();
        let response_result: WxPayResult<HttpResponse> = match method {
            HttpMethod::Get => self.http_client.get(&url, headers).await,
            HttpMethod::Post => {
                self.http_client
                    .post(&url, headers, request.body_str())
                    .await
            }
            HttpMethod::Put => {
                self.http_client
                    .put(&url, headers, request.body_str())
                    .await
            }
            HttpMethod::Delete => self.http_client.delete(&url, headers).await,
            HttpMethod::Patch => {
                self.http_client
                    .patch(&url, headers, request.body_str())
                    .await
            }
        };

        let elapsed_ms = started_at.elapsed().as_millis();
        let response = match response_result {
            Ok(response) => response,
            Err(error) => {
                let request_id = "-".to_string();
                let event = TransportEvent::error(
                    &self.config,
                    TransportErrorContext {
                        operation,
                        method: request.method_str(),
                        path,
                        status: 0,
                        request_id: &request_id,
                        elapsed_ms,
                        error: &error,
                    },
                );

                if let Some(observer) = &self.transport_observer {
                    observer.on_error(&event, &error);
                }

                tracing::error!(
                    operation,
                    method = request.method_str(),
                    path = path,
                    status = 0,
                    request_id = request_id,
                    error_code = event.error_code.clone().unwrap_or("-".to_string()),
                    error_kind = event.error_kind_label(),
                    alert_level = event.alert_level.as_str(),
                    alert_policy = event.alert_policy,
                    alert_key = %event.alert_key(),
                    should_retry = event.should_retry,
                    is_auth_error = %error.is_auth_error(),
                    should_alert = event.should_alert(),
                    elapsed_ms = elapsed_ms,
                    error = %error,
                    "wxpay transport request failed"
                );
                return Err(error);
            }
        };

        let elapsed_ms = started_at.elapsed().as_millis();
        let request_id = ResponseHandler::get_request_id(&response)
            .unwrap_or("-")
            .to_string();

        if response.is_success() {
            if let Some(observer) = &self.transport_observer {
                let event = TransportEvent::success(
                    operation,
                    request.method_str(),
                    path,
                    &self.config,
                    response.status,
                    &request_id,
                    elapsed_ms,
                );

                observer.on_success(&event);
            }

            tracing::info!(
                operation,
                method = request.method_str(),
                path = path,
                status = response.status,
                request_id = request_id,
                elapsed_ms = elapsed_ms,
                "wxpay request success"
            );
            return Ok(response);
        }

        let err = ResponseHandler::handle_error(&response);
        match err {
            Ok(_) => Ok(response),
            Err(error) => {
                let event = TransportEvent::error(
                    &self.config,
                    TransportErrorContext {
                        operation,
                        method: request.method_str(),
                        path,
                        status: response.status,
                        request_id: &request_id,
                        elapsed_ms,
                        error: &error,
                    },
                );

                if let Some(observer) = &self.transport_observer {
                    observer.on_error(&event, &error);
                }

                let error_kind = event.error_kind_label();
                let alert_key = event.alert_key();
                let alert_level = event.alert_level.as_str();
                let alert_policy = &event.alert_policy;
                let should_retry = event.should_retry;
                tracing::warn!(
                    operation,
                    method = request.method_str(),
                    path = path,
                    status = response.status,
                    request_id = request_id,
                    error_code = event.error_code.clone().unwrap_or("-".to_string()),
                    error_kind = error_kind,
                    alert_level = alert_level,
                    alert_policy = alert_policy,
                    alert_key = %alert_key,
                    should_retry = should_retry,
                    should_alert = event.should_alert(),
                    is_auth_error = %error.is_auth_error(),
                    elapsed_ms = elapsed_ms,
                    error = %error,
                    "wxpay request failed"
                );
                Err(error)
            }
        }
    }

    /// 发送请求并反序列化 JSON 响应
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
    ) -> WxPayResult<T> {
        let response = self.send(method, path, body, operation).await?;
        let body = ResponseHandler::handle(&response)?;
        serde_json::from_str(body).map_err(WxPayError::from)
    }

    /// 发送请求并在空响应体时返回默认值
    pub async fn request_default<T: DeserializeOwned + Default>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
    ) -> WxPayResult<T> {
        let response = self.send(method, path, body, operation).await?;
        let body = ResponseHandler::handle(&response)?;
        if body.trim().is_empty() {
            return Ok(T::default());
        }

        serde_json::from_str(body).map_err(WxPayError::from)
    }
}
