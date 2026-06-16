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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Sha256RsaSigner;
    use crate::config::WxPayConfig;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// 与 auth/verifier 测试同源的测试私钥（PEM），用于构造可实际签名的签名器。
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDQFwtb0xnMYumg\neu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz\n05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2\nL9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoe\naK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/r\nXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhf\nSes6QE3tAgMBAAECgf8ZVV+Mo6arELULVJaxcBj+WjW/epK3s4lhxSLDYx1LXKQo\nJa+FIw5dL3hBc5BwW7kUdHh33ikLGKdq3S4UjJlQ+XWNgYRpIDCCitpeRurF1G8i\npKp5m9u8Y29K7YhcnF/iVyuaDhuhFhh79avGDZjCpg/ni+6PKssc7llTYNy5MGya\nBNkxzXX2Oo5WI1IBOptOEUb6iWYz5FoAf91Ai0K8mFuB5tPCv67DqB2Rq4c6LMoX\nVzwzMZ64GhzYC6vyjltzMjtYTIDvheOZsOUgJe1pAaChwiGRDpmuf8/oybSQFFsy\n1PYF+TddnNk0NOQCPI0qXLHE2OXtdDAigPiA5v8CgYEA6/BnV4O/ZS34WvaGucPx\nQp9s59FolMyWtwELLxOZaO1LPAa9pdNC1+IfUl6zpeRu2z1kNG9f2TbgtTVrF7Lu\n5XvuhJ2OqnL8GgGYpS0vj2Sx5XRO8/pgxiAnpRy7Mkp1jA4+ZTpNQH3FoA6LZZfM\n1v/ijOH9NeHUWEw64OE/OoMCgYEA4ch19Yp73ijLvEUyAkqYrvPOkm7G02mlRD4T\nTUe2tGe8HUbOZGi5CphvItto9mssPDDsEVLilkrPDKlg3899L+ZLE8vHzw6QVoaK\n8LDQaapWbW3LazwLAna4kpNDd06h+Rx7j/n1lha6Vj/2dbEQhAAllos92B7SCNf8\nYIiXqs8CgYACC3tZztKB1fwpDantQj19DlSrTa1SXNORkni+V7Ukq6nTQ1uxbDtQ\nE62h0SBNd8VeMRIFQlHaWBdqeqQK+IoJgyF2FMd/wq9cqlbgV5vp6j2Ad5mXk7vy\n+6RcUfttXCfYpubziaXRwUVNNdMPdllYI6+a+Ppw1Rw6B68a89jQcQKBgFaW+JY4\njBTBdJE5wFocnb3LBxgln98IjzdCz0g+DpXVitF3jEP53a1wlH67wt9ubsKOyJpE\nPV4CRrHGa76p5oruOTDYYELKhRSJ+NMiHGvJxeelyfPQTTCes16TV7Zz066j+8dV\nx5fOE5xsX2r3gyv8mm3H7OnruAVoQAQNno0FAoGBAOvD07di46NEaY7OTGzt4JwE\nWa/0KzWvrQ6SCaHUnZ1yIqL6jEV7RCxKGr206cW9nlG2+n2QqAC8dinDrdLspLZG\noEqm/DoCUaghQOGnh7teguj3eqS+MHU5T/ugSJdJoMNtpQ/BlSnqkWLPoh+yrvh5\nmVKYyABhNkZONhC533bA\n-----END PRIVATE KEY-----\n";

    fn test_config() -> Arc<WxPayConfig> {
        let config = WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .private_key(TEST_PRIVATE_KEY_PEM.as_bytes().to_vec())
            .cert_serial_number("CERT123456")
            .build()
            .unwrap();
        Arc::new(config)
    }

    fn test_signer() -> Arc<dyn Signer> {
        Arc::new(
            Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456")
                .unwrap(),
        )
    }

    /// 记录单次请求的 mock HTTP 客户端，可配置返回的响应。
    struct MockHttpClient {
        response: HttpResponse,
        captured_url: Mutex<Option<String>>,
        captured_headers: Mutex<Vec<(String, String)>>,
        captured_body: Mutex<Option<String>>,
    }

    impl MockHttpClient {
        fn new(status: u16, body: &str) -> Self {
            Self {
                response: HttpResponse::new(
                    status,
                    vec![("Request-ID".to_string(), "mock-req-001".to_string())],
                    body.to_string(),
                ),
                captured_url: Mutex::new(None),
                captured_headers: Mutex::new(Vec::new()),
                captured_body: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn get(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers.clone();
            Ok(self.response.clone())
        }
        async fn post(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
            body: &str,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers.clone();
            *self.captured_body.lock().unwrap() = Some(body.to_string());
            Ok(self.response.clone())
        }
        async fn put(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
            body: &str,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers;
            *self.captured_body.lock().unwrap() = Some(body.to_string());
            Ok(self.response.clone())
        }
        async fn delete(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers;
            Ok(self.response.clone())
        }
        async fn patch(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
            body: &str,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers;
            *self.captured_body.lock().unwrap() = Some(body.to_string());
            Ok(self.response.clone())
        }
    }

    fn build_transport(http: Arc<MockHttpClient>) -> ServiceTransport {
        ServiceTransport::new(test_config(), http, test_signer())
    }

    #[tokio::test]
    async fn test_request_signs_and_parses_success() {
        let http = Arc::new(MockHttpClient::new(200, r#"{"prepay_id":"wx20240101"}"#));
        let transport = build_transport(http.clone());

        #[derive(serde::Deserialize)]
        struct Prepay {
            prepay_id: String,
        }

        let body = r#"{"app_id":"wx88888888"}"#;
        let resp: Prepay = transport
            .request(
                HttpMethod::Post,
                "/v3/pay/transactions/jsapi",
                Some(body),
                "test",
            )
            .await
            .unwrap();

        assert_eq!(resp.prepay_id, "wx20240101");

        // 验证请求被签名：Authorization 头存在且包含商户号与序列号。
        let headers = http.captured_headers.lock().unwrap().clone();
        let auth = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
            .map(|(_, v)| v.as_str())
            .expect("应携带 Authorization 头");
        assert!(auth.starts_with("WECHATPAY2-SHA256-RSA2048 "));
        assert!(auth.contains("mchid=\"1900000109\""));
        assert!(auth.contains("serial_no=\"CERT123456\""));
        assert!(auth.contains("signature=\""));

        // 验证 URL 被正确拼接为完整地址。
        let url = http.captured_url.lock().unwrap().clone().unwrap();
        assert_eq!(
            url,
            "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi"
        );

        // 验证请求体被透传。
        let captured_body = http.captured_body.lock().unwrap().clone().unwrap();
        assert_eq!(captured_body, body);
    }

    #[tokio::test]
    async fn test_request_default_handles_empty_body() {
        let http = Arc::new(MockHttpClient::new(204, ""));
        let transport = build_transport(http);

        #[derive(serde::Deserialize, Default)]
        struct Empty;

        // 空响应体应返回默认值，而非 JSON 解析错误。
        let resp: Empty = transport
            .request_default(HttpMethod::Post, "/v3/pay/close", Some("{}"), "test")
            .await
            .unwrap();
        let _ = resp;
    }

    #[tokio::test]
    async fn test_api_error_is_classified() {
        // 返回限流错误码，验证 transport 将其归一为 ApiError 并正确分类。
        let http = Arc::new(MockHttpClient::new(
            429,
            r#"{"code":"FREQ_LIMIT","message":"请求过于频繁"}"#,
        ));
        let transport = build_transport(http);

        let err = transport
            .request::<serde_json::Value>(HttpMethod::Get, "/v3/pay/transactions/x", None, "test")
            .await
            .unwrap_err();

        match &err {
            WxPayError::ApiError { code, message } => {
                assert_eq!(code, "FREQ_LIMIT");
                assert_eq!(message, "请求过于频繁");
            }
            other => panic!("应为 ApiError，实际: {other:?}"),
        }
        // 限流应被分类为 RateLimited 且建议重试。
        assert_eq!(err.api_kind(), Some(WxPayErrorKind::RateLimited));
        assert!(err.should_retry());
    }

    /// 记录 observer 回调的简单实现。
    struct CountingObserver {
        success: std::sync::atomic::AtomicUsize,
        error: std::sync::atomic::AtomicUsize,
        last_event: Mutex<Option<TransportEvent>>,
    }

    impl CountingObserver {
        fn new() -> Self {
            Self {
                success: std::sync::atomic::AtomicUsize::new(0),
                error: std::sync::atomic::AtomicUsize::new(0),
                last_event: Mutex::new(None),
            }
        }
    }

    impl TransportObserver for CountingObserver {
        fn on_success(&self, event: &TransportEvent) {
            self.success
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_event.lock().unwrap() = Some(clone_event(event));
        }
        fn on_error(&self, event: &TransportEvent, _error: &WxPayError) {
            self.error.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_event.lock().unwrap() = Some(clone_event(event));
        }
    }

    // TransportEvent 字段较多，手工克隆以避免为测试派生 Clone。
    fn clone_event(e: &TransportEvent) -> TransportEvent {
        TransportEvent {
            operation: e.operation.clone(),
            method: e.method.clone(),
            path: e.path.clone(),
            status: e.status,
            request_id: e.request_id.clone(),
            elapsed_ms: e.elapsed_ms,
            merchant_id: e.merchant_id.clone(),
            app_id: e.app_id.clone(),
            is_success: e.is_success,
            error_code: e.error_code.clone(),
            error_kind: e.error_kind,
            alert_level: e.alert_level,
            alert_policy: e.alert_policy.clone(),
            should_retry: e.should_retry,
            is_auth_error: e.is_auth_error,
        }
    }

    #[tokio::test]
    async fn test_observer_fires_on_success_and_error() {
        // 成功路径触发 on_success。
        let observer = Arc::new(CountingObserver::new());
        let http = Arc::new(MockHttpClient::new(200, r#"{"ok":true}"#));
        let transport = ServiceTransport::new_with_observer(
            test_config(),
            http,
            test_signer(),
            Some(observer.clone()),
        );
        let _: serde_json::Value = transport
            .request(HttpMethod::Get, "/v3/any", None, "ok-op")
            .await
            .unwrap();
        assert_eq!(
            observer.success.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        {
            let evt = observer.last_event.lock().unwrap();
            let evt = evt.as_ref().unwrap();
            assert!(evt.is_success);
            assert_eq!(evt.operation, "ok-op");
            assert_eq!(evt.status, 200);
            assert_eq!(evt.alert_policy, "success");
        }

        // 错误路径触发 on_error，且事件携带错误分类。
        let observer2 = Arc::new(CountingObserver::new());
        let http2 = Arc::new(MockHttpClient::new(
            401,
            r#"{"code":"SIGN_ERROR","message":"签名错误"}"#,
        ));
        let transport2 = ServiceTransport::new_with_observer(
            test_config(),
            http2,
            test_signer(),
            Some(observer2.clone()),
        );
        let _: Result<serde_json::Value, _> = transport2
            .request(HttpMethod::Get, "/v3/any", None, "err-op")
            .await;
        assert_eq!(observer2.error.load(std::sync::atomic::Ordering::SeqCst), 1);
        let evt = observer2.last_event.lock().unwrap();
        let evt = evt.as_ref().unwrap();
        assert!(!evt.is_success);
        assert_eq!(evt.error_kind, Some(WxPayErrorKind::Authentication));
        assert!(evt.is_auth_error);
        assert_eq!(evt.alert_policy, "security.auth");
    }

    #[tokio::test]
    async fn test_transport_event_helpers() {
        let evt = TransportEvent::success("op", "GET", "/v3/x", &test_config(), 200, "req-1", 42);
        assert_eq!(evt.alert_key(), "low.success");
        assert!(!evt.should_alert());

        let err = WxPayError::Timeout;
        let err_evt = TransportEvent::error(
            &test_config(),
            TransportErrorContext {
                operation: "op",
                method: "GET",
                path: "/v3/x",
                status: 0,
                request_id: "req-1",
                elapsed_ms: 42,
                error: &err,
            },
        );
        assert_eq!(err_evt.error_kind_label(), "non_api");
        assert!(err_evt.should_alert());
        assert_eq!(err_evt.alert_key(), "critical.network");
    }
}
