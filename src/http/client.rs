//! HTTP 客户端模块
//!
//! 提供基于 Reqwest 的 HTTP 客户端封装。

use std::time::Duration;

use async_trait::async_trait;
use rand::{RngExt, rng};
use reqwest::Client;
use tokio::time::sleep;

use crate::error::{WxPayError, WxPayResult};

/// HTTP 客户端 trait
///
/// 定义了发送 HTTP 请求的接口。
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// 发送 GET 请求
    async fn get(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse>;

    /// 发送 POST 请求
    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse>;

    /// 发送 PUT 请求
    async fn put(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse>;

    /// 发送 DELETE 请求
    async fn delete(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse>;

    /// 发送 PATCH 请求
    async fn patch(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse>;
}

/// HTTP 响应
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP 状态码
    pub status: u16,

    /// 响应头
    pub headers: Vec<(String, String)>,

    /// 响应体
    pub body: String,
}

impl HttpResponse {
    /// 创建新的 HTTP 响应
    pub fn new(status: u16, headers: Vec<(String, String)>, body: String) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// 获取响应头
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// 判断是否成功
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// 基于 Reqwest 的 HTTP 客户端
///
/// 使用 Reqwest 库实现的 HTTP 客户端。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::http::ReqwestHttpClient;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = ReqwestHttpClient::builder()
///     .timeout(30)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct ReqwestHttpClient {
    /// Reqwest 客户端
    client: Client,

    /// 最大重试次数
    max_retries: u32,
}

impl ReqwestHttpClient {
    /// 创建 HTTP 客户端构建器
    pub fn builder() -> ReqwestHttpClientBuilder {
        ReqwestHttpClientBuilder::new()
    }

    fn is_retriable_status(status: u16) -> bool {
        status == 429 || (500..=599).contains(&status)
    }

    fn retry_delay_ms(retry_count: u32) -> u64 {
        let base = 40_u64.saturating_mul(1_u64 << retry_count.min(8));
        let jitter = rng().random_range(0..=base / 2);
        base.saturating_add(jitter)
    }

    async fn read_response(response: reqwest::Response) -> WxPayResult<HttpResponse> {
        let status = response.status().as_u16();
        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response
            .text()
            .await
            .map_err(|e| WxPayError::ResponseParseError(format!("读取响应体失败：{}", e)))?;

        Ok(HttpResponse::new(status, response_headers, body))
    }

    async fn execute_with_retries<F>(
        &self,
        mut request_factory: F,
        retry_on_error: bool,
    ) -> WxPayResult<HttpResponse>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        for attempt in 0..=self.max_retries {
            let response = request_factory().send().await;

            match response {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let response = Self::read_response(response).await?;

                    if retry_on_error
                        && Self::is_retriable_status(status)
                        && attempt < self.max_retries
                    {
                        let delay = Duration::from_millis(Self::retry_delay_ms(attempt + 1));
                        sleep(delay).await;
                        continue;
                    }

                    return Ok(response);
                }
                Err(error) => {
                    if retry_on_error && attempt < self.max_retries {
                        let delay = Duration::from_millis(Self::retry_delay_ms(attempt + 1));
                        sleep(delay).await;
                        continue;
                    }

                    return Err(WxPayError::NetworkError(error));
                }
            }
        }

        Err(WxPayError::Timeout)
    }

    fn append_headers(
        request: reqwest::RequestBuilder,
        headers: &[(String, String)],
    ) -> reqwest::RequestBuilder {
        let mut request = request;

        for (name, value) in headers {
            request = request.header(name, value);
        }

        request
    }
}

/// Reqwest HTTP 客户端构建器
#[derive(Debug, Clone)]
pub struct ReqwestHttpClientBuilder {
    timeout: u64,
    max_idle_connections: usize,
    idle_timeout: u64,
    max_retries: u32,
}

impl ReqwestHttpClientBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            timeout: 30,
            max_idle_connections: 100,
            idle_timeout: 90,
            max_retries: 3,
        }
    }

    /// 设置请求超时时间（秒）
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置最大空闲连接数
    pub fn max_idle_connections(mut self, max_idle_connections: usize) -> Self {
        self.max_idle_connections = max_idle_connections;
        self
    }

    /// 设置空闲连接超时时间（秒）
    pub fn idle_timeout(mut self, idle_timeout: u64) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// 设置请求最大重试次数（重试 5xx、429 与网络错误）
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// 构建 HTTP 客户端
    pub fn build(self) -> WxPayResult<ReqwestHttpClient> {
        let client = Client::builder()
            .timeout(Duration::from_secs(self.timeout))
            .pool_max_idle_per_host(self.max_idle_connections)
            .pool_idle_timeout(Duration::from_secs(self.idle_timeout))
            .build()
            .map_err(|e| WxPayError::InternalError(format!("创建 HTTP 客户端失败：{}", e)))?;

        Ok(ReqwestHttpClient {
            client,
            max_retries: self.max_retries,
        })
    }
}

impl Default for ReqwestHttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        self.execute_with_retries(
            || {
                let request = self.client.get(url);
                Self::append_headers(request, &headers)
            },
            true,
        )
        .await
    }

    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        let body = body.to_string();

        self.execute_with_retries(
            move || {
                let request = self.client.post(url).body(body.clone());
                Self::append_headers(request, &headers)
            },
            false,
        )
        .await
    }

    async fn put(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        let body = body.to_string();

        self.execute_with_retries(
            move || {
                let request = self.client.put(url).body(body.clone());
                Self::append_headers(request, &headers)
            },
            false,
        )
        .await
    }

    async fn delete(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        self.execute_with_retries(
            || {
                let request = self.client.delete(url);
                Self::append_headers(request, &headers)
            },
            true,
        )
        .await
    }

    async fn patch(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        let body = body.to_string();

        self.execute_with_retries(
            move || {
                let request = self.client.patch(url).body(body.clone());
                Self::append_headers(request, &headers)
            },
            false,
        )
        .await
    }
}

impl std::fmt::Debug for ReqwestHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestHttpClient").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_response() {
        let response = HttpResponse::new(
            200,
            vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("X-Request-Id".to_string(), "12345".to_string()),
            ],
            r#"{"code":"SUCCESS"}"#.to_string(),
        );

        assert!(response.is_success());
        assert_eq!(response.status, 200);
        assert_eq!(
            response.get_header("Content-Type"),
            Some("application/json")
        );
        assert_eq!(response.get_header("X-Request-Id"), Some("12345"));
        assert_eq!(response.get_header("Non-Existent"), None);
    }

    #[test]
    fn test_http_response_not_success() {
        let response = HttpResponse::new(400, vec![], r#"{"code":"PARAM_ERROR"}"#.to_string());

        assert!(!response.is_success());
    }

    #[test]
    fn test_reqwest_http_client_builder() {
        let builder = ReqwestHttpClientBuilder::new()
            .timeout(60)
            .max_idle_connections(50)
            .idle_timeout(120)
            .max_retries(3);

        assert_eq!(builder.timeout, 60);
        assert_eq!(builder.max_idle_connections, 50);
        assert_eq!(builder.idle_timeout, 120);
        assert_eq!(builder.max_retries, 3);
    }

    #[test]
    fn test_reqwest_http_client_builder_default() {
        let builder = ReqwestHttpClientBuilder::default();
        assert_eq!(builder.timeout, 30);
        assert_eq!(builder.max_idle_connections, 100);
        assert_eq!(builder.idle_timeout, 90);
        assert_eq!(builder.max_retries, 3);
    }
}
