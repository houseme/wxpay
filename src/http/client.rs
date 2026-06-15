//! HTTP 客户端模块
//!
//! 提供基于 Reqwest 的 HTTP 客户端封装。

use std::time::Duration;
use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;

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
    async fn delete(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> WxPayResult<HttpResponse>;

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
}

impl ReqwestHttpClient {
    /// 创建 HTTP 客户端构建器
    pub fn builder() -> ReqwestHttpClientBuilder {
        ReqwestHttpClientBuilder::new()
    }
}

/// Reqwest HTTP 客户端构建器
#[derive(Debug, Clone)]
pub struct ReqwestHttpClientBuilder {
    timeout: u64,
    max_idle_connections: usize,
    idle_timeout: u64,
}

impl ReqwestHttpClientBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            timeout: 30,
            max_idle_connections: 100,
            idle_timeout: 90,
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

    /// 构建 HTTP 客户端
    pub fn build(self) -> WxPayResult<ReqwestHttpClient> {
        let client = Client::builder()
            .timeout(Duration::from_secs(self.timeout))
            .pool_max_idle_per_host(self.max_idle_connections)
            .pool_idle_timeout(Duration::from_secs(self.idle_timeout))
            .build()
            .map_err(|e| WxPayError::InternalError(format!("创建 HTTP 客户端失败：{}", e)))?;

        Ok(ReqwestHttpClient { client })
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
        let mut request = self.client.get(url);

        for (name, value) in headers {
            request = request.header(&name, &value);
        }

        let response = request
            .send()
            .await
            .map_err(WxPayError::NetworkError)?;

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

    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        let mut request = self.client.post(url);

        for (name, value) in headers {
            request = request.header(&name, &value);
        }

        let response = request
            .body(body.to_string())
            .send()
            .await
            .map_err(WxPayError::NetworkError)?;

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

    async fn put(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        let mut request = self.client.put(url);

        for (name, value) in headers {
            request = request.header(&name, &value);
        }

        let response = request
            .body(body.to_string())
            .send()
            .await
            .map_err(WxPayError::NetworkError)?;

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

    async fn delete(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> WxPayResult<HttpResponse> {
        let mut request = self.client.delete(url);

        for (name, value) in headers {
            request = request.header(&name, &value);
        }

        let response = request
            .send()
            .await
            .map_err(WxPayError::NetworkError)?;

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

    async fn patch(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        let mut request = self.client.patch(url);

        for (name, value) in headers {
            request = request.header(&name, &value);
        }

        let response = request
            .body(body.to_string())
            .send()
            .await
            .map_err(WxPayError::NetworkError)?;

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
        let response = HttpResponse::new(
            400,
            vec![],
            r#"{"code":"PARAM_ERROR"}"#.to_string(),
        );

        assert!(!response.is_success());
    }

    #[test]
    fn test_reqwest_http_client_builder() {
        let builder = ReqwestHttpClientBuilder::new()
            .timeout(60)
            .max_idle_connections(50)
            .idle_timeout(120);

        assert_eq!(builder.timeout, 60);
        assert_eq!(builder.max_idle_connections, 50);
        assert_eq!(builder.idle_timeout, 120);
    }

    #[test]
    fn test_reqwest_http_client_builder_default() {
        let builder = ReqwestHttpClientBuilder::default();
        assert_eq!(builder.timeout, 30);
        assert_eq!(builder.max_idle_connections, 100);
        assert_eq!(builder.idle_timeout, 90);
    }
}
