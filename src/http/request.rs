//! HTTP 请求构建器
//!
//! 提供构建微信支付 API 请求的功能。

use std::collections::HashMap;
use serde::Serialize;

use crate::error::WxPayResult;
use crate::utils::nonce::generate_nonce;
use crate::utils::timestamp::get_timestamp;

/// HTTP 请求方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET 请求
    Get,
    /// POST 请求
    Post,
    /// PUT 请求
    Put,
    /// DELETE 请求
    Delete,
    /// PATCH 请求
    Patch,
}

impl HttpMethod {
    /// 获取 HTTP 方法字符串
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
        }
    }
}

/// HTTP 请求构建器
///
/// 用于构建微信支付 API 请求。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::http::RequestBuilder;
/// use wxpay_rs::http::request::HttpMethod;
///
/// let request = RequestBuilder::new(HttpMethod::Post, "/v3/pay/transactions/jsapi")
///     .body(r#"{"app_id":"wx88888888"}"#)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    /// HTTP 方法
    method: HttpMethod,

    /// 请求路径
    path: String,

    /// 请求头
    headers: HashMap<String, String>,

    /// 请求体
    body: Option<String>,

    /// 时间戳
    timestamp: Option<i64>,

    /// 随机字符串
    nonce: Option<String>,
}

impl RequestBuilder {
    /// 创建新的请求构建器
    ///
    /// # 参数
    ///
    /// * `method` - HTTP 方法
    /// * `path` - 请求路径
    ///
    /// # 返回
    ///
    /// 返回请求构建器实例
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            body: None,
            timestamp: None,
            nonce: None,
        }
    }

    /// 设置请求头
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// 设置请求体
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// 设置 JSON 请求体
    pub fn json_body<T: Serialize>(self, value: &T) -> WxPayResult<Self> {
        let json = serde_json::to_string(value)?;
        Ok(self.body(json))
    }

    /// 设置时间戳
    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// 设置随机字符串
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// 构建请求
    pub fn build(self) -> WxPayRequest {
        let timestamp = self.timestamp.unwrap_or_else(get_timestamp);
        let nonce = self.nonce.unwrap_or_else(generate_nonce);

        WxPayRequest {
            method: self.method,
            path: self.path,
            headers: self.headers,
            body: self.body,
            timestamp,
            nonce,
        }
    }
}

/// 微信支付请求
#[derive(Debug, Clone)]
pub struct WxPayRequest {
    /// HTTP 方法
    pub method: HttpMethod,

    /// 请求路径
    pub path: String,

    /// 请求头
    pub headers: HashMap<String, String>,

    /// 请求体
    pub body: Option<String>,

    /// 时间戳
    pub timestamp: i64,

    /// 随机字符串
    pub nonce: String,
}

impl WxPayRequest {
    /// 获取 HTTP 方法字符串
    pub fn method_str(&self) -> &str {
        self.method.as_str()
    }

    /// 获取签名消息
    ///
    /// 微信支付 API v3 签名格式：
    /// HTTP_METHOD\nURL_PATH\nTIMESTAMP\nNONCE_STR\nBODY\n
    pub fn sign_message(&self) -> String {
        let body = self.body.as_deref().unwrap_or("");
        format!(
            "{}\n{}\n{}\n{}\n{}\n",
            self.method_str(),
            self.path,
            self.timestamp,
            self.nonce,
            body
        )
    }

    /// 获取完整 URL
    pub fn full_url(&self, base_url: &str) -> String {
        format!("{}{}", base_url, self.path)
    }

    /// 获取请求体
    pub fn body_str(&self) -> &str {
        self.body.as_deref().unwrap_or("")
    }

    /// 构建请求头列表
    pub fn headers_vec(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// 微信支付请求构建器
///
/// 专门用于构建微信支付 API 请求的构建器。
#[allow(dead_code)]
pub struct WxPayRequestBuilder {
    /// 商户号
    merchant_id: String,

    /// 证书序列号
    cert_serial_number: String,

    /// API 基础 URL
    base_url: String,
}

impl WxPayRequestBuilder {
    /// 创建新的请求构建器
    pub fn new(
        merchant_id: impl Into<String>,
        cert_serial_number: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            merchant_id: merchant_id.into(),
            cert_serial_number: cert_serial_number.into(),
            base_url: base_url.into(),
        }
    }

    /// 构建 GET 请求
    pub fn get(&self, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::Get, path)
    }

    /// 构建 POST 请求
    pub fn post(&self, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::Post, path)
    }

    /// 构建 PUT 请求
    pub fn put(&self, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::Put, path)
    }

    /// 构建 DELETE 请求
    pub fn delete(&self, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::Delete, path)
    }

    /// 构建 PATCH 请求
    pub fn patch(&self, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::Patch, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder() {
        let request = RequestBuilder::new(HttpMethod::Post, "/v3/pay/transactions/jsapi")
            .body(r#"{"app_id":"wx88888888"}"#)
            .timestamp(1609459200)
            .nonce("test_nonce")
            .build();

        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, "/v3/pay/transactions/jsapi");
        assert_eq!(request.timestamp, 1609459200);
        assert_eq!(request.nonce, "test_nonce");
        assert!(request.body.is_some());
    }

    #[test]
    fn test_request_sign_message() {
        let request = RequestBuilder::new(HttpMethod::Post, "/v3/pay/transactions/jsapi")
            .body(r#"{"app_id":"wx88888888"}"#)
            .timestamp(1609459200)
            .nonce("test_nonce")
            .build();

        let sign_message = request.sign_message();
        assert!(sign_message.starts_with("POST\n"));
        assert!(sign_message.contains("/v3/pay/transactions/jsapi"));
        assert!(sign_message.contains("1609459200"));
        assert!(sign_message.contains("test_nonce"));
        assert!(sign_message.ends_with("\n"));
    }

    #[test]
    fn test_request_full_url() {
        let request = RequestBuilder::new(HttpMethod::Get, "/v3/pay/transactions/jsapi")
            .build();

        let full_url = request.full_url("https://api.mch.weixin.qq.com");
        assert_eq!(full_url, "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi");
    }

    #[test]
    fn test_request_headers() {
        let request = RequestBuilder::new(HttpMethod::Post, "/v3/pay/transactions/jsapi")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .build();

        let headers = request.headers_vec();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
    }

    #[test]
    fn test_wxpay_request_builder() {
        let builder = WxPayRequestBuilder::new(
            "1900000109",
            "CERT123456",
            "https://api.mch.weixin.qq.com",
        );

        let request = builder.post("/v3/pay/transactions/jsapi").build();
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, "/v3/pay/transactions/jsapi");
    }
}
