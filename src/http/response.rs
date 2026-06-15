//! HTTP 响应处理模块
//!
//! 提供处理微信支付 API 响应的功能。

use serde::Deserialize;
use serde_json::Value;

use crate::error::{WxPayError, WxPayResult, ErrorResponse};
use crate::http::client::HttpResponse;

/// 响应处理器
///
/// 用于处理微信支付 API 响应。
#[derive(Debug, Clone)]
pub struct ResponseHandler;

impl ResponseHandler {
    /// 处理响应
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回响应体字符串
    pub fn handle(response: &HttpResponse) -> WxPayResult<&str> {
        if response.is_success() {
            Ok(&response.body)
        } else {
            Self::handle_error(response)
        }
    }

    fn extract_error_payload(response: &HttpResponse) -> Option<(String, String)> {
        if let Ok(error) = serde_json::from_str::<ErrorResponse>(&response.body) {
            return Some((error.code, error.message));
        }

        let value: Value = serde_json::from_str(&response.body).ok()?;

        let code = value
            .get("code")
            .and_then(Value::as_str)
            .or_else(|| value.get("error_code").and_then(Value::as_str))
            .or_else(|| value.get("errcode").and_then(Value::as_str))
            .map(ToOwned::to_owned);

        let message = value
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| value.get("error_message").and_then(Value::as_str))
            .or_else(|| value.get("errmsg").and_then(Value::as_str))
            .or_else(|| value.get("error_description").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .or_else(|| {
                value
                    .get("errors")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .and_then(|item| {
                        item.get("message")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .or_else(|| item.get("error").and_then(Value::as_str).map(ToOwned::to_owned))
                    })
            });

        match (code, message) {
            (Some(code), Some(message)) => Some((code, message)),
            _ => None,
        }
    }

    /// 处理错误响应
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回错误
    pub fn handle_error(response: &HttpResponse) -> WxPayResult<&str> {
        // 尝试解析错误响应
        if let Some((code, message)) = Self::extract_error_payload(response) {
            return Err(WxPayError::api(code, message));
        }

        // 如果无法解析，返回通用错误
        Err(WxPayError::UnexpectedStatusCode(response.status))
    }

    /// 解析响应体
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回解析后的结构体
    pub fn parse<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> WxPayResult<T> {
        let body = Self::handle(response)?;
        serde_json::from_str(body).map_err(WxPayError::from)
    }

    /// 获取响应头
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    /// * `name` - 头部名称
    ///
    /// # 返回
    ///
    /// 返回头部值
    pub fn get_header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
        response.get_header(name)
    }

    /// 获取请求 ID
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回请求 ID
    pub fn get_request_id(response: &HttpResponse) -> Option<&str> {
        response.get_header("Request-ID")
    }

    /// 获取微信支付签名
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回签名
    pub fn get_signature(response: &HttpResponse) -> Option<&str> {
        response.get_header("Wechatpay-Signature")
    }

    /// 获取微信支付证书序列号
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回证书序列号
    pub fn get_serial_number(response: &HttpResponse) -> Option<&str> {
        response.get_header("Wechatpay-Serial")
    }

    /// 获取微信支付时间戳
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回时间戳
    pub fn get_timestamp(response: &HttpResponse) -> Option<&str> {
        response.get_header("Wechatpay-Timestamp")
    }

    /// 获取微信支付随机字符串
    ///
    /// # 参数
    ///
    /// * `response` - HTTP 响应
    ///
    /// # 返回
    ///
    /// 返回随机字符串
    pub fn get_nonce(response: &HttpResponse) -> Option<&str> {
        response.get_header("Wechatpay-Nonce")
    }
}

/// 微信支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct WxPayResponse<T> {
    /// 响应数据
    #[serde(flatten)]
    pub data: T,

    /// 请求 ID
    #[serde(skip)]
    pub request_id: Option<String>,

    /// 签名
    #[serde(skip)]
    pub signature: Option<String>,

    /// 证书序列号
    #[serde(skip)]
    pub serial_number: Option<String>,

    /// 时间戳
    #[serde(skip)]
    pub timestamp: Option<String>,

    /// 随机字符串
    #[serde(skip)]
    pub nonce: Option<String>,
}

impl<T> WxPayResponse<T> {
    /// 创建新的响应
    pub fn new(data: T) -> Self {
        Self {
            data,
            request_id: None,
            signature: None,
            serial_number: None,
            timestamp: None,
            nonce: None,
        }
    }

    /// 设置请求 ID
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// 设置签名
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    /// 设置证书序列号
    pub fn with_serial_number(mut self, serial_number: impl Into<String>) -> Self {
        self.serial_number = Some(serial_number.into());
        self
    }

    /// 设置时间戳
    pub fn with_timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    /// 设置随机字符串
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

/// 空响应
#[derive(Debug, Clone, Deserialize)]
pub struct EmptyResponse {}

/// 分页响应
#[derive(Debug, Clone, Deserialize)]
pub struct PaginatedResponse<T> {
    /// 数据列表
    pub data: Vec<T>,

    /// 总数
    pub total: Option<u64>,

    /// 限制
    pub limit: Option<u64>,

    /// 偏移
    pub offset: Option<u64>,
}

/// 错误响应
#[derive(Debug, Clone, Deserialize)]
pub struct WxPayErrorResponse {
    /// 错误码
    pub code: String,

    /// 错误信息
    pub message: String,

    /// 错误详情
    #[serde(default)]
    pub detail: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_handler_success() {
        let response = HttpResponse::new(
            200,
            vec![],
            r#"{"code":"SUCCESS"}"#.to_string(),
        );

        let body = ResponseHandler::handle(&response).unwrap();
        assert_eq!(body, r#"{"code":"SUCCESS"}"#);
    }

    #[test]
    fn test_response_handler_error() {
        let response = HttpResponse::new(
            400,
            vec![],
            r#"{"code":"PARAM_ERROR","message":"参数错误"}"#.to_string(),
        );

        let result = ResponseHandler::handle(&response);
        assert!(result.is_err());

        match result.unwrap_err() {
            WxPayError::ApiError { code, message } => {
                assert_eq!(code, "PARAM_ERROR");
                assert_eq!(message, "参数错误");
            }
            _ => panic!("Expected ApiError"),
        }
    }

    #[test]
    fn test_response_handler_unexpected_status() {
        let response = HttpResponse::new(500, vec![], "Internal Server Error".to_string());

        let result = ResponseHandler::handle(&response);
        assert!(result.is_err());

        match result.unwrap_err() {
            WxPayError::UnexpectedStatusCode(status) => {
                assert_eq!(status, 500);
            }
            _ => panic!("Expected UnexpectedStatusCode"),
        }
    }

    #[test]
    fn test_response_handler_parse() {
        #[derive(Debug, Deserialize)]
        struct TestResponse {
            code: String,
        }

        let response = HttpResponse::new(
            200,
            vec![],
            r#"{"code":"SUCCESS"}"#.to_string(),
        );

        let parsed: TestResponse = ResponseHandler::parse(&response).unwrap();
        assert_eq!(parsed.code, "SUCCESS");
    }

    #[test]
    fn test_wxpay_response() {
        #[derive(Debug, Deserialize)]
        struct TestData {
            name: String,
        }

        let response = WxPayResponse::new(TestData {
            name: "test".to_string(),
        })
        .with_request_id("12345")
        .with_signature("test_signature")
        .with_serial_number("CERT123")
        .with_timestamp("1609459200")
        .with_nonce("test_nonce");

        assert_eq!(response.data.name, "test");
        assert_eq!(response.request_id, Some("12345".to_string()));
        assert_eq!(response.signature, Some("test_signature".to_string()));
        assert_eq!(response.serial_number, Some("CERT123".to_string()));
        assert_eq!(response.timestamp, Some("1609459200".to_string()));
        assert_eq!(response.nonce, Some("test_nonce".to_string()));
    }
}
