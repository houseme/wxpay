//! 微信支付 SDK 错误类型定义
//!
//! 定义了 SDK 中所有可能的错误类型，使用 thiserror 进行派生。

use thiserror::Error;
use serde_json::Value;

/// 微信支付 SDK 结果类型别名
pub type WxPayResult<T> = Result<T, WxPayError>;

/// 微信支付错误码分类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WxPayErrorKind {
    /// 参数错误
    InvalidParameter,
    /// 鉴权失败
    Authentication,
    /// 签名或验签异常
    Signature,
    /// 资源不存在
    ResourceNotFound,
    /// 超频/限流
    RateLimited,
    /// 业务受限
    BusinessBlocked,
    /// 系统内部错误
    Internal,
    /// 未知错误码
    Unknown,
}

/// 告警级别（用于日志告警策略）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WxPayAlertLevel {
    /// 观察
    Low,
    /// 注意
    Medium,
    /// 严重
    High,
    /// 紧急
    Critical,
}

impl WxPayAlertLevel {
    /// 转字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl WxPayErrorKind {
    /// 转字符串（用于告警/指标标签）
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidParameter => "invalid_parameter",
            Self::Authentication => "authentication",
            Self::Signature => "signature",
            Self::ResourceNotFound => "resource_not_found",
            Self::RateLimited => "rate_limited",
            Self::BusinessBlocked => "business_blocked",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        }
    }

    /// 从微信错误码映射到统一错误分类
    pub fn from_code(code: &str) -> Self {
        match code {
            "PARAM_ERROR" | "INVALID_REQUEST" | "INVALID_PARAMETER" => Self::InvalidParameter,
            "NO_AUTH" | "SIGN_ERROR" | "INVALID_SIGN" | "PERMISSION_DENIED" | "AUTH_ERROR" | "INVALID_CREDENTIAL" => {
                Self::Authentication
            }
            "SIGNATURE_ERROR" | "VERIFY_SIGNATURE_ERROR" => Self::Signature,
            "ORDER_NOT_EXIST" | "NOT_FOUND" | "RESOURCE_NOT_FOUND" => Self::ResourceNotFound,
            "FREQ_LIMIT" | "RATE_LIMIT" | "V2_API_DISABLED" => Self::RateLimited,
            "NO_AUTHORITY" | "NOT_PERMIT" | "ILLEGAL_REQUEST" => Self::BusinessBlocked,
            "SYSTEM_ERROR" | "SERVICE_UNAVAILABLE" => Self::Internal,
            _ => Self::Unknown,
        }
    }
}

impl From<WxPayErrorKind> for WxPayAlertLevel {
    fn from(kind: WxPayErrorKind) -> Self {
        match kind {
            WxPayErrorKind::Authentication | WxPayErrorKind::Signature => Self::Critical,
            WxPayErrorKind::RateLimited | WxPayErrorKind::BusinessBlocked => Self::High,
            WxPayErrorKind::Internal => Self::High,
            WxPayErrorKind::ResourceNotFound => Self::Medium,
            WxPayErrorKind::InvalidParameter | WxPayErrorKind::Unknown => Self::Low,
        }
    }
}

/// 微信支付 SDK 错误类型
#[derive(Error, Debug)]
pub enum WxPayError {
    // ========== 配置错误 ==========
    /// 配置错误
    #[error("配置错误：{message}")]
    ConfigError { message: String },

    /// 无效的私钥
    #[error("无效的私钥：{0}")]
    InvalidPrivateKey(String),

    /// 无效的证书
    #[error("无效的证书：{0}")]
    InvalidCertificate(String),

    /// 缺少必填配置项
    #[error("缺少必填配置项：{field}")]
    MissingConfig { field: String },

    // ========== 签名与验签错误 ==========
    /// 签名生成失败
    #[error("签名生成失败：{0}")]
    SignError(String),

    /// 签名验证失败
    #[error("签名验证失败")]
    SignatureVerificationFailed,

    /// 无效的签名格式
    #[error("无效的签名格式：{0}")]
    InvalidSignatureFormat(String),

    // ========== 加解密错误 ==========
    /// 加密失败
    #[error("加密失败：{0}")]
    EncryptionError(String),

    /// 解密失败
    #[error("解密失败：{0}")]
    DecryptionError(String),

    /// 无效的密钥
    #[error("无效的密钥：{0}")]
    InvalidKey(String),

    /// 无效的密文格式
    #[error("无效的密文格式：{0}")]
    InvalidCiphertext(String),

    // ========== 证书错误 ==========
    /// 证书下载失败
    #[error("证书下载失败：{0}")]
    CertificateDownloadError(String),

    /// 证书解析失败
    #[error("证书解析失败：{0}")]
    CertificateParseError(String),

    /// 证书已过期
    #[error("证书已过期")]
    CertificateExpired,

    /// 证书验证失败
    #[error("证书验证失败：{0}")]
    CertificateVerificationError(String),

    /// 找不到匹配的证书
    #[error("找不到匹配的证书：serial_number={0}")]
    CertificateNotFound(String),

    // ========== HTTP 错误 ==========
    /// 网络错误
    #[error("网络错误：{0}")]
    NetworkError(#[from] reqwest::Error),

    /// HTTP 请求构建失败
    #[error("HTTP 请求构建失败：{0}")]
    RequestBuildError(String),

    /// HTTP 响应解析失败
    #[error("HTTP 响应解析失败：{0}")]
    ResponseParseError(String),

    /// 请求超时
    #[error("请求超时")]
    Timeout,

    // ========== API 错误 ==========
    /// 微信支付 API 错误
    #[error("API 错误：code={code}, message={message}")]
    ApiError {
        /// 错误码
        code: String,
        /// 错误信息
        message: String,
    },

    /// API 返回了意外的状态码
    #[error("意外的 HTTP 状态码：{0}")]
    UnexpectedStatusCode(u16),

    /// 业务逻辑错误
    #[error("业务错误：{0}")]
    BusinessError(String),

    // ========== 通知错误 ==========
    /// 通知签名验证失败
    #[error("通知签名验证失败")]
    NotifySignatureVerificationFailed,

    /// 通知解密失败
    #[error("通知解密失败：{0}")]
    NotifyDecryptionError(String),

    /// 无效的通知格式
    #[error("无效的通知格式：{0}")]
    InvalidNotifyFormat(String),

    /// 无效的通知类型
    #[error("无效的通知类型：{0}")]
    InvalidNotifyType(String),

    // ========== 序列化错误 ==========
    /// JSON 序列化/反序列化错误
    #[error("JSON 错误：{0}")]
    JsonError(#[from] serde_json::Error),

    /// URL 编码错误
    #[error("URL 编码错误：{0}")]
    UrlEncodeError(String),

    /// URL 解析错误
    #[error("URL 解析错误：{0}")]
    UrlParseError(#[from] url::ParseError),

    // ========== 其他错误 ==========
    /// 内部错误
    #[error("内部错误：{0}")]
    InternalError(String),

    /// 不支持的操作
    #[error("不支持的操作：{0}")]
    UnsupportedOperation(String),

    /// 参数错误
    #[error("参数错误：{0}")]
    InvalidParameter(String),
}

/// HTTP 错误响应
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ErrorResponse {
    /// 错误码
    pub code: String,
    /// 错误信息
    pub message: String,
    /// 透传错误明细
    pub detail: Option<Value>,
}

impl WxPayError {
    /// 创建配置错误
    pub fn config(message: impl Into<String>) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }

    /// 创建缺少配置项错误
    pub fn missing_config(field: impl Into<String>) -> Self {
        Self::MissingConfig {
            field: field.into(),
        }
    }

    /// 创建签名错误
    pub fn sign(message: impl Into<String>) -> Self {
        Self::SignError(message.into())
    }

    /// 创建加密错误
    pub fn encryption(message: impl Into<String>) -> Self {
        Self::EncryptionError(message.into())
    }

    /// 创建解密错误
    pub fn decryption(message: impl Into<String>) -> Self {
        Self::DecryptionError(message.into())
    }

    /// 创建证书错误
    pub fn certificate_parse(message: impl Into<String>) -> Self {
        Self::CertificateParseError(message.into())
    }

    /// 创建证书下载错误
    pub fn certificate_download(message: impl Into<String>) -> Self {
        Self::CertificateDownloadError(message.into())
    }

    /// 创建证书验证错误
    pub fn certificate_verification(message: impl Into<String>) -> Self {
        Self::CertificateVerificationError(message.into())
    }

    /// 创建 API 错误
    pub fn api(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ApiError {
            code: code.into(),
            message: message.into(),
        }
    }

    /// 创建内部错误
    pub fn internal(message: impl Into<String>) -> Self {
        Self::InternalError(message.into())
    }

    /// 创建参数错误
    pub fn invalid_parameter(message: impl Into<String>) -> Self {
        Self::InvalidParameter(message.into())
    }

    /// 创建业务错误
    pub fn business(message: impl Into<String>) -> Self {
        Self::BusinessError(message.into())
    }

    /// 获取 API 错误分类
    pub fn api_kind(&self) -> Option<WxPayErrorKind> {
        match self {
            Self::ApiError { code, .. } => Some(WxPayErrorKind::from_code(code)),
            _ => None,
        }
    }

    /// 获取 API 错误码
    pub fn api_code(&self) -> Option<&str> {
        match self {
            Self::ApiError { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }

    /// 告警级别（用于结构化日志告警策略）
    pub fn alert_level(&self) -> WxPayAlertLevel {
        match self {
            Self::NetworkError(_) | Self::Timeout => WxPayAlertLevel::Critical,
            Self::ApiError { code, .. } => WxPayErrorKind::from_code(code).into(),
            Self::CertificateExpired
            | Self::CertificateVerificationError(_)
            | Self::CertificateDownloadError(_)
            | Self::CertificateNotFound(_)
            | Self::CertificateParseError(_)
            | Self::SignatureVerificationFailed => WxPayAlertLevel::High,
            Self::UnexpectedStatusCode(status) => {
                if *status >= 500 {
                    WxPayAlertLevel::High
                } else {
                    WxPayAlertLevel::Medium
                }
            }
            Self::SignError(_)
            | Self::InvalidSignatureFormat(_)
            | Self::RequestBuildError(_)
            | Self::ResponseParseError(_)
            | Self::JsonError(_)
            | Self::BusinessError(_) => WxPayAlertLevel::High,
            Self::InternalError(_) | Self::EncryptionError(_) | Self::DecryptionError(_) => {
                WxPayAlertLevel::Medium
            }
            _ => WxPayAlertLevel::Low,
        }
    }

    /// 告警策略键（用于指标/告警策略路由）
    pub fn alert_policy(&self) -> &'static str {
        match self {
            Self::ApiError { code, .. } => match WxPayErrorKind::from_code(code) {
                WxPayErrorKind::Authentication => "security.auth",
                WxPayErrorKind::Signature => "security.signature",
                WxPayErrorKind::RateLimited => "business.ratelimit",
                WxPayErrorKind::ResourceNotFound => "business.notfound",
                WxPayErrorKind::BusinessBlocked => "business.blocked",
                WxPayErrorKind::InvalidParameter => "params.invalid",
                WxPayErrorKind::Internal => "system.internal",
                WxPayErrorKind::Unknown => "unknown",
            },
            Self::NetworkError(_) | Self::Timeout => "network",
            Self::SignatureVerificationFailed | Self::SignError(_) | Self::InvalidSignatureFormat(_) => {
                "security.signature"
            }
            Self::CertificateExpired | Self::CertificateVerificationError(_) | Self::CertificateParseError(_) |
            Self::CertificateDownloadError(_) | Self::CertificateNotFound(_) => "certificate",
            Self::UnexpectedStatusCode(status) if *status >= 500 => "system.internal",
            Self::UnexpectedStatusCode(status) if *status >= 400 => "business.http",
            Self::UnexpectedStatusCode(_) => "business.http",
            Self::InternalError(_) => "system.internal",
            _ => "unknown",
        }
    }

    /// 是否建议重试
    pub fn should_retry(&self) -> bool {
        match self {
            Self::NetworkError(_) | Self::Timeout => true,
            Self::UnexpectedStatusCode(status) if *status >= 500 => true,
            Self::ApiError { code, .. } => matches!(
                WxPayErrorKind::from_code(code),
                WxPayErrorKind::RateLimited | WxPayErrorKind::Internal
            ),
            _ => false,
        }
    }

    /// 判断是否为网络错误
    pub fn is_network_error(&self) -> bool {
        matches!(self, Self::NetworkError(_) | Self::Timeout)
    }

    /// 判断是否为 API 错误
    pub fn is_api_error(&self) -> bool {
        matches!(self, Self::ApiError { .. })
    }

    /// 判断是否为鉴权相关错误
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self.api_kind(),
            Some(WxPayErrorKind::Authentication | WxPayErrorKind::Signature)
        )
    }

    /// 判断是否为签名/验签错误
    pub fn is_signature_error(&self) -> bool {
        matches!(
            self,
            Self::SignError(_) | Self::SignatureVerificationFailed | Self::InvalidSignatureFormat(_)
        )
    }

    /// 判断是否为证书错误
    pub fn is_certificate_error(&self) -> bool {
        matches!(
            self,
            Self::CertificateExpired
                | Self::CertificateNotFound(_)
                | Self::CertificateParseError(_)
                | Self::CertificateDownloadError(_)
                | Self::CertificateVerificationError(_)
        )
    }
}

/// 从 base64 错误转换
impl From<base64::DecodeError> for WxPayError {
    fn from(err: base64::DecodeError) -> Self {
        Self::InternalError(format!("Base64 解码错误：{}", err))
    }
}

/// 从 RSA 错误转换
impl From<rsa::Error> for WxPayError {
    fn from(err: rsa::Error) -> Self {
        Self::SignError(format!("RSA 错误：{}", err))
    }
}

/// 从 PKCS 错误转换
impl From<pkcs8::Error> for WxPayError {
    fn from(err: pkcs8::Error) -> Self {
        Self::InvalidPrivateKey(format!("PKCS8 错误：{}", err))
    }
}

/// 从 DER 错误转换
impl From<der::Error> for WxPayError {
    fn from(err: der::Error) -> Self {
        Self::CertificateParseError(format!("DER 解码错误：{}", err))
    }
}

/// 从时间解析错误转换
impl From<chrono::ParseError> for WxPayError {
    fn from(err: chrono::ParseError) -> Self {
        Self::InternalError(format!("时间解析错误：{}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WxPayError::config("missing app_id");
        assert_eq!(err.to_string(), "配置错误：missing app_id");

        let err = WxPayError::api("PARAM_ERROR", "参数错误");
        assert_eq!(err.to_string(), "API 错误：code=PARAM_ERROR, message=参数错误");
    }

    #[test]
    fn test_error_classification() {
        let err = WxPayError::Timeout;
        assert!(err.is_network_error());
        assert!(!err.is_api_error());
        assert!(matches!(err.alert_level(), WxPayAlertLevel::Critical));
        assert_eq!(err.alert_policy(), "network");
        assert!(err.should_retry());

        let err = WxPayError::api("ERROR", "msg");
        assert!(err.is_api_error());
        assert!(!err.is_network_error());
        assert_eq!(err.alert_policy(), "unknown");

        let err = WxPayError::SignatureVerificationFailed;
        assert!(err.is_signature_error());
        assert_eq!(err.alert_policy(), "security.signature");

        let err = WxPayError::CertificateExpired;
        assert!(err.is_certificate_error());
    }
}
