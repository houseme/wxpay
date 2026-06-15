//! 微信支付 SDK 错误类型定义
//!
//! 定义了 SDK 中所有可能的错误类型，使用 thiserror 进行派生。

use thiserror::Error;

/// 微信支付 SDK 结果类型别名
pub type WxPayResult<T> = Result<T, WxPayError>;

/// 微信支付 SDK 错误类型
#[derive(Error, Debug)]
pub enum WxPayError {
    // ========== 配置错误 ==========
    /// 配置错误
    #[error("配置错误: {message}")]
    ConfigError { message: String },

    /// 无效的私钥
    #[error("无效的私钥: {0}")]
    InvalidPrivateKey(String),

    /// 无效的证书
    #[error("无效的证书: {0}")]
    InvalidCertificate(String),

    /// 缺少必填配置项
    #[error("缺少必填配置项: {field}")]
    MissingConfig { field: String },

    // ========== 签名与验签错误 ==========
    /// 签名生成失败
    #[error("签名生成失败: {0}")]
    SignError(String),

    /// 签名验证失败
    #[error("签名验证失败")]
    SignatureVerificationFailed,

    /// 无效的签名格式
    #[error("无效的签名格式: {0}")]
    InvalidSignatureFormat(String),

    // ========== 加解密错误 ==========
    /// 加密失败
    #[error("加密失败: {0}")]
    EncryptionError(String),

    /// 解密失败
    #[error("解密失败: {0}")]
    DecryptionError(String),

    /// 无效的密钥
    #[error("无效的密钥: {0}")]
    InvalidKey(String),

    /// 无效的密文格式
    #[error("无效的密文格式: {0}")]
    InvalidCiphertext(String),

    // ========== 证书错误 ==========
    /// 证书下载失败
    #[error("证书下载失败: {0}")]
    CertificateDownloadError(String),

    /// 证书解析失败
    #[error("证书解析失败: {0}")]
    CertificateParseError(String),

    /// 证书已过期
    #[error("证书已过期")]
    CertificateExpired,

    /// 证书验证失败
    #[error("证书验证失败: {0}")]
    CertificateVerificationError(String),

    /// 找不到匹配的证书
    #[error("找不到匹配的证书: serial_number={0}")]
    CertificateNotFound(String),

    // ========== HTTP 错误 ==========
    /// 网络错误
    #[error("网络错误: {0}")]
    NetworkError(#[from] reqwest::Error),

    /// HTTP 请求构建失败
    #[error("HTTP 请求构建失败: {0}")]
    RequestBuildError(String),

    /// HTTP 响应解析失败
    #[error("HTTP 响应解析失败: {0}")]
    ResponseParseError(String),

    /// 请求超时
    #[error("请求超时")]
    Timeout,

    // ========== API 错误 ==========
    /// 微信支付 API 错误
    #[error("API 错误: code={code}, message={message}")]
    ApiError {
        /// 错误码
        code: String,
        /// 错误信息
        message: String,
    },

    /// API 返回了意外的状态码
    #[error("意外的 HTTP 状态码: {0}")]
    UnexpectedStatusCode(u16),

    /// 业务逻辑错误
    #[error("业务错误: {0}")]
    BusinessError(String),

    // ========== 通知错误 ==========
    /// 通知签名验证失败
    #[error("通知签名验证失败")]
    NotifySignatureVerificationFailed,

    /// 通知解密失败
    #[error("通知解密失败: {0}")]
    NotifyDecryptionError(String),

    /// 无效的通知格式
    #[error("无效的通知格式: {0}")]
    InvalidNotifyFormat(String),

    /// 无效的通知类型
    #[error("无效的通知类型: {0}")]
    InvalidNotifyType(String),

    // ========== 序列化错误 ==========
    /// JSON 序列化/反序列化错误
    #[error("JSON 错误: {0}")]
    JsonError(#[from] serde_json::Error),

    /// URL 编码错误
    #[error("URL 编码错误: {0}")]
    UrlEncodeError(String),

    /// URL 解析错误
    #[error("URL 解析错误: {0}")]
    UrlParseError(#[from] url::ParseError),

    // ========== 其他错误 ==========
    /// 内部错误
    #[error("内部错误: {0}")]
    InternalError(String),

    /// 不支持的操作
    #[error("不支持的操作: {0}")]
    UnsupportedOperation(String),

    /// 参数错误
    #[error("参数错误: {0}")]
    InvalidParameter(String),
}

/// HTTP 错误响应
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ErrorResponse {
    /// 错误码
    pub code: String,
    /// 错误信息
    pub message: String,
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

    /// 判断是否为网络错误
    pub fn is_network_error(&self) -> bool {
        matches!(self, Self::NetworkError(_) | Self::Timeout)
    }

    /// 判断是否为 API 错误
    pub fn is_api_error(&self) -> bool {
        matches!(self, Self::ApiError { .. })
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
        Self::InternalError(format!("Base64 解码错误: {}", err))
    }
}

/// 从 RSA 错误转换
impl From<rsa::Error> for WxPayError {
    fn from(err: rsa::Error) -> Self {
        Self::SignError(format!("RSA 错误: {}", err))
    }
}

/// 从 PKCS 错误转换
impl From<pkcs8::Error> for WxPayError {
    fn from(err: pkcs8::Error) -> Self {
        Self::InvalidPrivateKey(format!("PKCS8 错误: {}", err))
    }
}

/// 从 DER 错误转换
impl From<der::Error> for WxPayError {
    fn from(err: der::Error) -> Self {
        Self::CertificateParseError(format!("DER 解码错误: {}", err))
    }
}

/// 从时间解析错误转换
impl From<chrono::ParseError> for WxPayError {
    fn from(err: chrono::ParseError) -> Self {
        Self::InternalError(format!("时间解析错误: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WxPayError::config("missing app_id");
        assert_eq!(err.to_string(), "配置错误: missing app_id");

        let err = WxPayError::api("PARAM_ERROR", "参数错误");
        assert_eq!(err.to_string(), "API 错误: code=PARAM_ERROR, message=参数错误");
    }

    #[test]
    fn test_error_classification() {
        let err = WxPayError::Timeout;
        assert!(err.is_network_error());
        assert!(!err.is_api_error());

        let err = WxPayError::api("ERROR", "msg");
        assert!(err.is_api_error());
        assert!(!err.is_network_error());

        let err = WxPayError::SignatureVerificationFailed;
        assert!(err.is_signature_error());

        let err = WxPayError::CertificateExpired;
        assert!(err.is_certificate_error());
    }
}
