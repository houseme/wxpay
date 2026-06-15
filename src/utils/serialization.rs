//! 序列化工具
//!
//! 提供 JSON 序列化和 URL 编码相关的工具函数。

use crate::error::{WxPayError, WxPayResult};
use serde::Serialize;

/// 将结构体序列化为 JSON 字符串
///
/// # 参数
///
/// * `value` - 要序列化的值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::to_json;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Example {
///     name: String,
///     value: i32,
/// }
///
/// let example = Example {
///     name: "test".to_string(),
///     value: 42,
/// };
///
/// let json = to_json(&example).unwrap();
/// assert!(json.contains("test"));
/// ```
pub fn to_json<T: Serialize>(value: &T) -> WxPayResult<String> {
    serde_json::to_string(value).map_err(WxPayError::from)
}

/// 将结构体序列化为美化 JSON 字符串
///
/// # 参数
///
/// * `value` - 要序列化的值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::to_json_pretty;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Example {
///     name: String,
///     value: i32,
/// }
///
/// let example = Example {
///     name: "test".to_string(),
///     value: 42,
/// };
///
/// let json = to_json_pretty(&example).unwrap();
/// assert!(json.contains('\n'));
/// ```
pub fn to_json_pretty<T: Serialize>(value: &T) -> WxPayResult<String> {
    serde_json::to_string_pretty(value).map_err(WxPayError::from)
}

/// 将结构体序列化为 URL 编码字符串
///
/// # 参数
///
/// * `value` - 要序列化的值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::to_url_encoded;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Example {
///     name: String,
///     value: i32,
/// }
///
/// let example = Example {
///     name: "test".to_string(),
///     value: 42,
/// };
///
/// let encoded = to_url_encoded(&example).unwrap();
/// assert!(encoded.contains("name=test"));
/// ```
pub fn to_url_encoded<T: Serialize>(value: &T) -> WxPayResult<String> {
    serde_urlencoded::to_string(value)
        .map_err(|e| WxPayError::UrlEncodeError(format!("URL 编码失败：{}", e)))
}

/// 将 JSON 字符串反序列化为结构体
///
/// # 参数
///
/// * `json` - JSON 字符串
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::from_json;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Debug)]
/// struct Example {
///     name: String,
///     value: i32,
/// }
///
/// let json = r#"{"name":"test","value":42}"#;
/// let example: Example = from_json(json).unwrap();
/// assert_eq!(example.name, "test");
/// ```
pub fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> WxPayResult<T> {
    serde_json::from_str(json).map_err(WxPayError::from)
}

/// 将 JSON 字节反序列化为结构体
///
/// # 参数
///
/// * `bytes` - JSON 字节
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::from_json_bytes;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, Debug)]
/// struct Example {
///     name: String,
///     value: i32,
/// }
///
/// let json = br#"{"name":"test","value":42}"#;
/// let example: Example = from_json_bytes(json).unwrap();
/// assert_eq!(example.name, "test");
/// ```
pub fn from_json_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> WxPayResult<T> {
    serde_json::from_slice(bytes).map_err(WxPayError::from)
}

/// Base64 编码
///
/// # 参数
///
/// * `data` - 要编码的数据
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::base64_encode;
///
/// let encoded = base64_encode(b"Hello, World!");
/// assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
/// ```
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64 解码
///
/// # 参数
///
/// * `encoded` - Base64 编码的字符串
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::base64_decode;
///
/// let decoded = base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap();
/// assert_eq!(decoded, b"Hello, World!");
/// ```
pub fn base64_decode(encoded: &str) -> WxPayResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| WxPayError::InternalError(format!("Base64 解码失败：{}", e)))
}

/// Hex 编码
///
/// # 参数
///
/// * `data` - 要编码的数据
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::hex_encode;
///
/// let encoded = hex_encode(b"Hello");
/// assert_eq!(encoded, "48656c6c6f");
/// ```
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Hex 解码
///
/// # 参数
///
/// * `encoded` - Hex 编码的字符串
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::serialization::hex_decode;
///
/// let decoded = hex_decode("48656c6c6f").unwrap();
/// assert_eq!(decoded, b"Hello");
/// ```
pub fn hex_decode(encoded: &str) -> WxPayResult<Vec<u8>> {
    hex::decode(encoded).map_err(|e| WxPayError::InternalError(format!("Hex 解码失败：{}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        name: String,
        value: i32,
    }

    #[test]
    fn test_to_json() {
        let test = TestStruct {
            name: "test".to_string(),
            value: 42,
        };

        let json = to_json(&test).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_to_json_pretty() {
        let test = TestStruct {
            name: "test".to_string(),
            value: 42,
        };

        let json = to_json_pretty(&test).unwrap();
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_from_json() {
        let json = r#"{"name":"test","value":42}"#;
        let test: TestStruct = from_json(json).unwrap();
        assert_eq!(test.name, "test");
        assert_eq!(test.value, 42);
    }

    #[test]
    fn test_from_json_bytes() {
        let json = br#"{"name":"test","value":42}"#;
        let test: TestStruct = from_json_bytes(json).unwrap();
        assert_eq!(test.name, "test");
        assert_eq!(test.value, 42);
    }

    #[test]
    fn test_base64_encode_decode() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = b"Hello";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_to_url_encoded() {
        let test = TestStruct {
            name: "test".to_string(),
            value: 42,
        };

        let encoded = to_url_encoded(&test).unwrap();
        assert!(encoded.contains("name=test"));
        assert!(encoded.contains("value=42"));
    }
}
