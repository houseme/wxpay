//! 通知解析器模块
//!
//! 提供解析微信支付回调通知的功能。

use serde::Deserialize;

use crate::error::{WxPayError, WxPayResult};
use crate::notify::handler::{NotifyRequest, NotifyResource};

/// 通知解析器
///
/// 用于解析微信支付回调通知。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::notify::NotifyParser;
///
/// let body = r#"{
///     "id": "EV-2018022511223320873",
///     "create_time": "2015-05-20T13:29:35+08:00",
///     "type": "TRANSACTION.SUCCESS",
///     "resource": {
///         "algorithm": "AEAD_AES_256_GCM",
///         "ciphertext": "...",
///         "associated_data": "transaction",
///         "nonce": "..."
///     }
/// }"#;
///
/// let notify = NotifyParser::parse(body).unwrap();
/// assert_eq!(notify.notify_type, "TRANSACTION.SUCCESS");
/// ```
pub struct NotifyParser;

impl NotifyParser {
    /// 解析通知请求
    ///
    /// # 参数
    ///
    /// * `body` - 通知请求体（JSON 字符串）
    ///
    /// # 返回
    ///
    /// 返回解析后的通知请求
    pub fn parse(body: &str) -> WxPayResult<NotifyRequest> {
        serde_json::from_str(body)
            .map_err(|e| WxPayError::InvalidNotifyFormat(format!("解析通知失败: {}", e)))
    }

    /// 解析通知请求（从字节）
    ///
    /// # 参数
    ///
    /// * `bytes` - 通知请求体（字节）
    ///
    /// # 返回
    ///
    /// 返回解析后的通知请求
    pub fn parse_bytes(bytes: &[u8]) -> WxPayResult<NotifyRequest> {
        serde_json::from_slice(bytes)
            .map_err(|e| WxPayError::InvalidNotifyFormat(format!("解析通知失败: {}", e)))
    }

    /// 获取通知类型
    ///
    /// # 参数
    ///
    /// * `body` - 通知请求体（JSON 字符串）
    ///
    /// # 返回
    ///
    /// 返回通知类型
    pub fn get_notify_type(body: &str) -> WxPayResult<String> {
        #[derive(Deserialize)]
        struct NotifyType {
            #[serde(rename = "type")]
            notify_type: String,
        }

        let notify: NotifyType = serde_json::from_str(body)
            .map_err(|e| WxPayError::InvalidNotifyFormat(format!("解析通知类型失败: {}", e)))?;

        Ok(notify.notify_type)
    }

    /// 获取通知 ID
    ///
    /// # 参数
    ///
    /// * `body` - 通知请求体（JSON 字符串）
    ///
    /// # 返回
    ///
    /// 返回通知 ID
    pub fn get_notify_id(body: &str) -> WxPayResult<String> {
        #[derive(Deserialize)]
        struct NotifyId {
            id: String,
        }

        let notify: NotifyId = serde_json::from_str(body)
            .map_err(|e| WxPayError::InvalidNotifyFormat(format!("解析通知 ID 失败: {}", e)))?;

        Ok(notify.id)
    }

    /// 验证通知格式
    ///
    /// # 参数
    ///
    /// * `body` - 通知请求体（JSON 字符串）
    ///
    /// # 返回
    ///
    /// 返回验证结果
    pub fn validate(body: &str) -> WxPayResult<bool> {
        let notify = Self::parse(body)?;

        // 验证必填字段
        if notify.id.is_empty() {
            return Err(WxPayError::InvalidNotifyFormat(
                "通知 ID 不能为空".to_string(),
            ));
        }

        if notify.create_time.is_empty() {
            return Err(WxPayError::InvalidNotifyFormat(
                "通知创建时间不能为空".to_string(),
            ));
        }

        if notify.notify_type.is_empty() {
            return Err(WxPayError::InvalidNotifyFormat(
                "通知类型不能为空".to_string(),
            ));
        }

        // 验证资源信息
        if notify.resource.algorithm.is_empty() {
            return Err(WxPayError::InvalidNotifyFormat(
                "加密算法不能为空".to_string(),
            ));
        }

        if notify.resource.ciphertext.is_empty() {
            return Err(WxPayError::InvalidNotifyFormat("密文不能为空".to_string()));
        }

        if notify.resource.nonce.is_empty() {
            return Err(WxPayError::InvalidNotifyFormat(
                "随机串不能为空".to_string(),
            ));
        }

        Ok(true)
    }

    /// 获取通知资源信息
    ///
    /// # 参数
    ///
    /// * `body` - 通知请求体（JSON 字符串）
    ///
    /// # 返回
    ///
    /// 返回通知资源信息
    pub fn get_resource(body: &str) -> WxPayResult<NotifyResource> {
        let notify = Self::parse(body)?;
        Ok(notify.resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_notify() {
        let body = r#"{
            "id": "EV-2018022511223320873",
            "create_time": "2015-05-20T13:29:35+08:00",
            "type": "TRANSACTION.SUCCESS",
            "resource": {
                "algorithm": "AEAD_AES_256_GCM",
                "ciphertext": "...",
                "associated_data": "transaction",
                "nonce": "..."
            }
        }"#;

        let notify = NotifyParser::parse(body).unwrap();
        assert_eq!(notify.id, "EV-2018022511223320873");
        assert_eq!(notify.notify_type, "TRANSACTION.SUCCESS");
    }

    #[test]
    fn test_get_notify_type() {
        let body = r#"{
            "id": "EV-2018022511223320873",
            "create_time": "2015-05-20T13:29:35+08:00",
            "type": "TRANSACTION.SUCCESS",
            "resource": {
                "algorithm": "AEAD_AES_256_GCM",
                "ciphertext": "...",
                "associated_data": "transaction",
                "nonce": "..."
            }
        }"#;

        let notify_type = NotifyParser::get_notify_type(body).unwrap();
        assert_eq!(notify_type, "TRANSACTION.SUCCESS");
    }

    #[test]
    fn test_get_notify_id() {
        let body = r#"{
            "id": "EV-2018022511223320873",
            "create_time": "2015-05-20T13:29:35+08:00",
            "type": "TRANSACTION.SUCCESS",
            "resource": {
                "algorithm": "AEAD_AES_256_GCM",
                "ciphertext": "...",
                "associated_data": "transaction",
                "nonce": "..."
            }
        }"#;

        let notify_id = NotifyParser::get_notify_id(body).unwrap();
        assert_eq!(notify_id, "EV-2018022511223320873");
    }

    #[test]
    fn test_validate() {
        let body = r#"{
            "id": "EV-2018022511223320873",
            "create_time": "2015-05-20T13:29:35+08:00",
            "type": "TRANSACTION.SUCCESS",
            "resource": {
                "algorithm": "AEAD_AES_256_GCM",
                "ciphertext": "...",
                "associated_data": "transaction",
                "nonce": "..."
            }
        }"#;

        let result = NotifyParser::validate(body).unwrap();
        assert!(result);
    }

    #[test]
    fn test_validate_invalid_json() {
        let body = "invalid json";
        let result = NotifyParser::validate(body);
        assert!(result.is_err());
    }
}
