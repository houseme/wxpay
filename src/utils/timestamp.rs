//! 时间戳工具
//!
//! 提供获取和处理时间戳的功能，用于请求签名。

use chrono::{DateTime, Utc};

/// 获取当前 Unix 时间戳（秒）
///
/// 返回当前 UTC 时间的 Unix 时间戳，用于请求签名中的 timestamp 字段。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::get_timestamp;
///
/// let timestamp = get_timestamp();
/// assert!(timestamp > 0);
/// ```
pub fn get_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// 获取当前 Unix 时间戳（毫秒）
///
/// 返回当前 UTC 时间的 Unix 时间戳（毫秒精度）。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::timestamp::get_timestamp_millis;
///
/// let timestamp = get_timestamp_millis();
/// assert!(timestamp > 0);
/// ```
pub fn get_timestamp_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// 将时间戳转换为字符串
///
/// 将 Unix 时间戳（秒）转换为字符串格式，用于请求签名。
///
/// # 参数
///
/// * `timestamp` - Unix 时间戳（秒）
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::timestamp::timestamp_to_string;
///
/// let s = timestamp_to_string(1609459200);
/// assert_eq!(s, "1609459200");
/// ```
pub fn timestamp_to_string(timestamp: i64) -> String {
    timestamp.to_string()
}

/// 将字符串解析为时间戳
///
/// 将字符串格式的时间戳解析为 i64 类型。
///
/// # 参数
///
/// * `s` - 时间戳字符串
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::timestamp::parse_timestamp;
///
/// let timestamp = parse_timestamp("1609459200").unwrap();
/// assert_eq!(timestamp, 1609459200);
/// ```
pub fn parse_timestamp(s: &str) -> Result<i64, std::num::ParseIntError> {
    s.parse()
}

/// 将时间戳转换为 DateTime
///
/// 将 Unix 时间戳（秒）转换为 chrono::DateTime<Utc> 类型。
///
/// # 参数
///
/// * `timestamp` - Unix 时间戳（秒）
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::timestamp::timestamp_to_datetime;
///
/// let dt = timestamp_to_datetime(1609459200);
/// assert_eq!(dt.format("%Y-%m-%d").to_string(), "2021-01-01");
/// ```
pub fn timestamp_to_datetime(timestamp: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(timestamp, 0).unwrap_or_default()
}

/// 将 DateTime 转换为时间戳
///
/// 将 chrono::DateTime<Utc> 转换为 Unix 时间戳（秒）。
///
/// # 参数
///
/// * `dt` - DateTime 对象
///
/// # 示例
///
/// ```rust
/// use chrono::Utc;
/// use wxpay_rs::utils::timestamp::datetime_to_timestamp;
///
/// let dt = Utc::now();
/// let timestamp = datetime_to_timestamp(&dt);
/// assert!(timestamp > 0);
/// ```
pub fn datetime_to_timestamp(dt: &DateTime<Utc>) -> i64 {
    dt.timestamp()
}

/// 检查时间戳是否在有效范围内
///
/// 检查时间戳是否在当前时间的前后指定秒数内。
///
/// # 参数
///
/// * `timestamp` - 要检查的时间戳
/// * `tolerance_seconds` - 容差秒数
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::timestamp::is_timestamp_valid;
///
/// let now = chrono::Utc::now().timestamp();
/// assert!(is_timestamp_valid(now, 300)); // 5 分钟内有效
/// assert!(!is_timestamp_valid(0, 300)); // 1970 年无效
/// ```
pub fn is_timestamp_valid(timestamp: i64, tolerance_seconds: i64) -> bool {
    let now = Utc::now().timestamp();
    let diff = (now - timestamp).abs();
    diff <= tolerance_seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_timestamp() {
        let timestamp = get_timestamp();
        assert!(timestamp > 0);
        assert!(timestamp > 1600000000); // 2020 年之后
    }

    #[test]
    fn test_get_timestamp_millis() {
        let timestamp = get_timestamp_millis();
        assert!(timestamp > 0);
        assert!(timestamp > 1600000000000); // 2020 年之后（毫秒）
    }

    #[test]
    fn test_timestamp_to_string() {
        let s = timestamp_to_string(1609459200);
        assert_eq!(s, "1609459200");
    }

    #[test]
    fn test_parse_timestamp() {
        let timestamp = parse_timestamp("1609459200").unwrap();
        assert_eq!(timestamp, 1609459200);

        let result = parse_timestamp("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_to_datetime() {
        let dt = timestamp_to_datetime(1609459200);
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2021-01-01");
    }

    #[test]
    fn test_datetime_to_timestamp() {
        let dt = timestamp_to_datetime(1609459200);
        let timestamp = datetime_to_timestamp(&dt);
        assert_eq!(timestamp, 1609459200);
    }

    #[test]
    fn test_is_timestamp_valid() {
        let now = get_timestamp();
        assert!(is_timestamp_valid(now, 300));
        assert!(is_timestamp_valid(now - 299, 300));
        assert!(!is_timestamp_valid(now - 301, 300));
        assert!(!is_timestamp_valid(0, 300));
    }
}
