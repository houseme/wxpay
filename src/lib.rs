//! 微信支付 API v3 Rust SDK
//!
//! `wxpay-rs` 是一个用于微信支付 API v3 的 Rust SDK，提供支付、订单查询、退款、分账和批量转账接口。
//!
//! # 特性
//!
//! - **类型安全** - 使用 Rust 类型系统确保 API 调用的安全性
//! - **异步支持** - 基于 Tokio 的全异步实现
//! - **连接复用** - 多个业务服务共享 HTTP 连接池
//! - **平台验签** - 使用受信任的平台证书或公钥验证响应和通知
//!
//! # 快速开始
//!
//! ```rust,no_run
//! use wxpay_rs::{WxPayClient, WxPayConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 创建配置
//!     let config = WxPayConfig::builder()
//!         .app_id("wx88888888")
//!         .merchant_id("1900000109")
//!         .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
//!         .private_key_from_file("path/to/private_key.pem")
//!         .cert_serial_number("CERT123456")
//!         .platform_public_key(
//!             "PUB_KEY_ID_YOUR_PLATFORM_KEY_ID",
//!             std::fs::read("path/to/wechatpay_public_key.pem")?,
//!         )
//!         .timeout(30) // 秒
//!         .build()?;
//!
//!     // 创建客户端
//!     let client = WxPayClient::new(config).await?;
//!
//!     // 使用 JSAPI 服务
//!     let jsapi = client.jsapi();
//!     let _ = jsapi;
//!
//!     Ok(())
//! }
//! ```
//!
//! # 模块结构
//!
//! - [`config`] - 配置模块
//! - [`client`] - 客户端模块
//! - [`auth`] - 认证模块（签名、验签）
//! - [`crypto`] - 加解密模块
//! - [`cert`] - 证书管理模块
//! - [`http`] - HTTP 客户端模块
//! - [`services`] - 业务服务模块
//! - [`notify`] - 通知处理模块
//! - [`utils`] - 工具模块
//! - [`error`] - 错误类型模块

// 声明模块
pub mod auth;
pub mod cert;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod http;
pub mod notify;
pub mod services;
pub mod utils;

// 重导出常用类型
pub use client::{WxPayClient, WxPayClientBuilder};
pub use config::{Environment, NotifyConfig, NotifyConfigBuilder, WxPayConfig, WxPayConfigBuilder};
pub use error::{WxPayError, WxPayResult};
pub use services::transport::{TransportEvent, TransportObserver};

// 条件编译：文档特性
#[cfg(feature = "docs")]
pub mod docs;

/// SDK 版本号
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SDK 名称
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// 获取 SDK 版本信息
pub fn version() -> &'static str {
    VERSION
}

/// 获取 SDK 名称
pub fn name() -> &'static str {
    NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(name(), "wxpay-rs");
    }
}
