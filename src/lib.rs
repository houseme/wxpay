//! 微信支付 API v3 Rust SDK
//!
//! `wxpay-rs` 是一个用于微信支付 API v3 的 Rust SDK，提供了完整的支付、退款、转账等功能。
//!
//! # 特性
//!
//! - **类型安全** - 使用 Rust 类型系统确保 API 调用的安全性
//! - **异步支持** - 基于 Tokio 的全异步实现
//! - **高性能** - 零成本抽象，无 GC 停顿
//! - **完整功能** - 支持微信支付 API v3 的所有主要功能
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
pub mod error;
pub mod config;
pub mod utils;
pub mod auth;
pub mod crypto;
pub mod http;
pub mod cert;
pub mod services;
pub mod notify;
pub mod client;

// 重导出常用类型
pub use config::{WxPayConfig, WxPayConfigBuilder, Environment, NotifyConfig, NotifyConfigBuilder};
pub use error::{WxPayError, WxPayResult};
pub use client::{WxPayClient, WxPayClientBuilder};
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
