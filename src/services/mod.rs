//! 业务服务模块
//!
//! 提供微信支付 API 的各种业务服务。

pub mod payments;
pub mod refund;
pub mod transfer;
pub mod profit_sharing;
pub mod certificate;

// 重导出常用服务
pub use payments::JsapiService;
pub use payments::NativeService;
pub use payments::H5Service;
pub use payments::AppService;
pub use refund::RefundService;
pub use transfer::TransferService;
pub use profit_sharing::ProfitSharingService;
pub use certificate::CertificateService;
