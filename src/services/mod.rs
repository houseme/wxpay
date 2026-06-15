//! 业务服务模块
//!
//! 提供微信支付 API 的各种业务服务。

pub mod payments;
pub mod refund;
pub mod transfer;
pub mod profit_sharing;
pub mod certificate;
pub mod query;
pub mod transport;

// Go 风格兼容模块别名
pub use profit_sharing as profitsharing;
pub use refund as refunddomestic;
pub use transfer as transferbatch;

// 重导出常用服务
pub use payments::JsapiService;
pub use payments::NativeService;
pub use payments::H5Service;
pub use payments::AppService;
pub use refund::RefundService;
pub use transfer::TransferService;
pub use profit_sharing::{
    AddProfitSharingReceiverRequest,
    DeleteProfitSharingReceiverRequest,
    ProfitSharingFinishRequest,
    ProfitSharingFinishResponse,
    ProfitSharingReceiverResponse,
    ProfitSharingService,
    QueryProfitSharingRequest,
    ProfitSharingRequest,
    Receiver,
    ProfitSharingResponse,
};
pub use certificate::CertificateService;
pub use query::{
    QueryService,
    QueryByTransactionIdRequest,
    QueryByOutTradeNoRequest,
    QueryFilter,
    Transaction,
    CloseOrderRequest,
    CloseOrderResponse,
};
