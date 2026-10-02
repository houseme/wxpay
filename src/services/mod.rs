//! 业务服务模块
//!
//! 提供微信支付 API 的各种业务服务。

pub mod certificate;
pub mod payments;
pub mod profit_sharing;
pub mod query;
pub mod refund;
pub mod transfer;
pub mod transport;

// Go 风格兼容模块别名
pub use profit_sharing as profitsharing;
pub use refund as refunddomestic;
pub use transfer as transferbatch;

// 重导出常用服务
pub use certificate::CertificateService;
pub use payments::AppService;
pub use payments::H5Service;
pub use payments::JsapiService;
pub use payments::NativeService;
pub use profit_sharing::{
    AddProfitSharingReceiverRequest, DeleteProfitSharingReceiverRequest,
    ProfitSharingFinishRequest, ProfitSharingFinishResponse, ProfitSharingReceiverResponse,
    ProfitSharingRequest, ProfitSharingResponse, ProfitSharingService, QueryProfitSharingRequest,
    Receiver,
};
pub use query::{
    CloseOrderRequest, CloseOrderResponse, QueryByOutTradeNoRequest, QueryByTransactionIdRequest,
    QueryFilter, QueryService, Transaction,
};
pub use refund::RefundService;
pub use transfer::TransferService;

pub(crate) fn require_text(value: &str, field: &str) -> crate::error::WxPayResult<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(crate::error::WxPayError::invalid_parameter(format!(
            "{field} must be nonempty and contain no control characters"
        )));
    }
    Ok(())
}

// Encode one identifier before adding it to the signed path or query string.
pub(crate) fn encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

pub(crate) fn validate_notify_url(value: &str) -> crate::error::WxPayResult<()> {
    let url = url::Url::parse(value).map_err(|_| {
        crate::error::WxPayError::invalid_parameter("notify_url must be an absolute HTTP(S) URL")
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(crate::error::WxPayError::invalid_parameter(
            "notify_url must be an absolute HTTP(S) URL without credentials, query or fragment",
        ));
    }
    Ok(())
}

pub(crate) fn require_identifier(value: &str, field: &str) -> crate::error::WxPayResult<()> {
    require_text(value, field)?;
    if matches!(value, "." | "..") {
        return Err(crate::error::WxPayError::invalid_parameter(format!(
            "{field} cannot be a URL dot segment"
        )));
    }
    Ok(())
}
