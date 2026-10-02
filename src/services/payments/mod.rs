//! 支付服务模块
//!
//! 提供微信支付的各种支付方式。

pub mod app;
pub mod h5;
pub mod jsapi;
pub mod native;

pub use app::AppService;
pub use h5::H5Service;
pub use jsapi::JsapiService;
pub use native::NativeService;

use super::{require_text, validate_notify_url};
use crate::error::{WxPayError, WxPayResult};
use serde::Serialize;

/// Optional fields shared by payment products. Pass to `create_order_with_options`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PaymentOptions {
    /// Payment expiry in RFC3339 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_expire: Option<String>,
    /// Merchant data returned unchanged in payment notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach: Option<String>,
    /// Coupon tag attached to this order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_tag: Option<String>,
    /// Show the electronic invoice entry when supported by the merchant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_fapiao: Option<bool>,
    /// Settlement settings, including enabling profit sharing at order creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_info: Option<SettleInfo>,
}

/// Payment settlement settings.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SettleInfo {
    /// Freeze payment funds for subsequent profit sharing when true.
    pub profit_sharing: bool,
}

impl PaymentOptions {
    fn validate(&self) -> WxPayResult<()> {
        if let Some(expiry) = &self.time_expire {
            chrono::DateTime::parse_from_rfc3339(expiry)
                .map_err(|_| WxPayError::invalid_parameter("time_expire must be RFC3339"))?;
        }
        if self
            .attach
            .as_ref()
            .is_some_and(|s| s.chars().count() > 128)
            || self
                .goods_tag
                .as_ref()
                .is_some_and(|s| s.chars().count() > 32)
        {
            return Err(WxPayError::invalid_parameter(
                "attach or goods_tag exceeds the documented length",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PaymentBody<'a, T> {
    #[serde(flatten)]
    request: &'a T,
    #[serde(flatten)]
    options: &'a PaymentOptions,
}

fn payment_body<T: Serialize>(request: &T, options: &PaymentOptions) -> WxPayResult<String> {
    options.validate()?;
    Ok(serde_json::to_string(&PaymentBody { request, options })?)
}

fn validate_order(
    appid: &str,
    mchid: &str,
    description: &str,
    out_trade_no: &str,
    amount: Option<&jsapi::Amount>,
    notify_url: Option<&str>,
) -> WxPayResult<()> {
    for (value, field) in [
        (appid, "appid"),
        (mchid, "mchid"),
        (description, "description"),
        (out_trade_no, "out_trade_no"),
    ] {
        require_text(value, field)?;
    }
    let amount = amount.ok_or_else(|| WxPayError::invalid_parameter("amount is required"))?;
    if amount.total == 0 || amount.currency.as_deref().is_some_and(|c| c != "CNY") {
        return Err(WxPayError::invalid_parameter(
            "amount.total must be positive and currency must be CNY",
        ));
    }
    if description.chars().count() > 127 || out_trade_no.len() > 32 {
        return Err(WxPayError::invalid_parameter(
            "description or out_trade_no exceeds the documented length",
        ));
    }
    validate_notify_url(
        notify_url.ok_or_else(|| WxPayError::invalid_parameter("notify_url is required"))?,
    )
}
