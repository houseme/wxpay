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
