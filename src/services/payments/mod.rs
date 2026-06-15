//! 支付服务模块
//!
//! 提供微信支付的各种支付方式。

pub mod jsapi;
pub mod native;
pub mod h5;
pub mod app;

pub use jsapi::JsapiService;
pub use native::NativeService;
pub use h5::H5Service;
pub use app::AppService;
