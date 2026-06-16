//! 示例共享：从环境变量加载微信支付商户配置。
//!
//! 所有需要真实商户凭证的示例都通过 [`load_config`] 读取配置。
//! 若缺少任一必需的环境变量，会打印清晰的设置指引并返回 `Ok(None)`，
//! 使示例在“未配置凭证”时仍可编译运行并给出有用输出（而非直接 panic）。
//!
//! 可复用：在每个示例中通过 `#[path = "common/mod.rs"] mod common;` 引入。

use wxpay_rs::{WxPayConfig, WxPayResult};

/// 必需的环境变量及其含义。
const REQUIRED_VARS: &[(&str, &str)] = &[
    ("WXPAY_APP_ID", "应用 ID，例如 wx88888888"),
    ("WXPAY_MERCHANT_ID", "商户号，例如 1900000109"),
    ("WXPAY_API_V3_KEY", "APIv3 密钥（恰好 32 个字符）"),
    ("WXPAY_PRIVATE_KEY_PATH", "商户私钥 PEM 文件路径"),
    ("WXPAY_CERT_SERIAL_NUMBER", "商户证书序列号"),
];

/// 从环境变量加载配置；缺失任一变量时打印指引并返回 `None`。
pub fn load_config() -> WxPayResult<Option<WxPayConfig>> {
    let _ = dotenvy::dotenv();

    // 先校验所有必需变量是否就位，避免中途失败留下半截配置。
    let mut values: Vec<String> = Vec::with_capacity(REQUIRED_VARS.len());
    for (name, _) in REQUIRED_VARS {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => values.push(v),
            _ => {
                print_guide();
                return Ok(None);
            }
        }
    }

    let config = WxPayConfig::builder()
        .app_id(values[0].clone())
        .merchant_id(values[1].clone())
        .api_v3_key(values[2].clone())
        .private_key_from_file(values[3].clone())
        .cert_serial_number(values[4].clone())
        .build()?;

    Ok(Some(config))
}

/// 返回示例的可选覆盖值（缺失时返回提供的默认值）。
#[allow(dead_code)] // 并非每个示例都会用到
pub fn opt_env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn print_guide() {
    eprintln!("未检测到完整的微信支付商户凭证，跳过真实 API 调用。");
    eprintln!("请在 .env 或环境变量中设置以下变量后重试：\n");
    for (name, desc) in REQUIRED_VARS {
        eprintln!("  {name:<28} {desc}");
    }
    eprintln!("\n可参考项目根目录的 .env.example。");
}
