# 微信支付 API v3 Rust SDK

[![Crates.io](https://img.shields.io/crates/v/wxpay-rs.svg)](https://crates.io/crates/wxpay-rs)
[![Documentation](https://docs.rs/wxpay-rs/badge.svg)](https://docs.rs/wxpay-rs)
[![License](https://img.shields.io/crates/l/wxpay-rs.svg)](LICENSE)

**微信支付 API v3 的 Rust 实现 SDK**，提供类型安全、高性能的微信支付接口封装。

## ✨ 特性

- 🔐 **完整的签名与验签** - SHA256-RSA 签名算法，自动请求签名和应答验签
- 🔒 **敏感信息加解密** - RSA-OAEP 加密/解密，AES-256-GCM 回调通知解密
- 📜 **证书管理** - 自动定时下载和更新微信支付平台证书
- 💳 **全支付方式支持** - JSAPI、Native、H5、APP 支付
- 🔄 **回调通知处理** - 完整的支付回调验证和解密
- 📊 **丰富的业务 API** - 支付、退款、分账、转账等完整业务支持
- ⚡ **异步优先** - 基于 Tokio 的全异步实现，高性能并发
- 🛡️ **类型安全** - Rust 强类型系统保障，编译期错误检查

## 📦 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
wxpay-rs = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## 🚀 快速开始

### 初始化客户端

```rust
use wxpay_rs::{
    client::WxPayClient,
    config::WxPayConfig,
    error::WxPayResult,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> WxPayResult<()> {
    // 配置微信支付参数
    let config = WxPayConfig::new(
        "wx888888888",                              // AppID
        "1900000109",                               // 商户号
        "22222222",                                 // 商户 API 密钥
        PathBuf::from("/path/to/apiclient_cert.pem"),  // 商户证书
        PathBuf::from("/path/to/apiclient_key.pem"),   // 商户私钥
    )
    .api_v3_key("your_api_v3_key")                 // APIv3 密钥
    .timeout(6000)                                  // 超时时间（毫秒）
    .build();

    // 创建客户端
    let client = WxPayClient::new(config).await?;

    println!("微信支付客户端初始化成功！");
    Ok(())
}
```

### JSAPI 支付示例

```rust
use wxpay_rs::services::payments::jsapi::*;
use wxpay_rs::client::WxPayClient;

async fn create_jsapi_order(client: &WxPayClient) -> WxPayResult<()> {
    // 创建预支付请求
    let request = PrepayRequest {
        appid: "wx888888888".to_string(),
        mchid: "1900000109".to_string(),
        description: "测试商品".to_string(),
        out_trade_no: "20240101000001".to_string(),
        notify_url: "https://www.example.com/wxpay/notify".to_string(),
        amount: Some(Amount {
            total: 100,
            currency: Some("CNY".to_string()),
        }),
        payer: Some(Payer {
            openid: "oUpF8uMuAJO_M2pxb1Q9zNjWeS6o".to_string(),
        }),
        ..Default::default()
    };

    // 调用预支付接口
    let result = client.jsapi().prepay(request).await?;
    println!("预支付结果：{:?}", result);

    // 生成前端支付参数
    let pay_params = client.jsapi().build_pay_params(&result.prepay_id)?;
    println!("前端支付参数：{:?}", pay_params);

    Ok(())
}
```

### Native 支付示例

```rust
use wxpay_rs::services::payments::native::*;

async fn create_native_order(client: &WxPayClient) -> WxPayResult<()> {
    let request = PrepayRequest {
        appid: "wx888888888".to_string(),
        mchid: "1900000109".to_string(),
        description: "测试商品".to_string(),
        out_trade_no: "20240101000002".to_string(),
        notify_url: "https://www.example.com/wxpay/notify".to_string(),
        amount: Some(Amount {
            total: 100,
            currency: Some("CNY".to_string()),
        }),
        ..Default::default()
    };

    let result = client.native().prepay(request).await?;
    println!("二维码链接：{}", result.code_url);

    Ok(())
}
```

### 查询订单

```rust
use wxpay_rs::services::payments::query::*;

async fn query_order(client: &WxPayClient) -> WxPayResult<()> {
    // 通过商户订单号查询
    let result = client.query().by_out_trade_no("20240101000001").await?;
    println!("订单状态：{:?}", result.trade_state);

    // 通过微信支付订单号查询
    let result = client.query().by_transaction_id("4200001234202401010000001").await?;
    println!("订单详情：{:?}", result);

    Ok(())
}
```

### 申请退款

```rust
use wxpay_rs::services::refunddomestic::*;

async fn create_refund(client: &WxPayClient) -> WxPayResult<()> {
    let request = RefundRequest {
        out_trade_no: "20240101000001".to_string(),
        out_refund_no: "R20240101000001".to_string(),
        reason: Some("商品质量问题".to_string()),
        amount: RefundAmount {
            refund: 100,
            total: 100,
            currency: "CNY".to_string(),
        },
        ..Default::default()
    };

    let result = client.refund().create(request).await?;
    println!("退款单号：{}", result.refund_id);

    Ok(())
}
```

### 处理回调通知

```rust
use wxpay_rs::notify::{NotifyHandler, NotifyPayload};
use wxpay_rs::services::payments::Transaction;

async fn handle_payment_notify(
    handler: &NotifyHandler,
    body: &str,
    headers: &[(String, String)],
) -> WxPayResult<()> {
    // 验证签名并解密通知
    let transaction: Transaction = handler.parse_notify_request(body, headers).await?;

    // 处理支付结果
    match transaction.trade_state {
        TradeState::Success => {
            println!("支付成功！订单号：{}", transaction.out_trade_no);
            // 业务处理...
        }
        TradeState::Closed => {
            println!("订单已关闭：{}", transaction.out_trade_no);
        }
        _ => {
            println!("其他状态：{:?}", transaction.trade_state);
        }
    }

    Ok(())
}
```

## 📁 项目结构

```
wxpay-rs/
├── Cargo.toml                    # 项目配置
├── src/
│   ├── lib.rs                    # 库入口
│   ├── client.rs                 # HTTP 客户端实现
│   ├── config.rs                 # 配置管理
│   ├── error.rs                  # 错误类型定义
│   ├── auth/                     # 认证模块
│   │   ├── mod.rs
│   │   ├── signer.rs             # 签名器
│   │   ├── verifier.rs           # 验签器
│   │   └── credentials.rs        # 凭证管理
│   ├── cipher/                   # 加解密模块
│   │   ├── mod.rs
│   │   ├── rsa.rs                # RSA-OAEP 加解密
│   │   └── aes.rs                # AES-256-GCM 加解密
│   ├── cert/                     # 证书管理
│   │   ├── mod.rs
│   │   ├── downloader.rs         # 证书下载器
│   │   └── visitor.rs            # 证书访问器
│   ├── notify/                   # 回调通知处理
│   │   ├── mod.rs
│   │   └── handler.rs            # 通知处理器
│   ├── utils/                    # 工具函数
│   │   ├── mod.rs
│   │   ├── nonce.rs              # 随机数生成
│   │   ├── signature.rs          # 签名工具
│   │   └── xml.rs                # XML 处理（v2 兼容）
│   └── services/                 # 业务服务模块
│       ├── mod.rs
│       ├── certificates.rs       # 平台证书服务
│       ├── payments/             # 支付服务
│       │   ├── mod.rs
│       │   ├── jsapi.rs          # JSAPI 支付
│       │   ├── native.rs         # Native 支付
│       │   ├── h5.rs             # H5 支付
│       │   ├── app.rs            # APP 支付
│       │   └── query.rs          # 订单查询
│       ├── refunddomestic.rs     # 退款服务
│       ├── profitsharing.rs      # 分账服务
│       ├── transferbatch.rs      # 转账服务
│       └── fileuploader.rs       # 文件上传服务
├── examples/                     # 示例代码
│   ├── jsapi_payment.rs
│   ├── native_payment.rs
│   ├── refund.rs
│   └── notify.rs
└── tests/                        # 集成测试
    ├── integration_test.rs
    └── mock_server.rs
```

## 🔧 配置选项

### 完整配置示例

```rust
use wxpay_rs::config::{WxPayConfig, SignType, AuthType};
use std::path::PathBuf;

let config = WxPayConfig::builder()
    .app_id("wx888888888")
    .mch_id("1900000109")
    .api_v3_key("your_api_v3_key")
    .merchant_cert_path(PathBuf::from("/path/to/apiclient_cert.pem"))
    .merchant_key_path(PathBuf::from("/path/to/apiclient_key.pem"))
    .sign_type(SignType::Sha256Rsa)           // 签名类型
    .auth_type(AuthType::Certificate)          // 认证类型：证书或公钥
    .timeout(6000)                             // 超时时间
    .auto_download_certs(true)                 // 自动下载证书
    .cert_download_interval(3600)              // 证书下载间隔（秒）
    .base_url("https://api.mch.weixin.qq.com") // API 基础 URL
    .sandbox(false)                            // 是否使用沙箱环境
    .build()?;
```

### 使用公钥验签（新入驻商户）

```rust
let config = WxPayConfig::builder()
    .app_id("wx888888888")
    .mch_id("1900000109")
    .api_v3_key("your_api_v3_key")
    .merchant_cert_path(PathBuf::from("/path/to/apiclient_cert.pem"))
    .merchant_key_path(PathBuf::from("/path/to/apiclient_key.pem"))
    .auth_type(AuthType::PublicKey {
        public_key_id: "PUB_KEY_ID_00000000000000".to_string(),
        public_key_path: PathBuf::from("/path/to/public_key.pem"),
    })
    .build()?;
```

## 📚 支持的 API 列表

### 支付服务

| API | 说明 | 状态 |
|-----|------|------|
| `jsapi().prepay()` | JSAPI 预支付 | ✅ |
| `native().prepay()` | Native 预支付 | ✅ |
| `h5().prepay()` | H5 预支付 | ✅ |
| `app().prepay()` | APP 预支付 | ✅ |
| `query().by_transaction_id()` | 微信支付单号查询 | ✅ |
| `query().by_out_trade_no()` | 商户订单号查询 | ✅ |
| `query().by_filter()` | 复杂条件查询 | ✅ |
| `close()` | 关闭订单 | ✅ |

### 退款服务

| API | 说明 | 状态 |
|-----|------|------|
| `refund().create()` | 申请退款 | ✅ |
| `refund().query()` | 查询退款 | ✅ |

### 分账服务

| API | 说明 | 状态 |
|-----|------|------|
| `profitsharing().create()` | 创建分账 | ✅ |
| `profitsharing().query()` | 查询分账 | ✅ |
| `profitsharing().add_receiver()` | 添加分账接收方 | ✅ |
| `profitsharing().delete_receiver()` | 删除分账接收方 | ✅ |

### 转账服务

| API | 说明 | 状态 |
|-----|------|------|
| `transfer().create()` | 发起转账 | ✅ |
| `transfer().query()` | 查询转账 | ✅ |

### 证书服务

| API | 说明 | 状态 |
|-----|------|------|
| `certificates().download()` | 下载平台证书 | ✅ |
| `certificates().auto_refresh()` | 自动刷新证书 | ✅ |

### 文件服务

| API | 说明 | 状态 |
|-----|------|------|
| `fileuploader().upload_image()` | 上传图片 | ✅ |
| `fileuploader().upload_video()` | 上传视频 | ✅ |

## 🔐 安全特性

### 签名算法

- **SHA256-RSA** - 默认签名算法，推荐使用
- **HMAC-SHA256** - 备用签名算法

### 敏感信息加密

```rust
use wxpay_rs::cipher::RsaCipher;

// 加密敏感信息
let encrypted = RsaCipher::encrypt_with_certificate(
    "敏感信息",
    &platform_certificate,
)?;

// 解密敏感信息
let decrypted = RsaCipher::decrypt_with_private_key(
    &encrypted_data,
    &merchant_private_key,
)?;
```

### 回调通知验证

```rust
use wxpay_rs::notify::NotifyHandler;

// 验证通知签名
let is_valid = handler.verify_signature(
    &signature,
    &timestamp,
    &nonce,
    &body,
)?;

// 解密通知数据
let decrypted = handler.decrypt_notification(
    &ciphertext,
    &nonce,
    &associated_data,
)?;
```

## 🧪 测试

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行集成测试
cargo test --test integration_test

# 运行示例
cargo run --example jsapi_payment
```

### 沙箱环境测试

```rust
let config = WxPayConfig::builder()
    .sandbox(true)
    // ... 其他配置
    .build()?;
```

## 📖 示例代码

### 完整的支付流程示例

```rust
use wxpay_rs::{
    client::WxPayClient,
    config::WxPayConfig,
    services::payments::jsapi::*,
    notify::NotifyHandler,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化配置
    let config = WxPayConfig::new(
        "wx888888888",
        "1900000109",
        "22222222",
        PathBuf::from("/path/to/cert.pem"),
        PathBuf::from("/path/to/key.pem"),
    )
    .api_v3_key("your_api_v3_key")
    .build()?;

    // 2. 创建客户端
    let client = WxPayClient::new(config).await?;

    // 3. 创建预支付订单
    let request = PrepayRequest {
        appid: "wx888888888".to_string(),
        mchid: "1900000109".to_string(),
        description: "测试商品".to_string(),
        out_trade_no: format!("ORDER_{}", chrono::Utc::now().timestamp()),
        notify_url: "https://www.example.com/notify".to_string(),
        amount: Some(Amount {
            total: 100,
            currency: Some("CNY".to_string()),
        }),
        payer: Some(Payer {
            openid: "oUpF8uMuAJO_M2pxb1Q9zNjWeS6o".to_string(),
        }),
        ..Default::default()
    };

    let prepay_result = client.jsapi().prepay(request).await?;

    // 4. 生成前端调起支付的参数
    let pay_params = client.jsapi().build_pay_params(&prepay_result.prepay_id)?;
    println!("前端支付参数：{:#?}", pay_params);

    // 5. 处理支付回调（在回调接口中）
    // let handler = client.notify_handler();
    // let transaction = handler.parse_notify_request(body, headers).await?;

    Ok(())
}
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/houseme/wxpay.git
cd wxpay

# 运行测试
cargo test

# 运行示例
cargo run --example jsapi_payment
```

## 📄 许可证

本项目采用 [Apache-2.0](LICENSE) 许可证。

## 🔗 相关链接

- [微信支付官方文档](https://pay.weixin.qq.com)
- [微信支付 API v3 文档](https://pay.weixin.qq.com/wiki/doc/apiv3/index.shtml)
- [微信支付 Go SDK](https://github.com/wechatpay-apiv3/wechatpay-go)
- [Rust 官方网站](https://www.rust-lang.org)

## ⚠️ 注意事项

1. **密钥安全**：请妥善保管商户私钥和 APIv3 密钥，不要泄露或提交到代码仓库
2. **证书更新**：建议启用自动证书下载功能，确保证书及时更新
3. **错误处理**：所有 API 调用都应进行适当的错误处理
4. **日志记录**：建议开启日志记录，便于问题排查
5. **超时设置**：根据业务需求合理设置超时时间

## 📞 支持

如有问题，请通过以下方式联系：

- 提交 [GitHub Issue](https://github.com/houseme/wxpay/issues)
- 邮件联系：housemecn@gmail.com
