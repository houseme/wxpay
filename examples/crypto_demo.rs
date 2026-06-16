//! 加解密能力演示（无需任何商户凭证，开箱即跑）。
//!
//! 展示 SDK 内置的对称加密与摘要工具：
//! - [`Aes256GcmCipher`]：APIv3 通知解密所用的 AES-256-GCM（此处演示加解密往返）。
//! - [`wxpay_rs::crypto`] 下的 SHA-256 / HMAC-SHA256 助手。
//!
//! 运行：`cargo run --example crypto_demo`

use wxpay_rs::crypto::{Aes256GcmCipher, hash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // APIv3 密钥恰好 32 个字符；这里用一个演示值。
    let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";

    println!("=== AES-256-GCM 加解密往返 ===");
    let cipher = Aes256GcmCipher::new(api_v3_key)?;
    let plaintext = "微信支付敏感数据 hello, world";

    let (nonce_b64, ciphertext_b64) = cipher.encrypt(plaintext)?;
    println!("明文     : {plaintext}");
    println!("nonce    : {nonce_b64}");
    println!("密文     : {ciphertext_b64}");

    let recovered = cipher.decrypt(&nonce_b64, &ciphertext_b64)?;
    println!("解密     : {recovered}");
    assert_eq!(plaintext, recovered, "AES-256-GCM 往返结果应一致");
    println!("✓ 往返校验通过\n");

    println!("=== 摘要工具 ===");
    let payload = b"request-body-or-canonical-string";

    let digest = hash::sha256(payload);
    println!("sha256(...) 字节 : {} bytes", digest.len());

    let hex = hash::sha256_hex(payload);
    println!("sha256(...) hex  : {hex}");

    let b64 = hash::sha256_base64(payload);
    println!("sha256(...) b64  : {b64}");

    let key = b"some-secret-key";
    let mac = hash::hmac_sha256(key, payload);
    println!("hmac 字节        : {} bytes", mac.len());

    let mac_b64 = hash::hmac_sha256_base64(key, payload);
    println!("hmac b64         : {mac_b64}");

    println!("\n✓ crypto_demo 完成。");
    Ok(())
}
