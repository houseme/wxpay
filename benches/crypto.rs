//! 加解密与签名热路径基准测试。
//!
//! 覆盖每次请求都会走过的关键路径：nonce 生成、摘要、AES-256-GCM、SHA256-RSA 签名。
//! 用以量化已应用的性能优化（`String::with_capacity` + `write!` 取代 `format!`、
//! `Uuid::simple()` 取代 `to_string().replace('-','')` 等）在热路径上的效果。
//!
//! 运行全部：`cargo bench`
//! 仅运行本组：`cargo bench --bench crypto`

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tokio::runtime::Runtime;
use wxpay_rs::auth::{Sha256RsaSigner, Signer};
use wxpay_rs::crypto::{Aes256GcmCipher, hash};
use wxpay_rs::utils::nonce::generate_nonce;

/// APIv3 演示密钥（恰好 32 字符）。
const API_V3_KEY: &str = "abcdefghijklmnopqrstuvwxyz123456";

/// 测试用 2048-bit PKCS#8 私钥（PEM），用于构造签名器基准。
const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDQFwtb0xnMYumg\neu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz\n05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2\nL9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoe\naK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/r\nXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhf\nSes6QE3tAgMBAAECgf8ZVV+Mo6arELULVJaxcBj+WjW/epK3s4lhxSLDYx1LXKQo\nJa+FIw5dL3hBc5BwW7kUdHh33ikLGKdq3S4UjJlQ+XWNgYRpIDCCitpeRurF1G8i\npKp5m9u8Y29K7YhcnF/iVyuaDhuhFhh79avGDZjCpg/ni+6PKssc7llTYNy5MGya\nBNkxzXX2Oo5WI1IBOptOEUb6iWYz5FoAf91Ai0K8mFuB5tPCv67DqB2Rq4c6LMoX\nVzwzMZ64GhzYC6vyjltzMjtYTIDvheOZsOUgJe1pAaChwiGRDpmuf8/oybSQFFsy\n1PYF+TddnNk0NOQCPI0qXLHE2OXtdDAigPiA5v8CgYEA6/BnV4O/ZS34WvaGucPx\nQp9s59FolMyWtwELLxOZaO1LPAa9pdNC1+IfUl6zpeRu2z1kNG9f2TbgtTVrF7Lu\n5XvuhJ2OqnL8GgGYpS0vj2Sx5XRO8/pgxiAnpRy7Mkp1jA4+ZTpNQH3FoA6LZZfM\n1v/ijOH9NeHUWEw64OE/OoMCgYEA4ch19Yp73ijLvEUyAkqYrvPOkm7G02mlRD4T\nTUe2tGe8HUbOZGi5CphvItto9mssPDDsEVLilkrPDKlg3899L+ZLE8vHzw6QVoaK\n8LDQaapWbW3LazwLAna4kpNDd06h+Rx7j/n1lha6Vj/2dbEQhAAllos92B7SCNf8\nYIiXqs8CgYACC3tZztKB1fwpDantQj19DlSrTa1SXNORkni+V7Ukq6nTQ1uxbDtQ\nE62h0SBNd8VeMRIFQlHaWBdqeqQK+IoJgyF2FMd/wq9cqlbgV5vp6j2Ad5mXk7vy\n+6RcUfttXCfYpubziaXRwUVNNdMPdllYI6+a+Ppw1Rw6B68a89jQcQKBgFaW+JY4\njBTBdJE5wFocnb3LBxgln98IjzdCz0g+DpXVitF3jEP53a1wlH67wt9ubsKOyJpE\nPV4CRrHGa76p5oruOTDYYELKhRSJ+NMiHGvJxeelyfPQTTCes16TV7Zz066j+8dV\nx5fOE5xsX2r3gyv8mm3H7OnruAVoQAQNno0FAoGBAOvD07di46NEaY7OTGzt4JwE\nWa/0KzWvrQ6SCaHUnZ1yIqL6jEV7RCxKGr206cW9nlG2+n2QqAC8dinDrdLspLZG\noEqm/DoCUaghQOGnh7teguj3eqS+MHU5T/ugSJdJoMNtpQ/BlSnqkWLPoh+yrvh5\nmVKYyABhNkZONhC533bA\n-----END PRIVATE KEY-----\n";

/// 代表性 APIv3 签名规范串（行尾含 `\n`），与微信签名规范一致。
const CANONICAL_MESSAGE: &str = "GET\n/v3/pay/transactions/out-trade-no/out_001?mchid=1900000109\n1700000000\n5b8c9b0a3f4e4d2c\n\n";

fn bench_hashes(c: &mut Criterion) {
    let payload = b"the quick brown fox jumps over the lazy dog 1234567890".repeat(4); // ~220 B
    let payload = payload.as_slice();
    let key = b"benchmark-hmac-key";

    c.bench_function("sha256/220B", |b| {
        b.iter(|| black_box(hash::sha256(black_box(payload))))
    });
    c.bench_function("sha256_hex/220B", |b| {
        b.iter(|| black_box(hash::sha256_hex(black_box(payload))))
    });
    c.bench_function("hmac_sha256_base64/220B", |b| {
        b.iter(|| black_box(hash::hmac_sha256_base64(black_box(key), black_box(payload))))
    });
}

fn bench_nonce(c: &mut Criterion) {
    c.bench_function("generate_nonce", |b| b.iter(|| black_box(generate_nonce())));
}

fn bench_aes(c: &mut Criterion) {
    let cipher = Aes256GcmCipher::new(API_V3_KEY).expect("AES cipher");
    let plaintext = "wechatpay-sensitive-resource-payload";
    // 预先生成一对 nonce/密文，供解密基准循环复用，避免把加密成本计入解密。
    let (nonce_b64, ct_b64) = cipher.encrypt(plaintext).expect("pre-encrypt");

    c.bench_function("aes_gcm/encrypt", |b| {
        b.iter(|| {
            let _ = black_box(cipher.encrypt(black_box(plaintext)));
        })
    });
    c.bench_function("aes_gcm/decrypt", |b| {
        b.iter(|| {
            let _ = black_box(cipher.decrypt(black_box(&nonce_b64), black_box(&ct_b64)));
        })
    });
}

fn bench_rsa_sign(c: &mut Criterion) {
    // 不依赖 criterion 的 async 执行器（版本差异较大），直接用 tokio 运行时阻塞驱动。
    let rt = Runtime::new().expect("tokio runtime");
    let signer = Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456")
        .expect("signer");

    c.bench_function("rsa_sha256/sign_canonical", |b| {
        b.iter(|| {
            let sig = rt
                .block_on(signer.sign(black_box(CANONICAL_MESSAGE)))
                .expect("sign");
            black_box(sig);
        })
    });
}

criterion_group!(
    benches,
    bench_hashes,
    bench_nonce,
    bench_aes,
    bench_rsa_sign
);
criterion_main!(benches);
