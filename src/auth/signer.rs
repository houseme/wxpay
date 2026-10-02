//! 签名器模块
//!
//! 提供请求签名功能，使用 SHA256-RSA 算法。

use async_trait::async_trait;
use aws_lc_rs::{rand::SystemRandom, rsa::KeyPair, signature::RSA_PKCS1_SHA256};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::crypto::rsa::parse_rsa_private_key;

use crate::error::{WxPayError, WxPayResult};

/// 签名器 trait
///
/// 定义了生成请求签名的接口。
#[async_trait]
pub trait Signer: Send + Sync {
    /// 生成签名
    ///
    /// # 参数
    ///
    /// * `message` - 要签名的消息
    ///
    /// # 返回
    ///
    /// 返回 Base64 编码的签名字符串
    async fn sign(&self, message: &str) -> WxPayResult<String>;

    /// 获取商户号
    fn merchant_id(&self) -> &str;

    /// 获取证书序列号
    fn cert_serial_number(&self) -> &str;
}

/// SHA256-RSA 签名器
///
/// 使用 SHA256WithRSA 算法生成请求签名。
///
/// 私钥计算在 Tokio blocking 线程执行，须在 Tokio 运行时内调用。
/// 默认最多排队 64 个请求；可用 [`Self::with_signing_capacity`] 调整并发与队列容量。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::auth::{Signer, Sha256RsaSigner};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let private_key_pem = std::fs::read_to_string("path/to/private_key.pem")?;
/// let signer = Sha256RsaSigner::new(
///     "1900000109",
///     private_key_pem.as_bytes(),
///     "CERT123456",
/// )?;
///
/// let signature = signer.sign("test message").await?;
/// # Ok(())
/// # }
/// ```
pub struct Sha256RsaSigner {
    /// 商户号
    merchant_id: String,
    /// 商户私钥
    private_key: Arc<KeyPair>,
    /// 同时执行签名的任务数（等待时不会占用 Tokio blocking 线程）。
    workers: Arc<Semaphore>,
    /// 执行和等待总容量；超出时拒绝，避免无界积压。
    admission: Arc<Semaphore>,
    /// 证书序列号
    cert_serial_number: String,
}

impl Sha256RsaSigner {
    /// 创建新的 SHA256-RSA 签名器
    ///
    /// # 参数
    ///
    /// * `merchant_id` - 商户号
    /// * `private_key_pem` - 私钥（PEM 格式）
    /// * `cert_serial_number` - 证书序列号
    ///
    /// # 返回
    ///
    /// 返回签名器实例
    pub fn new(
        merchant_id: impl Into<String>,
        private_key_pem: &[u8],
        cert_serial_number: impl Into<String>,
    ) -> WxPayResult<Self> {
        let private_key = parse_rsa_private_key(private_key_pem)?;
        let workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(32);
        Ok(Self {
            merchant_id: merchant_id.into(),
            private_key: Arc::new(private_key),
            workers: Arc::new(Semaphore::new(workers)),
            admission: Arc::new(Semaphore::new(workers + 64)),
            cert_serial_number: cert_serial_number.into(),
        })
    }

    /// 配置此签名器的并行计算数与等待容量。
    ///
    /// 默认并行数为可用 CPU 数（最多 32），最多额外排队 64 个调用。
    /// 超过总容量立即返回 `SignError`；等待许可期间不会复制消息或提交 blocking 任务。
    /// 已开始的 RSA 操作无法取消，调用方取消后仍会持有许可直到计算完成。
    /// 必须在 Tokio 运行时内调用 [`Signer::sign`]。
    pub fn with_signing_capacity(
        mut self,
        max_concurrent: usize,
        max_queued: usize,
    ) -> WxPayResult<Self> {
        let total = max_concurrent
            .checked_add(max_queued)
            .filter(|&total| max_concurrent > 0 && total <= Semaphore::MAX_PERMITS)
            .ok_or_else(|| {
                WxPayError::InvalidParameter("签名并发数必须大于零且总容量不能溢出".into())
            })?;
        self.workers = Arc::new(Semaphore::new(max_concurrent));
        self.admission = Arc::new(Semaphore::new(total));
        Ok(self)
    }

    /// 构建签名消息
    ///
    /// 微信支付 API v3 签名格式：
    /// HTTP_METHOD\nURL_PATH\nTIMESTAMP\nNONCE_STR\nBODY\n
    pub fn build_sign_message(
        method: &str,
        url: &str,
        timestamp: i64,
        nonce: &str,
        body: &str,
    ) -> String {
        // 性能优化：预分配容量并就地格式化时间戳，避免 `format!` 的临时 String 分配。
        use std::fmt::Write;
        let mut s = String::with_capacity(
            method.len() + url.len() + nonce.len() + body.len() + /*timestamp*/ 20 + /*换行*/ 5,
        );
        let _ = write!(
            s,
            "{}\n{}\n{}\n{}\n{}\n",
            method, url, timestamp, nonce, body
        );
        s
    }

    /// 构建 Authorization Header
    ///
    /// 格式：WECHATPAY2-SHA256-RSA2048 mchid="...",nonce_str="...",timestamp="...",serial_no="...",signature="..."
    pub fn build_authorization_header(
        &self,
        nonce: &str,
        timestamp: i64,
        signature: &str,
    ) -> String {
        build_authorization_header(
            &self.merchant_id,
            &self.cert_serial_number,
            nonce,
            timestamp,
            signature,
        )
    }
}

/// 构建业务请求和证书下载共用的完整 Authorization Header。
///
/// 参数顺序为商户号、商户证书序列号、随机串、时间戳和 Base64 签名。
pub fn build_authorization_header(
    merchant_id: &str,
    cert_serial_number: &str,
    nonce: &str,
    timestamp: i64,
    signature: &str,
) -> String {
    use std::fmt::Write;
    let mut header = String::with_capacity(
        merchant_id.len() + cert_serial_number.len() + nonce.len() + signature.len() + 128,
    );
    let _ = write!(
        header,
        r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}""#,
        merchant_id, nonce, timestamp, cert_serial_number, signature,
    );
    header
}

#[async_trait]
impl Signer for Sha256RsaSigner {
    async fn sign(&self, message: &str) -> WxPayResult<String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| WxPayError::SignError("RSA 异步签名需要 Tokio 运行时".into()))?;
        let admission = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| WxPayError::SignError("RSA 签名队列已满，请稍后重试".into()))?;
        let worker = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WxPayError::SignError("RSA 签名器已关闭".into()))?;
        let private_key = Arc::clone(&self.private_key);
        let message = message.to_owned();
        runtime
            .spawn_blocking(move || {
                // 两个许可都交给计算任务，即使调用方取消，也不能提前释放并发配额。
                let (_admission, _worker) = (admission, worker);
                let mut signature = vec![0; private_key.public_modulus_len()];
                private_key
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &SystemRandom::new(),
                        message.as_bytes(),
                        &mut signature,
                    )
                    .map_err(|_| WxPayError::SignError("RSA 签名失败".into()))?;
                Ok(base64::engine::general_purpose::STANDARD.encode(signature))
            })
            .await
            .map_err(|_| WxPayError::SignError("RSA 签名任务失败".into()))?
    }

    fn merchant_id(&self) -> &str {
        &self.merchant_id
    }

    fn cert_serial_number(&self) -> &str {
        &self.cert_serial_number
    }
}

impl std::fmt::Debug for Sha256RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256RsaSigner")
            .field("merchant_id", &self.merchant_id)
            .field("cert_serial_number", &self.cert_serial_number)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    use crate::crypto::test_fixtures::{
        PKCS1_PRIVATE_KEY_PEM, PRIVATE_KEY_PEM, SHA256_SIGNATURE, SIGN_MESSAGE,
    };

    fn test_signer() -> Sha256RsaSigner {
        Sha256RsaSigner::new("1900000109", PRIVATE_KEY_PEM.as_bytes(), "CERT123456")
            .expect("测试签名器应创建成功")
    }

    #[tokio::test]
    async fn matches_openssl_sha256_pkcs1_signature() {
        for key in [PRIVATE_KEY_PEM, PKCS1_PRIVATE_KEY_PEM] {
            let signer = Sha256RsaSigner::new("merchant", key.as_bytes(), "serial").unwrap();
            assert_eq!(signer.sign(SIGN_MESSAGE).await.unwrap(), SHA256_SIGNATURE);
        }
    }

    #[test]
    fn rejects_invalid_signing_capacity() {
        assert!(test_signer().with_signing_capacity(0, 1).is_err());
        assert!(test_signer().with_signing_capacity(1, usize::MAX).is_err());
    }

    #[tokio::test]
    async fn bounded_queue_rejects_overload_and_releases_cancelled_waiter() {
        let signer = Arc::new(test_signer().with_signing_capacity(1, 1).unwrap());
        // Occupy one executing operation, then queue exactly one pending signature.
        let worker = signer.workers.clone().acquire_owned().await.unwrap();
        let admission = signer.admission.clone().acquire_owned().await.unwrap();
        let queued_signer = Arc::clone(&signer);
        let queued = tokio::spawn(async move { queued_signer.sign("queued").await });
        tokio::task::yield_now().await;
        assert_eq!(signer.admission.available_permits(), 0);
        assert!(matches!(
            signer.sign("overloaded").await,
            Err(WxPayError::SignError(_))
        ));
        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());
        drop((worker, admission));
        assert_eq!(signer.admission.available_permits(), 2);
        assert!(signer.sign("after cancellation").await.is_ok());
    }

    #[test]
    fn cancellation_keeps_capacity_until_blocking_task_completes() {
        use std::sync::mpsc;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (release, blocked) = mpsc::channel();
        let blocker = runtime.spawn_blocking(move || blocked.recv().unwrap());
        let signer = Arc::new(test_signer().with_signing_capacity(1, 0).unwrap());
        runtime.block_on(async {
            let signing = Arc::clone(&signer);
            let task = tokio::spawn(async move { signing.sign("cancelled").await });
            tokio::task::yield_now().await;
            // The RSA task is queued behind blocker, so this also proves the runtime yielded.
            assert_eq!(signer.workers.available_permits(), 0);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert!(signer.sign("overloaded").await.is_err());
            release.send(()).unwrap();
            blocker.await.unwrap();
        });
        // Runtime drop joins blocking tasks; permits then become available again.
        drop(runtime);
        assert_eq!(signer.workers.available_permits(), 1);
        assert_eq!(signer.admission.available_permits(), 1);
    }

    #[test]
    fn test_build_sign_message() {
        let message = Sha256RsaSigner::build_sign_message(
            "POST",
            "/v3/pay/transactions/jsapi",
            1609459200,
            "test_nonce",
            r#"{"app_id":"wx88888888"}"#,
        );

        assert!(message.starts_with("POST\n"));
        assert!(message.contains("/v3/pay/transactions/jsapi"));
        assert!(message.contains("1609459200"));
        assert!(message.contains("test_nonce"));
        assert!(message.ends_with("\n"));

        // 性能优化回归：与 format! 产物逐字节等价。
        assert_eq!(
            message,
            "POST\n/v3/pay/transactions/jsapi\n1609459200\ntest_nonce\n{\"app_id\":\"wx88888888\"}\n"
        );
    }

    #[test]
    fn test_build_authorization_header() {
        // 用真实签名器实例构建，验证格式正确性（商户号、序列号、时间戳、nonce、签名均嵌入）。
        let signer = test_signer();
        let header = signer.build_authorization_header("nonce_abc", 1700000000, "sig_xyz");

        assert!(header.starts_with("WECHATPAY2-SHA256-RSA2048 "));
        assert!(header.contains("mchid=\"1900000109\""));
        assert!(header.contains("nonce_str=\"nonce_abc\""));
        assert!(header.contains("timestamp=\"1700000000\""));
        assert!(header.contains("serial_no=\"CERT123456\""));
        assert!(header.contains("signature=\"sig_xyz\""));
    }

    #[tokio::test]
    async fn test_sign_is_deterministic_and_well_formed() {
        // PKCS1v15 + SHA256 是确定性签名：同一消息两次签名应完全一致。
        let signer = test_signer();
        let message = r#"{"app_id":"wx88888888","mchid":"1900000109"}"#;

        let sig_a = signer.sign(message).await.unwrap();
        let sig_b = signer.sign(message).await.unwrap();
        assert_eq!(sig_a, sig_b, "PKCS1v15 签名应为确定性的");

        // 2048-bit RSA 签名 = 256 字节 -> base64 长度 344（含可能的填充）。
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_a)
            .expect("签名应为合法 base64");
        assert_eq!(bytes.len(), 256, "2048 位密钥签名应为 256 字节");

        // 不同消息应产生不同签名。
        let sig_other = signer.sign("different message").await.unwrap();
        assert_ne!(sig_a, sig_other);
    }

    #[tokio::test]
    async fn test_signer_accessors() {
        let signer = test_signer();
        assert_eq!(signer.merchant_id(), "1900000109");
        assert_eq!(signer.cert_serial_number(), "CERT123456");
    }

    #[test]
    fn test_new_rejects_invalid_private_key() {
        let result = Sha256RsaSigner::new("mch", b"not a valid pem", "serial");
        assert!(matches!(result, Err(WxPayError::InvalidPrivateKey(_))));
    }

    #[test]
    fn test_new_rejects_non_utf8_key() {
        // 非 UTF-8 字节应被拒绝，而非 panic。
        let result = Sha256RsaSigner::new("mch", &[0xff, 0xfe, 0xfd], "serial");
        assert!(matches!(result, Err(WxPayError::InvalidPrivateKey(_))));
    }
}
