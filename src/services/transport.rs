use std::sync::Arc;
use std::time::Instant;

use serde::de::DeserializeOwned;

use crate::auth::{Sha256RsaSigner, Sha256RsaVerifier, Signer, Verifier};
use crate::cert::CertManager;
use crate::config::WxPayConfig;
use crate::error::{WxPayAlertLevel, WxPayError, WxPayErrorKind, WxPayResult};
use crate::http::client::HttpResponse;
use crate::http::{HttpClient, HttpMethod, ResponseHandler};

/// User-Agent 常量（编译期拼入 crate 版本，避免每次请求重复格式化）。
const USER_AGENT: &str = concat!("wxpay-rs/", env!("CARGO_PKG_VERSION"));

/// 统一服务请求执行器
#[derive(Debug)]
pub struct TransportEvent {
    /// 操作标识
    pub operation: String,
    /// HTTP 方法
    pub method: String,
    /// 请求路径
    pub path: String,
    /// HTTP 状态码
    pub status: u16,
    /// 请求 ID
    pub request_id: String,
    /// 请求耗时（毫秒）
    pub elapsed_ms: u128,
    /// 商户号
    pub merchant_id: String,
    /// 应用 ID
    pub app_id: String,
    /// 是否成功
    pub is_success: bool,
    /// 微信 API 错误码
    pub error_code: Option<String>,
    /// 错误分类
    pub error_kind: Option<WxPayErrorKind>,
    /// 告警级别
    pub alert_level: WxPayAlertLevel,
    /// 告警策略
    pub alert_policy: String,
    /// 是否建议重试
    pub should_retry: bool,
    /// 是否鉴权/签名类错误
    pub is_auth_error: bool,
}

struct TransportErrorContext<'a> {
    operation: &'a str,
    method: &'a str,
    path: &'a str,
    status: u16,
    request_id: &'a str,
    elapsed_ms: u128,
    error: &'a WxPayError,
}

impl TransportEvent {
    fn success(
        operation: &str,
        method: &str,
        path: &str,
        config: &WxPayConfig,
        status: u16,
        request_id: &str,
        elapsed_ms: u128,
    ) -> Self {
        Self {
            operation: operation.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            status,
            request_id: request_id.to_string(),
            elapsed_ms,
            merchant_id: config.merchant_id.clone(),
            app_id: config.app_id.clone(),
            is_success: true,
            error_code: None,
            error_kind: None,
            alert_level: WxPayAlertLevel::Low,
            alert_policy: "success".to_string(),
            should_retry: false,
            is_auth_error: false,
        }
    }

    fn error(config: &WxPayConfig, context: TransportErrorContext<'_>) -> Self {
        Self {
            operation: context.operation.to_string(),
            method: context.method.to_string(),
            path: context.path.to_string(),
            status: context.status,
            request_id: context.request_id.to_string(),
            elapsed_ms: context.elapsed_ms,
            merchant_id: config.merchant_id.clone(),
            app_id: config.app_id.clone(),
            is_success: false,
            error_code: context.error.api_code().map(str::to_string),
            error_kind: context.error.api_kind(),
            alert_level: context.error.alert_level(),
            alert_policy: context.error.alert_policy().to_string(),
            should_retry: context.error.should_retry(),
            is_auth_error: context.error.is_auth_error(),
        }
    }

    /// 错误分类字符串（用于日志/告警标签）
    pub fn error_kind_label(&self) -> &'static str {
        self.error_kind
            .map(|kind| kind.as_str())
            .unwrap_or("non_api")
    }

    /// 统一告警路由键（告警系统规则直接引用）
    pub fn alert_key(&self) -> String {
        // 性能优化：预分配容量就地拼接，避免 `format!` 的额外开销。
        let level = self.alert_level.as_str();
        let mut s = String::with_capacity(level.len() + 1 + self.alert_policy.len());
        s.push_str(level);
        s.push('.');
        s.push_str(&self.alert_policy);
        s
    }

    /// 是否建议立即触发告警（用于结构化日志策略）
    pub fn should_alert(&self) -> bool {
        matches!(
            self.alert_level,
            WxPayAlertLevel::High | WxPayAlertLevel::Critical
        ) || self.should_retry
    }
}

/// 传输观测回调。回调在请求任务内同步执行，请勿执行阻塞 I/O。
pub trait TransportObserver: Send + Sync {
    /// 请求成功回调（可用于指标计数/延迟统计）
    fn on_success(&self, _event: &TransportEvent) {}

    /// 请求失败回调（可用于告警/链路打点）
    fn on_error(&self, _event: &TransportEvent, _error: &WxPayError) {}
}

#[derive(Debug)]
pub struct NoopTransportObserver;

impl TransportObserver for NoopTransportObserver {}

#[derive(Clone)]
pub struct ServiceTransport {
    config: Arc<WxPayConfig>,
    http_client: Arc<dyn HttpClient>,
    signer: Arc<dyn Signer>,
    transport_observer: Option<Arc<dyn TransportObserver>>,
    trust: Arc<Result<TransportTrust, String>>,
}

struct TransportTrust {
    require_active_key: bool,
    verifier: Arc<dyn Verifier>,
    cert_manager: Arc<CertManager>,
}

impl std::fmt::Debug for ServiceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTransport")
            .field("transport_observer", &self.transport_observer.is_some())
            .finish()
    }
}

impl ServiceTransport {
    /// 创建执行器
    pub fn new(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self::new_with_observer(config, http_client, signer, None)
    }

    /// 创建执行器（携带观测回调）
    pub fn new_with_observer(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> Self {
        let trust = CertManager::from_material(
            config.platform_certificates.clone(),
            config.platform_public_keys.clone(),
        )
        .map(|manager| {
            let cert_manager = Arc::new(manager);
            TransportTrust {
                require_active_key: true,
                verifier: Arc::new(Sha256RsaVerifier::from_manager(cert_manager.clone())),
                cert_manager,
            }
        })
        .map_err(|error| error.to_string());
        Self {
            config,
            http_client,
            signer,
            transport_observer,
            trust: Arc::new(trust),
        }
    }

    /// 使用共享验签器和证书管理器创建执行器。
    pub(crate) fn new_with_verifier(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        verifier: Arc<dyn Verifier>,
        cert_manager: Arc<CertManager>,
        require_active_key: bool,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> Self {
        Self {
            config,
            http_client,
            signer,
            transport_observer,
            trust: Arc::new(Ok(TransportTrust {
                require_active_key,
                verifier,
                cert_manager,
            })),
        }
    }

    fn trust(&self) -> WxPayResult<&TransportTrust> {
        self.trust
            .as_ref()
            .as_ref()
            .map_err(|message| WxPayError::CertificateParseError(message.clone()))
    }

    /// 同一次请求的所有敏感字段使用同一个平台密钥快照。
    /// 所有字段加密成功后才替换原值，返回值用于 Wechatpay-Serial 请求头。
    pub(crate) async fn encrypt_sensitive_fields(
        &self,
        fields: &mut [&mut String],
    ) -> WxPayResult<Option<String>> {
        if fields.is_empty() {
            return Ok(None);
        }
        let (serial, cipher) = self.trust()?.cert_manager.encryption_key().await?;
        let encrypted = fields
            .iter()
            .map(|field| cipher.encrypt(field))
            .collect::<WxPayResult<Vec<_>>>()?;
        for (field, ciphertext) in fields.iter_mut().zip(encrypted) {
            **field = ciphertext;
        }
        Ok(Some(serial))
    }

    fn build_headers(
        &self,
        nonce: &str,
        timestamp: i64,
        method: HttpMethod,
        signature: &str,
        mut headers: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        let authorization = crate::auth::signer::build_authorization_header(
            &self.config.merchant_id,
            &self.config.cert_serial_number,
            nonce,
            timestamp,
            signature,
        );
        headers.push(("Authorization".to_string(), authorization));
        headers.push(("Accept".to_string(), "application/json".to_string()));
        headers.push(("User-Agent".to_string(), USER_AGENT.to_string()));
        if matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
        ) {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        headers
    }

    async fn send(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        mut extra_headers: Vec<(String, String)>,
    ) -> WxPayResult<HttpResponse> {
        self.config.validate()?;
        let trust = self.trust()?;
        if trust.require_active_key && trust.cert_manager.verification_keys().is_empty() {
            return Err(WxPayError::CertificateVerificationError(
                "发送业务请求前必须配置有效的平台证书或公钥".to_string(),
            ));
        }
        // 公钥灰度期间，普通请求也必须声明接受的公钥 ID。
        // 敏感字段已经选定密钥时保留其 serial，不能替换或追加第二个值。
        if !extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Wechatpay-Serial"))
            && let Some(id) = trust.cert_manager.preferred_public_key_id()
        {
            extra_headers.push(("Wechatpay-Serial".to_string(), id));
        }
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let body = body.unwrap_or("");
        // 借用序列化后的请求体；仅签名串及 HTTP 后端按需要分配。
        let message =
            Sha256RsaSigner::build_sign_message(method.as_str(), path, timestamp, &nonce, body);
        let signature = self.signer.sign(&message).await?;
        let headers = self.build_headers(&nonce, timestamp, method, &signature, extra_headers);
        let url = format!("{}{}", self.config.base_url(), path);
        match method {
            HttpMethod::Get => self.http_client.get(&url, headers).await,
            HttpMethod::Post => self.http_client.post(&url, headers, body).await,
            HttpMethod::Put => self.http_client.put(&url, headers, body).await,
            HttpMethod::Delete => self.http_client.delete(&url, headers).await,
            HttpMethod::Patch => self.http_client.patch(&url, headers, body).await,
        }
    }

    fn signature_header<'a>(response: &'a HttpResponse, name: &str) -> WxPayResult<&'a str> {
        let mut matching = response
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name));
        let (_, value) = matching
            .next()
            .ok_or_else(|| WxPayError::InvalidSignatureFormat(format!("缺少响应头 {name}")))?;
        if value.is_empty()
            || matching.next().is_some()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(WxPayError::InvalidSignatureFormat(format!(
                "无效或重复的响应头 {name}"
            )));
        }
        Ok(value)
    }

    async fn verify_response(&self, response: &HttpResponse) -> WxPayResult<()> {
        // 部分网关错误没有签名头：只允许交付错误，绝不视为已认证业务数据。
        // 一旦出现任意签名头，必须完整验证，不能降级为无签名错误。
        let signature_headers = [
            "Wechatpay-Timestamp",
            "Wechatpay-Nonce",
            "Wechatpay-Serial",
            "Wechatpay-Signature",
            "Wechatpay-Signature-Type",
        ];
        if !response.is_success()
            && !signature_headers
                .iter()
                .any(|name| response.get_header(name).is_some())
        {
            return Ok(());
        }
        let timestamp = Self::signature_header(response, "Wechatpay-Timestamp")?;
        let nonce = Self::signature_header(response, "Wechatpay-Nonce")?;
        let serial = Self::signature_header(response, "Wechatpay-Serial")?;
        let signature = Self::signature_header(response, "Wechatpay-Signature")?;
        if response.get_header("Wechatpay-Signature-Type").is_some()
            && Self::signature_header(response, "Wechatpay-Signature-Type")?
                != "WECHATPAY2-SHA256-RSA2048"
        {
            return Err(WxPayError::InvalidSignatureFormat(
                "不支持的响应签名算法".to_string(),
            ));
        }
        let parsed_timestamp = timestamp
            .parse::<i64>()
            .map_err(|_| WxPayError::InvalidSignatureFormat("无效的响应时间戳".to_string()))?;
        if !timestamp.bytes().all(|value| value.is_ascii_digit())
            || crate::utils::timestamp::get_timestamp().abs_diff(parsed_timestamp) > 300
        {
            return Err(WxPayError::SignatureVerificationFailed);
        }
        // 保留时间戳原文及响应原始字符串，不重新序列化 JSON。
        let message = format!("{timestamp}\n{nonce}\n{}\n", response.body);
        if !self
            .trust()?
            .verifier
            .verify_with_serial(&message, signature, serial)
            .await?
        {
            return Err(WxPayError::SignatureVerificationFailed);
        }
        Ok(())
    }

    async fn execute<T>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
        extra_headers: Vec<(String, String)>,
        parse: impl FnOnce(&str) -> WxPayResult<T>,
    ) -> WxPayResult<T> {
        let started_at = Instant::now();
        let response = match self.send(method, path, body, extra_headers).await {
            Ok(response) => response,
            Err(error) => {
                self.observe(
                    operation,
                    method,
                    path,
                    0,
                    "-",
                    started_at.elapsed().as_millis(),
                    &Err::<(), _>(&error),
                );
                return Err(error);
            }
        };
        let request_id = ResponseHandler::get_request_id(&response).unwrap_or("-");
        let result = async {
            self.verify_response(&response).await?;
            let body = ResponseHandler::handle(&response)?;
            parse(body)
        }
        .await;
        self.observe(
            operation,
            method,
            path,
            response.status,
            request_id,
            started_at.elapsed().as_millis(),
            &result.as_ref(),
        );
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn observe<T>(
        &self,
        operation: &str,
        method: HttpMethod,
        path: &str,
        status: u16,
        request_id: &str,
        elapsed_ms: u128,
        result: &Result<T, &WxPayError>,
    ) {
        match result {
            Ok(_) => {
                if let Some(observer) = &self.transport_observer {
                    let event = TransportEvent::success(
                        operation,
                        method.as_str(),
                        path,
                        &self.config,
                        status,
                        request_id,
                        elapsed_ms,
                    );
                    observer.on_success(&event);
                }
                tracing::info!(
                    operation,
                    method = method.as_str(),
                    path,
                    status,
                    request_id,
                    elapsed_ms,
                    "wxpay request success"
                );
            }
            Err(error) => {
                let event = TransportEvent::error(
                    &self.config,
                    TransportErrorContext {
                        operation,
                        method: method.as_str(),
                        path,
                        status,
                        request_id,
                        elapsed_ms,
                        error,
                    },
                );
                if let Some(observer) = &self.transport_observer {
                    observer.on_error(&event, error);
                }
                tracing::warn!(operation, method = method.as_str(), path, status, request_id, elapsed_ms,
                    error_code = event.error_code.as_deref().unwrap_or("-"),
                    error_kind = event.error_kind_label(), alert_level = event.alert_level.as_str(),
                    alert_policy = event.alert_policy, alert_key = %event.alert_key(),
                    should_retry = event.should_retry, should_alert = event.should_alert(),
                    is_auth_error = event.is_auth_error, "wxpay request failed");
            }
        }
    }

    /// 发送请求，验证响应签名后反序列化 JSON。
    /// 缺少签名头的非 2xx 应答仅可产生错误，其错误内容未经过签名认证。
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
    ) -> WxPayResult<T> {
        self.request_with_headers(method, path, body, operation, Vec::new())
            .await
    }

    /// 携带服务层附加头发送请求并验证响应。
    pub(crate) async fn request_with_headers<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
        headers: Vec<(String, String)>,
    ) -> WxPayResult<T> {
        self.execute(method, path, body, operation, headers, |body| {
            serde_json::from_str(body).map_err(WxPayError::from)
        })
        .await
    }

    /// 验证响应后在空响应体时返回默认值。
    pub async fn request_default<T: DeserializeOwned + Default>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        operation: &str,
    ) -> WxPayResult<T> {
        self.execute(method, path, body, operation, Vec::new(), |body| {
            if body.trim().is_empty() {
                Ok(T::default())
            } else {
                serde_json::from_str(body).map_err(WxPayError::from)
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Sha256RsaSigner;
    use crate::config::WxPayConfig;
    use async_trait::async_trait;
    use base64::Engine;
    use std::sync::Mutex;

    /// 与 auth/verifier 测试同源的测试私钥（PEM），用于构造可实际签名的签名器。
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDQFwtb0xnMYumg\neu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz\n05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2\nL9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoe\naK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/r\nXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhf\nSes6QE3tAgMBAAECgf8ZVV+Mo6arELULVJaxcBj+WjW/epK3s4lhxSLDYx1LXKQo\nJa+FIw5dL3hBc5BwW7kUdHh33ikLGKdq3S4UjJlQ+XWNgYRpIDCCitpeRurF1G8i\npKp5m9u8Y29K7YhcnF/iVyuaDhuhFhh79avGDZjCpg/ni+6PKssc7llTYNy5MGya\nBNkxzXX2Oo5WI1IBOptOEUb6iWYz5FoAf91Ai0K8mFuB5tPCv67DqB2Rq4c6LMoX\nVzwzMZ64GhzYC6vyjltzMjtYTIDvheOZsOUgJe1pAaChwiGRDpmuf8/oybSQFFsy\n1PYF+TddnNk0NOQCPI0qXLHE2OXtdDAigPiA5v8CgYEA6/BnV4O/ZS34WvaGucPx\nQp9s59FolMyWtwELLxOZaO1LPAa9pdNC1+IfUl6zpeRu2z1kNG9f2TbgtTVrF7Lu\n5XvuhJ2OqnL8GgGYpS0vj2Sx5XRO8/pgxiAnpRy7Mkp1jA4+ZTpNQH3FoA6LZZfM\n1v/ijOH9NeHUWEw64OE/OoMCgYEA4ch19Yp73ijLvEUyAkqYrvPOkm7G02mlRD4T\nTUe2tGe8HUbOZGi5CphvItto9mssPDDsEVLilkrPDKlg3899L+ZLE8vHzw6QVoaK\n8LDQaapWbW3LazwLAna4kpNDd06h+Rx7j/n1lha6Vj/2dbEQhAAllos92B7SCNf8\nYIiXqs8CgYACC3tZztKB1fwpDantQj19DlSrTa1SXNORkni+V7Ukq6nTQ1uxbDtQ\nE62h0SBNd8VeMRIFQlHaWBdqeqQK+IoJgyF2FMd/wq9cqlbgV5vp6j2Ad5mXk7vy\n+6RcUfttXCfYpubziaXRwUVNNdMPdllYI6+a+Ppw1Rw6B68a89jQcQKBgFaW+JY4\njBTBdJE5wFocnb3LBxgln98IjzdCz0g+DpXVitF3jEP53a1wlH67wt9ubsKOyJpE\nPV4CRrHGa76p5oruOTDYYELKhRSJ+NMiHGvJxeelyfPQTTCes16TV7Zz066j+8dV\nx5fOE5xsX2r3gyv8mm3H7OnruAVoQAQNno0FAoGBAOvD07di46NEaY7OTGzt4JwE\nWa/0KzWvrQ6SCaHUnZ1yIqL6jEV7RCxKGr206cW9nlG2+n2QqAC8dinDrdLspLZG\noEqm/DoCUaghQOGnh7teguj3eqS+MHU5T/ugSJdJoMNtpQ/BlSnqkWLPoh+yrvh5\nmVKYyABhNkZONhC533bA\n-----END PRIVATE KEY-----\n";

    const TEST_CERT_DER_B64: &str = "MIIDMTCCAhmgAwIBAgIUO0KjQ4nVBzRZyR/2689auBsGMPcwDQYJKoZIhvcNAQELBQAwJzEWMBQGA1UEAwwNd3hwYXktcnMtdGVzdDENMAsGA1UECgwEdGVzdDAgFw0yNjA2MTYwNDE3MDlaGA8yMDUzMTEwMTA0MTcwOVowJzEWMBQGA1UEAwwNd3hwYXktcnMtdGVzdDENMAsGA1UECgwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAXC1vTGcxi6aB67mWFz4W/9d9TaElw+da2OGbcxUGEQzvd2axnTKu87Fm0mGzh18qzwGVYq8MiefPTn7aWsN0CQ02+3RcT/QHnmfYduTjJkjHrM5+wmWtwSgsxN8Txg2GYZ5GYT4vc4nYv0gB4xlbkh/dPbQTrn7wGiETyfAthed1cNMxkPUwAePd/KAKfZNkcqotR/2XNih5orlZz0DySY7p0xx59eSyS8koln5L8bR/7VoVw3wxojsYWBSR2zOCcSVkpbF+K/+tdC3ZPzxlwrQCmzKmXl+W51b0jMqOlOsm0bHxHi1V9nS95DPfFNTuOhFTuZSMHKF9J6zpATe0CAwEAAaNTMFEwHQYDVR0OBBYEFGo+jzczvrST9JVBo875auuysJS3MB8GA1UdIwQYMBaAFGo+jzczvrST9JVBo875auuysJS3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAChV2tnTzVIRbSHRrP0unCUYxf9mPldpVVB3Zbzb+S1oMllYwtUuNCgOuaIWz8LlA2A9yEoV5zvPJfrQFNJ3KYrMyAXJ7Q9UDFMSpP5aaqvtIq1GcLfw8EiyuGN3nQwHBPA2AN3JznDufWY5LI2TLDwiX/mv8U4ZzWHMOye7huI3AEIVTXv01NXWleI2TA/MxTMppaO8t5lzlaDXgPMnZqW5qsuHZzGk+aq07SO9KitKO4E5PoNYfE6ywWn13mOZrRklCtT9mauaE/kCHIAQPuyfWrZ2lvkjWIefQ/onZBxAKP5z6VcSb3Z/3G85MQm9kSnwUFjKw7yuauDv/wyq/AU=";

    fn test_config() -> Arc<WxPayConfig> {
        let config = WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .private_key(TEST_PRIVATE_KEY_PEM.as_bytes().to_vec())
            .cert_serial_number("CERT123456")
            .platform_certificate(
                base64::engine::general_purpose::STANDARD
                    .decode(TEST_CERT_DER_B64)
                    .unwrap(),
            )
            .build()
            .unwrap();
        Arc::new(config)
    }

    fn test_signer() -> Arc<dyn Signer> {
        Arc::new(
            Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456")
                .unwrap(),
        )
    }

    /// 记录单次请求的 mock HTTP 客户端，可配置返回的响应。
    struct MockHttpClient {
        response: HttpResponse,
        captured_url: Mutex<Option<String>>,
        captured_headers: Mutex<Vec<(String, String)>>,
        captured_body: Mutex<Option<String>>,
    }

    impl MockHttpClient {
        fn new(status: u16, body: &str) -> Self {
            Self {
                response: HttpResponse::new(
                    status,
                    vec![("Request-ID".to_string(), "mock-req-001".to_string())],
                    body.to_string(),
                ),
                captured_url: Mutex::new(None),
                captured_headers: Mutex::new(Vec::new()),
                captured_body: Mutex::new(None),
            }
        }
        async fn signed_response(&self) -> HttpResponse {
            let mut response = self.response.clone();
            let timestamp = crate::utils::timestamp::get_timestamp().to_string();
            let nonce = "response-nonce";
            let message = format!("{timestamp}\n{nonce}\n{}\n", response.body);
            let signature = test_signer().sign(&message).await.unwrap();
            response.headers.extend([
                ("Wechatpay-Timestamp".into(), timestamp),
                ("Wechatpay-Nonce".into(), nonce.into()),
                (
                    "Wechatpay-Serial".into(),
                    "3B42A34389D5073459C91FF6EBCF5AB81B0630F7".into(),
                ),
                ("Wechatpay-Signature".into(), signature),
            ]);
            response
        }
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn get(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers.clone();
            Ok(self.signed_response().await)
        }
        async fn post(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
            body: &str,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers.clone();
            *self.captured_body.lock().unwrap() = Some(body.to_string());
            Ok(self.signed_response().await)
        }
        async fn put(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
            body: &str,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers;
            *self.captured_body.lock().unwrap() = Some(body.to_string());
            Ok(self.signed_response().await)
        }
        async fn delete(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers;
            Ok(self.signed_response().await)
        }
        async fn patch(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
            body: &str,
        ) -> WxPayResult<HttpResponse> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            *self.captured_headers.lock().unwrap() = headers;
            *self.captured_body.lock().unwrap() = Some(body.to_string());
            Ok(self.signed_response().await)
        }
    }

    fn build_transport(http: Arc<MockHttpClient>) -> ServiceTransport {
        ServiceTransport::new(test_config(), http, test_signer())
    }

    #[tokio::test]
    async fn test_request_signs_and_parses_success() {
        let http = Arc::new(MockHttpClient::new(200, r#"{"prepay_id":"wx20240101"}"#));
        let transport = build_transport(http.clone());

        #[derive(serde::Deserialize)]
        struct Prepay {
            prepay_id: String,
        }

        let body = r#"{"app_id":"wx88888888"}"#;
        let resp: Prepay = transport
            .request(
                HttpMethod::Post,
                "/v3/pay/transactions/jsapi",
                Some(body),
                "test",
            )
            .await
            .unwrap();

        assert_eq!(resp.prepay_id, "wx20240101");

        // 验证请求被签名：Authorization 头存在且包含商户号与序列号。
        let headers = http.captured_headers.lock().unwrap().clone();
        let auth = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
            .map(|(_, v)| v.as_str())
            .expect("应携带 Authorization 头");
        assert!(auth.starts_with("WECHATPAY2-SHA256-RSA2048 "));
        assert!(auth.contains("mchid=\"1900000109\""));
        assert!(auth.contains("serial_no=\"CERT123456\""));
        assert!(auth.contains("signature=\""));

        // 验证 URL 被正确拼接为完整地址。
        let url = http.captured_url.lock().unwrap().clone().unwrap();
        assert_eq!(
            url,
            "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi"
        );

        // 验证请求体被透传。
        let captured_body = http.captured_body.lock().unwrap().clone().unwrap();
        assert_eq!(captured_body, body);
    }

    #[tokio::test]
    async fn test_request_default_handles_empty_body() {
        let http = Arc::new(MockHttpClient::new(204, ""));
        let transport = build_transport(http);

        #[derive(serde::Deserialize, Default)]
        struct Empty;

        // 空响应体应返回默认值，而非 JSON 解析错误。
        let resp: Empty = transport
            .request_default(HttpMethod::Post, "/v3/pay/close", Some("{}"), "test")
            .await
            .unwrap();
        let _ = resp;
    }

    #[tokio::test]
    async fn test_api_error_is_classified() {
        // 返回限流错误码，验证 transport 将其归一为 ApiError 并正确分类。
        let http = Arc::new(MockHttpClient::new(
            429,
            r#"{"code":"FREQ_LIMIT","message":"请求过于频繁"}"#,
        ));
        let transport = build_transport(http);

        let err = transport
            .request::<serde_json::Value>(HttpMethod::Get, "/v3/pay/transactions/x", None, "test")
            .await
            .unwrap_err();

        match &err {
            WxPayError::ApiError { code, message } => {
                assert_eq!(code, "FREQ_LIMIT");
                assert_eq!(message, "请求过于频繁");
            }
            other => panic!("应为 ApiError，实际: {other:?}"),
        }
        // 限流应被分类为 RateLimited 且建议重试。
        assert_eq!(err.api_kind(), Some(WxPayErrorKind::RateLimited));
        assert!(err.should_retry());
    }

    /// 记录 observer 回调的简单实现。
    struct CountingObserver {
        success: std::sync::atomic::AtomicUsize,
        error: std::sync::atomic::AtomicUsize,
        last_event: Mutex<Option<TransportEvent>>,
    }

    impl CountingObserver {
        fn new() -> Self {
            Self {
                success: std::sync::atomic::AtomicUsize::new(0),
                error: std::sync::atomic::AtomicUsize::new(0),
                last_event: Mutex::new(None),
            }
        }
    }

    impl TransportObserver for CountingObserver {
        fn on_success(&self, event: &TransportEvent) {
            self.success
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_event.lock().unwrap() = Some(clone_event(event));
        }
        fn on_error(&self, event: &TransportEvent, _error: &WxPayError) {
            self.error.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_event.lock().unwrap() = Some(clone_event(event));
        }
    }

    // TransportEvent 字段较多，手工克隆以避免为测试派生 Clone。
    fn clone_event(e: &TransportEvent) -> TransportEvent {
        TransportEvent {
            operation: e.operation.clone(),
            method: e.method.clone(),
            path: e.path.clone(),
            status: e.status,
            request_id: e.request_id.clone(),
            elapsed_ms: e.elapsed_ms,
            merchant_id: e.merchant_id.clone(),
            app_id: e.app_id.clone(),
            is_success: e.is_success,
            error_code: e.error_code.clone(),
            error_kind: e.error_kind,
            alert_level: e.alert_level,
            alert_policy: e.alert_policy.clone(),
            should_retry: e.should_retry,
            is_auth_error: e.is_auth_error,
        }
    }

    #[tokio::test]
    async fn test_observer_fires_on_success_and_error() {
        // 成功路径触发 on_success。
        let observer = Arc::new(CountingObserver::new());
        let http = Arc::new(MockHttpClient::new(200, r#"{"ok":true}"#));
        let transport = ServiceTransport::new_with_observer(
            test_config(),
            http,
            test_signer(),
            Some(observer.clone()),
        );
        let _: serde_json::Value = transport
            .request(HttpMethod::Get, "/v3/any", None, "ok-op")
            .await
            .unwrap();
        assert_eq!(
            observer.success.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        {
            let evt = observer.last_event.lock().unwrap();
            let evt = evt.as_ref().unwrap();
            assert!(evt.is_success);
            assert_eq!(evt.operation, "ok-op");
            assert_eq!(evt.status, 200);
            assert_eq!(evt.alert_policy, "success");
        }

        // 错误路径触发 on_error，且事件携带错误分类。
        let observer2 = Arc::new(CountingObserver::new());
        let http2 = Arc::new(MockHttpClient::new(
            401,
            r#"{"code":"SIGN_ERROR","message":"签名错误"}"#,
        ));
        let transport2 = ServiceTransport::new_with_observer(
            test_config(),
            http2,
            test_signer(),
            Some(observer2.clone()),
        );
        let _: Result<serde_json::Value, _> = transport2
            .request(HttpMethod::Get, "/v3/any", None, "err-op")
            .await;
        assert_eq!(observer2.error.load(std::sync::atomic::Ordering::SeqCst), 1);
        let evt = observer2.last_event.lock().unwrap();
        let evt = evt.as_ref().unwrap();
        assert!(!evt.is_success);
        assert_eq!(evt.error_kind, Some(WxPayErrorKind::Authentication));
        assert!(evt.is_auth_error);
        assert_eq!(evt.alert_policy, "security.auth");
    }

    #[tokio::test]
    async fn test_transport_event_helpers() {
        let evt = TransportEvent::success("op", "GET", "/v3/x", &test_config(), 200, "req-1", 42);
        assert_eq!(evt.alert_key(), "low.success");
        assert!(!evt.should_alert());

        let err = WxPayError::Timeout;
        let err_evt = TransportEvent::error(
            &test_config(),
            TransportErrorContext {
                operation: "op",
                method: "GET",
                path: "/v3/x",
                status: 0,
                request_id: "req-1",
                elapsed_ms: 42,
                error: &err,
            },
        );
        assert_eq!(err_evt.error_kind_label(), "non_api");
        assert!(err_evt.should_alert());
        assert_eq!(err_evt.alert_key(), "critical.network");
    }

    #[tokio::test]
    async fn explicit_encryption_serial_survives_public_key_rotation_without_duplication() {
        use der::{Decode, Encode};
        let http = Arc::new(MockHttpClient::new(200, "{}"));
        let transport = build_transport(http.clone());
        let mut name = "张三".to_string();
        let serial = transport
            .encrypt_sensitive_fields(&mut [&mut name])
            .await
            .unwrap()
            .unwrap();
        assert_ne!(name, "张三");
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(TEST_CERT_DER_B64)
            .unwrap();
        let key = x509_cert::Certificate::from_der(&certificate)
            .unwrap()
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        transport
            .trust()
            .unwrap()
            .cert_manager
            .add_public_key("PUB_KEY_ID_NEW".into(), key)
            .await
            .unwrap();
        let _: serde_json::Value = transport
            .request_with_headers(
                HttpMethod::Post,
                "/v3/test",
                Some("{}"),
                "encrypted",
                vec![("wechatpay-serial".to_string(), serial.clone())],
            )
            .await
            .unwrap();
        let headers = http.captured_headers.lock().unwrap();
        let serials: Vec<_> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Wechatpay-Serial"))
            .map(|(_, value)| value)
            .collect();
        assert_eq!(serials, vec![&serial]);
    }
}
