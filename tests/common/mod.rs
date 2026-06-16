//! 集成测试共享夹具与桩实现。
//!
//! - `test_private_key_pem()`：与单元测试同源的 2048-bit PKCS#8 私钥（PEM）。
//! - `StubHttpClient`：实现公开 `HttpClient` trait 的内存桩，可预设返回响应并捕获请求，
//!   用于在不依赖真实网络的情况下端到端验证：签名 → 头构建 → 分发 → 响应解析 → 错误映射。

use async_trait::async_trait;
use std::sync::Mutex;
use wxpay_rs::WxPayConfig;
use wxpay_rs::error::WxPayResult;
use wxpay_rs::http::HttpClient;
use wxpay_rs::http::client::HttpResponse;

/// 测试用 PKCS#8 私钥（PEM），2048-bit。
pub const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDQFwtb0xnMYumg\neu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz\n05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2\nL9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoe\naK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/r\nXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhf\nSes6QE3tAgMBAAECgf8ZVV+Mo6arELULVJaxcBj+WjW/epK3s4lhxSLDYx1LXKQo\nJa+FIw5dL3hBc5BwW7kUdHh33ikLGKdq3S4UjJlQ+XWNgYRpIDCCitpeRurF1G8i\npKp5m9u8Y29K7YhcnF/iVyuaDhuhFhh79avGDZjCpg/ni+6PKssc7llTYNy5MGya\nBNkxzXX2Oo5WI1IBOptOEUb6iWYz5FoAf91Ai0K8mFuB5tPCv67DqB2Rq4c6LMoX\nVzwzMZ64GhzYC6vyjltzMjtYTIDvheOZsOUgJe1pAaChwiGRDpmuf8/oybSQFFsy\n1PYF+TddnNk0NOQCPI0qXLHE2OXtdDAigPiA5v8CgYEA6/BnV4O/ZS34WvaGucPx\nQp9s59FolMyWtwELLxOZaO1LPAa9pdNC1+IfUl6zpeRu2z1kNG9f2TbgtTVrF7Lu\n5XvuhJ2OqnL8GgGYpS0vj2Sx5XRO8/pgxiAnpRy7Mkp1jA4+ZTpNQH3FoA6LZZfM\n1v/ijOH9NeHUWEw64OE/OoMCgYEA4ch19Yp73ijLvEUyAkqYrvPOkm7G02mlRD4T\nTUe2tGe8HUbOZGi5CphvItto9mssPDDsEVLilkrPDKlg3899L+ZLE8vHzw6QVoaK\n8LDQaapWbW3LazwLAna4kpNDd06h+Rx7j/n1lha6Vj/2dbEQhAAllos92B7SCNf8\nYIiXqs8CgYACC3tZztKB1fwpDantQj19DlSrTa1SXNORkni+V7Ukq6nTQ1uxbDtQ\nE62h0SBNd8VeMRIFQlHaWBdqeqQK+IoJgyF2FMd/wq9cqlbgV5vp6j2Ad5mXk7vy\n+6RcUfttXCfYpubziaXRwUVNNdMPdllYI6+a+Ppw1Rw6B68a89jQcQKBgFaW+JY4\njBTBdJE5wFocnb3LBxgln98IjzdCz0g+DpXVitF3jEP53a1wlH67wt9ubsKOyJpE\nPV4CRrHGa76p5oruOTDYYELKhRSJ+NMiHGvJxeelyfPQTTCes16TV7Zz066j+8dV\nx5fOE5xsX2r3gyv8mm3H7OnruAVoQAQNno0FAoGBAOvD07di46NEaY7OTGzt4JwE\nWa/0KzWvrQ6SCaHUnZ1yIqL6jEV7RCxKGr206cW9nlG2+n2QqAC8dinDrdLspLZG\noEqm/DoCUaghQOGnh7teguj3eqS+MHU5T/ugSJdJoMNtpQ/BlSnqkWLPoh+yrvh5\nmVKYyABhNkZONhC533bA\n-----END PRIVATE KEY-----\n";

/// 构造测试用 `WxPayConfig`（使用测试私钥与 32 位 api_v3_key）。
pub fn test_config() -> WxPayConfig {
    WxPayConfig::builder()
        .app_id("wx88888888")
        .merchant_id("1900000109")
        .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
        .private_key(TEST_PRIVATE_KEY_PEM.as_bytes().to_vec())
        .cert_serial_number("CERT123456")
        .build()
        .expect("测试配置应构建成功")
}

/// 内存桩 HTTP 客户端：每次请求返回预设响应，并捕获最后一次请求的 URL/头/体。
pub struct StubHttpClient {
    status: u16,
    body: String,
    request_id: Option<String>,
    last_url: Mutex<Option<String>>,
    last_headers: Mutex<Vec<(String, String)>>,
    last_body: Mutex<Option<String>>,
    request_count: Mutex<usize>,
}

impl StubHttpClient {
    /// 创建返回固定 JSON 的桩（无响应头）。
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            request_id: None,
            last_url: Mutex::new(None),
            last_headers: Mutex::new(Vec::new()),
            last_body: Mutex::new(None),
            request_count: Mutex::new(0),
        }
    }

    /// 创建带 `Request-ID` 响应头的成功桩（便于校验链路追踪）。
    pub fn ok_with_request_id(body: &str, request_id: &str) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            request_id: Some(request_id.to_string()),
            last_url: Mutex::new(None),
            last_headers: Mutex::new(Vec::new()),
            last_body: Mutex::new(None),
            request_count: Mutex::new(0),
        }
    }

    fn make_response(&self) -> HttpResponse {
        let mut headers = Vec::new();
        if let Some(id) = &self.request_id {
            headers.push(("Request-ID".to_string(), id.clone()));
        }
        HttpResponse::new(self.status, headers, self.body.clone())
    }

    pub fn captured_url(&self) -> Option<String> {
        self.last_url.lock().unwrap().clone()
    }

    pub fn captured_headers(&self) -> Vec<(String, String)> {
        self.last_headers.lock().unwrap().clone()
    }

    pub fn captured_body(&self) -> Option<String> {
        self.last_body.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        *self.request_count.lock().unwrap()
    }

    /// 捕获到的 Authorization 头（用于断言签名）。
    pub fn captured_authorization(&self) -> Option<String> {
        self.captured_headers()
            .into_iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
            .map(|(_, v)| v)
    }
}

#[async_trait]
impl HttpClient for StubHttpClient {
    async fn get(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        *self.last_url.lock().unwrap() = Some(url.to_string());
        *self.last_headers.lock().unwrap() = headers;
        *self.request_count.lock().unwrap() += 1;
        Ok(self.make_response())
    }

    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        *self.last_url.lock().unwrap() = Some(url.to_string());
        *self.last_headers.lock().unwrap() = headers;
        *self.last_body.lock().unwrap() = Some(body.to_string());
        *self.request_count.lock().unwrap() += 1;
        Ok(self.make_response())
    }

    async fn put(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        *self.last_url.lock().unwrap() = Some(url.to_string());
        *self.last_headers.lock().unwrap() = headers;
        *self.last_body.lock().unwrap() = Some(body.to_string());
        *self.request_count.lock().unwrap() += 1;
        Ok(self.make_response())
    }

    async fn delete(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        *self.last_url.lock().unwrap() = Some(url.to_string());
        *self.last_headers.lock().unwrap() = headers;
        *self.request_count.lock().unwrap() += 1;
        Ok(self.make_response())
    }

    async fn patch(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> WxPayResult<HttpResponse> {
        *self.last_url.lock().unwrap() = Some(url.to_string());
        *self.last_headers.lock().unwrap() = headers;
        *self.last_body.lock().unwrap() = Some(body.to_string());
        *self.request_count.lock().unwrap() += 1;
        Ok(self.make_response())
    }
}
