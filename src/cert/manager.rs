//! Shared, parsed platform certificate and public-key store.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::signature::{ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::crypto::RsaOaepCipher;
use crate::error::{WxPayError, WxPayResult};
use crate::utils::timestamp::get_timestamp;

#[derive(Clone)]
pub(crate) struct VerificationKey {
    pub(crate) key: Arc<ParsedPublicKey>,
    cipher: Arc<RsaOaepCipher>,
    canonical_der: Arc<[u8]>,
    not_before: i64,
    not_after: i64,
}

impl VerificationKey {
    fn new(der: &[u8], not_before: i64, not_after: i64) -> WxPayResult<Self> {
        let key = ParsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, der).map_err(|e| {
            WxPayError::CertificateParseError(format!("Invalid RSA public key: {e}"))
        })?;
        let canonical: PublicKeyX509Der<'_> = key
            .as_der()
            .map_err(|_| WxPayError::CertificateParseError("Cannot encode public key".into()))?;
        let canonical_der = Arc::from(canonical.as_ref());
        Ok(Self {
            key: Arc::new(key),
            canonical_der,
            cipher: Arc::new(RsaOaepCipher::from_public_key_der(der)?),
            not_before,
            not_after,
        })
    }

    pub(crate) fn check_validity_at(&self, now: i64) -> WxPayResult<()> {
        if now > self.not_after {
            return Err(WxPayError::CertificateExpired);
        }
        if now < self.not_before {
            return Err(WxPayError::CertificateVerificationError(
                "Certificate is not effective yet".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct CertEntry {
    cert: Certificate,
    der: Vec<u8>,
    verification: VerificationKey,
}

impl CertEntry {
    pub(crate) fn parse(data: &[u8]) -> WxPayResult<(String, Self)> {
        let der = decode_pem_or_der(data, "CERTIFICATE")?;
        let cert = Certificate::from_der(&der)
            .map_err(|e| WxPayError::CertificateParseError(format!("Invalid certificate: {e}")))?;
        let tbs = cert.tbs_certificate();
        let serial = normalize_serial(&hex::encode(tbs.serial_number().as_bytes()))?;
        let validity = tbs.validity();
        let not_before = validity.not_before.to_unix_duration().as_secs() as i64;
        let not_after = validity.not_after.to_unix_duration().as_secs() as i64;
        if not_before > not_after {
            return Err(WxPayError::CertificateVerificationError(
                "Invalid certificate validity interval".into(),
            ));
        }
        let spki = tbs.subject_public_key_info().to_der()?;
        let verification = VerificationKey::new(&spki, not_before, not_after)?;
        Ok((
            serial,
            Self {
                cert,
                der,
                verification,
            },
        ))
    }

    /// Signed API metadata can retire a certificate before its X.509 expiry.
    pub(crate) fn restrict_validity(
        &mut self,
        effective_time: Option<&str>,
        expire_time: Option<&str>,
    ) -> WxPayResult<()> {
        if let Some(time) = effective_time {
            self.verification.not_before = self
                .verification
                .not_before
                .max(chrono::DateTime::parse_from_rfc3339(time)?.timestamp());
        }
        if let Some(time) = expire_time {
            self.verification.not_after = self
                .verification
                .not_after
                .min(chrono::DateTime::parse_from_rfc3339(time)?.timestamp());
        }
        if self.verification.not_before > self.verification.not_after {
            return Err(WxPayError::CertificateVerificationError(
                "Invalid certificate activation/retirement interval".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn der(&self) -> &[u8] {
        &self.der
    }
}

#[derive(Default)]
struct KeyStore {
    certificates: BTreeMap<String, CertEntry>,
    public_keys: BTreeMap<String, VerificationKey>,
}

/// Shared platform trust store. Certificate serials are canonical hexadecimal;
/// public-key IDs retain their exact, case-sensitive identity.
///
/// Only load certificates/public keys obtained through a trusted channel. The
/// downloader authenticates encrypted certificates before publishing a batch.
#[derive(Clone, Default)]
pub struct CertManager {
    store: Arc<RwLock<KeyStore>>,
}

impl CertManager {
    /// Create an empty trust store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse configured trust material once. Accepts PEM or DER certificates
    /// and PUBLIC KEY PEM/DER keys paired with their `PUB_KEY_ID_...` IDs.
    pub fn from_material(
        certificates: Vec<Vec<u8>>,
        public_keys: Vec<(String, Vec<u8>)>,
    ) -> WxPayResult<Self> {
        let mut store = KeyStore::default();
        for data in certificates {
            let (serial, entry) = CertEntry::parse(&data)?;
            insert_certificate(&mut store.certificates, serial, entry)?;
        }
        for (id, pem) in public_keys {
            let key = parse_public_key(&id, &pem)?;
            if store.public_keys.insert(id, key).is_some() {
                return Err(WxPayError::InvalidCertificate(
                    "Duplicate public-key ID".into(),
                ));
            }
        }
        Ok(Self {
            store: Arc::new(RwLock::new(store)),
        })
    }

    /// Add trusted certificate data, deriving each serial from X.509. The whole
    /// batch is parsed and validated before one atomic store update.
    pub async fn add_certificates(&self, certificates: Vec<Vec<u8>>) -> WxPayResult<()> {
        let mut batch = BTreeMap::new();
        for data in certificates {
            let (serial, entry) = CertEntry::parse(&data)?;
            insert_certificate(&mut batch, serial, entry)?;
        }
        self.publish_batch(batch)
    }

    /// Add a trusted PEM/DER certificate. The supplied serial must match X.509.
    pub async fn add_certificate(&self, serial_number: String, data: Vec<u8>) -> WxPayResult<()> {
        let (serial, entry) = CertEntry::parse(&data)?;
        if normalize_serial(&serial_number)? != serial {
            return Err(WxPayError::InvalidCertificate(
                "Certificate serial mismatch".into(),
            ));
        }
        self.publish_batch(BTreeMap::from([(serial, entry)]))
    }

    /// Add a trusted platform public key. IDs are not hexadecimal certificate serials.
    pub async fn add_public_key(&self, id: String, pem: Vec<u8>) -> WxPayResult<()> {
        let key = parse_public_key(&id, &pem)?;
        let mut store = self.store.write().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = store.public_keys.get(&id) {
            return if existing.canonical_der == key.canonical_der {
                Ok(())
            } else {
                Err(WxPayError::InvalidCertificate(
                    "Conflicting public-key ID".into(),
                ))
            };
        }
        store.public_keys.insert(id, key);
        Ok(())
    }

    /// Remove a pinned public key, for example after its retirement.
    pub async fn remove_public_key(&self, id: &str) {
        self.store
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .public_keys
            .remove(id);
    }

    pub(crate) fn publish_batch(&self, mut batch: BTreeMap<String, CertEntry>) -> WxPayResult<()> {
        let mut store = self.store.write().unwrap_or_else(|p| p.into_inner());
        // Preflight every collision before mutating the live store.
        for (serial, incoming) in &batch {
            if let Some(existing) = store.certificates.get(serial)
                && existing.der != incoming.der
            {
                return Err(WxPayError::InvalidCertificate(
                    "Conflicting certificate serial".into(),
                ));
            }
        }
        // Retirement is monotonic for an installed identity: an omitted or later
        // expiry must not reactivate a certificate the platform already retired.
        for (serial, incoming) in &mut batch {
            if let Some(existing) = store.certificates.get(serial) {
                incoming.verification.not_before = incoming
                    .verification
                    .not_before
                    .max(existing.verification.not_before);
                incoming.verification.not_after = incoming
                    .verification
                    .not_after
                    .min(existing.verification.not_after);
            }
        }
        let now = get_timestamp();
        // Keep retired entries as tombstones until intrinsic X.509 expiry, so a
        // later refresh cannot bootstrap the same identity without its retirement.
        store.certificates.retain(|_, entry| {
            entry
                .cert
                .tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration()
                .as_secs() as i64
                >= now
        });
        store.certificates.extend(batch);
        Ok(())
    }

    pub(crate) fn from_batch(batch: BTreeMap<String, CertEntry>) -> Self {
        Self {
            store: Arc::new(RwLock::new(KeyStore {
                certificates: batch,
                public_keys: BTreeMap::new(),
            })),
        }
    }

    pub(crate) fn verification_key(&self, id: &str) -> WxPayResult<VerificationKey> {
        let store = self.store.read().unwrap_or_else(|p| p.into_inner());
        let key = if id.starts_with("PUB_KEY_ID_") {
            store.public_keys.get(id)
        } else {
            let serial =
                normalize_serial(id).map_err(|_| WxPayError::CertificateNotFound(id.to_owned()))?;
            store
                .certificates
                .get(&serial)
                .map(|entry| &entry.verification)
        }
        .ok_or_else(|| WxPayError::CertificateNotFound(id.to_owned()))?;
        key.check_validity_at(get_timestamp())?;
        Ok(key.clone())
    }

    pub(crate) fn verification_keys(&self) -> Vec<VerificationKey> {
        let store = self.store.read().unwrap_or_else(|p| p.into_inner());
        let now = get_timestamp();
        store
            .public_keys
            .values()
            .chain(store.certificates.values().map(|entry| &entry.verification))
            .filter(|key| key.check_validity_at(now).is_ok())
            .cloned()
            .collect()
    }

    /// Preferred pinned public-key ID for `Wechatpay-Serial` response-signature
    /// negotiation. Returns `None` in certificate mode. Uses the same stable
    /// ordering as [`Self::encryption_key`] and reflects shared-store changes.
    pub fn preferred_public_key_id(&self) -> Option<String> {
        self.store
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .public_keys
            .last_key_value()
            .map(|(id, _)| id.clone())
    }

    /// Get one stable key/ID pair for all sensitive fields of a request. Pinned
    /// public keys take precedence; otherwise the latest active certificate wins.
    pub async fn encryption_key(&self) -> WxPayResult<(String, Arc<RsaOaepCipher>)> {
        let store = self.store.read().unwrap_or_else(|p| p.into_inner());
        if let Some((id, key)) = store.public_keys.last_key_value() {
            return Ok((id.clone(), key.cipher.clone()));
        }
        let now = get_timestamp();
        let (serial, entry) = store
            .certificates
            .iter()
            .filter(|(_, entry)| entry.verification.check_validity_at(now).is_ok())
            .max_by_key(|(_, entry)| entry.verification.not_before)
            .ok_or_else(|| {
                WxPayError::CertificateVerificationError("No active platform encryption key".into())
            })?;
        Ok((serial.clone(), entry.verification.cipher.clone()))
    }

    /// Return a certificate by its case-insensitive hexadecimal serial.
    pub async fn get_certificate(&self, serial: &str) -> Option<Certificate> {
        let serial = normalize_serial(serial).ok()?;
        self.store
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .certificates
            .get(&serial)
            .map(|entry| entry.cert.clone())
    }

    /// Return certificate data in DER format.
    pub async fn get_certificate_data(&self, serial: &str) -> Option<Vec<u8>> {
        let serial = normalize_serial(serial).ok()?;
        self.store
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .certificates
            .get(&serial)
            .map(|entry| entry.der.clone())
    }

    /// List installed certificate serial numbers.
    pub async fn get_serial_numbers(&self) -> Vec<String> {
        self.store
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .certificates
            .keys()
            .cloned()
            .collect()
    }

    /// Remove a certificate by serial.
    pub async fn remove_certificate(&self, serial: &str) -> WxPayResult<()> {
        let serial = normalize_serial(serial)?;
        self.store
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .certificates
            .remove(&serial);
        Ok(())
    }

    /// Clear all certificates and pinned public keys.
    pub async fn clear(&self) {
        *self.store.write().unwrap_or_else(|p| p.into_inner()) = KeyStore::default();
    }

    /// Number of installed certificates, excluding pinned public keys.
    pub async fn count(&self) -> usize {
        self.store
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .certificates
            .len()
    }

    /// Check whether a certificate is installed (it may be inactive or expired).
    pub async fn has_certificate(&self, serial: &str) -> bool {
        let Ok(serial) = normalize_serial(serial) else {
            return false;
        };
        self.store
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .certificates
            .contains_key(&serial)
    }
}

impl std::fmt::Debug for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertManager").finish_non_exhaustive()
    }
}

pub(crate) fn normalize_serial(serial: &str) -> WxPayResult<String> {
    if serial.is_empty() || !serial.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(WxPayError::InvalidCertificate(
            "Certificate serial must be hexadecimal".into(),
        ));
    }
    let serial = serial.trim_start_matches('0');
    Ok(if serial.is_empty() {
        "0".into()
    } else {
        serial.to_ascii_uppercase()
    })
}

pub(crate) fn decode_pem_or_der(data: &[u8], expected_label: &str) -> WxPayResult<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.trim_start().starts_with("-----BEGIN")
    {
        let (label, document) = der::Document::from_pem(text.trim())?;
        if label != expected_label {
            return Err(WxPayError::CertificateParseError(format!(
                "Expected {expected_label} PEM"
            )));
        }
        return Ok(document.as_bytes().to_vec());
    }
    Ok(data.to_vec())
}

fn parse_public_key(id: &str, pem: &[u8]) -> WxPayResult<VerificationKey> {
    if !id.starts_with("PUB_KEY_ID_")
        || id.len() == "PUB_KEY_ID_".len()
        || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err(WxPayError::InvalidCertificate(
            "Invalid platform public-key ID".into(),
        ));
    }
    let der = decode_pem_or_der(pem, "PUBLIC KEY")?;
    VerificationKey::new(&der, 0, i64::MAX)
}

pub(crate) fn insert_certificate(
    batch: &mut BTreeMap<String, CertEntry>,
    serial: String,
    entry: CertEntry,
) -> WxPayResult<()> {
    if batch.insert(serial, entry).is_some() {
        return Err(WxPayError::InvalidCertificate(
            "Duplicate certificate serial in batch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verifier::tests::{test_cert_der, test_signer};
    use crate::auth::{Sha256RsaVerifier, Signer, Verifier};

    #[tokio::test]
    async fn verifier_tracks_shared_updates_and_removal() {
        let manager = Arc::new(CertManager::new());
        let verifier = Sha256RsaVerifier::from_manager(manager.clone());
        let (serial, _) = CertEntry::parse(&test_cert_der()).unwrap();
        assert!(manager.preferred_public_key_id().is_none());
        let signature = test_signer().sign("rotation message").await.unwrap();
        assert!(matches!(
            verifier
                .verify_with_serial("rotation message", &signature, &serial)
                .await,
            Err(WxPayError::CertificateNotFound(_))
        ));
        manager
            .add_certificates(vec![test_cert_der()])
            .await
            .unwrap();
        assert!(
            verifier
                .verify_with_serial(
                    "rotation message",
                    &signature,
                    &format!("00{}", serial.to_lowercase())
                )
                .await
                .unwrap()
        );
        manager.remove_certificate(&serial).await.unwrap();
        assert!(
            verifier
                .verify_with_serial("rotation message", &signature, &serial)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn pem_der_and_serial_integrity() {
        let pem = der::Document::try_from(test_cert_der().as_slice())
            .unwrap()
            .to_pem("CERTIFICATE", der::pem::LineEnding::LF)
            .unwrap();
        // Support the standard LF/CRLF line endings and surrounding file whitespace.
        let crlf = format!("  \n{}\n\t", pem.replace('\n', "\r\n"));
        let (_, crlf_entry) = CertEntry::parse(crlf.as_bytes()).unwrap();
        assert_eq!(crlf_entry.der(), test_cert_der());
        let manager = CertManager::from_material(vec![pem.into_bytes()], vec![]).unwrap();
        let (serial, _) = CertEntry::parse(&test_cert_der()).unwrap();
        assert_eq!(
            manager
                .get_certificate_data(&serial.to_lowercase())
                .await
                .unwrap(),
            test_cert_der()
        );
        assert!(
            manager
                .add_certificate("FF".into(), test_cert_der())
                .await
                .is_err()
        );
        assert_eq!(manager.count().await, 1);
    }

    #[tokio::test]
    async fn invalid_batch_does_not_publish_partial_trust() {
        let manager = CertManager::new();
        assert!(
            manager
                .add_certificates(vec![test_cert_der(), b"invalid".to_vec()])
                .await
                .is_err()
        );
        assert_eq!(manager.count().await, 0);
        assert!(
            manager
                .add_certificates(vec![test_cert_der(), test_cert_der()])
                .await
                .is_err()
        );
        assert_eq!(manager.count().await, 0);
    }

    #[tokio::test]
    async fn public_key_ids_are_exact_and_separate_from_certificate_serials() {
        let (_, entry) = CertEntry::parse(&test_cert_der()).unwrap();
        let der = entry
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        let pem = der::Document::try_from(der.as_slice())
            .unwrap()
            .to_pem("PUBLIC KEY", der::pem::LineEnding::LF)
            .unwrap();
        let id = "PUB_KEY_ID_AbC123";
        let manager = Arc::new(
            CertManager::from_material(vec![], vec![(id.into(), pem.into_bytes())]).unwrap(),
        );
        let verifier = Sha256RsaVerifier::from_manager(manager.clone());
        let signature = test_signer().sign("public-key message").await.unwrap();
        assert!(
            verifier
                .verify_with_serial("public-key message", &signature, id)
                .await
                .unwrap()
        );
        assert!(
            verifier
                .verify_with_serial("public-key message", &signature, "PUB_KEY_ID_ABC123")
                .await
                .is_err()
        );
        assert!(
            verifier
                .verify_with_serial("public-key message", &signature, "ABC123")
                .await
                .is_err()
        );
        assert_eq!(manager.encryption_key().await.unwrap().0, id);
        assert_eq!(manager.preferred_public_key_id().as_deref(), Some(id));
        let next_id = "PUB_KEY_ID_Zzz456";
        manager
            .add_public_key(next_id.into(), der.clone())
            .await
            .unwrap();
        assert_eq!(manager.preferred_public_key_id().as_deref(), Some(next_id));
        assert_eq!(manager.encryption_key().await.unwrap().0, next_id);
        manager.remove_public_key(next_id).await;
        assert_eq!(manager.preferred_public_key_id().as_deref(), Some(id));
        assert!(manager.add_public_key(id.into(), der).await.is_ok());
        manager.remove_public_key(id).await;
        assert!(manager.preferred_public_key_id().is_none());
        assert!(
            verifier
                .verify_with_serial("public-key message", &signature, id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn validity_is_checked_for_every_verification_and_encryption() {
        let now = get_timestamp();
        let (serial, mut entry) = CertEntry::parse(&test_cert_der()).unwrap();
        entry.verification.not_after = now - 1;
        let manager = CertManager::from_batch(BTreeMap::from([(serial.clone(), entry)]));
        assert!(matches!(
            manager.verification_key(&serial),
            Err(WxPayError::CertificateExpired)
        ));
        assert!(manager.encryption_key().await.is_err());
        let (_, mut entry) = CertEntry::parse(&test_cert_der()).unwrap();
        entry.verification.not_before = now + 60;
        let manager = CertManager::from_batch(BTreeMap::from([(serial.clone(), entry)]));
        assert!(matches!(
            manager.verification_key(&serial),
            Err(WxPayError::CertificateVerificationError(_))
        ));
        assert!(manager.encryption_key().await.is_err());
    }

    #[tokio::test]
    async fn refresh_or_reloading_pins_cannot_undo_a_retirement() {
        let (serial, mut entry) = CertEntry::parse(&test_cert_der()).unwrap();
        let retired_at = get_timestamp() - 1;
        entry.verification.not_after = retired_at;
        let manager = CertManager::from_batch(BTreeMap::from([(serial.clone(), entry)]));
        manager
            .add_certificates(vec![test_cert_der()])
            .await
            .unwrap();
        assert!(matches!(
            manager.verification_key(&serial),
            Err(WxPayError::CertificateExpired)
        ));
        // Publishing another empty batch retains the tombstone until X.509 expiry.
        manager.publish_batch(BTreeMap::new()).unwrap();
        manager
            .add_certificates(vec![test_cert_der()])
            .await
            .unwrap();
        assert!(matches!(
            manager.verification_key(&serial),
            Err(WxPayError::CertificateExpired)
        ));
    }

    #[tokio::test]
    async fn an_existing_public_key_id_cannot_be_rebound() {
        let (_, entry) = CertEntry::parse(&test_cert_der()).unwrap();
        let mut der = entry
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        let id = "PUB_KEY_ID_COLLISION";
        let manager = CertManager::from_material(vec![], vec![(id.into(), der.clone())]).unwrap();
        // Keep valid RSA encoding but change the exponent to another odd value.
        *der.last_mut().unwrap() ^= 2;
        parse_public_key(id, &der).unwrap();
        assert!(manager.add_public_key(id.into(), der).await.is_err());
        let signature = test_signer().sign("unchanged").await.unwrap();
        let verifier = Sha256RsaVerifier::from_manager(Arc::new(manager));
        assert!(
            verifier
                .verify_with_serial("unchanged", &signature, id)
                .await
                .unwrap()
        );
    }

    #[test]
    fn signed_retirement_can_only_narrow_x509_validity() {
        let (_, mut entry) = CertEntry::parse(&test_cert_der()).unwrap();
        let x509_expiry = entry.verification.not_after;
        entry
            .restrict_validity(None, Some("2099-01-01T00:00:00+00:00"))
            .unwrap();
        assert_eq!(entry.verification.not_after, x509_expiry);
        entry
            .restrict_validity(None, Some("2026-06-17T00:00:00+00:00"))
            .unwrap();
        assert!(entry.verification.not_after < x509_expiry);
    }
}
