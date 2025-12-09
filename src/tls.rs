use crate::{Result, error::ConfigCheckIssue};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type TlsResult<T> = std::result::Result<T, rustls::Error>;

#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[zeroize(skip)]
    cert: PathBuf,
    #[zeroize(skip)]
    key: PathBuf,
    #[serde(skip)]
    #[zeroize(skip)]
    pub cert_buf: Arc<parking_lot::Mutex<Zeroizing<Vec<u8>>>>,
    #[serde(skip)]
    #[zeroize(skip)]
    pub key_buf: Arc<parking_lot::Mutex<Zeroizing<Vec<u8>>>>,
}

impl Config {
    pub fn load_files(&mut self) -> Result<()> {
        *self.cert_buf.lock() = Zeroizing::new(fs_err::read(&self.cert)?);
        *self.key_buf.lock() = Zeroizing::new(fs_err::read(&self.key)?);
        Ok(())
    }
    pub fn canonicalize_path(&mut self, work_dir: &Path) {
        if !self.cert.is_absolute() {
            self.cert = work_dir.join(&self.cert);
        }
        if !self.key.is_absolute() {
            self.key = work_dir.join(&self.key);
        }
    }
    pub fn check(&self, config_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        let cert_path = if self.cert.is_absolute() {
            self.cert.clone()
        } else {
            config_dir.join(&self.cert)
        };
        if !cert_path.exists() {
            issues.push(ConfigCheckIssue::Error(format!(
                "TLS certificate path does not exist: {}",
                cert_path.display()
            )));
        }
        let key_path = if self.key.is_absolute() {
            self.key.clone()
        } else {
            config_dir.join(&self.key)
        };
        if !key_path.exists() {
            issues.push(ConfigCheckIssue::Error(format!(
                "TLS key path does not exist: {}",
                key_path.display()
            )));
        }
        issues
    }
}

#[derive(Debug)]
pub struct NoCertVerifier {}

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> TlsResult<rustls::client::danger::ServerCertVerified> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> TlsResult<rustls::client::danger::HandshakeSignatureValid> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> TlsResult<rustls::client::danger::HandshakeSignatureValid> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::ML_DSA_44,
            rustls::SignatureScheme::ML_DSA_65,
            rustls::SignatureScheme::ML_DSA_87,
        ]
    }
}
