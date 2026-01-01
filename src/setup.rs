use crate::{Error, Result};
use std::{
    io::Write as _, net::IpAddr, os::unix::fs::OpenOptionsExt as _, path::Path, time::Duration,
};

use chrono::{Datelike as _, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

use p256::ecdsa::SigningKey;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::SeedableRng as _;
use tokio::{fs, io::AsyncWriteExt as _};
use zeroize::Zeroizing;

const CONFIG_TOML_DEFAULT: &str = include_str!("../etc/config.toml.default");
const CLIENT_TOML_DEFAULT: &str = include_str!("../etc/client.toml.default");

const APP_PLAIN_TOML_DEFAULT: &str = include_str!("../etc/app.d/plain.toml.default");
const APP_SYSTEM_TOML_DEFAULT: &str = include_str!("../etc/app.d/system.toml.default");

const APP_EXAMPLE_TOML_DEFAULT: &str = include_str!("../share/app.d/example.toml");

pub fn generate_default_config(path: &Path) -> Result<()> {
    let config_dir = path
        .parent()
        .ok_or_else(|| Error::io("invalid config path"))?;
    std::fs::create_dir_all(config_dir).ok();
    write_secure_sync(path, CONFIG_TOML_DEFAULT.as_bytes())?;
    let client_toml_path = config_dir.join("client.toml");
    if !client_toml_path.exists() {
        write_secure_sync(&client_toml_path, CLIENT_TOML_DEFAULT.as_bytes())?;
    }
    let app_dir_dir = config_dir.join("app.d");
    if !app_dir_dir.exists() {
        std::fs::create_dir_all(&app_dir_dir)?;
        std::fs::write(
            app_dir_dir.join("plain.toml"),
            APP_PLAIN_TOML_DEFAULT.as_bytes(),
        )?;
        std::fs::write(
            app_dir_dir.join("system.toml"),
            APP_SYSTEM_TOML_DEFAULT.as_bytes(),
        )?;
        std::fs::write(
            app_dir_dir.join("example.toml"),
            APP_EXAMPLE_TOML_DEFAULT.as_bytes(),
        )?;
    }
    Ok(())
}

pub async fn generate_signing_key(path: Option<&Path>) -> Result<SigningKey> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let key = SigningKey::random(&mut rng);
    if let Some(path) = path {
        let pkcs8 = Zeroizing::new(key.to_pkcs8_pem(LineEnding::LF).map_err(Error::crypto)?);
        write_secure(path, pkcs8.as_bytes()).await?;
    }
    Ok(key)
}

pub fn generate_test_x509_pair(cert_path: &Path, key_path: &Path) -> Result<()> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;

    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().map_err(Error::crypto)?),
        SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let mut now = Utc::now();
    now = now.checked_sub_days(chrono::Days::new(1)).unwrap_or(now);

    params.not_before = rcgen::date_time_ymd(
        now.year(),
        u8::try_from(now.month()).unwrap_or(1),
        u8::try_from(now.day()).unwrap_or(1),
    );
    params.not_after = params.not_before + Duration::from_secs(3650 * 86_400); // 10 years

    let key_pair = Zeroizing::new(KeyPair::generate().map_err(Error::crypto)?);

    let cert = params.self_signed(&*key_pair).map_err(Error::crypto)?;

    std::fs::write(cert_path, cert.pem())?;

    let key_pem = Zeroizing::new(key_pair.serialize_pem());
    write_secure_sync(key_path, key_pem.as_bytes())?;

    Ok(())
}

fn write_secure_sync(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

async fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(data).await?;
    Ok(())
}
