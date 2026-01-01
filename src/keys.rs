use crate::{Error, Result};
use std::path::Path;

use p256::ecdsa::SigningKey;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::SeedableRng as _;
use tokio::io::AsyncWriteExt as _;
use zeroize::Zeroizing;

pub async fn generate_signing_key(path: Option<&Path>) -> Result<SigningKey> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let key = SigningKey::random(&mut rng);
    if let Some(ref path) = path {
        let pkcs8 = Zeroizing::new(key.to_pkcs8_pem(LineEnding::LF).map_err(Error::crypto)?);
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .await?;
        f.write_all(pkcs8.as_bytes()).await?;
    }
    Ok(key)
}
