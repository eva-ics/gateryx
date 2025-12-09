use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{error, info, trace};

use super::{AuthResult, Authenticator};
use crate::Result;
use crate::authenticator::RandomSleeper;
use crate::util::synth_sleep;

pub struct HtpasswdAuthenticator {
    inner: Arc<Mutex<HtpasswdAuthenticatorInner>>,
    worker: JoinHandle<()>,
}

impl Drop for HtpasswdAuthenticator {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

struct HtpasswdAuthenticatorInner {
    mtime: SystemTime,
    path: PathBuf,
    passwords: BTreeMap<String, String>,
}

#[async_trait::async_trait]
impl Authenticator for HtpasswdAuthenticator {
    async fn verify(&self, login: &str, password: &str) -> AuthResult {
        let random_sleeper = RandomSleeper::new(100..300);
        match self.verify_password(login, password).await {
            Ok(v) => {
                random_sleeper.sleep().await;
                v
            }
            Err(e) => {
                random_sleeper.sleep().await;
                synth_sleep().await;
                error!(%e, "error verifying password");
                AuthResult::Failure
            }
        }
    }
    async fn present(&self, login: &str) -> bool {
        let inner = self.inner.lock().await;
        inner.passwords.contains_key(login)
    }
}

impl HtpasswdAuthenticator {
    pub async fn create<P: AsRef<Path>>(password_file: P) -> Result<Self> {
        info!(path = %password_file.as_ref().display(), "creating htpasswd authenticator");
        let mtime = tokio::fs::metadata(&password_file).await?.modified()?;
        let mut inner = HtpasswdAuthenticatorInner {
            mtime,
            path: password_file.as_ref().to_path_buf(),
            passwords: <_>::default(),
        };
        inner.reload().await?;
        let inner = Arc::new(Mutex::new(inner));
        // the worker is spawned before priv. drop to have full access to the password file
        let worker = tokio::spawn(Self::reload_worker(inner.clone()));
        Ok(Self { inner, worker })
    }
    async fn verify_password(&self, login: &str, password: &str) -> Result<AuthResult> {
        let inner = self.inner.lock().await;
        if let Some(hash) = inner.passwords.get(login) {
            if !bcrypt::verify(password, hash).unwrap_or(false) {
                return Ok(AuthResult::Failure);
            }
            return Ok(AuthResult::Success);
        }
        Ok(AuthResult::Failure)
    }
    async fn reload_worker(inner: Arc<Mutex<HtpasswdAuthenticatorInner>>) {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = inner.lock().await.reload_if_required().await {
                error!(%e, "error reloading password file");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

impl HtpasswdAuthenticatorInner {
    async fn reload_if_required(&mut self) -> Result<()> {
        let mtime = tokio::fs::metadata(&self.path).await?.modified()?;
        if mtime > self.mtime {
            self.reload().await?;
            self.mtime = mtime;
        }
        Ok(())
    }
    async fn reload(&mut self) -> Result<()> {
        info!(path = %self.path.display(), "loading password file");
        let data = tokio::fs::read_to_string(&self.path).await?;
        let mut map = BTreeMap::new();
        for line in data.trim().lines() {
            let parts: Vec<&str> = line.trim().split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            if parts[0].starts_with('#') {
                continue;
            }
            let login = parts[0].trim().to_owned();
            trace!(login = login, "loaded password");
            map.insert(login, parts[1].trim().to_owned());
        }
        self.passwords = map;
        Ok(())
    }
}
