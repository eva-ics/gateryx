use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use bma_ts::Timestamp;
use serde::Deserialize;
use tokio::task::JoinHandle;
use tracing::error;
use webauthn_rs::prelude::Passkey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ConfigCheckIssue, Result,
    authenticator::{GroupInfo, UserInfo},
    util::{GDuration, Numeric},
};

mod dummy;
mod sqlt;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    fn spawn_cleanup_worker(self: Arc<Self>, int: Duration) -> JoinHandle<()>
    where
        Self: Send + Sync + 'static,
    {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(int);
            loop {
                interval.tick().await;
                if let Err(e) = self.cleanup().await {
                    error!(error = %e, "Storage cleanup failed" );
                }
            }
        })
    }

    async fn invalidate(&self, sub: &str, record_expires: Duration) -> Result<()>;

    async fn is_token_revoked(&self, sub: &str, t_issued: Timestamp) -> Result<bool>;

    async fn lookup_passkey(&self, cred_id: &[u8]) -> Result<Option<(String, Passkey)>>;

    async fn save_passkey(&self, user: &str, passkey: Passkey) -> Result<()>;

    async fn has_passkey(&self, user: &str) -> Result<bool>;

    async fn delete_passkey(&self, user: &str) -> Result<()>;

    async fn create_user(&self, user: &str, _password_hash: &str) -> Result<()>;

    async fn set_user_password(&self, _user: &str, _password_hash: &str) -> Result<()>;

    async fn delete_user(&self, user: &str) -> Result<()>;

    // returns password hash
    async fn lookup_user(&self, user: &str) -> Result<Option<String>>;

    async fn touch_user(&self, user: &str) -> Result<()>;

    async fn list_users(&self) -> Result<Vec<UserInfo>>;

    async fn user_groups(&self, user: &str) -> Result<Vec<String>>;

    async fn list_groups(&self) -> Result<Vec<GroupInfo>>;

    async fn add_group(&self, group: &str) -> Result<()>;

    async fn delete_group(&self, group: &str) -> Result<()>;

    async fn add_user_to_group(&self, user: &str, group: &str) -> Result<()>;

    async fn remove_user_from_group(&self, user: &str, group: &str) -> Result<()>;
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    uri: String,
    #[zeroize(skip)]
    pool_size: Numeric,
    #[zeroize(skip)]
    timeout: GDuration,
}

impl Config {
    pub fn check(&self, _work_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        if !self.uri.starts_with("sqlite://") {
            issues.push(ConfigCheckIssue::Error(
                "Only sqlite storage is supported".to_string(),
            ));
        }
        if u32::from(self.pool_size) == 0 {
            issues.push(ConfigCheckIssue::Error(
                "Pool size must be greater than 0".to_string(),
            ));
        }
        if self.timeout.as_secs() == 0 {
            issues.push(ConfigCheckIssue::Error(
                "Timeout must be greater than 0".to_string(),
            ));
        }
        issues
    }
}

pub async fn create(config: Option<&Config>) -> Result<Arc<dyn Storage + Send + Sync + 'static>> {
    let Some(config) = config else {
        return Ok(Arc::new(dummy::Storage::default()));
    };
    Ok(Arc::new(sqlt::Storage::create(config).await?))
}
