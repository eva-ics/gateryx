use std::time::Duration;

use bma_ts::Timestamp;
use tracing::warn;
use webauthn_rs::prelude::Passkey;

use crate::{Error, Result, authenticator::UserInfo};

#[derive(Default)]
pub struct Storage {}

#[async_trait::async_trait]
impl super::Storage for Storage {
    async fn invalidate(&self, _sub: &str, _record_expires: Duration) -> Result<()> {
        warn!("Token revocation is not supported with Dummy storage");
        Ok(())
    }

    async fn is_token_revoked(&self, _sub: &str, _t_issued: Timestamp) -> Result<bool> {
        Ok(false)
    }

    async fn lookup_passkey(&self, _cred_id: &[u8]) -> Result<Option<(String, Passkey)>> {
        Ok(None)
    }

    async fn save_passkey(&self, _user: &str, _passkey: Passkey) -> Result<()> {
        Err(Error::failed(
            "Passkey storage is not supported with Dummy storage",
        ))
    }

    async fn has_passkey(&self, _user: &str) -> Result<bool> {
        Ok(false)
    }

    async fn delete_passkey(&self, _user: &str) -> Result<()> {
        Ok(())
    }

    async fn create_user(&self, _user: &str, _password_hash: &str) -> Result<()> {
        Err(Error::failed(
            "User storage is not supported with Dummy storage",
        ))
    }

    async fn set_user_password(&self, _user: &str, _password_hash: &str) -> Result<()> {
        Ok(())
    }

    async fn delete_user(&self, _user: &str) -> Result<()> {
        Ok(())
    }

    async fn lookup_user(&self, _user: &str) -> Result<Option<String>> {
        Ok(None)
    }

    async fn touch_user(&self, _user: &str) -> Result<()> {
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<UserInfo>> {
        Ok(Vec::new())
    }

    async fn user_groups(&self, _user: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
}
