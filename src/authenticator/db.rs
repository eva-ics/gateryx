use std::sync::Arc;

use pbkdf2::{
    Pbkdf2,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString, rand_core::OsRng,
    },
};
use tracing::error;

use crate::{
    Error, Result,
    authenticator::{
        AuthResult, Authenticator, GroupInfo, PasswordPolicy, RandomSleeper, UserInfo,
    },
    storage::Storage,
    util::synth_sleep,
};

pub struct DbAuth {
    storage: Arc<dyn Storage>,
    policy: Option<PasswordPolicy>,
}

impl DbAuth {
    pub fn new(storage: Arc<dyn Storage>, policy: Option<PasswordPolicy>) -> Self {
        Self { storage, policy }
    }
    fn hash_password(&self, password: &str) -> Result<String> {
        if let Some(policy) = &self.policy {
            policy.validate(password)?;
        }
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Pbkdf2
            .hash_password(password.as_bytes(), &salt)
            .map_err(Error::failed)?
            .to_string();
        Ok(password_hash)
    }
    async fn verify_password(&self, login: &str, password: &str) -> AuthResult {
        match self.storage.lookup_user(login).await {
            Ok(Some(password_hash)) => {
                let parsed_hash = match PasswordHash::new(&password_hash) {
                    Ok(h) => h,
                    Err(e) => {
                        error!(%e, "error parsing password hash from database");
                        return AuthResult::Failure;
                    }
                };
                if Pbkdf2
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    self.storage.touch_user(login).await.ok();
                    let groups = match self.storage.user_groups(login).await {
                        Ok(gs) => gs,
                        Err(e) => {
                            error!(%e, "error retrieving user groups from database");
                            return AuthResult::Failure;
                        }
                    };
                    AuthResult::Success { groups }
                } else {
                    AuthResult::Failure
                }
            }
            Ok(None) => AuthResult::Failure,
            Err(e) => {
                error!(%e, "error looking up user in database");
                AuthResult::Failure
            }
        }
    }
}

#[async_trait::async_trait]
impl Authenticator for DbAuth {
    async fn present(&self, login: &str) -> bool {
        match self.storage.lookup_user(login).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                error!(%e, "error looking up user in database");
                false
            }
        }
    }
    async fn verify(&self, login: &str, password: &str) -> AuthResult {
        let random_sleeper = RandomSleeper::new(100..300);
        match self.verify_password(login, password).await {
            AuthResult::Success { groups } => {
                random_sleeper.sleep().await;
                AuthResult::Success { groups }
            }
            AuthResult::Failure => {
                random_sleeper.sleep().await;
                synth_sleep().await;
                AuthResult::Failure
            }
        }
    }
    async fn user_groups(&self, login: &str) -> Result<Vec<String>> {
        self.storage.user_groups(login).await
    }
    async fn add(&self, login: &str, password: &str) -> Result<()> {
        let password_hash = self.hash_password(password)?;
        self.storage.create_user(login, &password_hash).await
    }
    async fn delete(&self, login: &str) -> Result<()> {
        self.storage.delete_user(login).await
    }
    async fn set_password_forced(&self, login: &str, password: &str) -> Result<()> {
        let password_hash = self.hash_password(password)?;
        self.storage.set_user_password(login, &password_hash).await
    }
    async fn set_password(
        &self,
        login: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        match self.verify_password(login, old_password).await {
            AuthResult::Success { .. } => self.set_password_forced(login, new_password).await,
            AuthResult::Failure => Err(Error::failed("authentication failed")),
        }
    }
    async fn list(&self) -> Result<Vec<UserInfo>> {
        self.storage.list_users().await
    }
    async fn list_groups(&self) -> Result<Vec<GroupInfo>> {
        self.storage.list_groups().await
    }
    async fn add_group(&self, group: &str) -> Result<()> {
        self.storage.add_group(group).await
    }
    async fn delete_group(&self, group: &str) -> Result<()> {
        self.storage.delete_group(group).await
    }
    async fn add_user_to_group(&self, login: &str, group: &str) -> Result<()> {
        self.storage.add_user_to_group(login, group).await
    }
    async fn remove_user_from_group(&self, login: &str, group: &str) -> Result<()> {
        self.storage.remove_user_from_group(login, group).await
    }
}
