use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bma_ts::{Monotonic, Timestamp};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ConfigCheckIssue, Error, Result, bp, passkeys, storage::Storage, tokens};

pub mod db;
pub mod htpasswd;
pub mod ldap;

#[derive(Default, Deserialize, Clone)]
pub struct UserAgentList(Vec<String>);

impl UserAgentList {
    pub fn matches(&self, user_agent: &str) -> bool {
        for pattern in &self.0 {
            if let Some(id) = pattern.strip_suffix('*') {
                if user_agent.starts_with(id) {
                    return true;
                }
            } else if user_agent == pattern {
                return true;
            }
        }
        false
    }
}

fn default_401_agent_list() -> UserAgentList {
    UserAgentList(vec![
        "curl/*".to_string(),
        "Wget/*".to_string(),
        "git/*".to_string(),
    ])
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub authenticator: AuthenticatorConfig,
    pub breakin_protection: bp::Config,
    #[zeroize(skip)]
    pub www_root: PathBuf,
    pub tokens: tokens::Config,
    #[serde(default)]
    pub passkeys: Option<passkeys::Config>,
    #[serde(default = "default_401_agent_list")]
    #[zeroize(skip)]
    pub reply_401_to_user_agents: UserAgentList,
}

impl Config {
    pub fn canonicalize_path(&mut self, work_dir: &Path) {
        self.authenticator.canonicalize_path(work_dir);
        self.tokens.canonicalize_path(work_dir);
    }
    pub fn check(&self, config_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        issues.extend(self.authenticator.check(config_dir));
        issues.extend(self.tokens.check(config_dir));
        if !self.www_root.exists() {
            issues.push(ConfigCheckIssue::Error(format!(
                "Auth www root path does not exist: {}",
                self.www_root.display()
            )));
        }
        issues
    }
}

fn default_min_length() -> usize {
    8
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub login: String,
    pub active: u8,
    pub created: Timestamp,
    pub last_login: Timestamp,
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupInfo {
    pub name: String,
    pub users: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordPolicy {
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default)]
    pub require_uppercase: bool,
    #[serde(default)]
    pub require_lowercase: bool,
    #[serde(default)]
    pub require_digit: bool,
    #[serde(default)]
    pub require_special: bool,
}

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<()> {
        if password.len() < self.min_length {
            return Err(Error::failed(format!(
                "password must be at least {} characters long",
                self.min_length
            )));
        }
        if self.require_uppercase && !password.chars().any(char::is_uppercase) {
            return Err(Error::failed(
                "password must contain at least one uppercase letter",
            ));
        }
        if self.require_lowercase && !password.chars().any(char::is_lowercase) {
            return Err(Error::failed(
                "password must contain at least one lowercase letter",
            ));
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(Error::failed("password must contain at least one digit"));
        }
        if self.require_special
            && !password
                .chars()
                .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
        {
            return Err(Error::failed(
                "password must contain at least one special character",
            ));
        }
        Ok(())
    }
}

struct DummyAuthenticator;

#[async_trait::async_trait]
impl Authenticator for DummyAuthenticator {
    async fn present(&self, _login: &str) -> bool {
        false
    }
    async fn verify(&self, _login: &str, _password: &str) -> AuthResult {
        AuthResult::Failure
    }
    async fn user_groups(&self, _login: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

#[derive(Deserialize, Default, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields, tag = "kind", content = "params")]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorConfig {
    #[default]
    None,
    Htpasswd {
        #[zeroize(skip)]
        path: PathBuf,
    },
    Db {
        policy: Option<PasswordPolicy>,
    },
    Ldap(ldap::Config),
}

impl AuthenticatorConfig {
    pub fn check(&self, work_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        match self {
            AuthenticatorConfig::None | AuthenticatorConfig::Db { .. } => {}
            AuthenticatorConfig::Htpasswd { path } => {
                let full_path = if path.is_absolute() {
                    path.clone()
                } else {
                    work_dir.join(path)
                };
                if !full_path.exists() {
                    issues.push(ConfigCheckIssue::Error(format!(
                        "Htpasswd file does not exist at path: {}",
                        full_path.display()
                    )));
                }
            }
            AuthenticatorConfig::Ldap(config) => {
                if let Some(ref ca) = config.ca {
                    let full_path = if ca.is_absolute() {
                        ca.clone()
                    } else {
                        work_dir.join(ca)
                    };
                    if !full_path.exists() {
                        issues.push(ConfigCheckIssue::Error(format!(
                            "LDAP CA certificate file does not exist at path: {}",
                            full_path.display()
                        )));
                    }
                }
            }
        }
        issues
    }
}

impl AuthenticatorConfig {
    pub fn canonicalize_path(&mut self, work_dir: &Path) {
        match self {
            AuthenticatorConfig::None | AuthenticatorConfig::Db { .. } => {}
            AuthenticatorConfig::Htpasswd { path } => {
                if !path.is_absolute() {
                    *path = work_dir.join(&*path);
                }
            }
            AuthenticatorConfig::Ldap(config) => {
                if let Some(ref mut ca) = config.ca
                    && !ca.is_absolute()
                {
                    *ca = work_dir.join(&*ca);
                }
            }
        }
    }
}

pub enum AuthResult {
    Success { groups: Vec<String> },
    Failure,
}

#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    async fn present(&self, login: &str) -> bool;
    async fn user_groups(&self, login: &str) -> Result<Vec<String>>;
    async fn verify(&self, login: &str, password: &str) -> AuthResult;
    async fn add(&self, _login: &str, _password: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn spawn_secure_workers(&self) -> Result<()> {
        Ok(())
    }
    async fn delete(&self, _login: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn set_password_forced(&self, _login: &str, _password: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn set_password(
        &self,
        login: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        if !matches!(
            self.verify(login, old_password).await,
            AuthResult::Success { .. }
        ) {
            return Err(Error::failed("authentication failed"));
        }
        self.set_password_forced(login, new_password).await
    }
    async fn list(&self) -> Result<Vec<UserInfo>> {
        Err(Error::NotImplemented)
    }
    async fn list_groups(&self) -> Result<Vec<GroupInfo>> {
        Err(Error::NotImplemented)
    }
    async fn add_group(&self, _name: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn delete_group(&self, _name: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn add_user_to_group(&self, _login: &str, _group: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn remove_user_from_group(&self, _login: &str, _group: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }
}

pub async fn create_authenticator(
    config: &Config,
    db: Arc<dyn Storage>,
) -> Result<Box<dyn Authenticator>> {
    match &config.authenticator {
        AuthenticatorConfig::None => {
            warn!("no authenticator configured");
            let auth = DummyAuthenticator;
            Ok(Box::new(auth))
        }
        AuthenticatorConfig::Htpasswd { path } => {
            let auth = htpasswd::HtpasswdAuthenticator::create(path).await?;
            Ok(Box::new(auth))
        }
        AuthenticatorConfig::Db { policy } => {
            let auth = db::DbAuth::new(db, policy.clone());
            Ok(Box::new(auth))
        }
        AuthenticatorConfig::Ldap(ldap_config) => {
            let auth = ldap::LdapAuthenticator::create(ldap_config).await?;
            Ok(Box::new(auth))
        }
    }
}

/// Used to prevent timing attacks by adding a random delay to authentication attempts.
pub struct RandomSleeper {
    start: Monotonic,
    ms_range: std::ops::Range<u64>,
}

impl RandomSleeper {
    pub fn new(ms_range: std::ops::Range<u64>) -> Self {
        Self {
            start: Monotonic::now(),
            ms_range,
        }
    }
    pub async fn sleep(&self) {
        let mut sleep_duration =
            Duration::from_millis(rand::thread_rng().gen_range(self.ms_range.clone()));
        let elapsed = self.start.elapsed();
        if elapsed > sleep_duration {
            return;
        }
        sleep_duration -= elapsed;
        tokio::time::sleep(sleep_duration).await;
    }
}
