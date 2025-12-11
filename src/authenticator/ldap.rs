use crate::{
    Error, Result,
    authenticator::RandomSleeper,
    util::{GDuration, synth_sleep},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use super::{AuthResult, Authenticator};
use ldap3::{LdapConnAsync, SearchEntry};
use native_tls::{Certificate, TlsConnector};
use serde::Deserialize;
use simple_pool::ResourcePool;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};
use tracing::{debug, error, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct LdapAuthenticator {
    pool: LdapPool,
}

impl LdapAuthenticator {
    pub async fn create(config: &Config) -> Result<Self> {
        let cert = if let Some(ca) = &config.ca {
            Some(read_tls_certificate(ca).await?)
        } else {
            None
        };
        let pool = LdapPool::init(config, cert.as_ref());
        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl Authenticator for LdapAuthenticator {
    async fn present(&self, login: &str) -> bool {
        let random_sleeper = RandomSleeper::new(100..300);
        match self.pool.user_present(login).await {
            Ok(present) => {
                random_sleeper.sleep().await;
                present
            }
            Err(e) => {
                random_sleeper.sleep().await;
                synth_sleep().await;
                error!(%e, "error checking user presence");
                false
            }
        }
    }
    async fn spawn_secure_workers(&self) -> Result<()> {
        self.pool.start_connector().await;
        Ok(())
    }
    async fn verify(&self, login: &str, password: &str) -> AuthResult {
        let random_sleeper = RandomSleeper::new(100..300);
        match self.pool.verify_password(login, password).await {
            Ok(()) => {
                random_sleeper.sleep().await;
                AuthResult::Success
            }
            Err(e) => {
                random_sleeper.sleep().await;
                synth_sleep().await;
                error!(%e, "error verifying password");
                AuthResult::Failure
            }
        }
    }
}

#[derive(Deserialize, Default, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "lowercase")]
enum Provider {
    #[default]
    Generic,
    Msad,
    Authentik,
}

fn default_pool_size() -> usize {
    1
}

fn default_auth_pool_size() -> usize {
    1
}

#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    path: String,
    service_user: String,
    service_password: String,
    url: String,
    #[serde(default)]
    starttls: bool,
    #[zeroize(skip)]
    pub(crate) ca: Option<PathBuf>,
    #[serde(default)]
    no_tls_verify: bool,
    #[serde(default)]
    provider: Provider,
    #[serde(default = "crate::util::default_timeout")]
    #[zeroize(skip)]
    timeout: GDuration,
    #[serde(default = "default_pool_size")]
    pool_size: usize,
    #[serde(default = "default_auth_pool_size")]
    auth_pool_size: usize,
}

pub async fn read_tls_certificate(ca: &Path) -> Result<Certificate> {
    let data = tokio::fs::read(ca).await?;

    let cert = if Path::new(ca)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
    {
        native_tls::Certificate::from_der(&data).map_err(Error::crypto)?
    } else {
        native_tls::Certificate::from_pem(&data).map_err(Error::crypto)?
    };
    Ok(cert)
}

struct LdapPool {
    pool: Arc<Mutex<Option<Arc<ResourcePool<Ldap>>>>>,
    auth_perms: Semaphore,
    connector: Arc<Mutex<Option<JoinHandle<()>>>>,
    timeout: Duration,
    config: Config,
    cert: Option<Certificate>,
}

async fn try_init_pool(config: &Config, cert: Option<&Certificate>) -> Result<ResourcePool<Ldap>> {
    let pool = ResourcePool::new();
    for _ in 0..config.pool_size {
        let ldap = Ldap::connect(config, cert, None).await?;
        pool.append(ldap);
    }
    Ok(pool)
}

impl LdapPool {
    fn init(config: &Config, cert: Option<&Certificate>) -> Self {
        let timeout = config.timeout.into();
        let ldap_pool: Arc<Mutex<Option<Arc<ResourcePool<Ldap>>>>> = <_>::default();
        Self {
            pool: ldap_pool,
            auth_perms: Semaphore::new(config.auth_pool_size),
            connector: <_>::default(),
            timeout,
            cert: cert.cloned(),
            config: config.clone(),
        }
    }
    async fn start_connector(&self) {
        let connector = tokio::spawn({
            let ldap_pool = self.pool.clone();
            let config = self.config.clone();
            let cert = self.cert.clone();
            async move {
                loop {
                    match try_init_pool(&config, cert.as_ref()).await {
                        Ok(pool) => {
                            ldap_pool.lock().await.replace(pool.into());
                            info!("LDAP pool initialized");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to initialize LDAP pool");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        });
        self.connector.lock().await.replace(connector);
    }
    pub async fn get_user_by_email(&self, email: &str) -> Result<String> {
        let res = tokio::time::timeout(self.timeout, self.get_user_by_email_impl(email)).await??;
        Ok(res)
    }
    async fn get_user_by_email_impl(&self, email: &str) -> Result<String> {
        let pool = self.get_pool().await?;
        let mut ldap = pool.get().await;
        ldap.get_user_by_email(email).await
    }
    async fn get_pool(&self) -> Result<Arc<ResourcePool<Ldap>>> {
        let Some(pool) = self.pool.lock().await.as_ref().cloned() else {
            return Err(Error::failed("LDAP pool not initialized"));
        };
        Ok(pool)
    }
    async fn user_present(&self, user: &str) -> Result<bool> {
        let res = tokio::time::timeout(self.timeout, self.user_present_impl(user)).await??;
        Ok(res)
    }
    async fn user_present_impl(&self, user: &str) -> Result<bool> {
        let pool = self.get_pool().await?;
        let mut ldap = pool.get().await;
        let mut attrs = vec!["cn"];
        match self.config.provider {
            Provider::Generic => {}
            Provider::Msad => attrs.push("userAccountControl"),
            Provider::Authentik => {
                attrs.push("ak-active");
            }
        }
        let ldap_user = if user.contains('@') {
            format!(
                "cn={},{}",
                ldap.get_user_by_email(user).await?,
                self.config.path
            )
        } else {
            format!("cn={},{}", user, self.config.path)
        };
        let (rs, _) = ldap
            .inner
            .search(&ldap_user, ldap3::Scope::Base, "(objectClass=*)", attrs)
            .await
            .map_err(Error::failed)?
            .success()
            .map_err(Error::failed)?;
        if rs.is_empty() {
            return Ok(false);
        }
        let se = SearchEntry::construct(
            rs.into_iter()
                .next()
                .ok_or_else(|| Error::failed("No search entry found"))?,
        );
        let active = match self.config.provider {
            Provider::Generic => true,
            Provider::Msad => {
                let uac = se
                    .attrs
                    .get("userAccountControl")
                    .ok_or_else(|| Error::failed("No userAccountControl attribute found"))?
                    .first()
                    .ok_or_else(|| Error::failed("No userAccountControl value found"))?
                    .parse::<u32>()
                    .map_err(|e| {
                        Error::failed(format!("Failed to parse userAccountControl: {}", e))
                    })?;
                (uac & 0x2) == 0
            }
            Provider::Authentik => se
                .attrs
                .get("ak-active")
                .and_then(|v| v.first())
                .is_some_and(|s| s == "TRUE"),
        };
        if !active {
            debug!(user = %user, "LDAP user is inactive");
        }
        Ok(active)
    }
    async fn verify_password(&self, user: &str, password: &str) -> Result<()> {
        tokio::time::timeout(self.timeout, self.verify_password_impl(user, password)).await??;
        Ok(())
    }
    async fn verify_password_impl(&self, user: &str, password: &str) -> Result<()> {
        let _perm = self.auth_perms.acquire().await.map_err(Error::failed)?;
        let ldap_user = if user.contains('@') {
            self.get_user_by_email(user).await?
        } else {
            user.to_string()
        };
        let creds = Creds {
            user: ldap_user,
            password,
        };
        let mut user_ldap = Ldap::connect(&self.config, None, Some(creds)).await?;
        user_ldap.test().await?;
        Ok(())
    }
}

impl Drop for LdapPool {
    fn drop(&mut self) {
        let connector = self.connector.clone();
        tokio::spawn(async move {
            if let Some(f) = connector.lock().await.take() {
                f.abort();
            }
        });
    }
}

#[derive(Clone)]
struct Ldap {
    inner: ldap3::Ldap,
    bind_login: String,
}

struct Creds<'a> {
    user: String,
    password: &'a str,
}

impl Ldap {
    async fn connect(
        config: &Config,
        cert: Option<&Certificate>,
        creds: Option<Creds<'_>>,
    ) -> Result<Self> {
        let (bind_login, password) = if let Some(ref creds) = creds {
            (format!("cn={},{}", creds.user, config.path), creds.password)
        } else {
            (
                format!("cn={},{}", config.service_user, config.path),
                config.service_password.as_str(),
            )
        };
        let timeout = config.timeout.into();
        let mut settings = ldap3::LdapConnSettings::new()
            .set_no_tls_verify(config.no_tls_verify)
            .set_starttls(config.starttls)
            .set_conn_timeout(timeout);
        if let Some(cert) = cert {
            let mut builder = TlsConnector::builder();
            if config.no_tls_verify {
                builder.danger_accept_invalid_certs(true);
            }
            builder.add_root_certificate(cert.clone());

            let connector = builder.build().map_err(Error::crypto)?;
            settings = settings.set_connector(connector);
        }
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
            .await
            .map_err(Error::io)?;
        ldap3::drive!(conn);
        debug!(login = %bind_login, "Binding LDAP user");
        ldap.simple_bind(&bind_login, password)
            .await
            .map_err(Error::access)?
            .success()
            .map_err(Error::access)?;
        Ok(Self {
            inner: ldap,
            bind_login,
        })
    }
    async fn test(&mut self) -> Result<()> {
        self.inner
            .search(
                &self.bind_login,
                ldap3::Scope::Subtree,
                "(objectClass=*)",
                vec!["cn"],
            )
            .await
            .map_err(Error::failed)?
            .success()
            .map_err(Error::failed)?;
        Ok(())
    }
    async fn get_user_by_email(&mut self, email: &str) -> Result<String> {
        let (rs, _res) = self
            .inner
            .search(
                "ou=users,dc=lab,dc=bma,dc=ai",
                ldap3::Scope::Subtree,
                &format!("(mail={})", email),
                vec!["cn"],
            )
            .await
            .map_err(Error::failed)?
            .success()
            .map_err(Error::failed)?;
        if rs.is_empty() {
            return Err(Error::failed("No user found"));
        }
        if rs.len() > 1 {
            return Err(Error::failed("Multiple users found"));
        }
        let se = SearchEntry::construct(
            rs.into_iter()
                .next()
                .ok_or_else(|| Error::failed("No search entry found"))?,
        );
        let cn = se
            .attrs
            .get("cn")
            .ok_or_else(|| Error::failed("No cn attribute found"))?
            .first()
            .ok_or_else(|| Error::failed("No cn attribute found"))?
            .clone();
        Ok(cn)
    }
}
