use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ConfigCheckIssue, Error, Result,
    util::{GDuration, default_true},
};

#[derive(Deserialize, Copy, Clone, Default)]
pub enum AppClientKind {
    #[serde(rename = "http1.0")]
    Http0,
    #[default]
    #[serde(rename = "http1.1", alias = "http1")]
    Http1,
    #[serde(rename = "http2")]
    Http2,
}

impl AppClientKind {
    pub fn insert_gateryx_headers(self) -> bool {
        match self {
            AppClientKind::Http0 => false,
            AppClientKind::Http1 | AppClientKind::Http2 => true,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub allow_tokens: bool,
    #[serde(default)]
    pub url: String,
    #[zeroize(skip)]
    pub icon: Option<PathBuf>,
    #[serde(default)]
    pub icon_image: Option<Vec<u8>>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub remote: String,
    #[serde(default)]
    pub compress: bool,
    #[serde(default)]
    #[zeroize(skip)]
    pub client: AppClientKind,
    #[serde(default = "crate::util::default_timeout")]
    #[zeroize(skip)]
    pub timeout: GDuration,
    #[serde(default = "crate::util::default_true")]
    pub use_auth: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub skip_remote_tls_verify: bool,
    #[zeroize(skip)]
    pub websocket: Option<crate::ws::Config>,
    #[zeroize(skip)]
    pub settings: Option<serde_json::Value>,
}

impl Config {
    pub fn check(&self, config_dir: &Path, app_config_path: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        if self.url.starts_with("gateryx://") {
            // TODO: check virtual apps for issues
            return issues;
        }
        if !self.url.is_empty() && Url::parse(&self.url).is_err() {
            issues.push(ConfigCheckIssue::Warning(format!(
                "{} invalid app url: {}",
                app_config_path.display(),
                self.url
            )));
        }
        if Url::parse(&self.remote).is_err() {
            issues.push(ConfigCheckIssue::Error(format!(
                "{} invalid app remote url: {}",
                app_config_path.display(),
                self.remote
            )));
        }
        if let Some(ref icon) = self.icon {
            let icon_path = if icon.is_absolute() {
                icon.clone()
            } else {
                config_dir.join(icon)
            };
            if !icon_path.exists() {
                issues.push(ConfigCheckIssue::Warning(format!(
                    "{} app icon path does not exist: {}",
                    app_config_path.display(),
                    icon_path.display()
                )));
            }
        }
        if self.hosts.is_empty() {
            issues.push(ConfigCheckIssue::Error(format!(
                "{} no hosts configured for app",
                app_config_path.display()
            )));
        }
        issues
    }
}

#[derive(Default)]
pub struct AppHostMap {
    inner: Mutex<AppHostMapInner>,
}

impl AppHostMap {
    pub async fn has_skip_remote_tls_verify(&self) -> bool {
        self.inner
            .lock()
            .await
            .apps
            .values()
            .any(|config| config.skip_remote_tls_verify)
    }
    pub async fn app_icon(&self, name: &str) -> Option<Vec<u8>> {
        let inner = self.inner.lock().await;
        inner.app_icon(name)
    }
    pub async fn apps(&self) -> Vec<AppView> {
        let inner = self.inner.lock().await;
        inner.apps()
    }
    pub fn set_default_app(&self, name: Option<&str>) {
        let mut inner = self.inner.blocking_lock();
        inner.set_default_app(name);
    }
    pub fn add_sync(&self, name: &str, config: Config) -> Result<()> {
        let mut inner = self.inner.blocking_lock();
        inner.add(name, config)
    }
    pub async fn add(&self, name: &str, config: Config) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.add(name, config)
    }
    pub async fn remove(&self, name: &str) {
        let mut inner = self.inner.lock().await;
        inner.remove(name);
    }
    pub async fn get_by_host(&self, host: &str) -> Option<Arc<Config>> {
        let inner = self.inner.lock().await;
        inner
            .app_hosts
            .get(host)
            .cloned()
            .or_else(|| inner.default.as_ref().map(|(_, c)| c.clone()))
    }
    pub async fn get_by_name(&self, id: &str) -> Option<Arc<Config>> {
        let inner = self.inner.lock().await;
        inner.apps.get(id).cloned()
    }
    pub fn default_app_present(&self) -> bool {
        let inner = self.inner.blocking_lock();
        inner.default_app_present()
    }
}

#[derive(Default)]
struct AppHostMapInner {
    default_app_name: Option<String>,
    apps: BTreeMap<String, Arc<Config>>,
    app_hosts: BTreeMap<String, Arc<Config>>,
    default: Option<(String, Arc<Config>)>,
}

#[derive(Serialize)]
pub struct AppView {
    name: String,
    display_name: String,
    has_icon: bool,
    allow_tokens: bool,
    url: String,
}

impl AppHostMapInner {
    fn app_icon(&self, name: &str) -> Option<Vec<u8>> {
        self.apps
            .get(name)
            .and_then(|config| config.icon_image.clone())
    }
    fn apps(&self) -> Vec<AppView> {
        let mut res: Vec<AppView> = self
            .apps
            .iter()
            .filter_map(|(n, config)| {
                if config.hidden {
                    None
                } else {
                    Some(AppView {
                        name: n.clone(),
                        display_name: config.name.clone(),
                        has_icon: config.icon.is_some(),
                        allow_tokens: config.allow_tokens,
                        url: config.url.clone(),
                    })
                }
            })
            .collect();
        res.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        res
    }
    fn set_default_app(&mut self, name: Option<&str>) {
        let Some(name) = name else {
            self.default_app_name = None;
            self.default = None;
            return;
        };
        if let Some(config) = self.apps.get(name) {
            self.default = Some((name.to_string(), config.clone()));
        }
        self.default_app_name = Some(name.to_string());
    }
    fn add(&mut self, name: &str, config: Config) -> Result<()> {
        let config = Arc::new(config);
        if self.apps.contains_key(name) {
            return Err(Error::AppAlreadyExists);
        }
        for h in &config.hosts {
            if self.app_hosts.contains_key(h) {
                return Err(Error::HostAlreadyExists);
            }
            self.app_hosts.insert(h.clone(), config.clone());
        }
        if self.default_app_name.as_ref().is_some_and(|n| n == name) {
            self.default = Some((name.to_string(), config.clone()));
        }
        self.apps.insert(name.to_string(), config);
        Ok(())
    }
    fn remove(&mut self, name: &str) {
        if let Some(config) = self.apps.remove(name) {
            for h in &config.hosts {
                self.app_hosts.remove(h);
            }
        }
        if self.default.as_ref().is_some_and(|(n, _)| n == name) {
            self.default = None;
        }
    }
    fn default_app_present(&self) -> bool {
        self.default.is_some()
    }
}
