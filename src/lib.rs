use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use http::{Response, header::HeaderName};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

const DEVELOPER_USER: &str = "gateryx_dev";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod admin;
pub mod app;
pub mod app_util;
pub mod authenticator;
mod bp;
mod compress;
pub mod eapi;
mod error;
mod gate;
mod headers;
mod logger;
mod ml;
pub mod panic_handler;
mod passkeys;
pub mod rpc;
mod serve;
pub mod setup;
mod storage;
mod tls;
mod tokens;
pub mod util;
pub mod vapp;
mod ws;

pub use app::AppHostMap;
pub use error::{ConfigCheckIssue, Error};
pub use gate::run;
pub use vapp::VAppMap;

use crate::util::{AllowRemoteAny, GDuration, Numeric};

pub type Result<T> = std::result::Result<T, Error>;
pub type ByteResponse = Response<BoxBody<Bytes, StdError>>;
pub type HByteResult = std::result::Result<ByteResponse, hyper::http::Error>;
pub type HResult<T> = std::result::Result<T, hyper::http::Error>;

fn is_developent_mode() -> bool {
    std::env::var("GATERYX_DEVELOPMENT").is_ok_and(|v| v == "1")
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub auth: Option<authenticator::Config>,
    #[serde(default)]
    pub eapi: Option<eapi::Config>,
    #[serde(default)]
    pub listener: Vec<ListenerConfig>,
    pub server: ServerConfig,
    pub ml: Option<ml::Config>,
    pub db: Option<storage::Config>,
    #[serde(default = "ws::Config::default")]
    #[zeroize(skip)]
    pub websocket_default: ws::Config,
    pub admin: Option<admin::Config>,
    #[serde(default)]
    pub app: Vec<app::Config>,
    #[zeroize(skip)]
    #[serde(default)]
    pub headers: headers::Headers,
}

impl Config {
    pub fn canonicalize_path(&mut self, work_dir: &Path) {
        if let Some(ref mut auth_config) = self.auth {
            auth_config.canonicalize_path(work_dir);
        }
        for listener in &mut self.listener {
            if let Some(ref mut tls_config) = listener.tls {
                tls_config.canonicalize_path(work_dir);
            }
        }
        if let Some(ref mut admin_config) = self.admin {
            admin_config.canonicalize_path(work_dir);
        }
    }
    pub fn check(&self, config_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        if let Some(ref auth_config) = self.auth {
            issues.extend(auth_config.check(config_dir));
        }
        for listener in &self.listener {
            issues.extend(listener.check(config_dir));
        }
        issues.extend(self.server.check(config_dir));
        if let Some(ref db_config) = self.db {
            issues.extend(db_config.check(config_dir));
        }
        if let Some(ref admin_config) = self.admin {
            issues.extend(admin_config.check(config_dir));
        }
        issues
    }
}

fn default_threads() -> Numeric {
    1u32.into()
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[zeroize(skip)]
    pub timeout: GDuration,
    #[serde(default = "default_threads")]
    #[zeroize(skip)]
    pub master_threads: Numeric,
    #[serde(default = "default_threads")]
    #[zeroize(skip)]
    pub worker_threads: Numeric,
    #[zeroize(skip)]
    pub http_log: Option<PathBuf>,
    pub default_app: Option<String>,
    #[zeroize(skip)]
    pub max_body_size: Option<Numeric>,
    pub user: Option<String>,
    /// When set, use the value of this HTTP header as the client IP instead of the connection IP (e.g. "X-Forwarded-For" or "X-Real-IP"). For comma-separated values (e.g. X-Forwarded-For), the first element is used.
    pub remote_real_ip: Option<String>,
}

impl ServerConfig {
    pub fn check(&self, _config_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        if let Some(ref h) = self.remote_real_ip
            && HeaderName::from_bytes(h.as_bytes()).is_err()
        {
            issues.push(ConfigCheckIssue::Error(format!(
                "server.remote_real_ip is not a valid HTTP header name: {h:?}"
            )));
        }
        if self.max_body_size.is_none() {
            issues.push(ConfigCheckIssue::Warning(
                "No max_body_size configured, defaulting to unlimited".to_string(),
            ));
        }
        issues
    }
}

fn default_max_clients() -> Numeric {
    100u32.into()
}

fn default_max_workers() -> Numeric {
    200u32.into()
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum L7Protocol {
    #[default]
    #[serde(alias = "http", alias = "http1", alias = "http1.1")]
    Http1,
    Http2,
}

#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub bind: String,
    #[serde(default = "default_max_clients")]
    #[zeroize(skip)]
    max_clients: Numeric,
    #[serde(default = "default_max_workers")]
    #[zeroize(skip)]
    max_workers: Numeric,
    pub tls: Option<tls::Config>,
    #[zeroize(skip)]
    pub app: Option<Arc<String>>,
    #[serde(default)]
    #[zeroize(skip)]
    pub protocol: L7Protocol,
    #[zeroize(skip)]
    #[serde(default)]
    pub allow: AllowRemoteAny,
}

impl ListenerConfig {
    pub fn check(&self, config_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        if let Some(ref tls_config) = self.tls {
            issues.extend(tls_config.check(config_dir));
        }
        if !self.bind.contains(':') {
            issues.push(ConfigCheckIssue::Error(format!(
                "Listener bind address must include port: {}",
                self.bind
            )));
        }
        if let Some((h, p)) = self.bind.rsplit_once(':') {
            if h.is_empty() {
                issues.push(ConfigCheckIssue::Error(format!(
                    "Listener bind address has empty host: {}",
                    self.bind
                )));
            }
            if p.parse::<u16>().is_err() {
                issues.push(ConfigCheckIssue::Error(format!(
                    "Listener bind address has invalid port: {}",
                    self.bind
                )));
            }
        } else {
            issues.push(ConfigCheckIssue::Error(format!(
                "Listener bind address must include port: {}",
                self.bind
            )));
        }
        issues
    }
}
