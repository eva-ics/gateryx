use std::{sync::Arc, time::Duration};

use crate::{Error, Result, util::GDuration};
use busrt::rpc::{Rpc as _, RpcClient};
use serde::Deserialize;
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{AuthResult, Authenticator};

fn default_eva_svc_id() -> String {
    "gateryx".to_string()
}

fn default_eva_hmi_svc() -> String {
    "eva.hmi.default".to_string()
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct EvaBusConfig {
    path: String,
}

impl Default for EvaBusConfig {
    fn default() -> Self {
        Self {
            path: "/opt/eva4/var/bus.ipc".to_string(),
        }
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct Config {
    #[serde(default = "default_eva_svc_id")]
    id: String,
    auth_svcs: Vec<String>,
    #[serde(default)]
    bus: EvaBusConfig,
    #[zeroize(skip)]
    #[serde(default = "crate::util::default_timeout")]
    timeout: GDuration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: default_eva_svc_id(),
            auth_svcs: <_>::default(),
            bus: EvaBusConfig::default(),
            timeout: crate::util::default_timeout(),
        }
    }
}

pub struct EvaAuthenticator {
    config: Config,
    timeout: Duration,
    bus_rpc_client: Mutex<Option<Arc<RpcClient>>>,
}

impl EvaAuthenticator {
    pub fn new(config: &Config) -> Self {
        let timeout = config.timeout.into();
        Self {
            config: config.clone(),
            timeout,
            bus_rpc_client: <_>::default(),
        }
    }
    pub async fn rpc_client(&self) -> Result<Arc<RpcClient>> {
        let mut b = self.bus_rpc_client.lock().await;
        if let Some(c) = &*b
            && c.is_connected()
        {
            return Ok(c.clone());
        }
        let bus_config = busrt::ipc::Config::new(&self.config.bus.path, &self.config.id);
        let bus =
            tokio::time::timeout(self.timeout, busrt::ipc::Client::connect(&bus_config)).await??;
        let rpc = Arc::new(busrt::rpc::RpcClient::new0(bus));
        *b = Some(rpc.clone());
        Ok(rpc)
    }
}

#[async_trait::async_trait]
impl Authenticator for EvaAuthenticator {
    async fn present(&self, login: &str) -> bool {
        todo!()
    }
    async fn user_groups(&self, login: &str) -> Result<Vec<String>> {
        todo!()
    }
    async fn verify(&self, login: &str, password: &str) -> AuthResult {
        todo!()
    }
    async fn set_password(
        &self,
        _login: &str,
        old_password: &str,
        _new_password: &str,
    ) -> Result<()> {
        Err(Error::NotImplemented)
    }
}
