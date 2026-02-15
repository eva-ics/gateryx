//! EAPI (EVA ICS bus) configuration and shared RPC client.

use std::sync::Arc;
use std::time::Duration;

use busrt::rpc::{Rpc as _, RpcClient};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{error, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, util::GDuration};

fn default_eva_svc_id() -> String {
    "gateryx".to_string()
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct BusConfig {
    path: String,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            path: "/opt/eva4/var/bus.ipc".to_string(),
        }
    }
}

/// Global [eapi] section configuration.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_eva_svc_id")]
    pub id: String,
    #[serde(default)]
    pub bus: BusConfig,
    #[zeroize(skip)]
    #[serde(default = "crate::util::default_timeout")]
    pub timeout: GDuration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: default_eva_svc_id(),
            bus: BusConfig::default(),
            timeout: crate::util::default_timeout(),
        }
    }
}

struct EAPIBusInner {
    client: Mutex<Option<Arc<RpcClient>>>,
    config: Config,
}

impl EAPIBusInner {
    fn connect_timeout(&self) -> Duration {
        self.config.timeout.into()
    }

    /// Get RPC client, reconnecting if the current connection is down.
    async fn get_rpc_client(&self) -> Result<Arc<RpcClient>> {
        let mut guard = self.client.lock().await;
        if let Some(ref c) = *guard
            && c.is_connected()
        {
            return Ok(Arc::clone(c));
        }
        let timeout = self.connect_timeout();
        let bus_config = busrt::ipc::Config::new(&self.config.bus.path, &self.config.id);
        let bus = tokio::time::timeout(timeout, busrt::ipc::Client::connect(&bus_config))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::failed(format!("EAPI bus connect failed: {e}")))?;
        let rpc = Arc::new(busrt::rpc::RpcClient::new0(bus));
        info!(bus_path = %self.config.bus.path, "Connected to EVA ICS bus");
        *guard = Some(Arc::clone(&rpc));
        Ok(rpc)
    }
}

/// Shared EAPI bus connection with RPC client for bus operations.
pub struct EAPIBus {
    inner: Arc<EAPIBusInner>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
}

impl EAPIBus {
    /// Connect to the EVA ICS bus and create an EAPIBus; spawns a verification worker.
    pub async fn connect(config: &Config) -> Result<Arc<Self>> {
        let inner = Arc::new(EAPIBusInner {
            client: Mutex::new(None),
            config: config.clone(),
        });
        inner.get_rpc_client().await?;
        let inner_for_worker = Arc::clone(&inner);
        let worker_handle = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;
                if let Err(e) = inner_for_worker.get_rpc_client().await {
                    error!(error = %e, "EVA ICS bus connection failed");
                }
            }
        });
        Ok(Arc::new(Self {
            inner,
            worker_handle: Some(worker_handle),
        }))
    }

    /// Returns the default timeout for bus operations, if configured.
    pub fn timeout(&self) -> Option<Duration> {
        Some(self.inner.connect_timeout())
    }

    /// Get RPC client, reconnecting if necessary. Reconnection is wrapped in timeout.
    pub async fn rpc_client(&self) -> Result<Arc<RpcClient>> {
        let timeout = self.inner.connect_timeout();
        tokio::time::timeout(timeout, self.inner.get_rpc_client())
            .await
            .map_err(|_| Error::Timeout)?
    }
}

impl Drop for EAPIBus {
    fn drop(&mut self) {
        if let Some(h) = self.worker_handle.take() {
            h.abort();
        }
    }
}
