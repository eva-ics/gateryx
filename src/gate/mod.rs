use std::{
    mem,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bincode::{Decode, Encode};
use busrt::rpc::RpcEvent;
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{AppHostMap, Config, Error, ListenerConfig, Result, VAppMap, logger, ml, serve, util};

pub mod master;
pub mod worker;

#[inline]
fn pack<T: Encode>(value: T) -> Result<Vec<u8>> {
    let encoded = bincode::encode_to_vec(value, bincode::config::standard())?;
    Ok(encoded)
}

#[inline]
fn unpack<T>(data: &[u8]) -> Result<T>
where
    T: Decode<()>,
{
    let (decoded, _) = bincode::decode_from_slice::<T, _>(data, bincode::config::standard())?;
    Ok(decoded)
}

#[inline]
fn pack_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(&value)?;
    Ok(encoded)
}

trait RpcEventExt {
    fn unpack_payload<T>(&self) -> Result<T>
    where
        T: Decode<()>;
    fn unpack_payload_ser<T>(&self) -> Result<T>
    where
        T: serde::de::DeserializeOwned;
}

impl RpcEventExt for RpcEvent {
    fn unpack_payload<T>(&self) -> Result<T>
    where
        T: Decode<()>,
    {
        unpack::<T>(self.payload())
    }
    fn unpack_payload_ser<T>(&self) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let data = self.payload();
        let value = serde_json::from_slice::<T>(data)?;
        Ok(value)
    }
}

#[derive(Serialize, Deserialize, Encode, Decode)]
pub struct AuthPayload {
    user: String,
    #[bincode(with_serde)]
    password: Zeroizing<String>,
    captcha_id: Option<String>,
    captcha_str: Option<String>,
}

#[derive(Encode, Decode)]
pub struct ChangePasswordPayload {
    #[bincode(with_serde)]
    token_str: Zeroizing<String>,
    #[bincode(with_serde)]
    old_password: Zeroizing<String>,
    #[bincode(with_serde)]
    new_password: Zeroizing<String>,
}

impl AuthPayload {
    pub fn user(&self) -> &str {
        &self.user
    }
    pub fn captcha_filled(&self) -> bool {
        self.captcha_id.is_some()
    }
}

#[derive(Encode, Decode, Serialize, Deserialize)]
pub enum AuthResponse {
    Success((String, String, u64)),
    AuthNotEnabled,
    InvalidCredentials(Option<String>),
    CaptchaRequired(String),
}

async fn run_gate(
    mut context_data: worker::ContextData,
    has_http_logger: bool,
    ml_config: Option<ml::Config>,
    listener_configs: Vec<ListenerConfig>,
    listeners: Vec<TcpListener>,
    master_client_fd: i32,
    active: Arc<AtomicBool>,
) -> Result<()> {
    worker::register_signals();
    if context_data.development {
        warn!("RUNNING IN DEVELOPMENT MODE");
    }
    let master_client = worker::Client::create(master_client_fd).await?;
    context_data.token_factory_public = master_client.token_factory_public().await?;
    if has_http_logger {
        context_data.http_logger = Some(logger::spawn(master_client.clone()));
    }
    if let Some(ml_config) = ml_config {
        context_data.meta_extractor = Some(ml::extractor::RequestFeatureExtractor::new(
            ml_config.window_size.as_secs(),
        ));
        if ml_config.extractor_output.is_some() {
            context_data.meta_logger = Some(logger::spawn_meta(master_client.clone()));
        }
    }
    context_data.master_client = master_client;
    let context: worker::Context = context_data.into();
    let mut fut = Vec::new();
    for (listener_config, listener) in listener_configs.iter().zip(listeners.into_iter()) {
        let context = context.clone();
        let listener_config = listener_config.clone();
        fut.push(tokio::spawn({
            async move {
                let bind = listener_config.bind.clone();
                info!(bind = %bind, "Starting listener");
                if let Err(e) = serve::handle_listener(listener, listener_config, context).await {
                    error!(bind = %bind, error = %e, "Listener exited with error");
                }
            }
        }));
    }
    while active.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

pub fn run(
    mut config: Zeroizing<Config>,
    app_map: AppHostMap,
    virtual_app_map: VAppMap,
    primary_system_host: Option<String>,
) -> Result<()> {
    let virtual_app_map = Arc::new(virtual_app_map);
    let (master_sock, worker_sock) = socketpair::socketpair_stream().map_err(|e| {
        Error::failed(format!(
            "Failed to create socketpair for privilege separation: {e}",
        ))
    })?;
    let active = Arc::new(AtomicBool::new(true));
    if let fork::Fork::Parent(pid) = fork::fork()
        .map_err(|e| Error::failed(format!("Failed to fork for privilege separation: {e}")))?
    {
        return master::serve(
            master_sock.as_raw_fd(),
            pid,
            config,
            virtual_app_map,
            primary_system_host,
        );
    }
    let master_client_fd = worker_sock.as_raw_fd();
    for listener in &mut config.listener {
        if let Some(ref mut tls_config) = listener.tls {
            tls_config.load_files()?;
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.server.worker_threads)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let (context_data, listeners) =
            worker::prepare_privileged(&config, app_map, virtual_app_map, primary_system_host)
                .await?;
        let has_http_logger = config.server.http_log.is_some();
        let meta_config = config.ml.clone();
        let listener_configs = mem::take(&mut config.listener);
        let user = config.server.user.clone();
        // ensure config is zeroized in worker after use
        config.zeroize();
        if let Some(user) = user {
            util::drop_privileges(&user)?;
        }
        run_gate(
            context_data,
            has_http_logger,
            meta_config,
            listener_configs,
            listeners,
            master_client_fd,
            active,
        )
        .await?;
        Ok::<(), Error>(())
    })?;
    Ok(())
}
