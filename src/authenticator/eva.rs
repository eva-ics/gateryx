use std::collections::HashMap;
use std::{sync::Arc, time::Duration};

use crate::{Error, Result, util::GDuration};
use busrt::rpc::{Rpc as _, RpcClient};
use mini_moka::sync::Cache;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{error, info, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{AuthResult, Authenticator};

fn default_eva_svc_id() -> String {
    "gateryx".to_string()
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
    // cache for user groups
    user_cache: parking_lot::Mutex<Cache<String, Vec<String>>>,
}

impl EvaAuthenticator {
    pub fn new(config: &Config) -> Self {
        let timeout = config.timeout.into();
        Self {
            config: config.clone(),
            timeout,
            bus_rpc_client: <_>::default(),
            user_cache: parking_lot::Mutex::new(
                Cache::builder()
                    .max_capacity(16384)
                    .time_to_live(timeout)
                    .build(),
            ),
        }
    }
    pub async fn rpc_client(&self) -> Result<Arc<RpcClient>> {
        match self.get_rpc_client().await {
            Ok(c) => Ok(c),
            Err(e) => {
                error!(error = ?e, "Failed to get EVA ICS bus RPC client");
                Err(e)
            }
        }
    }
    async fn get_rpc_client(&self) -> Result<Arc<RpcClient>> {
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
        info!(bus_path = %self.config.bus.path, "Connected to EVA ICS bus");
        *b = Some(rpc.clone());
        Ok(rpc)
    }
    pub async fn get_user_groups(
        &self,
        login: &str,
        password: Option<&str>,
        otp: Option<&str>,
    ) -> Result<Vec<String>> {
        tokio::time::timeout(
            self.timeout,
            self.get_user_groups_impl(login, password, otp),
        )
        .await?
    }
    async fn get_user_groups_impl(
        &self,
        login: &str,
        password: Option<&str>,
        otp: Option<&str>,
    ) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Response {
            from: Vec<String>,
        }
        let payload = rmp_serde::to_vec_named(&if let Some(p) = password {
            let mut xopts = HashMap::new();
            if let Some(otp) = otp {
                xopts.insert("otp", otp);
            }
            json! {{
                "login": login,
                "password": p,
                "xopts": xopts,
            }}
        } else {
            json! {{
                "login": login,
                "externally_verified": true,
            }}
        })
        .map_err(|e| Error::failed(format!("Failed to serialize payload: {e}")))?;
        let rpc_client = self.rpc_client().await?;
        for svc in &self.config.auth_svcs {
            match rpc_client
                .call(
                    svc,
                    "auth.user",
                    busrt::borrow::Cow::Borrowed(&payload),
                    busrt::QoS::No,
                )
                .await
            {
                Ok(v) => match rmp_serde::from_slice::<Response>(v.payload()) {
                    Ok(resp) => {
                        trace!(service = svc, "Got user groups from auth service");
                        return Ok(resp.from);
                    }
                    Err(e) => {
                        error!(error = ?e, service = svc, "Failed to deserialize response from auth service");
                    }
                },
                Err(e) if e.code() == -32022 => {
                    match std::str::from_utf8(e.data().unwrap_or_default()) {
                        Ok(s) => {
                            let mut sp = s.split('|');
                            sp.next().unwrap();
                            let kind = sp.next().unwrap_or_default();
                            if kind == "OTP" {
                                trace!(service = svc, "Auth service requires OTP");
                            } else {
                                error!(service = svc, error = %s, "Auth service returned an error");
                                continue;
                            }
                            let Some(_otp_svc) = sp.next() else {
                                error!(
                                    service = svc,
                                    "Auth service returned an OTP error without a service"
                                );
                                continue;
                            };
                            let Some(otp_op) = sp.next() else {
                                error!(
                                    service = svc,
                                    "Auth service returned an OTP error without an operation"
                                );
                                continue;
                            };
                            return Err(Error::AccessDeniedMoreDataRequired(format!(
                                "|OTP|{otp_op}"
                            )));
                        }
                        Err(_) => {
                            error!(
                                service = svc,
                                "Auth service returned an error with non-UTF8 data"
                            );
                        }
                    }
                }
                Err(e) => {
                    trace!(error = ?e, service = svc, "Failed to call auth service");
                }
            }
        }
        Err(Error::access("Failed to get user groups"))
    }
}

#[async_trait::async_trait]
impl Authenticator for EvaAuthenticator {
    async fn present(&self, login: &str) -> bool {
        if self.user_cache.lock().contains_key(&login.to_owned()) {
            return true;
        }
        if let Ok(groups) = self.get_user_groups(login, None, None).await {
            self.user_cache.lock().insert(login.to_string(), groups);
            return true;
        }
        false
    }
    async fn user_groups(&self, login: &str) -> Result<Vec<String>> {
        let login = login.to_owned();
        if let Some(groups) = self.user_cache.lock().get(&login) {
            return Ok(groups.clone());
        }
        let groups = self.get_user_groups(&login, None, None).await?;
        self.user_cache.lock().insert(login, groups.clone());
        Ok(groups)
    }
    async fn verify(&self, login: &str, password: &str, otp: Option<&str>) -> AuthResult {
        match self.get_user_groups(login, Some(password), otp).await {
            Ok(groups) => {
                self.user_cache
                    .lock()
                    .insert(login.to_owned(), groups.clone());
                AuthResult::Success { groups }
            }
            Err(Error::AccessDeniedMoreDataRequired(ref msg)) => {
                let op = msg.split('|').nth(2).unwrap_or_default().trim();
                if op == "REQ" {
                    AuthResult::OtpRequested
                } else if op == "INVALID" {
                    AuthResult::OtpInvalid
                } else if let Some(secret) = op.strip_prefix("SETUP=") {
                    AuthResult::OtpSetup {
                        secret: secret.to_string(),
                    }
                } else {
                    trace!(op = %op, "Unrecognized OTP op from auth service");
                    AuthResult::Failure
                }
            }
            Err(e) => {
                error!(error = ?e, "Failed to get user groups");
                AuthResult::Failure
            }
        }
    }
    async fn set_password(
        &self,
        _login: &str,
        _old_password: &str,
        _new_password: &str,
    ) -> Result<()> {
        Err(Error::NotImplemented)
    }
}
