use std::collections::HashMap;
use std::{sync::Arc, time::Duration};

use crate::{Error, Result, util::GDuration};
use busrt::rpc::Rpc as _;
use mini_moka::sync::Cache;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{AuthMasterContext, AuthResult, Authenticator};

#[derive(Default, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    auth_svcs: Vec<String>,
    #[zeroize(skip)]
    #[serde(default)]
    timeout: Option<GDuration>,
}

pub struct EvaAuthenticator {
    config: Config,
    context: Arc<AuthMasterContext>,
    timeout: Duration,
    // cache for user groups
    user_cache: parking_lot::Mutex<Cache<String, Vec<String>>>,
}

impl EvaAuthenticator {
    pub fn new(config: &Config, context: Arc<AuthMasterContext>) -> Self {
        let timeout = config
            .timeout
            .map(Duration::from)
            .or_else(|| context.eapi_bus.as_ref().and_then(|b| b.timeout()))
            .unwrap_or(crate::util::default_timeout().into());
        Self {
            config: config.clone(),
            context,
            timeout,
            user_cache: parking_lot::Mutex::new(
                Cache::builder()
                    .max_capacity(16384)
                    .time_to_live(timeout)
                    .build(),
            ),
        }
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
        let bus = self
            .context
            .eapi_bus
            .as_ref()
            .ok_or_else(|| Error::failed("EAPIBus not configured for Eva authenticator"))?;
        let rpc_client = bus.rpc_client().await?;
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
                            let _ = sp.next();
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
                let op = msg.split('|').nth(2).map_or("", str::trim);
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
