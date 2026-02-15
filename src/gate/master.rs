use std::{
    net::IpAddr,
    os::fd::FromRawFd as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{
    Result,
    admin::TransferredRequest,
    app::AdminAppView,
    authenticator::RandomSleeper,
    passkeys::{Base64UrlSafeData, PublicKeyCredential, RegisterPublicKeyCredential},
    rpc::{RpcRequest as JsonRpcRequest, RpcResponse as JsonRpcResponse},
};
use busrt::{
    async_trait,
    broker::Broker,
    rpc::{RpcClient, RpcError, RpcEvent, RpcHandlers, RpcResult},
};
use serde::Deserialize;
use serde_json::{Value, to_value};
use tokio::{
    net::UnixStream,
    signal::unix::{SignalKind, signal},
    sync::Mutex,
};
use tracing::{debug, error, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    Config, DEVELOPER_USER, Error, VAppMap, admin, authenticator, bp, eapi, is_developent_mode,
    logger::Logger,
    passkeys,
    storage::{self, Storage},
    tokens::{self, ClaimsView},
};

use super::{AuthPayload, AuthResponse, ChangePasswordPayload, RpcEventExt, pack};

const CLEANUP_WORKER_INTERVAL: Duration = Duration::from_secs(60);

struct Context {
    admin_auth: Option<admin::Auth>,
    apps: Vec<AdminAppView>,
    authenticator: Option<Box<dyn authenticator::Authenticator>>,
    bp: Option<Arc<bp::BreakinProtection>>,
    eapi_bus: Option<Arc<eapi::EAPIBus>>,
    passkey_factory: Option<passkeys::Factory>,
    logger: Option<Mutex<Logger>>,
    meta_logger: Option<Mutex<Logger>>,
    token_factory: Option<tokens::Factory>,
    token_domain: Option<String>,
    token_domain_dot_prefixed: Option<String>,
    storage: Arc<dyn Storage>,
    development: bool,
}

impl Context {
    fn report_auth_success(&self, ip_address: IpAddr, username: &str) {
        if let Some(bp_engine) = &self.bp {
            bp_engine.report_success(ip_address, username);
        }
    }
    fn report_auth_failed(&self, ip_address: IpAddr, username: &str) {
        if let Some(bp_engine) = &self.bp {
            bp_engine.report_failure(ip_address, username);
        }
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub fn process_alive_nondefunct(pid: libc::pid_t) -> bool {
    use libproc::bsd_info::BSDInfo;
    use libproc::libproc::proc_pid;
    if let Ok(info) = proc_pid::pidinfo::<BSDInfo>(pid, 0) {
        // pbi_status values:
        // SIDL = 1, SRUN = 2, SSLEEP = 3, SSTOP = 4, SZOMB = 5
        info.pbi_status != 5 // 5 = SZOMB
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
pub fn process_alive_nondefunct(pid: libc::pid_t) -> bool {
    let f = std::fs::read_to_string(format!("/proc/{}/stat", pid));
    if let Ok(content) = f {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() > 2 {
            let state = parts[2];
            state != "Z" // Z = zombie
        } else {
            false
        }
    } else {
        false
    }
}

struct MasterHandlers {
    context: Context,
}

impl MasterHandlers {
    async fn authenticate_passkey(
        &self,
        challenge: Base64UrlSafeData,
        auth: PublicKeyCredential,
        remote_ip: IpAddr,
    ) -> Result<AuthResponse> {
        let Some(ref token_factory) = self.context.token_factory else {
            return Ok(AuthResponse::AuthNotEnabled);
        };
        let Some(ref passkey_factory) = self.context.passkey_factory else {
            return Ok(AuthResponse::AuthNotEnabled);
        };
        let user = passkey_factory
            .finish_authentication(&challenge, auth, &*self.context.storage)
            .await?;
        if passkey_factory.need_check_login_present()
            && let Some(ref auth) = self.context.authenticator
            && !auth.present(&user).await
        {
            return Ok(AuthResponse::InvalidCredentials(None));
        }
        let groups = if let Some(ref auth) = self.context.authenticator {
            auth.user_groups(&user).await?
        } else {
            vec![]
        };
        self.context.report_auth_success(remote_ip, &user);
        let (token_str, exp) = token_factory.issue(&user, groups, vec![], None, false)?;
        Ok(AuthResponse::Success((token_str, user, exp)))
    }
    async fn authenticate(&self, p: AuthPayload, remote_ip: IpAddr) -> Result<AuthResponse> {
        macro_rules! maybe_need_captcha {
            ($success: expr) => {
                if let Some(ref bp) = self.context.bp {
                    if let Some(captcha_id) = bp.need_captcha(remote_ip, &p.user)? {
                        if $success {
                            return Ok(AuthResponse::CaptchaRequired(captcha_id.to_string()));
                        }
                        return Ok(AuthResponse::InvalidCredentials(Some(
                            captcha_id.to_string(),
                        )));
                    }
                };
            };
        }

        let Some(ref factory) = self.context.token_factory else {
            return Ok(AuthResponse::AuthNotEnabled);
        };
        let Some(ref auth) = self.context.authenticator else {
            return Ok(AuthResponse::AuthNotEnabled);
        };
        match auth
            .verify(&p.user, &p.password, p.otp.as_ref().map(|z| z.as_str()))
            .await
        {
            crate::authenticator::AuthResult::Success { groups } => {
                if p.otp.is_none()
                    && !self.verify_captcha(
                        p.captcha_id.as_deref(),
                        p.captcha_str.as_deref(),
                        remote_ip,
                    )?
                {
                    maybe_need_captcha!(true);
                }
                self.context.report_auth_success(remote_ip, &p.user);
                let (token_str, exp) = factory.issue(&p.user, groups, vec![], None, false)?;
                Ok(AuthResponse::Success((token_str, p.user.clone(), exp)))
            }
            crate::authenticator::AuthResult::Failure => {
                self.context.report_auth_failed(remote_ip, &p.user);
                warn!(ip = %remote_ip, user = %p.user, "Failed login attempt");
                maybe_need_captcha!(false);
                Ok(AuthResponse::InvalidCredentials(None))
            }
            crate::authenticator::AuthResult::OtpRequested => Ok(AuthResponse::OtpRequested),
            crate::authenticator::AuthResult::OtpSetup { secret } => {
                Ok(AuthResponse::OtpSetup(secret))
            }
            crate::authenticator::AuthResult::OtpInvalid => {
                self.context.report_auth_failed(remote_ip, &p.user);
                Ok(AuthResponse::OtpInvalid)
            }
        }
    }
    fn verify_captcha(
        &self,
        captcha_id: Option<&str>,
        captcha_str: Option<&str>,
        remote_ip: IpAddr,
    ) -> Result<bool> {
        let Some(ref bp) = self.context.bp else {
            return Ok(true);
        };
        let Some(captcha_id) = captcha_id else {
            return Ok(false);
        };
        if captcha_id.is_empty() {
            return Ok(false);
        }
        let Some(captcha_str) = captcha_str else {
            return Ok(false);
        };
        let Ok(captcha_id) = uuid::Uuid::parse_str(captcha_id) else {
            return Ok(false);
        };
        if !bp.verify_captcha(captcha_id, remote_ip, captcha_str)? {
            return Ok(false);
        }
        Ok(true)
    }
    async fn get_user(&self, token_str: &str) -> Result<String> {
        if self.context.development {
            return Ok(DEVELOPER_USER.to_string());
        }
        let Some(ref token_factory) = self.context.token_factory else {
            return Err(Error::failed("Authentication is not enabled"));
        };
        match token_factory
            .validate(token_str.to_string(), self.context.storage.as_ref(), false)
            .await
        {
            tokens::ValidationResponse::Valid { claims: c, .. } => Ok(c.sub),
            tokens::ValidationResponse::Invalid => Err(Error::access("Invalid token")),
        }
    }
    async fn handle_admin_rpc(
        &self,
        admin_request: TransferredRequest,
        remote_ip: IpAddr,
    ) -> Result<Value> {
        let Some(ref auth) = self.context.admin_auth else {
            return Err(Error::access("Admin API is not enabled"));
        };
        let body = auth
            .parse_transferred_request(admin_request, remote_ip)
            .await?;
        let rpc_request = match JsonRpcRequest::try_from(&body[..]) {
            Ok(r) => r,
            Err(e) => {
                error!(ip = %remote_ip, error = %e, "Failed to parse RPC request");
                let response = JsonRpcResponse::new_error(Value::Null, e);
                return Ok(to_value(response)?);
            }
        };
        let JsonRpcRequest {
            id, method, params, ..
        } = rpc_request;
        match self.jsonrpc_admin(&method, params, remote_ip).await {
            Ok(response) => Ok(to_value(JsonRpcResponse::new_result(id, response))?),
            Err(e) => Ok(to_value(JsonRpcResponse::new_error(id, e))?),
        }
    }
    #[allow(clippy::too_many_lines)]
    async fn jsonrpc_admin(
        &self,
        method: &str,
        params: Value,
        _remote_ip: IpAddr,
    ) -> Result<Value> {
        macro_rules! auth_not_configured {
            () => {
                return Err(Error::failed("Authenticator not configured"));
            };
        }
        match method {
            "admin.test" => Ok(serde_json::json!({"ok": true})),
            "admin.app.list" => Ok(to_value(&self.context.apps)?),
            "admin.user.issue_app_token" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                    apps: Vec<String>,
                    exp: Option<u64>,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref token_factory) = self.context.token_factory else {
                    auth_not_configured!();
                };
                let (token_str, token_exp) =
                    token_factory.issue(&p.user, vec![], p.apps, p.exp, true)?;
                Ok(to_value(serde_json::json!({
                    "token": token_str,
                    "exp": token_exp,
                }))?)
            }
            "admin.invalidate" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                }
                let p: Params = serde_json::from_value(params)?;
                if self.context.token_factory.is_none() {
                    auth_not_configured!();
                }
                self.context.storage.invalidate(&p.user).await?;
                Ok(Value::Null)
            }
            "admin.user.create" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                    password: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                auth.add(&p.user, &p.password).await?;
                Ok(Value::Null)
            }
            "admin.user.delete" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                if let Err(e) = auth.delete(&p.user).await
                    && !matches!(e, Error::NotImplemented)
                    && !matches!(e, Error::NotFound(_))
                {
                    return Err(e);
                }
                if self.context.token_factory.is_some() {
                    self.context.storage.invalidate(&p.user).await?;
                }
                self.context.storage.delete_passkey(&p.user).await?;
                Ok(Value::Null)
            }
            "admin.user.list" => {
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                let users = auth.list().await?;
                Ok(to_value(users)?)
            }
            "admin.user.set_password" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                    password: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                auth.set_password_forced(&p.user, &p.password).await?;
                if self.context.token_factory.is_some() {
                    self.context.storage.invalidate(&p.user).await?;
                }
                Ok(Value::Null)
            }
            "admin.group.list" => {
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                let groups = auth.list_groups().await?;
                Ok(to_value(groups)?)
            }
            "admin.group.create" => {
                #[derive(Deserialize)]
                struct Params {
                    group: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                auth.add_group(&p.group).await?;
                Ok(Value::Null)
            }
            "admin.group.delete" => {
                #[derive(Deserialize)]
                struct Params {
                    group: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                auth.delete_group(&p.group).await?;
                Ok(Value::Null)
            }
            "admin.group.add_user" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                    group: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                auth.add_user_to_group(&p.user, &p.group).await?;
                Ok(Value::Null)
            }
            "admin.group.remove_user" => {
                #[derive(Deserialize)]
                struct Params {
                    user: String,
                    group: String,
                }
                let p: Params = serde_json::from_value(params)?;
                let Some(ref auth) = self.context.authenticator else {
                    auth_not_configured!();
                };
                auth.remove_user_from_group(&p.user, &p.group).await?;
                Ok(Value::Null)
            }
            _ => Err(Error::RpcMethodNotFound(format!(
                "Admin RPC method '{}' not found",
                method
            ))),
        }
    }
}

#[async_trait]
impl RpcHandlers for MasterHandlers {
    #[allow(clippy::too_many_lines)]
    async fn handle_call(&self, event: RpcEvent) -> RpcResult {
        match event.parse_method()? {
            // log http message
            "l" => {
                let Some(ref logger) = self.context.logger else {
                    return Err(RpcError::internal(None));
                };
                let payload = event.payload();
                logger
                    .lock()
                    .await
                    .write(payload)
                    .await
                    .map_err(|_| RpcError::internal(None))?;
                Ok(None)
            }
            "lm" => {
                let Some(ref meta_logger) = self.context.meta_logger else {
                    return Err(RpcError::internal(None));
                };
                let payload = event.payload();
                meta_logger
                    .lock()
                    .await
                    .write(payload)
                    .await
                    .map_err(|_| RpcError::internal(None))?;
                Ok(None)
            }
            // validate token
            "t.v" => {
                let Some(ref token_factory) = self.context.token_factory else {
                    return Err(RpcError::method(None));
                };
                let (token_str, allow_app_tokens): (String, bool) = event.unpack_payload()?;
                let res = token_factory
                    .validate(token_str, self.context.storage.as_ref(), allow_app_tokens)
                    .await;
                Ok(Some(pack(res)?))
            }
            // is token revoked
            "t.rev" => {
                let cv: ClaimsView = event.unpack_payload()?;
                let res = self
                    .context
                    .storage
                    .is_token_revoked(&cv.sub, cv.iat)
                    .await?;
                Ok(Some(pack(res)?))
            }
            // get token factory public
            "t.public" => {
                let public = self
                    .context
                    .token_factory
                    .as_ref()
                    .map(tokens::Factory::to_public);
                Ok(Some(pack(public)?))
            }
            "t.iapps" => {
                let (token_str, apps, exp): (String, Vec<String>, u64) = event.unpack_payload()?;
                let Some(ref token_factory) = self.context.token_factory else {
                    return Err(RpcError::method(None));
                };
                let tokens::ValidationResponse::Valid { claims, .. } = token_factory
                    .validate(token_str.clone(), self.context.storage.as_ref(), false)
                    .await
                else {
                    return Err(Error::access("Invalid token").into());
                };
                if apps.is_empty() {
                    return Err(Error::invalid_data("Audience list is empty").into());
                }
                let sleeper = RandomSleeper::new(100..300);
                let (token, _token_exp) =
                    token_factory.issue(&claims.sub, vec![], apps, Some(exp), false)?;
                sleeper.sleep().await;
                Ok(Some(pack(token)?))
            }
            "c.get" => {
                let (uuid_str, ip_address): (String, IpAddr) = event.unpack_payload()?;
                let uuid = Uuid::parse_str(&uuid_str).map_err(|_| RpcError::invalid(None))?;
                let secret = if let Some(ref bp) = self.context.bp {
                    bp.get_captcha_secret(uuid, ip_address)?
                } else {
                    None
                };
                Ok(Some(pack(secret)?))
            }
            "a" => {
                let (payload, remote_ip): (AuthPayload, IpAddr) = event.unpack_payload()?;
                let res = self.authenticate(payload, remote_ip).await?;
                Ok(Some(pack(res)?))
            }
            "pk.present" => {
                let token_str: Zeroizing<String> = event.unpack_payload()?;
                if self.context.passkey_factory.is_none() {
                    return Ok(Some(pack(None::<bool>)?));
                }
                let user = self.get_user(&token_str).await?;
                Ok(Some(pack(Some(
                    self.context.storage.has_passkey(&user).await?,
                ))?))
            }
            "pk.delete" => {
                let token_str: Zeroizing<String> = event.unpack_payload()?;
                let user = self.get_user(&token_str).await?;
                self.context.storage.delete_passkey(&user).await?;
                Ok(Some(pack(true)?))
            }
            "pk.sa" => {
                let remote_ip: IpAddr = event.unpack_payload()?;
                if self.context.token_factory.is_none() {
                    return Err(RpcError::method(None));
                }
                let Some(ref passkey_factory) = self.context.passkey_factory else {
                    return Err(RpcError::method(None));
                };
                let res = passkey_factory.start_authentication(remote_ip)?;
                Ok(Some(pack(res)?))
            }
            "pk.fa" => {
                let (challenge, auth, remote_ip): (Base64UrlSafeData, PublicKeyCredential, IpAddr) =
                    event.unpack_payload()?;
                let res = self
                    .authenticate_passkey(challenge, auth, remote_ip)
                    .await?;
                Ok(Some(pack(res)?))
            }
            "pk.sr" => {
                let token_str: String = event.unpack_payload()?;
                let user = self.get_user(&token_str).await?;
                let Some(ref passkey_factory) = self.context.passkey_factory else {
                    return Err(RpcError::method(None));
                };
                let res = passkey_factory.start_registration(&user)?;
                Ok(Some(pack(res)?))
            }
            "pk.fr" => {
                let (token_str, reg): (String, RegisterPublicKeyCredential) =
                    event.unpack_payload()?;
                let user = self.get_user(&token_str).await?;
                let Some(ref passkey_factory) = self.context.passkey_factory else {
                    return Err(RpcError::method(None));
                };
                passkey_factory
                    .finish_registration(user, reg, &*self.context.storage)
                    .await?;
                Ok(Some(pack(true)?))
            }
            "a.passwd" => {
                let (p, _remote_ip): (ChangePasswordPayload, IpAddr) = event.unpack_payload()?;
                let user = self.get_user(&p.token_str).await?;
                if let Some(ref auth) = self.context.authenticator {
                    auth.set_password(&user, &p.old_password, &p.new_password)
                        .await?;
                    if self.context.token_factory.is_some() {
                        self.context.storage.invalidate(&user).await?;
                    }
                    Ok(Some(pack(true)?))
                } else {
                    Err(Error::failed("Authenticator not configured").into())
                }
            }
            "a.inv" => {
                let token_str: String = event.unpack_payload()?;
                let Some(token_factory) = &self.context.token_factory else {
                    return Err(RpcError::method(None));
                };
                let tokens::ValidationResponse::Valid { claims, .. } = token_factory
                    .validate(token_str, self.context.storage.as_ref(), false)
                    .await
                else {
                    return Err(Error::access("Invalid token").into());
                };
                self.context.storage.invalidate(&claims.sub).await?;
                Ok(Some(pack(true)?))
            }
            "!" => {
                let (admin_request, remote_ip): (TransferredRequest, IpAddr) =
                    event.unpack_payload()?;
                let res = self.handle_admin_rpc(admin_request, remote_ip).await?;
                Ok(Some(pack(res)?))
            }
            _ => Err(RpcError::method(None)),
        }
    }
}

async fn terminate(active: Arc<AtomicBool>) {
    if !active.load(Ordering::Relaxed) {
        return;
    }
    active.store(false, Ordering::Relaxed);
    crate::panic_handler::term_childs();
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::process::exit(0);
}

fn register_signals(active: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut sig_hup = signal(SignalKind::hangup()).unwrap();
        let mut sig_int = signal(SignalKind::interrupt()).unwrap();
        let mut sig_term = signal(SignalKind::terminate()).unwrap();
        loop {
            tokio::select! {
                _ = sig_hup.recv() => {
                }

                _ = sig_int.recv() => {
                    terminate(active.clone()).await;
                }

                _ = sig_term.recv() => {
                    terminate(active.clone()).await;
                }
            }
        }
    });
}

#[allow(clippy::too_many_lines)]
async fn run_master_api_impl(
    fd: i32,
    child_pid: libc::pid_t,
    config: Zeroizing<Config>,
    virtual_app_map: Arc<VAppMap>,
    primary_system_host: Option<String>,
    apps: Vec<AdminAppView>,
) -> Result<()> {
    let active = Arc::new(AtomicBool::new(true));
    register_signals(active.clone());
    let storage = storage::create(config.db.as_ref()).await?;
    storage.init().await?;
    storage
        .clone()
        .spawn_cleanup_worker(CLEANUP_WORKER_INTERVAL);
    let mut context = Context {
        admin_auth: None,
        apps,
        authenticator: None,
        bp: None,
        eapi_bus: None,
        passkey_factory: None,
        logger: None,
        meta_logger: None,
        token_factory: None,
        token_domain: None,
        token_domain_dot_prefixed: None,
        storage: storage.clone(),
        development: is_developent_mode(),
    };
    if let Some(ref admin_config) = config.admin {
        let admin_auth = admin::Auth::init(admin_config).await?;
        context.admin_auth = Some(admin_auth);
    }
    if let Some(ref eapi_config) = config.eapi {
        match eapi::EAPIBus::connect(eapi_config).await {
            Ok(bus) => {
                context.eapi_bus = Some(bus);
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to EAPI bus");
                return Err(e);
            }
        }
    }
    if let Some(ref auth_config) = config.auth {
        let auth_master_ctx = if matches!(
            auth_config.authenticator,
            authenticator::AuthenticatorConfig::Eva(_)
        ) {
            context.eapi_bus.as_ref().map(|_| {
                Arc::new(authenticator::AuthMasterContext {
                    eapi_bus: context.eapi_bus.clone(),
                })
            })
        } else {
            None
        };
        let authenticator =
            authenticator::create_authenticator(auth_config, storage.clone(), auth_master_ctx)
                .await?;
        authenticator.spawn_secure_workers().await?;
        context.authenticator.replace(authenticator);
        context.token_factory.replace(
            tokens::Factory::init(&auth_config.tokens, primary_system_host.as_deref()).await?,
        );
        context.token_domain.clone_from(&auth_config.tokens.domain);
        context.token_domain_dot_prefixed = auth_config
            .tokens
            .domain
            .as_ref()
            .map(|d| format!(".{}", d));
        let bp_engine = Arc::new(bp::BreakinProtection::from_config(
            &auth_config.breakin_protection,
        ));
        bp_engine
            .clone()
            .spawn_cleanup_worker(CLEANUP_WORKER_INTERVAL);
        context.bp.replace(bp_engine);
        if let Some(system_hosts) = virtual_app_map.system_hosts()
            && let Some(ref passkey_config) = auth_config.passkeys
        {
            match passkeys::Factory::create(system_hosts, passkey_config) {
                Ok(factory) => {
                    context.passkey_factory.replace(factory);
                }
                Err(e) => {
                    error!(error = %e, "Failed to create passkey factory");
                }
            }
        }
    } else {
        warn!("AUTHENTICATION ENGINE IS DISABLED");
    }
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(std_stream)?;
    context.logger = config
        .server
        .http_log
        .as_ref()
        .map(|path| Mutex::new(Logger::new(path)));
    context.meta_logger = config
        .ml
        .as_ref()
        .and_then(|m| m.extractor_output.as_ref())
        .map(|path| Mutex::new(Logger::new(path)));
    let mut broker = Broker::new();
    let master_config = busrt::broker::ServerConfig::new()
        .payload_size_limit(4196)
        .timeout(Duration::from_secs(5));

    let core_client = broker.register_client("m").await?;
    let _crpc = RpcClient::new(core_client, MasterHandlers { context });
    debug!("master: API server starting...");
    broker.spawn_server_connection(stream, master_config)?;
    debug!("master: API server started");
    tokio::time::sleep(Duration::from_secs(2)).await;
    loop {
        assert!(
            process_alive_nondefunct(child_pid) || !active.load(Ordering::Relaxed),
            "worker died"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub fn serve(
    fd: i32,
    child_pid: libc::pid_t,
    config: Zeroizing<Config>,
    virtual_app_map: Arc<VAppMap>,
    primary_system_host: Option<String>,
    apps: Vec<AdminAppView>,
) -> Result<()> {
    crate::panic_handler::register_pid(child_pid);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_master_api_impl(
        fd,
        child_pid,
        config,
        virtual_app_map,
        primary_system_host,
        apps,
    ))?;
    Ok(())
}
