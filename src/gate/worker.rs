use std::{net::IpAddr, os::fd::FromRawFd as _, sync::Arc, time::Duration};

use http::header::HeaderName;
use crate::{
    AppHostMap, Config, Result, VAppMap,
    admin::TransferredRequest,
    authenticator::UserAgentList,
    headers::WebHeaders,
    is_developent_mode,
    logger::{LogSender, MetaLogSender},
    ml,
    passkeys::{
        Base64UrlSafeData, CreationChallengeResponse, PublicKeyCredential,
        RegisterPublicKeyCredential,
    },
    tls::NoCertVerifier,
    tokens::TOKEN_COOKIE_NAME_PREFIX,
    util::AllowRemoteStrict,
    ws,
};
use busrt::{
    QoS,
    rpc::{Rpc as _, RpcClient},
};
use hyper_rustls::ConfigBuilderExt as _;
use hyper_staticfile::Static;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::{
    net::{TcpListener, UnixStream},
    signal::unix::{SignalKind, signal},
    task::JoinHandle,
};
use tracing::{debug, info};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    Error, passkeys,
    tokens::{self, ClaimsView},
};

use super::{AuthPayload, AuthResponse, ChangePasswordPayload, pack, unpack};

pub type Context = Arc<ContextData>;

pub struct ContextData {
    pub app_map: AppHostMap,
    pub virtual_app_map: Arc<VAppMap>,
    pub admin_allow_remote: Option<AllowRemoteStrict>,
    pub auth_www_static: Option<Static>,
    pub primary_host: Option<String>,
    pub token_domain: Option<String>,
    pub token_domain_dot_prefixed: Option<String>,
    pub token_factory_public: Option<tokens::Public>,
    pub timeout: Duration,
    pub max_body_size: Option<u64>,
    pub http_logger: Option<LogSender>,
    pub meta_logger: Option<MetaLogSender>,
    pub meta_extractor: Option<ml::extractor::RequestFeatureExtractor>,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub dangerous_tls_config: Option<Arc<rustls::ClientConfig>>,
    pub websocket_config: ws::Config,
    pub development: bool,
    pub master_client: Client,
    pub token_cookie_name: String,
    pub headers: WebHeaders,
    pub reply_401_to_user_agents: UserAgentList,
    /// When set, the value of this header is used as the client IP instead of the connection IP.
    pub remote_real_ip_header: Option<HeaderName>,
}

impl ContextData {
    pub fn token_domain_if_matches(&self, host: &str) -> Option<&str> {
        if self
            .token_domain_dot_prefixed
            .as_ref()
            .is_some_and(|d| host.ends_with(d))
        {
            self.token_domain.as_deref()
        } else {
            None
        }
    }
}

#[derive(Copy, Clone)]
enum ApiMethod {
    WriteLog,
    WriteMetaLog,
    IsTokenRevoked,
    ValidateToken,
    IssueAppsToken,
    TokenFactoryPublic,
    GetCaptchaSecret,
    Authenticate,
    ChangePassword,
    UserInvalidate,
    PasskeyPresent,
    PasskeyDelete,
    PasskeyAuthStart,
    PasskeyAuthFinish,
    PasskeyRegStart,
    PasskeyRegFinish,
    Admin,
}

impl ApiMethod {
    fn as_str(&self) -> &str {
        match self {
            ApiMethod::WriteLog => "l",
            ApiMethod::WriteMetaLog => "lm",
            ApiMethod::IsTokenRevoked => "t.rev",
            ApiMethod::ValidateToken => "t.v",
            ApiMethod::IssueAppsToken => "t.iapps",
            ApiMethod::TokenFactoryPublic => "t.public",
            ApiMethod::GetCaptchaSecret => "c.get",
            ApiMethod::Authenticate => "a",
            ApiMethod::ChangePassword => "a.passwd",
            ApiMethod::UserInvalidate => "a.inv",
            ApiMethod::PasskeyPresent => "pk.present",
            ApiMethod::PasskeyDelete => "pk.delete",
            ApiMethod::PasskeyAuthStart => "pk.sa",
            ApiMethod::PasskeyAuthFinish => "pk.fa",
            ApiMethod::PasskeyRegStart => "pk.sr",
            ApiMethod::PasskeyRegFinish => "pk.fr",
            ApiMethod::Admin => "!",
        }
    }
}

pub struct Client {
    inner: Option<Arc<ClientInner>>,
}

struct ClientInner {
    rpc: Arc<RpcClient>,
    checker: JoinHandle<()>,
}

impl Client {
    pub fn uninitialized() -> Self {
        Client { inner: None }
    }
    pub async fn create(fd: i32) -> Result<Self> {
        debug!("worker: connecting to Master API...");
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let stream = UnixStream::from_std(std_stream)?;
        let client_config = busrt::ipc::Config::new(".ipc", "w").timeout(Duration::from_secs(5));
        let client = busrt::ipc::Client::connect_stream(stream, &client_config).await?;
        let rpc = Arc::new(RpcClient::new0(client));
        debug!("worker: master API client connected");
        let checker = tokio::spawn({
            let rpc = rpc.clone();
            async move {
                loop {
                    assert!(rpc.is_connected(), "Lost connection to Master API");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        });
        Ok(Client {
            inner: Some(Arc::new(ClientInner { rpc, checker })),
        })
    }
    pub async fn write_meta_log_record(&self, data: &[u8]) -> Result<()> {
        self.inner
            .as_ref()
            .unwrap()
            .rpc
            .call(
                "m",
                ApiMethod::WriteMetaLog.as_str(),
                busrt::borrow::Cow::Borrowed(data),
                QoS::No,
            )
            .await
            .map_err(|e| Error::failed(format!("Failed to send meta log record: {e}")))?;
        Ok(())
    }
    pub async fn write_log_record(&self, data: &[u8]) -> Result<()> {
        self.inner
            .as_ref()
            .unwrap()
            .rpc
            .call(
                "m",
                ApiMethod::WriteLog.as_str(),
                busrt::borrow::Cow::Borrowed(data),
                QoS::No,
            )
            .await
            .map_err(|e| Error::failed(format!("Failed to send log record: {e}")))?;
        Ok(())
    }
    async fn call<P, R>(&self, method: ApiMethod, params: P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let payload = busrt::borrow::Cow::Owned(pack(params)?);
        let res = self
            .inner
            .as_ref()
            .unwrap()
            .rpc
            .call("m", method.as_str(), payload, QoS::No)
            .await?;
        let result = unpack(res.payload())?;
        Ok(result)
    }
    pub fn is_token_revoked(&self, cv: &ClaimsView) -> impl Future<Output = Result<bool>> {
        self.call(ApiMethod::IsTokenRevoked, cv)
    }
    pub fn validate_token<'a>(
        &'a self,
        token_str: &'a str,
        allow_app_tokens: bool,
    ) -> impl Future<Output = Result<tokens::ValidationResponse>> + 'a {
        self.call(ApiMethod::ValidateToken, (token_str, allow_app_tokens))
    }
    pub fn token_factory_public(&self) -> impl Future<Output = Result<Option<tokens::Public>>> {
        self.call(ApiMethod::TokenFactoryPublic, ())
    }
    pub fn issue_apps_token<'a>(
        &self,
        token_str: &'a str,
        aud: Vec<&'a str>,
        exp: u64,
    ) -> impl Future<Output = Result<Zeroizing<String>>> {
        self.call(ApiMethod::IssueAppsToken, (token_str, aud, exp))
    }
    pub fn invalidate(&self, token_str: Zeroizing<String>) -> impl Future<Output = Result<bool>> {
        self.call(ApiMethod::UserInvalidate, token_str)
    }
    pub fn get_captcha_secret(
        &self,
        uuid: Uuid,
        ip_address: IpAddr,
    ) -> impl Future<Output = Result<Option<String>>> {
        self.call(ApiMethod::GetCaptchaSecret, (uuid.to_string(), ip_address))
    }
    pub fn authenticate(
        &self,
        payload: &AuthPayload,
        remote_ip: IpAddr,
    ) -> impl Future<Output = Result<AuthResponse>> {
        self.call(ApiMethod::Authenticate, (payload, remote_ip))
    }
    pub fn change_password(
        &self,
        token_str: Zeroizing<String>,
        old_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
        remote_ip: IpAddr,
    ) -> impl Future<Output = Result<bool>> {
        self.call(
            ApiMethod::ChangePassword,
            (
                ChangePasswordPayload {
                    token_str,
                    old_password,
                    new_password,
                },
                remote_ip,
            ),
        )
    }
    pub fn passkey_present(
        &self,
        token_str: Zeroizing<String>,
    ) -> impl Future<Output = Result<Option<bool>>> {
        self.call(ApiMethod::PasskeyPresent, token_str)
    }
    pub fn passkey_delete(
        &self,
        token_str: Zeroizing<String>,
    ) -> impl Future<Output = Result<bool>> {
        self.call(ApiMethod::PasskeyDelete, token_str)
    }
    pub fn passkey_auth_start(
        &self,
        remote_ip: IpAddr,
    ) -> impl Future<Output = Result<passkeys::RequestChallengeResponse>> {
        self.call(ApiMethod::PasskeyAuthStart, remote_ip)
    }
    pub fn passkey_auth_finish(
        &self,
        challenge: Base64UrlSafeData,
        auth: PublicKeyCredential,
        remote_ip: IpAddr,
    ) -> impl Future<Output = Result<AuthResponse>> {
        self.call(ApiMethod::PasskeyAuthFinish, (challenge, auth, remote_ip))
    }
    pub fn passkey_reg_start(
        &self,
        token_str: Zeroizing<String>,
    ) -> impl Future<Output = Result<CreationChallengeResponse>> {
        self.call(ApiMethod::PasskeyRegStart, token_str)
    }
    pub fn passkey_reg_finish(
        &self,
        token_str: Zeroizing<String>,
        reg: RegisterPublicKeyCredential,
    ) -> impl Future<Output = Result<bool>> {
        self.call(ApiMethod::PasskeyRegFinish, (token_str, reg))
    }
    pub fn admin(
        &self,
        req: TransferredRequest,
        remote_ip: IpAddr,
    ) -> impl Future<Output = Result<Value>> {
        self.call(ApiMethod::Admin, (req, remote_ip))
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.checker.abort();
    }
}

// the method is started in privileged runtime
// the privileges are dropped after the serve thread receives ContextData and listeners
#[allow(clippy::too_many_lines)]
pub async fn prepare_privileged(
    config: &Config,
    app_map: AppHostMap,
    virtual_app_map: Arc<VAppMap>,
    primary_system_host: Option<String>,
) -> Result<(ContextData, Vec<TcpListener>)> {
    let mut listeners = Vec::with_capacity(config.listener.len());
    for listener_config in &config.listener {
        info!(
            bind = %listener_config.bind,
            "Initializing listener"
        );
        let listener = TcpListener::bind(&listener_config.bind).await?;
        listeners.push(listener);
    }
    let timeout = Duration::from(config.server.timeout);
    let tls_config = rustls::ClientConfig::builder()
        .with_native_roots()?
        .with_no_client_auth();
    let dangerous_tls_config = if app_map.has_skip_remote_tls_verify().await {
        let mut dangerous_tls_config = tls_config.clone();
        dangerous_tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertVerifier {}));
        Some(dangerous_tls_config)
    } else {
        None
    };
    let mut context_data = ContextData {
        app_map,
        virtual_app_map,
        admin_allow_remote: config
            .admin
            .as_ref()
            .map(|admin_config| admin_config.allow.clone()),
        primary_host: primary_system_host.clone(),
        auth_www_static: None,
        token_domain: None,
        token_domain_dot_prefixed: None,
        token_factory_public: None,
        timeout,
        max_body_size: config.server.max_body_size.map(Into::into),
        http_logger: None,
        meta_logger: None,
        meta_extractor: None,
        tls_config: Arc::new(tls_config),
        dangerous_tls_config: dangerous_tls_config.map(Arc::new),
        websocket_config: config.websocket_default.clone(),
        development: is_developent_mode(),
        master_client: Client::uninitialized(),
        token_cookie_name: <_>::default(),
        headers: config.headers.clone().try_into()?,
        reply_401_to_user_agents: config
            .auth
            .as_ref()
            .map(|auth_config| auth_config.reply_401_to_user_agents.clone())
            .unwrap_or_default(),
        remote_real_ip_header: config
            .server
            .remote_real_ip
            .as_ref()
            .and_then(|s| HeaderName::from_bytes(s.as_bytes()).ok()),
    };
    if let Some(ref auth_config) = config.auth {
        context_data
            .token_domain
            .clone_from(&auth_config.tokens.domain);
        context_data.token_domain_dot_prefixed =
            auth_config.tokens.domain.as_ref().map(|d| format!(".{d}"));
        context_data.token_cookie_name = format!(
            "{}{}",
            TOKEN_COOKIE_NAME_PREFIX,
            auth_config.tokens.cookie.clone()
        );
        context_data
            .auth_www_static
            .replace(Static::new(&auth_config.www_root));
    }
    Ok((context_data, listeners))
}

pub fn register_signals() {
    tokio::spawn(async move {
        let mut sig_hup = signal(SignalKind::hangup()).unwrap();
        let mut sig_int = signal(SignalKind::interrupt()).unwrap();
        let mut sig_term = signal(SignalKind::terminate()).unwrap();
        loop {
            tokio::select! {
                _ = sig_hup.recv() => {
                }

                _ = sig_int.recv() => {
                }

                _ = sig_term.recv() => {
                    info!("Shutting down");
                    std::process::exit(0);
                }
            }
        }
    });
}
