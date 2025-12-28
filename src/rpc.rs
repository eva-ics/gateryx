use core::fmt;
use std::fmt::Write as _;
use std::net::IpAddr;

use http::{HeaderMap, Request, Response};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::{Value, to_value};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::{
    ByteResponse, Error, HByteResult, Result, StdError,
    admin::TransferredRequest,
    gate::{AuthPayload, AuthResponse, worker::Context},
    passkeys::{Base64UrlSafeData, PublicKeyCredential, RegisterPublicKeyCredential},
    tokens,
    util::{http_response, http_ser_json_response, resolve_host, synth_sleep},
};

const JSON_RPC_VERSION: &str = "2.0";

pub const URI_RPC: &str = "/.gateryx/rpc";

pub const URI_RPC_ADMIN: &str = "/.gateryx/rpc.admin";

#[derive(Deserialize, Default, Copy, Clone)]
#[serde(rename_all = "lowercase")]
enum SetAuthCookie {
    #[default]
    #[serde(alias = "n")]
    No,
    #[serde(alias = "u")]
    Untrusted,
    #[serde(alias = "t")]
    Trusted,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Value,
}

impl TryFrom<&[u8]> for RpcRequest {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self> {
        let request = match serde_json::from_slice::<RpcRequest>(value) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::invalid_data(format!(
                    "Failed to parse RPC request body as JSON: {}",
                    e
                )));
            }
        };
        if request.jsonrpc != JSON_RPC_VERSION {
            return Err(Error::invalid_data(format!(
                "Invalid JSON-RPC version: {}",
                request.jsonrpc
            )));
        }
        Ok(request)
    }
}

impl RpcRequest {
    pub fn create<I: Serialize, M: AsRef<str>, P: Serialize>(
        id: I,
        method: M,
        params: P,
    ) -> Result<Self> {
        Ok(RpcRequest {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id: to_value(id)?,
            method: method.as_ref().to_string(),
            params: to_value(params)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct RpcResultResponse {
    jsonrpc: String,
    pub id: Value,
    pub result: Value,
}

#[derive(Serialize, Deserialize)]
pub struct RpcErrorResponse {
    jsonrpc: String,
    id: Value,
    pub error: RpcError,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcResponse {
    Result(RpcResultResponse),
    Error(RpcErrorResponse),
}

impl RpcResponse {
    pub fn new_result(id: Value, result: Value) -> RpcResponse {
        RpcResponse::Result(RpcResultResponse {
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            id,
            result,
        })
    }
    pub fn new_error(id: Value, error: Error) -> RpcResponse {
        RpcResponse::Error(RpcErrorResponse {
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            id,
            error: error.into(),
        })
    }
    pub fn error(&self) -> Option<&RpcError> {
        match self {
            RpcResponse::Error(e) => Some(&e.error),
            RpcResponse::Result(_) => None,
        }
    }
}

impl From<Error> for RpcError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound(m) => RpcError::new(ERR_CODE_NOT_FOUND, Some(m)),
            Error::AppAlreadyExists => RpcError::new(ERR_CODE_BUSY, Some("App already exists")),
            Error::HostAlreadyExists => RpcError::new(ERR_CODE_BUSY, Some("Host already exists")),
            Error::Io(m) => RpcError::new(ERR_CODE_IO, Some(m)),
            Error::AccessDenied(m) => RpcError::new(ERR_CODE_ACCESS_DENIED, Some(m)),
            Error::AccessDeniedMoreDataRequired(s) => {
                RpcError::new(ERR_ACCESS_DENIED_MORE_DATA_REQUIRED, Some(s))
            }
            Error::RpcMethodNotFound(m) => RpcError::new(ERR_CODE_METHOD_NOT_FOUND, Some(m)),
            Error::InvalidData(m) => RpcError::new(ERR_CODE_INVALID_DATA, Some(m)),
            Error::Crypto(m) | Error::Failed(m) => RpcError::new(ERR_CODE_FUNC_FAILED, Some(m)),
            Error::NotImplemented => RpcError::new(ERR_CODE_FUNC_FAILED, Some("Not implemented")),
            Error::Timeout => RpcError::new(ERR_CODE_FUNC_FAILED, Some("Operation timed out")),
            Error::Database(m) => RpcError::new(ERR_CODE_FUNC_FAILED, Some(m.clone())),
        }
    }
}

impl RpcResponse {
    async fn into_hyper_resonse(self, header_map: Option<HeaderMap>) -> ByteResponse {
        let body = match serde_json::to_vec(&self) {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "Failed to serialize RPC response");
                return http_response(500, "Internal Server Error").await;
            }
        };
        #[allow(unused_mut)]
        let mut b = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len());
        #[cfg(debug_assertions)]
        {
            b = b.header("Access-Control-Allow-Origin", "*");
            b = b.header("Access-Control-Allow-Headers", "Content-Type");
        }
        if let Some(h) = header_map {
            for (k, v) in &h {
                b = b.header(k, v);
            }
        }
        b.body(
            Full::from(body)
                .map_err(|e| Box::new(e) as StdError)
                .boxed(),
        )
        .unwrap()
    }
}

#[derive(Serialize, Deserialize)]
pub struct RpcError {
    pub code: i16,
    pub message: Option<String>,
}

impl RpcError {
    fn new<S: AsRef<str>>(code: i16, message: Option<S>) -> Self {
        RpcError {
            code,
            message: message.map(|m| m.as_ref().to_string()),
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref msg) = self.message {
            write!(f, "RPC Error {}: {}", self.code, msg)
        } else {
            write!(f, "RPC Error {}", self.code)
        }
    }
}

pub const ERR_CODE_NOT_FOUND: i16 = -32001;
pub const ERR_CODE_INVALID_DATA: i16 = -32009;
pub const ERR_CODE_FUNC_FAILED: i16 = -32010;
pub const ERR_CODE_ACCESS_DENIED: i16 = -32002;
pub const ERR_CODE_BUSY: i16 = -32013;
pub const ERR_CODE_METHOD_NOT_FOUND: i16 = -32601;
pub const ERR_CODE_IO: i16 = -32016;
pub const ERR_ACCESS_DENIED_MORE_DATA_REQUIRED: i16 = -32022;

#[inline]
fn get_token_str(headers: &HeaderMap, context: &Context) -> Result<Zeroizing<String>> {
    tokens::get_token_from_cookie_header(headers, context)
        .map(Zeroizing::new)
        .ok_or_else(|| Error::access("Valid authentication token required"))
}

fn token_cookie_hmap(
    host: &str,
    token_str: &Zeroizing<String>,
    exp: u64,
    set_auth_cookie: SetAuthCookie,
    context: &Context,
) -> Option<HeaderMap> {
    if matches!(set_auth_cookie, SetAuthCookie::No) {
        return None;
    }
    let domain = context.token_domain_if_matches(host);
    let mut cookie_str = format!(
        "{}={}; Path=/; SameSite=Lax",
        context.token_cookie_name, &**token_str
    );
    if let Some(d) = domain {
        write!(cookie_str, "; Domain={}", d).ok()?;
    }
    match set_auth_cookie {
        SetAuthCookie::Trusted => {
            if let Ok(exp_utc) = bma_ts::Timestamp::from_secs(exp + 86400).try_into_datetime_utc() {
                write!(
                    cookie_str,
                    "; Expires={}",
                    exp_utc.format("%a, %d %b %Y %H:%M:%S GMT")
                )
                .ok()?;
            }
        }
        SetAuthCookie::Untrusted => {}
        SetAuthCookie::No => unreachable!(),
    }
    let mut header_map = HeaderMap::new();
    match cookie_str.parse() {
        Ok(v) => {
            header_map.append(http::header::SET_COOKIE, v);
            Some(header_map)
        }
        Err(e) => {
            error!(error = %e, "Failed to create Set-Cookie header for auth token");
            None
        }
    }
}

fn token_value(
    host: &str,
    token_str: Zeroizing<String>,
    exp: u64,
    set_auth_cookie: SetAuthCookie,
    context: &Context,
) -> (Value, Option<HeaderMap>) {
    let domain = context.token_domain_if_matches(host);
    let val = serde_json::json!({ "token": token_str, "exp": exp, "domain": domain});
    (
        val,
        token_cookie_hmap(host, &token_str, exp, set_auth_cookie, context),
    )
}

async fn process_auth<F>(
    host: &str,
    auth: F,
    p: Option<&AuthPayload>,
    remote_ip: IpAddr,
    set_auth_cookie: SetAuthCookie,
    context: &Context,
) -> Result<(Value, Option<HeaderMap>)>
where
    F: Future<Output = Result<AuthResponse>>,
{
    macro_rules! need_captcha {
        ($xtra: expr, $id: expr) => {
            return Err(Error::AccessDeniedMoreDataRequired(format!(
                "|CAPTCHA_REQUIRED|{}|CAPTCHA_ID={}",
                $xtra, $id
            )))
        };
    }
    match auth.await {
        Ok(AuthResponse::Success((token_str, user, exp))) => {
            let token_str = Zeroizing::new(token_str);
            info!(ip = %remote_ip, user = %user, "User logged in successfully");
            Ok(token_value(host, token_str, exp, set_auth_cookie, context))
        }
        Ok(AuthResponse::AuthNotEnabled) => {
            synth_sleep().await;
            warn!(ip = %remote_ip, "Authentication attempt when not enabled");
            Err(Error::access("Authentication not enabled"))
        }
        Ok(AuthResponse::InvalidCredentials(captcha_id)) => {
            synth_sleep().await;
            warn!(ip = %remote_ip, user = %p.map(AuthPayload::user).unwrap_or_default(), "Failed login attempt");
            if let Some(c) = captcha_id {
                need_captcha!("AUTH", c);
            }
            Err(Error::access("Invalid username or password"))
        }
        Ok(AuthResponse::CaptchaRequired(id)) => {
            synth_sleep().await;
            warn!(ip = %remote_ip, user = %p.map(AuthPayload::user).unwrap_or_default(), "Login attempt requiring CAPTCHA");
            need_captcha!(
                if p.is_some_and(AuthPayload::captcha_filled) {
                    "CAPTCHA"
                } else {
                    ""
                },
                id
            );
        }
        Err(e) => {
            error!(ip = %remote_ip, error = %e, "Failed to authenticate user");
            synth_sleep().await;
            Err(Error::failed("Failed to authenticate user"))
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn rpc_regular(
    host: &str,
    headers: &HeaderMap,
    method: &str,
    params: Value,
    remote_ip: IpAddr,
    context: &Context,
) -> Result<(Value, Option<HeaderMap>)> {
    macro_rules! no_reply {
        () => {
            (Value::Null, None)
        };
    }
    macro_rules! logout_hmap {
        () => {
            token_cookie_hmap(
                host,
                &Zeroizing::new(String::new()),
                0,
                SetAuthCookie::Trusted,
                context,
            )
        };
    }
    match method {
        "test" => {
            synth_sleep().await;
            Ok((serde_json::json!({"ok": true}), None))
        }
        "gate.logout" => Ok((Value::Null, logout_hmap!())),
        "gate.passkey.register.start" => {
            let token_str = get_token_str(headers, context)?;
            let res = context.master_client.passkey_reg_start(token_str).await?;
            Ok((to_value(res)?, None))
        }
        "gate.passkey.register.finish" => {
            let token_str = get_token_str(headers, context)?;
            let reg: RegisterPublicKeyCredential = serde_json::from_value(params)?;
            context
                .master_client
                .passkey_reg_finish(token_str, reg)
                .await?;
            Ok(no_reply!())
        }
        "gate.passkey.auth.start" => {
            synth_sleep().await;
            if context.token_domain_if_matches(host).is_none() {
                return Ok(no_reply!());
            }
            let challenge = match context.master_client.passkey_auth_start(remote_ip).await {
                Ok(v) => v,
                Err(e) => {
                    error!(ip = %remote_ip, error = %e, "Failed to start passkey authentication");
                    return Err(Error::access("Failed to start passkey authentication"));
                }
            };
            Ok((to_value(challenge)?, None))
        }
        "gate.passkey.auth.finish" => {
            #[derive(Deserialize)]
            struct Params {
                challenge: Base64UrlSafeData,
                auth: PublicKeyCredential,
                #[serde(default)]
                set_auth_cookie: SetAuthCookie,
            }
            synth_sleep().await;
            let p: Params = serde_json::from_value(params)?;
            if p.challenge.len() > 4096 {
                warn!(ip = %remote_ip, "Passkey authentication challenge too large");
                return Err(Error::invalid_data(
                    "Invalid passkey authentication challenge",
                ));
            }
            process_auth(
                host,
                context
                    .master_client
                    .passkey_auth_finish(p.challenge, p.auth, remote_ip),
                None,
                remote_ip,
                p.set_auth_cookie,
                context,
            )
            .await
        }
        "gate.passkey.present" => {
            let token_str = get_token_str(headers, context)?;
            Ok((
                to_value(context.master_client.passkey_present(token_str).await?)?,
                None,
            ))
        }
        "gate.passkey.delete" => {
            let token_str = get_token_str(headers, context)?;
            context.master_client.passkey_delete(token_str).await?;
            info!(ip = %remote_ip, "User deleted passkey");
            Ok(no_reply!())
        }
        "gate.invalidate" => {
            let token_str = get_token_str(headers, context)?;
            context.master_client.invalidate(token_str).await?;
            warn!(ip = %remote_ip, "User invalidated tokens");
            Ok((Value::Null, logout_hmap!()))
        }
        "gate.issue_aud_token" => {
            #[derive(Deserialize)]
            struct Params {
                app: String,
                exp: u64,
            }
            let token_str = get_token_str(headers, context)?;
            let p: Params = serde_json::from_value(params)?;
            let app = context
                .app_map
                .get_by_name(&p.app)
                .await
                .ok_or_else(|| Error::failed(format!("App '{}' not found", p.app)))?;
            let aud_token_str = context
                .master_client
                .issue_apps_token(
                    &token_str,
                    app.hosts.iter().map(String::as_str).collect(),
                    p.exp,
                )
                .await?;
            info!(ip = %remote_ip, app = %p.app, "Issued audience token for app");
            Ok((serde_json::json!({ "aud_token": aud_token_str }), None))
        }
        "gate.set_password" => {
            #[derive(Deserialize)]
            struct Params {
                old_password: Zeroizing<String>,
                new_password: Zeroizing<String>,
            }
            let token_str = get_token_str(headers, context)?;
            let p: Params = serde_json::from_value(params)?;
            context
                .master_client
                .change_password(token_str, p.old_password, p.new_password, remote_ip)
                .await?;
            info!(ip = %remote_ip, "User changed password");
            Ok(no_reply!())
        }
        "gate.authenticate" => {
            #[derive(Deserialize)]
            struct Params {
                #[serde(flatten)]
                auth: AuthPayload,
                #[serde(default)]
                set_auth_cookie: SetAuthCookie,
            }
            let p: Params = serde_json::from_value(params)?;
            if !p.auth.valid() {
                synth_sleep().await;
                warn!(ip = %remote_ip, "Invalid authentication payload");
                return Err(Error::invalid_data("Invalid authentication payload"));
            }
            process_auth(
                host,
                context.master_client.authenticate(&p.auth, remote_ip),
                Some(&p.auth),
                remote_ip,
                p.set_auth_cookie,
                context,
            )
            .await
        }
        _ => {
            synth_sleep().await;
            Err(Error::RpcMethodNotFound(format!(
                "RPC method '{}' not found",
                method
            )))
        }
    }
}

pub(crate) async fn handle_admin(
    http_request: Request<Incoming>,
    remote_ip: IpAddr,
    context: &Context,
) -> HByteResult {
    let Some(ref admin_allow) = context.admin_allow_remote else {
        error!(ip = %remote_ip, "Admin access not allowed");
        return Ok(http_response(403, "Admin access not allowed").await);
    };
    if !admin_allow.verify_ip(remote_ip) {
        error!(ip = %remote_ip, "Admin access from disallowed IP");
        return Ok(http_response(403, "Admin access not allowed").await);
    }
    if http_request.method() != http::Method::POST {
        error!(ip = %remote_ip, method = %http_request.method(), "Invalid RPC request method");
        return Ok(http_response(405, "Method Not Allowed").await);
    }
    let req = match TransferredRequest::create(http_request, remote_ip).await {
        Ok(r) => r,
        Err(e) => {
            error!(ip = %remote_ip, error = %e, "Failed to create transferred admin request");
            return Ok(http_response(400, "Bad Request").await);
        }
    };
    match context.master_client.admin(req, remote_ip).await {
        Ok(response) => Ok(http_ser_json_response(response).await),
        Err(e) => {
            if matches!(e, Error::AccessDenied(_)) {
                warn!(ip = %remote_ip, error = %e, "Admin access denied");
                return Ok(http_response(403, "Admin API Access Denied").await);
            }
            error!(ip = %remote_ip, error = %e, "Admin request failed");
            Ok(http_response(500, "Internal Server Error").await)
        }
    }
}

pub(crate) async fn handle(
    http_request: Request<Incoming>,
    remote_ip: IpAddr,
    context: &Context,
) -> HByteResult {
    let host = resolve_host(&http_request).unwrap_or_default();
    let (parts, body) = http_request.into_parts();
    if parts.method == http::Method::OPTIONS {
        #[cfg(debug_assertions)]
        return Ok(Response::builder()
            .status(204)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Content-Type")
            .body(
                Full::from(vec![])
                    .map_err(|e| Box::new(e) as StdError)
                    .boxed(),
            )
            .unwrap());
        #[cfg(not(debug_assertions))]
        return Ok(http_response(204, "").await);
    }
    if parts.method != http::Method::POST {
        error!(ip = %remote_ip, method = %parts.method, "Invalid RPC request method");
        return Ok(http_response(405, "Method Not Allowed").await);
    }
    let Ok(body_collected) = body.collect().await else {
        error!(ip = %remote_ip, "Failed to read RPC request body");
        return Ok(http_response(400, "Bad Request").await);
    };
    let bytes = body_collected.to_bytes();
    let rpc_request = match RpcRequest::try_from(&bytes[..]) {
        Ok(r) => r,
        Err(e) => {
            error!(ip = %remote_ip, error = %e, "Failed to parse RPC request");
            let response = RpcResponse::new_error(Value::Null, e);
            return Ok(response.into_hyper_resonse(None).await);
        }
    };
    let RpcRequest {
        id, method, params, ..
    } = rpc_request;
    match rpc_regular(&host, &parts.headers, &method, params, remote_ip, context).await {
        Ok((response, hmap)) => {
            info!(ip = %remote_ip, method = %method, "RPC method call succeeded");
            Ok(RpcResponse::new_result(id, response)
                .into_hyper_resonse(hmap)
                .await)
        }
        Err(e) => {
            error!(ip = %remote_ip, method = %method, error = %e, "RPC method call failed");
            let response = RpcResponse::new_error(id, e);
            Ok(response.into_hyper_resonse(None).await)
        }
    }
}
