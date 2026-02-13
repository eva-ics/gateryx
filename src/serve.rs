use std::{collections::BTreeSet, io::Cursor, mem, net::IpAddr, sync::Arc, time::Duration};

use http::{HeaderValue, Method, header, uri::PathAndQuery};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response, Uri,
    body::{Body as _, Bytes, Incoming},
    rt::Executor,
    service::service_fn,
};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioIo, server::conn::auto::Builder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

const URI_AUTH: &str = "/.gateryx/auth";
const URI_AUTH_PREFIX: &str = "/.gateryx/auth/";
const URI_AUTH_CAPTCHA: &str = "/.gateryx/auth/captcha";

//const CONNECTION_CLOSE: HeaderValue = HeaderValue::from_static("close");
const CONNECTION_KEEP_ALIVE: HeaderValue = HeaderValue::from_static("keep-alive");

const ALLOWED_STRICT_WS_HEADERS: &[&str] = &[
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "host",
    "connection",
    "upgrade",
    "cookie",
    "origin",
];

type UpstreamClient =
    Arc<Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Incoming>>;

use crate::{
    ByteResponse, DEVELOPER_USER, HByteResult, ListenerConfig, Result, StdError,
    app::Config as AppConfig,
    bp, compress,
    gate::worker::Context,
    logger::LogRecord,
    rpc::{self, URI_RPC, URI_RPC_ADMIN},
    tokens,
    util::{
        self, AllowRemoteAny, downgrade_to_http11, http_internal_server_error, http_response,
        http_response_forbidden, resolve_host, synth_sleep,
    },
    vapp::VirtualApp,
    ws,
};

pub struct TaskPool(pub Arc<tokio_task_pool::Pool>);

impl<F> Executor<F> for TaskPool
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        let pool = self.0.clone();
        if let Err(e) = pool.try_spawn(future) {
            error!(error = %e, "Failed to execute task in pool");
        }
    }
}

impl Clone for TaskPool {
    fn clone(&self) -> Self {
        TaskPool(self.0.clone())
    }
}

async fn auth_file(mut request: Request<Full<Bytes>>, context: &Context) -> ByteResponse {
    let Some(ref auth_www_static) = context.auth_www_static else {
        return http_response(404, "Authentication not configured").await;
    };
    let relative_uri_str = request
        .uri()
        .path_and_query()
        .unwrap()
        .to_string()
        .trim_start_matches(URI_AUTH)
        .to_owned();
    *request.uri_mut() = Uri::try_from(relative_uri_str).unwrap();
    match auth_www_static.clone().serve(request).await {
        Ok(v) => {
            let (parts, body) = v.into_parts();
            Response::from_parts(parts, body.map_err(|e| Box::new(e) as StdError).boxed())
        }
        Err(e) => {
            error!(error = %e, "Failed to serve auth static file");
            http_internal_server_error().await
        }
    }
}

enum ServeApp {
    App(Arc<AppConfig>),
    VirtualApp(Arc<dyn VirtualApp>),
}

impl ServeApp {
    fn allow_tokens(&self) -> bool {
        match self {
            ServeApp::App(app) => app.allow_tokens,
            ServeApp::VirtualApp(_) => false,
        }
    }
    fn use_auth(&self) -> bool {
        match self {
            ServeApp::App(app) => app.use_auth,
            ServeApp::VirtualApp(_) => true,
        }
    }
    fn hosts(&self) -> Vec<&str> {
        match self {
            ServeApp::App(app) => app.hosts.iter().map(String::as_str).collect(),
            ServeApp::VirtualApp(_) => vec![],
        }
    }
    fn verify_ip(&self, ip: IpAddr) -> bool {
        match self {
            ServeApp::App(app) => app.allow.verify_ip(ip),
            ServeApp::VirtualApp(vapp) => vapp.verify_ip(ip),
        }
    }
    fn groups(&self) -> &[String] {
        match self {
            ServeApp::App(app) => &app.allow_groups,
            ServeApp::VirtualApp(_) => &[],
        }
    }
    fn api_allowed(&self) -> bool {
        match self {
            ServeApp::App(app) => app.gateryx_api,
            ServeApp::VirtualApp(_) => true,
        }
    }
    async fn resolve_force(context: &Context, app_name: &str) -> Option<Self> {
        if let Some(v) = context.virtual_app_map.get_by_id(app_name) {
            Some(ServeApp::VirtualApp(v))
        } else {
            context
                .app_map
                .get_by_name(app_name)
                .await
                .map(ServeApp::App)
        }
    }
    async fn resolve(
        context: &Context,
        host: &str,
        force_app: Option<Arc<String>>,
    ) -> Option<Self> {
        if let Some(force_app) = force_app {
            return Self::resolve_force(context, &force_app).await;
        }
        if let Some(v) = context.virtual_app_map.get_by_host(host) {
            Some(ServeApp::VirtualApp(v))
        } else {
            context.app_map.get_by_host(host).await.map(ServeApp::App)
        }
    }
}

fn insert_jwt_assertion(
    jwt_token: Option<&str>,
    request: &mut Request<Incoming>,
    context: &Context,
) {
    let Some(token) = jwt_token else {
        return;
    };
    let header_value: HeaderValue = match token.parse() {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, token = %token, "Invalid JWT header value");
            return;
        }
    };
    request
        .headers_mut()
        .insert(&context.headers.jwt_assertion, header_value);
}

async fn serve_captcha(
    request: Request<Incoming>,
    remote_ip: IpAddr,
    context: &Context,
) -> ByteResponse {
    synth_sleep().await;
    let Ok(uuid) = Uuid::parse_str(request.uri().query().unwrap_or("")) else {
        error!(ip = %remote_ip, "Invalid captcha id");
        return http_response(400, "Bad Request").await;
    };
    match context
        .master_client
        .get_captcha_secret(uuid, remote_ip)
        .await
    {
        Ok(Some(v)) => {
            let Some(png) = bp::get_captcha_png(&v) else {
                error!(ip = %remote_ip, id = %uuid, "Captcha PNG generation failed");
                return http_internal_server_error().await;
            };
            Response::builder()
                .status(200)
                .header("Content-Type", "image/png")
                .body(Full::from(png).map_err(|e| Box::new(e) as StdError).boxed())
                .unwrap()
        }
        Ok(None) => {
            error!(ip = %remote_ip, id = %uuid, "Captcha not found");
            http_response(404, "Captcha not found").await
        }
        Err(e) => {
            error!(ip = %remote_ip, id = %uuid, error = %e, "Failed to get captcha");
            http_internal_server_error().await
        }
    }
}

async fn serve_auth(
    request: Request<Incoming>,
    remote_ip: IpAddr,
    context: &Context,
) -> ByteResponse {
    let (parts, body) = request.into_parts();
    let bytes = match body.collect().await {
        Ok(b) => b,
        Err(e) => {
            error!(ip = %remote_ip, error = %e, "Failed to read auth request body");
            return http_response(400, "Bad Request").await;
        }
    };
    auth_file(
        Request::from_parts(parts, Full::from(bytes.to_bytes())),
        context,
    )
    .await
}

fn auth_redirect(
    host: &str,
    original_host: &str,
    uri: &Uri,
    with_tls: bool,
    remote_ip: IpAddr,
) -> ByteResponse {
    let mut s = format!(
        "{}://{}{}",
        if with_tls { "https" } else { "http" },
        original_host,
        uri.path()
    );
    if let Some(q) = uri.query() {
        s.push('?');
        s.push_str(q);
    }
    let encoded = urlencoding::encode(&s);
    let redirect_uri = format!(
        "{}://{}{}?r={}",
        if with_tls { "https" } else { "http" },
        host,
        URI_AUTH_PREFIX,
        encoded
    );
    debug!(ip = %remote_ip, %redirect_uri, "Redirecting to primary host for authentication");
    Response::builder()
        .status(302)
        .header("Location", redirect_uri)
        .body(
            Full::from(vec![])
                .map_err(|e| Box::new(e) as StdError)
                .boxed(),
        )
        .unwrap()
}

async fn deny_robots() -> ByteResponse {
    let body = "User-agent: *\nDisallow: /\n";
    synth_sleep().await;
    Response::builder()
        .status(200)
        .header("Content-Type", "text/plain")
        .body(
            Full::from(body)
                .map_err(|e| Box::new(e) as StdError)
                .boxed(),
        )
        .unwrap()
}

async fn invalid_token_result(
    remote_ip: IpAddr,
    original_host: &str,
    request: &Request<Incoming>,
    allow_tokens: bool,
    with_tls: bool,
    context: &Context,
) -> ByteResponse {
    debug!(ip = %remote_ip, "No valid token");
    synth_sleep().await;
    // web browser clients
    if request
        .headers()
        .get("accept")
        .is_some_and(|v| v.to_str().ok().is_some_and(|s| s.contains("text/html")))
    {
        let primary_host = context
            .primary_host
            .as_ref()
            .filter(|_| {
                context
                    .token_domain_dot_prefixed
                    .as_ref()
                    .is_some_and(|v| original_host.ends_with(v))
            })
            .map(String::as_str);
        return auth_redirect(
            primary_host.unwrap_or(original_host),
            original_host,
            request.uri(),
            with_tls,
            remote_ip,
        );
    }
    if allow_tokens {
        let user_agent = request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok());
        // return basic auth for git and similar clients
        if user_agent.is_some_and(|ua| context.reply_401_to_user_agents.matches(ua)) {
            return Response::builder()
                .status(401)
                .header(
                    "WWW-Authenticate",
                    "Basic realm=\"Gateryx\", charset=\"UTF-8\"",
                )
                .body(
                    Full::from(vec![])
                        .map_err(|e| Box::new(e) as StdError)
                        .boxed(),
                )
                .unwrap();
        }
        // return 401 with WWW-Authenticate header
        return Response::builder()
            .status(401)
            .header(
                "WWW-Authenticate",
                "Bearer realm=\"Gateryx\", error=\"invalid_token\"",
            )
            .body(
                Full::from(vec![])
                    .map_err(|e| Box::new(e) as StdError)
                    .boxed(),
            )
            .unwrap();
    }
    http_response_forbidden().await
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_http_request(
    mut request: Request<Incoming>,
    remote_ip: IpAddr,
    mut upstream_client: UpstreamClient,
    dangerous_upstream_client: Option<UpstreamClient>,
    context: &Context,
    worker_pool: TaskPool,
    with_tls: bool,
    http2: bool,
    allow: AllowRemoteAny,
    force_app: Option<Arc<String>>,
    token_sub: &mut Option<String>,
) -> HByteResult {
    debug!(ip = %remote_ip, request = ?request);
    if !allow.verify_ip(remote_ip) {
        warn!(ip = %remote_ip, "Remote IP not allowed");
        synth_sleep().await;
        return Ok(http_response_forbidden().await);
    }
    if let Some(ref extractor) = context.meta_extractor {
        let meta = extractor.extract(&request, remote_ip);
        if let Some(ref logger) = context.meta_logger {
            if let Err(e) = logger.send(meta).await {
                warn!(ip = %remote_ip, error = %e, "Failed to send request meta");
            }
        } else {
            error!("Meta logger not configured, but extractor is present! (BUG)");
        }
    }
    let size = request.body().size_hint().upper().unwrap_or_default();
    if context.max_body_size.is_some_and(|max| size > max) {
        error!(ip = %remote_ip, size, max = context.max_body_size, "Request body too large");
        return Ok(http_response(413, "Payload Too Large").await);
    }
    let Some(original_host) = resolve_host(&request) else {
        return Ok(http_response(400, "Bad Request").await);
    };
    info!(
        ip = %remote_ip,
        host = %original_host,
        uri = %request.uri(),
        method = %request.method(),
        size = size,
        "Request"
    );
    let Some(app) = ServeApp::resolve(context, &original_host, force_app).await else {
        error!(ip = %remote_ip, host = %original_host, "No app configured for host");
        return Ok(http_response(404, "Not Found").await);
    };
    if !app.verify_ip(remote_ip) {
        warn!(ip = %remote_ip, host = %original_host, "Remote IP not allowed for app");
        synth_sleep().await;
        return Ok(http_response_forbidden().await);
    }
    if request.uri().path() == "/robots.txt" {
        return Ok(deny_robots().await);
    }

    if app.api_allowed() {
        if request.uri().path() == URI_RPC {
            if request.method() != Method::POST {
                return Ok(http_response(405, "Method Not Allowed").await);
            }
            return rpc::handle(request, remote_ip, context).await;
        }
        if request.uri().path() == URI_RPC_ADMIN {
            if request.method() != Method::POST {
                return Ok(http_response(405, "Method Not Allowed").await);
            }
            return rpc::handle_admin(request, remote_ip, context).await;
        }
        if request.uri().path() == URI_AUTH_CAPTCHA && request.method() == Method::GET {
            return Ok(serve_captcha(request, remote_ip, context).await);
        }
        if request.uri().path().starts_with(URI_AUTH_PREFIX) {
            return Ok(serve_auth(request, remote_ip, context).await);
        }
    }
    if let ServeApp::VirtualApp(ref v) = app
        && let Some(res) = v
            .serve_insecure(&request, remote_ip, with_tls, context)
            .await?
    {
        return Ok(res);
    }
    let mut claims = None;
    let mut jwt_token = None;
    // authenticate if required
    if app.use_auth() {
        if context.development {
            *token_sub = Some(DEVELOPER_USER.to_string());
        } else {
            macro_rules! invalid_token {
                () => {
                    error!(ip = %remote_ip, host = %original_host, "Invalid or missing token");
                    return Ok(invalid_token_result(
                        remote_ip,
                        &original_host,
                        &request,
                        app.allow_tokens(),
                        with_tls,
                        context,
                    )
                    .await);
                };
            }
            let Some(token_str) = tokens::extract_token_from_headers(
                request.headers_mut(),
                app.allow_tokens(),
                context,
            )
            .map(Zeroizing::new) else {
                invalid_token!();
            };
            match context
                .master_client
                .validate_token(&token_str, app.allow_tokens())
                .await
            {
                Ok(tokens::ValidationResponse::Valid { token_s, claims: c }) => {
                    debug!(ip = %remote_ip, claims = ?c, "Token validated");
                    if c.apps.is_empty() {
                        // user token
                        let groups = app.groups();
                        if !groups.is_empty() && !c.groups.iter().any(|g| groups.contains(g)) {
                            error!(ip = %remote_ip, host = %original_host, user = %c.sub,
                                    user_groups = ?c.groups, app_groups = ?groups,
                                "Token groups do not match app allowed groups");
                            synth_sleep().await;
                            return Ok(http_response_forbidden().await);
                        }
                    } else {
                        // app token
                        let hosts = app.hosts();
                        if hosts.is_empty() {
                            error!(ip = %remote_ip,
                                host = %original_host, "Attempting to access a virtual app with an app-restricted token");
                            invalid_token!();
                        } // system app
                        if !c.apps.iter().any(|a| hosts.contains(&a.as_str())) {
                            error!(ip = %remote_ip, host = %original_host, aud = ?c.apps,
                                    host = %original_host, "Token audience does not match app hosts");
                            invalid_token!();
                        }
                    }
                    let sub = c.sub.clone();
                    debug!(ip = %remote_ip, user = %sub, "Valid token");
                    *token_sub = Some(sub);
                    claims = Some(c);
                    jwt_token = Some(token_s);
                }
                Ok(tokens::ValidationResponse::Invalid) => {
                    invalid_token!();
                }
                Err(e) => {
                    error!(ip = %remote_ip, error = %e, "Failed to validate token");
                    return Ok(http_internal_server_error().await);
                }
            }
        }
    }
    let app = match app {
        ServeApp::App(a) => a,
        ServeApp::VirtualApp(v) => {
            return v
                .serve_authenticated(request, remote_ip, with_tls, claims.as_ref(), context)
                .await;
        }
    };
    if app.skip_remote_tls_verify {
        upstream_client = if let Some(dangerous) = dangerous_upstream_client {
            debug!(ip = %remote_ip, host = %original_host, "Using dangerous TLS config to skip remote TLS verification");
            dangerous
        } else {
            error!(
                "Dangerous TLS config not available for app that skips remote TLS verification, BUG!"
            );
            return Ok(http_internal_server_error().await);
        };
    }
    let app_timeout = Duration::from(app.timeout);
    let Ok(remote_uri) = Uri::try_from(&app.remote) else {
        error!(ip = %remote_ip, host = %original_host, remote = %app.remote, "Invalid remote URI");
        return Ok(http_response(500, "Invalid remote URI").await);
    };
    let Some(scheme) = remote_uri.scheme_str() else {
        error!(ip = %remote_ip, host = %original_host, remote = %app.remote, "Remote URI missing scheme");
        return Ok(http_response(500, "Remote URI missing scheme").await);
    };
    let Some(authority) = remote_uri.authority() else {
        error!(ip = %remote_ip, host = %original_host, remote = %app.remote, "Remote URI missing authority");
        return Ok(http_response(500, "Remote URI missing authority").await);
    };
    let Ok(remote_uri) = Uri::builder()
        .scheme(scheme)
        .authority(authority.clone())
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map_or("/", PathAndQuery::as_str),
        )
        .build()
    else {
        error!(ip = %remote_ip, host = %original_host, remote = %app.remote, "Failed to build remote URI");
        return Ok(http_response(500, "Failed to build remote URI").await);
    };
    // replace host header with authority
    request
        .headers_mut()
        .insert("host", authority.as_str().parse().unwrap());
    request.headers_mut().insert(
        "origin",
        format!("{}://{}", scheme, authority.as_str())
            .parse()
            .unwrap(),
    );
    let is_websocket = request
        .headers()
        .get("upgrade")
        .is_some_and(|v| v == "websocket");
    if app.client.insert_gateryx_headers()
        && (!is_websocket || app.websocket.as_ref().is_none_or(|w| !w.strict))
    {
        request.headers_mut().insert(
            &context.headers.real_ip,
            remote_ip.to_string().parse().unwrap(),
        );
        if let Some(sub) = token_sub
            && let Ok(s) = sub.parse()
        {
            request.headers_mut().insert(&context.headers.user, s);
        }
        insert_jwt_assertion(jwt_token.as_deref(), &mut request, context);
    }
    if is_websocket {
        if app.websocket.as_ref().is_some_and(|w| w.strict) {
            downgrade_to_http11(&mut request, false);
            let (mut parts, body) = request.into_parts();
            let mut headers = http::HeaderMap::new();
            for h in ALLOWED_STRICT_WS_HEADERS {
                if let Some(v) = parts.headers.remove(*h) {
                    headers.insert(*h, v);
                }
            }
            parts.headers = headers;
            request = Request::from_parts(parts, body);
        }
        let response = ws::handle(
            request,
            claims,
            remote_ip,
            remote_uri,
            app.clone(),
            context.clone(),
            worker_pool,
        )
        .await;
        return Ok(response);
    }
    let (mut parts, body) = request.into_parts();
    parts.uri = remote_uri.clone();
    let mut request = Request::from_parts(parts, body);
    let keep_alive = request
        .headers()
        .get(header::CONNECTION)
        .is_some_and(|v| v == "keep-alive");
    // get all accept-encoding headers into a set
    let accept_encodings: BTreeSet<String> = if app.compress {
        request
            .headers()
            .get_all(header::ACCEPT_ENCODING)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(',').map(|s| s.trim().to_lowercase()))
            .collect()
    } else {
        <_>::default()
    };
    match app.client {
        crate::app::AppClientKind::Http0 => {
            downgrade_to_http11(&mut request, false);
            // remove unsafe http/1.1 headers
            request.headers_mut().remove(header::ACCEPT_ENCODING);
            request
                .headers_mut()
                .insert(header::CONNECTION, CONNECTION_KEEP_ALIVE.clone());
        }
        crate::app::AppClientKind::Http1 => {
            if http2 {
                downgrade_to_http11(&mut request, true);
            }
        }
        crate::app::AppClientKind::Http2 => {}
    }
    debug!(ip = %remote_ip, request=?request, "Forwarding request to upstream");
    let res = match tokio::time::timeout(app_timeout, upstream_client.request(request)).await {
        Ok(Ok(v)) => {
            // convert body to boxed body, keep headers and status code
            let (mut parts, body) = v.into_parts();
            parts
                .headers
                .append(&context.headers.via, "Gateryx".parse().unwrap());
            if http2 {
                parts.headers.remove(header::CONNECTION);
            } else if keep_alive {
                // preserve keep-alive for http/1.1 clients
                parts
                    .headers
                    .insert(header::CONNECTION, CONNECTION_KEEP_ALIVE.clone());
            }
            // rewrite location header with ME
            util::rewrite_location_header(&mut parts.headers, &original_host, with_tls);
            let boxed_body =
                compress::process_body(&accept_encodings, &remote_uri, &mut parts.headers, body);
            Response::from_parts(parts, boxed_body)
        }
        Ok(Err(e)) => {
            // return http 500 Internal Server Error
            error!(error = %e, "Failed to process request");
            http_response(500, "Gateway failure").await
        }
        Err(e) => {
            error!(error = %e, "Gateway timeout");
            http_response(504, "Gateway timeout").await
        }
    };
    Ok(res)
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_stream<S>(
    io: TokioIo<S>,
    ip: IpAddr,
    worker_pool: TaskPool,
    context: Context,
    with_tls: bool,
    http2: bool,
    allow: AllowRemoteAny,
    force_app: Option<Arc<String>>,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let development = context.development;
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(context.tls_config.as_ref().clone())
        .https_or_http()
        .enable_all_versions()
        .build();
    let upstream_client = Arc::new(
        Client::builder(worker_pool.clone())
            .pool_idle_timeout(context.timeout)
            .http1_title_case_headers(true)
            .build(connector),
    );
    let dangerous_upstream_client: Option<UpstreamClient> =
        context.dangerous_tls_config.as_ref().map(|cfg| {
            let dangerous_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(cfg.as_ref().clone())
                .https_or_http()
                .enable_all_versions()
                .build();
            Arc::new(
                Client::builder(worker_pool.clone())
                    .pool_idle_timeout(context.timeout)
                    .http1_title_case_headers(true)
                    .build(dangerous_connector),
            )
        });
    if let Err(e) = Builder::new(worker_pool.clone())
        .serve_connection_with_upgrades(
            io,
            service_fn(|req: Request<hyper::body::Incoming>| {
                let upstream_client = upstream_client.clone();
                let dangerous_upstream_client = dangerous_upstream_client.clone();
                let context = context.clone();
                let worker_pool = worker_pool.clone();
                let force_app = force_app.clone();
                let allow = allow.clone();
                async move {
                    let log_record = if context.http_logger.is_some() {
                        Some(LogRecord::new(ip, &req, with_tls))
                    } else {
                        None
                    };
                    let mut token_sub = None;
                    let mut res = handle_http_request(
                        req,
                        ip,
                        upstream_client,
                        dangerous_upstream_client,
                        &context,
                        worker_pool,
                        with_tls,
                        http2,
                        allow,
                        force_app,
                        &mut token_sub,
                    )
                    .await;
                    debug!(ip = ?ip, response = ?res);

                    if let Some(ref extractor) = context.meta_extractor
                        && let Ok(ref response) = res
                    {
                        extractor.analyze(ip, response.status().as_u16());
                    }

                    if let Some(mut log_record) = log_record {
                        log_record.set_size(res.as_ref().map_or(0, |r| {
                            usize::try_from(r.body().size_hint().upper().unwrap_or_default())
                                .unwrap_or(usize::MAX)
                        }));
                        if let Some(status) = res.as_ref().ok().map(|r| r.status().as_u16()) {
                            log_record.set_status(status);
                        }
                        if let Some(sub) = token_sub {
                            log_record.set_user(sub);
                        }
                        debug!("{}", log_record);
                        context
                            .http_logger
                            .as_ref()
                            .unwrap()
                            .send(log_record)
                            .await
                            .ok();
                    }
                    if development && let Ok(ref mut r) = res {
                        r.headers_mut().insert(
                            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                            "*".parse().unwrap(),
                        );
                        r.headers_mut().insert(
                            hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
                            "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap(),
                        );
                        r.headers_mut().insert(
                            hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
                            "Content-Type".parse().unwrap(),
                        );
                    }
                    res
                }
            }),
        )
        .await
    {
        let err_str = e.to_string();
        if err_str != "connection closed before message completed" {
            error!(error = %e, "Failed to serve connection");
        }
    }
}

#[allow(clippy::too_many_lines)]
pub async fn handle_listener(
    listener: TcpListener,
    config: ListenerConfig,
    context: Context,
) -> Result<()> {
    let proto = config.protocol;
    let mut http2 = false;
    let acceptor = if let Some(ref tls) = config.tls {
        let mut certs_buf: Cursor<Vec<u8>> = Cursor::new(mem::take(tls.cert_buf.lock().as_mut()));
        let certs = CertificateDer::pem_reader_iter(&mut certs_buf)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut tls_key_buf = tls.key_buf.lock();
        let key = PrivateKeyDer::from_pem_slice(&tls_key_buf)?;
        mem::take::<Zeroizing<Vec<u8>>>(&mut tls_key_buf);
        let mut tls_config = tokio_rustls::rustls::ServerConfig::builder_with_protocol_versions(
            &tls.protocols
                .iter()
                .map(|p| p.as_supported_rustls_version())
                .collect::<Vec<&rustls::SupportedProtocolVersion>>(),
        )
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        match proto {
            crate::L7Protocol::Http1 => {}
            crate::L7Protocol::Http2 => {
                tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                http2 = true;
            }
        }
        Some(TlsAcceptor::from(Arc::new(tls_config)))
    } else {
        None
    };
    let force_app = config.app.clone();
    let client_pool = Arc::new(
        tokio_task_pool::Pool::bounded(config.max_clients.into())
            .with_spawn_timeout(context.timeout),
    );
    let worker_pool = TaskPool(Arc::new(tokio_task_pool::Pool::bounded(
        config.max_workers.into(),
    )));
    let allow = config.allow.clone();
    tokio::spawn({
        let client_pool = client_pool.clone();
        let worker_pool = worker_pool.clone();
        async move {
            let mut int = tokio::time::interval(Duration::from_secs(1));
            loop {
                int.tick().await;
                let client_busy = client_pool.busy_permits().unwrap_or_default();
                let client_avail = client_pool.available_permits().unwrap_or_default();
                let worker_busy = worker_pool.0.busy_permits().unwrap_or_default();
                let worker_avail = worker_pool.0.available_permits().unwrap_or_default();
                debug!(
                    listener = ?config.bind,
                    "pools: client: {}/{}, worker: {}/{}", client_busy, client_avail, worker_busy, worker_avail
                );
            }
        }
    });
    loop {
        let (stream, client) = match listener.accept().await {
            Ok((stream, client)) => (stream, client),
            Err(e) => {
                error!(error = %e, "Failed to accept connection");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        info!(ip = %client.ip(), "Accepted connection from client");
        let worker_pool = worker_pool.clone();
        let context = context.clone();
        let allow = allow.clone();
        if let Err(e) = client_pool
            .spawn({
                let context = context.clone();
                let force_app = force_app.clone();
                async move {
                    if let Some(acceptor) = acceptor {
                        match tokio::time::timeout(context.timeout, acceptor.accept(stream)).await {
                            Ok(Ok(s)) => {
                                handle_stream(
                                    TokioIo::new(s),
                                    client.ip(),
                                    worker_pool,
                                    context,
                                    true,
                                    http2,
                                    allow,
                                    force_app,
                                )
                                .await;
                            }
                            Ok(Err(e)) => {
                                error!(ip = %client.ip(), error = %e, "TLS handshake failed");
                            }
                            Err(e) => {
                                error!(ip = %client.ip(), error = %e, "TLS handshake timeout");
                            }
                        }
                    } else {
                        handle_stream(
                            TokioIo::new(stream),
                            client.ip(),
                            worker_pool,
                            context,
                            false,
                            http2,
                            allow,
                            force_app,
                        )
                        .await;
                    }
                }
            })
            .await
        {
            error!(error = %e, "Failed to spawn client task");
        }
    }
}
