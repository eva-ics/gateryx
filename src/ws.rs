use std::{net::IpAddr, sync::Arc, time::Duration};

use atomic_timer::AtomicTimer;
use bma_ts::Timestamp;
use futures::{SinkExt as _, StreamExt as _};
use http_body_util::BodyExt as _;
use hyper::{HeaderMap, Request, Response, Uri, body::Incoming, upgrade::Upgraded};
use hyper_tungstenite::upgrade;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::WebSocketConfig};
use tracing::{debug, error, info, warn};

use crate::{
    ByteResponse, StdError,
    app::Config as AppConfig,
    gate::worker::Context,
    serve::TaskPool,
    tokens::ClaimsView,
    util::{http_internal_server_error, http_response},
};

const TOKEN_CHECK_MAX_TIME: Duration = Duration::from_secs(5);

fn default_websocket_read_buffer_size() -> usize {
    1024 * 16
}

fn default_websocket_write_buffer_size() -> usize {
    1024 * 16
}

fn default_websocket_max_message_size() -> usize {
    1024 * 1024 * 4
}

fn default_websocket_max_frame_size() -> usize {
    1024 * 1024
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_websocket_read_buffer_size")]
    pub read_buffer: usize,
    #[serde(default = "default_websocket_write_buffer_size")]
    pub write_buffer: usize,
    #[serde(default = "default_websocket_max_message_size")]
    pub max_message_size: usize,
    #[serde(default = "default_websocket_max_frame_size")]
    pub max_frame_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            read_buffer: default_websocket_read_buffer_size(),
            write_buffer: default_websocket_write_buffer_size(),
            max_message_size: default_websocket_max_message_size(),
            max_frame_size: default_websocket_max_frame_size(),
        }
    }
}

impl From<Config> for tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    fn from(c: Config) -> Self {
        let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        config.read_buffer_size = c.read_buffer;
        config.write_buffer_size = c.write_buffer;
        config.max_write_buffer_size = c.write_buffer * 2;
        config.max_message_size = Some(c.max_message_size);
        config.max_frame_size = Some(c.max_frame_size);
        config
    }
}

struct StreamChecker {
    stream_name: String,
    cv: Option<ClaimsView>,
    ip: IpAddr,
    context: Context,
    timer: AtomicTimer,
}

impl StreamChecker {
    fn new(stream_name: &str, ip: IpAddr, cv: Option<ClaimsView>, context: Context) -> Self {
        Self {
            stream_name: stream_name.to_string(),
            cv,
            ip,
            context,
            timer: AtomicTimer::new(TOKEN_CHECK_MAX_TIME),
        }
    }
    async fn check(&self) -> bool {
        if !self.timer.reset_if_expired() {
            return true;
        }
        let Some(ref cv) = self.cv else {
            return true;
        };
        if Timestamp::now() > cv.exp {
            debug!(ip = %self.ip, user = %cv.sub,
                    stream=self.stream_name, "Token expired, closing WebSocket server stream");
            return false;
        }
        match self.context.master_client.is_token_revoked(cv).await {
            Ok(true) => {
                debug!(ip = %self.ip, user = %cv.sub,
                    stream=self.stream_name,
                                "Token revoked, closing WebSocket server stream");
                return false;
            }
            Ok(false) => {}
            Err(e) => {
                debug!(ip = %self.ip, user = %cv.sub,
                    stream=self.stream_name,
                                error = %e, "Failed to check token revocation, closing WebSocket stream");
                return false;
            }
        }
        true
    }
}

async fn init_ws(
    ws_request: Request<()>,
    tcp_stream: TcpStream,
    app: &AppConfig,
    context: &Context,
) -> std::result::Result<
    WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    let ws_config: WebSocketConfig = app
        .websocket
        .as_ref()
        .map_or_else(|| context.websocket_config.clone(), Clone::clone)
        .into();
    if app.skip_remote_tls_verify {
        let Some(ref dangerous_tls_config) = context.dangerous_tls_config else {
            error!("dangerous TLS config not available for skipping websocket verification, BUG!");
            return Err(tokio_tungstenite::tungstenite::Error::Utf8(
                "dangerous TLS config not available".to_owned(),
            ));
        };
        let connector = tokio_tungstenite::Connector::Rustls(dangerous_tls_config.clone());
        tokio_tungstenite::client_async_tls_with_config(
            ws_request,
            tcp_stream,
            Some(ws_config),
            Some(connector),
        )
        .await
        .map(|(ws_stream, _)| ws_stream)
    } else {
        tokio_tungstenite::client_async_tls_with_config(
            ws_request,
            tcp_stream,
            Some(ws_config),
            None,
        )
        .await
        .map(|(ws_stream, _)| ws_stream)
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn proxy_ws_with_headers(
    client_ws: WebSocketStream<TokioIo<Upgraded>>,
    claims: Option<ClaimsView>,
    remote_ip: IpAddr,
    uri: Uri,
    headers: HeaderMap,
    remote_uri: Uri,
    app: Arc<AppConfig>,
    context: Context,
) -> tokio::io::Result<()> {
    let (scheme, port) = if remote_uri.scheme_str() == Some("https") {
        ("wss", remote_uri.port_u16().unwrap_or(443))
    } else {
        ("ws", remote_uri.port_u16().unwrap_or(80))
    };
    let Some(authority) = remote_uri.authority() else {
        error!(ip = %remote_ip, "Remote URI missing authority");
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidInput,
            "Remote URI missing authority",
        ));
    };
    let upstream_uri = format!(
        "{}://{}{}",
        scheme,
        authority.host(),
        uri.path_and_query().map_or("", |pq| pq.as_str())
    );
    info!(ip=%remote_ip, upstream_uri, "Proxying WebSocket to upstream",);
    if app.skip_remote_tls_verify {
        warn!(ip = %remote_ip, upstream_uri, "Using dangerous TLS config to skip remote TLS verification");
    }

    let mut req_builder = Request::builder().method("GET").uri(upstream_uri);

    for (key, value) in &headers {
        req_builder = req_builder.header(key, value);
    }

    let Ok(ws_request) = req_builder.body(()) else {
        error!(ip = %remote_ip, "Failed to build WebSocket request");
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidInput,
            "Failed to build WebSocket request",
        ));
    };

    let tcp_stream = TcpStream::connect((authority.host(), port)).await?;
    //tcp_stream.set_nodelay(true)?;

    debug!(ip = %remote_ip, ws_request = ?ws_request, "Requesting upstream WebSocket server");

    let timeout = Duration::from(app.timeout);

    let server_ws = match tokio::time::timeout(
        timeout,
        init_ws(ws_request, tcp_stream, &app, &context),
    )
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            error!(
                ip = %remote_ip,
                error = %e, "Failed to connect to upstream WebSocket server");
            return Err(tokio::io::Error::other(e));
        }
        Err(e) => {
            error!(
                ip = %remote_ip,
                error = %e, "Timeout connecting to upstream WebSocket server");
            return Err(tokio::io::Error::new(tokio::io::ErrorKind::TimedOut, e));
        }
    };

    debug!(ip = %remote_ip, "Connected to upstream WebSocket server");

    let (mut client_sink, mut client_stream) = client_ws.split();
    let (mut server_sink, mut server_stream) = server_ws.split();

    let client_to_server_checker = StreamChecker::new(
        "client-to-server",
        remote_ip,
        claims.clone(),
        context.clone(),
    );

    let server_to_client_checker = StreamChecker::new(
        "server-to-client",
        remote_ip,
        claims.clone(),
        context.clone(),
    );

    let client_to_server = async move {
        while let Some(msg) = client_stream.next().await {
            if !client_to_server_checker.check().await {
                break;
            }
            if let Ok(m) = msg {
                debug!(ip = %remote_ip, msg = ?m, "ws send");
                match tokio::time::timeout(timeout, server_sink.send(m)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        debug!(
                            ip = %remote_ip,
                            error = %e, "Failed to send message to upstream WebSocket server");
                        break;
                    }
                    Err(e) => {
                        debug!(
                            ip = %remote_ip,
                            error = %e, "Timeout sending message to upstream WebSocket server");
                        break;
                    }
                }
            } else {
                break;
            }
        }
    };

    let server_to_client = async move {
        while let Some(msg) = server_stream.next().await {
            if !server_to_client_checker.check().await {
                break;
            }
            if let Ok(m) = msg {
                debug!(ip = %remote_ip, msg = ?m, "ws recv");
                match tokio::time::timeout(timeout, client_sink.send(m)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        debug!(
                            ip = %remote_ip,
                            error = %e, "Failed to send message to client WebSocket");
                        break;
                    }
                    Err(e) => {
                        debug!(
                            ip = %remote_ip,
                            error = %e, "Timeout sending message to client WebSocket");
                        break;
                    }
                }
            } else {
                break;
            }
        }
    };

    tokio::select! {
        () = client_to_server => {},
        () = server_to_client => {},
    }

    debug!(ip = %remote_ip, "WebSocket proxying ended");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle(
    req: Request<Incoming>,
    claims: Option<ClaimsView>,
    remote_ip: IpAddr,
    remote_uri: Uri,
    app: Arc<AppConfig>,
    context: Context,
    worker_pool: TaskPool,
) -> ByteResponse {
    if hyper_tungstenite::is_upgrade_request(&req) {
        let timeout = Duration::from(app.timeout);
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        // Extract upgrade
        let Ok((response, websocket)) = upgrade(req, None) else {
            error!(
                ip = %remote_ip,
                "Failed to extract WebSocket upgrade");
            return http_internal_server_error().await;
        };

        // Spawn a task to handle it
        if let Err(e) = Box::pin(worker_pool.0.spawn(async move {
            match tokio::time::timeout(timeout, websocket).await {
                Ok(Ok(ws)) => {
                    if let Err(e) = proxy_ws_with_headers(
                        ws, claims, remote_ip, uri, headers, remote_uri, app, context,
                    )
                    .await
                    {
                        error!(
                            ip = %remote_ip,
                            error = %e, "WebSocket proxy error");
                    }
                }
                Ok(Err(e)) => {
                    error!(
                        ip = %remote_ip,
                        error = %e, "WebSocket upgrade error");
                }
                Err(e) => {
                    error!(
                        ip = %remote_ip,
                        error = %e, "WebSocket upgrade timeout");
                }
            }
        }))
        .await
        {
            error!(
                ip = %remote_ip,
                error = %e, "Failed to spawn WebSocket handling task");
            return http_response(500, "Failed to spawn WebSocket handling task").await;
        }

        let (parts, body) = response.into_parts();
        Response::from_parts(parts, body.map_err(|e| Box::new(e) as StdError).boxed())
    } else {
        error!(
        ip = %remote_ip,
        "Not a WebSocket upgrade request");
        http_response(400, "Not a WebSocket upgrade request").await
    }
}
