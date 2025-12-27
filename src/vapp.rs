use std::{collections::BTreeMap, net::IpAddr, path::Path, sync::Arc};

use crate::{ByteResponse, HByteResult, HResult, util::AllowRemoteAny};
use async_trait::async_trait;
use http::{Method, Request, Response};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper_staticfile::Static;
use serde::Deserialize;
use tracing::error;

#[derive(Default)]
pub struct VAppMap {
    apps_by_host: BTreeMap<String, Arc<dyn VirtualApp>>,
    apps_by_id: BTreeMap<String, Arc<dyn VirtualApp>>,
    system_hosts: Option<Vec<String>>,
}

impl VAppMap {
    pub fn add<HOSTS, H, S>(&mut self, hosts: HOSTS, id: S, app: Arc<dyn VirtualApp>)
    where
        HOSTS: Clone + IntoIterator<Item = H>,
        H: AsRef<str>,
        S: AsRef<str>,
    {
        if id.as_ref() == System::id() {
            let system_hosts: Vec<String> = hosts
                .clone()
                .into_iter()
                .map(|h| h.as_ref().to_string())
                .collect();
            self.system_hosts = Some(system_hosts);
        }
        for host in hosts {
            self.apps_by_host
                .insert(host.as_ref().to_string(), app.clone());
        }
        self.apps_by_id.insert(id.as_ref().to_string(), app);
    }
    pub fn get_by_host(&self, host: &str) -> Option<Arc<dyn VirtualApp>> {
        self.apps_by_host.get(host).cloned()
    }
    pub fn get_by_id(&self, id: &str) -> Option<Arc<dyn VirtualApp>> {
        self.apps_by_id.get(id).cloned()
    }
    pub fn system_hosts(&self) -> Option<&[String]> {
        self.system_hosts.as_deref()
    }
}

use crate::{
    StdError,
    gate::worker::Context,
    util::{
        http_internal_server_error, http_json_response, http_response, http_ser_json_response,
        resolve_host, synth_sleep,
    },
};

#[async_trait]
pub trait VirtualApp: Send + Sync {
    async fn serve_insecure(
        &self,
        _request: &Request<Incoming>,
        _remote_ip: IpAddr,
        _with_tls: bool,
        _context: &Context,
    ) -> HResult<Option<ByteResponse>> {
        Ok(None)
    }
    async fn serve_authenticated(
        &self,
        _request: Request<Incoming>,
        _remote_ip: IpAddr,
        _with_tls: bool,
        _context: &Context,
    ) -> HByteResult {
        Ok(http_response(404, "Not Found").await)
    }
    fn verify_ip(&self, ip: IpAddr) -> bool;
}

const URI_WELL_KNOWN: &str = "/.well-known/";

pub struct Plain {
    www_root: Static,
    settings: PlainSettings,
    allow: AllowRemoteAny,
}

fn default_plain_target_port() -> u16 {
    443
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainSettings {
    #[serde(default = "default_plain_target_port")]
    target_port: u16,
}

impl Default for PlainSettings {
    fn default() -> Self {
        Self {
            target_port: default_plain_target_port(),
        }
    }
}

impl Plain {
    pub fn create<P: AsRef<Path>>(
        path: P,
        settings: Option<serde_json::Value>,
        allow: AllowRemoteAny,
    ) -> Arc<dyn VirtualApp> {
        let settings = if let Some(s) = settings {
            match serde_json::from_value::<PlainSettings>(s) {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "Failed to parse plain virtual app settings, using default");
                    PlainSettings::default()
                }
            }
        } else {
            PlainSettings::default()
        };
        let www_root = Static::new(path.as_ref());
        Arc::new(Self {
            www_root,
            settings,
            allow,
        })
    }
    pub fn id() -> &'static str {
        "plain"
    }
    async fn file(&self, request: Request<Full<Bytes>>) -> ByteResponse {
        match self.www_root.clone().serve(request).await {
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
}

#[async_trait]
impl VirtualApp for Plain {
    async fn serve_insecure(
        &self,
        request: &Request<Incoming>,
        _remote_ip: IpAddr,
        with_tls: bool,
        _context: &Context,
    ) -> HResult<Option<ByteResponse>> {
        if with_tls {
            return Ok(None);
        }
        if request.uri().path().starts_with(URI_WELL_KNOWN) {
            synth_sleep().await;
            let req = Request::builder()
                .method(request.method())
                .uri(request.uri())
                .version(request.version())
                .body(Full::from(vec![]))
                .unwrap();
            return Ok(Some(self.file(req).await));
        }
        if request.method() != Method::GET
            && request.method() != Method::HEAD
            && request.method() != Method::OPTIONS
        {
            return Ok(None);
        }
        // redirect to https
        let host = resolve_host(request).unwrap_or_default();
        let port = if self.settings.target_port == 443 {
            String::new()
        } else {
            format!(":{}", self.settings.target_port)
        };
        let mut uri = format!("https://{}{}{}", host, port, request.uri().path());
        if let Some(query) = request.uri().query() {
            uri.push('?');
            uri.push_str(query);
        }
        let response = Response::builder()
            .status(301)
            .header("Location", uri)
            .body(
                Full::from(vec![])
                    .map_err(|e| Box::new(e) as StdError)
                    .boxed(),
            )
            .unwrap();
        Ok(Some(response))
    }
    fn verify_ip(&self, ip: IpAddr) -> bool {
        self.allow.verify_ip(ip)
    }
}

const URI_WELL_KNOWN_PUBLIC_PEM: &str = "/.well-known/public.pem";
const URI_WELL_KNOWN_OPENID_CONFIGURATION: &str = "/.well-known/openid-configuration";

const URI_SYSTEM_APPS_JSON: &str = "/.gateryx/system/apps.json";
const URI_SYSTEM_APP_ICON: &str = "/.gateryx/system/app_icon";

pub struct System {
    www_root: Static,
    allow: AllowRemoteAny,
}

impl System {
    pub fn id() -> &'static str {
        "system"
    }
    pub fn create<P: AsRef<Path>>(path: P, allow: AllowRemoteAny) -> Arc<dyn VirtualApp> {
        let www_root = Static::new(path.as_ref());
        Arc::new(Self { www_root, allow })
    }
    async fn system_file(&self, request: Request<Full<Bytes>>) -> ByteResponse {
        match self.www_root.clone().serve(request).await {
            Ok(v) => {
                let (parts, body) = v.into_parts();
                Response::from_parts(parts, body.map_err(|e| Box::new(e) as StdError).boxed())
            }
            Err(e) => {
                error!(error = %e, "Failed to serve system static file");
                http_internal_server_error().await
            }
        }
    }
}

#[async_trait]
impl VirtualApp for System {
    async fn serve_insecure(
        &self,
        request: &Request<Incoming>,
        _remote_ip: IpAddr,
        _with_tls: bool,
        context: &Context,
    ) -> HResult<Option<ByteResponse>> {
        if !request.uri().path().starts_with(URI_WELL_KNOWN) {
            return Ok(None);
        }
        if request.uri().path() == URI_WELL_KNOWN_PUBLIC_PEM
            && let Some(ref public) = context.token_factory_public
        {
            synth_sleep().await;
            let pem = public.public_pem().to_owned();
            let response = Response::builder()
                .status(200)
                .header("Content-Type", "application/x-pem-file")
                .body(Full::from(pem).map_err(|e| Box::new(e) as StdError).boxed())
                .unwrap();
            return Ok(Some(response));
        }
        if request.uri().path() == URI_WELL_KNOWN_OPENID_CONFIGURATION
            && let Some(ref public) = context.token_factory_public
        {
            synth_sleep().await;
            return Ok(Some(http_json_response(
                public.openid_configuration().to_owned(),
            )));
        }
        if let Some(ref public) = context.token_factory_public
            && Some(request.uri().path()) == public.jwks_path()
        {
            synth_sleep().await;
            return Ok(Some(http_ser_json_response(public.jwks()).await));
        }
        Ok(Some(http_response(404, "").await))
    }
    async fn serve_authenticated(
        &self,
        request: Request<Incoming>,
        _remote_ip: IpAddr,
        _with_tls: bool,
        context: &Context,
    ) -> HByteResult {
        if request.uri().path() == URI_SYSTEM_APPS_JSON {
            let apps = context.app_map.apps().await;
            let domain = context.token_domain.as_deref();
            return Ok(
                http_ser_json_response(serde_json::json!({"apps": apps, "domain": domain})).await,
            );
        }
        if request.uri().path() == URI_SYSTEM_APP_ICON {
            let app_name = request.uri().query().unwrap_or_default();
            let Some(app_icon) = context.app_map.app_icon(app_name).await else {
                return Ok(http_response(404, "App icon not found").await);
            };
            let response = Response::builder()
                .status(200)
                .header("Content-Type", "image/png")
                .body(
                    Full::from(app_icon)
                        .map_err(|e| Box::new(e) as StdError)
                        .boxed(),
                )
                .unwrap();
            return Ok(response);
        }
        Ok(self
            .system_file(Request::from_parts(
                request.into_parts().0,
                Full::from(vec![]),
            ))
            .await)
    }
    fn verify_ip(&self, ip: IpAddr) -> bool {
        self.allow.verify_ip(ip)
    }
}
