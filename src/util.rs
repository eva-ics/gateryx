use core::fmt;
use std::{str::FromStr, time::Duration};

use crate::{ByteResponse, Error, Result, StdError, tokens::TOKEN_COOKIE_WITH_EQ};
use http::{HeaderValue, Request};
use http_body_util::{BodyExt as _, Full};
use hyper::{HeaderMap, Response, Uri, body::Incoming};
use serde::{Deserialize, Serialize};
use tracing::error;

#[cfg(target_os = "linux")]
use std::ffi::CString;

fn parse_header_value<V: AsRef<str>>(s: V) -> Result<HeaderValue> {
    match s.as_ref().parse::<HeaderValue>() {
        Ok(hv) => Ok(hv),
        Err(e) => {
            error!(error = %e, value=%s.as_ref(), "Failed to parse header value");
            Err(Error::invalid_data("invalid header value"))
        }
    }
}

pub fn rewrite_location_header(headers: &mut HeaderMap, original_host: &str, with_tls: bool) {
    let Some(location) = headers.get("location") else {
        return;
    };
    let Ok(location_str) = location.to_str() else {
        return;
    };
    let Ok(location_uri) = Uri::try_from(location_str) else {
        return;
    };
    let had_scheme_and_authority =
        location_uri.scheme().is_some() && location_uri.authority().is_some();
    let new_path_and_query = location_uri.path_and_query().map_or(
        "/",
        tokio_tungstenite::tungstenite::http::uri::PathAndQuery::as_str,
    );
    let new_uri = if had_scheme_and_authority {
        let original_scheme = if with_tls { "https" } else { "http" };
        format!(
            "{}://{}{}",
            original_scheme, original_host, new_path_and_query
        )
    } else {
        new_path_and_query.to_string()
    };
    if let Ok(new_location_uri) = Uri::try_from(new_uri) {
        let Ok(v) = parse_header_value(new_location_uri.to_string()) else {
            return;
        };
        headers.insert("location", v);
    }
}

/// # Panics
///
/// Should be used by internal / verified methods only
pub async fn http_response<T: fmt::Display>(code: u16, text: T) -> ByteResponse {
    if code >= 400 {
        synth_sleep().await;
    }
    Response::builder()
        .status(code)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(
            Full::from(text.to_string())
                .map_err(|e| Box::new(e) as StdError)
                .boxed(),
        )
        .unwrap()
}

pub async fn http_internal_server_error() -> ByteResponse {
    http_response(500, "Internal Server Error").await
}

pub async fn http_ser_json_response<V: Serialize>(value: V) -> ByteResponse {
    let json_body = match serde_json::to_string(&value) {
        Ok(body) => body,
        Err(e) => {
            error!(error = %e, "Failed to serialize JSON response");
            return http_internal_server_error().await;
        }
    };
    http_json_response(json_body)
}

/// # Panics
///
/// Should be used by internal / verified methods only
pub fn http_json_response(json_body: String) -> ByteResponse {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(
            Full::from(json_body)
                .map_err(|e| Box::new(e) as StdError)
                .boxed(),
        )
        .unwrap()
}

// A synthetic sleep to mitigate error attacks and other similar
pub async fn synth_sleep() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

pub fn resolve_host(request: &Request<Incoming>) -> Option<String> {
    if let Some(authority) = request.uri().authority() {
        return Some(authority.as_str().to_owned());
    }
    if let Some(host_header) = request.headers().get("host")
        && let Ok(host_str) = host_header.to_str()
    {
        return Some(host_str.to_owned());
    }
    None
}

pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_headers = headers.get_all("cookie");
    for header_value in cookie_headers {
        if let Ok(header_str) = header_value.to_str() {
            for cookie in header_str.split(';').map(str::trim) {
                let Some((cookie_name, cookie_value)) = cookie.split_once('=') else {
                    continue;
                };
                if cookie_name == name {
                    return Some(cookie_value.to_string());
                }
            }
        }
    }
    None
}

pub fn downgrade_to_http11(request: &mut Request<Incoming>, keep_token_cookie: bool) {
    request.version_mut().clone_from(&hyper::Version::HTTP_11);
    // combine cookies
    let mut cookies = vec![];
    for cookie_header in &request.headers().get_all("cookie") {
        if let Ok(s) = cookie_header.to_str() {
            if !keep_token_cookie {
                let filtered: Vec<&str> = s
                    .split(';')
                    .map(str::trim)
                    .filter(|c| !c.starts_with(&*TOKEN_COOKIE_WITH_EQ))
                    .collect();
                if filtered.is_empty() {
                    continue;
                }
                cookies.push(filtered.join("; "));
                continue;
            }
            cookies.push(s.to_owned());
        }
    }
    request.headers_mut().remove("cookie");
    if !cookies.is_empty() {
        let combined = cookies.join("; ");
        let Ok(v) = parse_header_value(combined) else {
            return;
        };
        request.headers_mut().insert("cookie", v);
    }
}

#[cfg(target_os = "linux")]
pub fn drop_privileges(user: &str) -> Result<()> {
    let u = get_system_user(user)?;
    if nix::unistd::getuid() != u.uid {
        let c_user = CString::new(user)
            .map_err(|e| Error::failed(format!("Failed to parse user {}: {}", user, e)))?;

        let groups = nix::unistd::getgrouplist(&c_user, u.gid)
            .map_err(|e| Error::failed(format!("Failed to get groups for user {}: {}", user, e)))?;
        nix::unistd::setgroups(&groups).map_err(|e| {
            Error::failed(format!(
                "Failed to switch the process groups for user {}: {}",
                user, e
            ))
        })?;
        nix::unistd::setgid(u.gid).map_err(|e| {
            Error::failed(format!(
                "Failed to switch the process group for user {}: {}",
                user, e
            ))
        })?;
        nix::unistd::setuid(u.uid).map_err(|e| {
            Error::failed(format!(
                "Failed to switch the process user to {}: {}",
                user, e
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
pub fn drop_privileges(_user: &str) -> Result<()> {
    tracing::warn!("WARNING privileges not dropped");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn get_system_user(user: &str) -> Result<nix::unistd::User> {
    let u = nix::unistd::User::from_name(user)
        .map_err(|e| Error::failed(format!("failed to get the system user {}: {}", user, e)))?
        .ok_or_else(|| Error::failed(format!("Failed to locate the system user {}", user)))?;
    Ok(u)
}

pub fn default_true() -> bool {
    true
}

pub fn default_timeout() -> GDuration {
    GDuration(Duration::from_secs(10))
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Numeric(u32);

impl From<u32> for Numeric {
    fn from(n: u32) -> Self {
        Numeric(n)
    }
}

impl From<Numeric> for u32 {
    fn from(n: Numeric) -> Self {
        n.0
    }
}

impl From<Numeric> for u64 {
    fn from(n: Numeric) -> Self {
        u64::from(n.0)
    }
}

impl From<Numeric> for usize {
    fn from(n: Numeric) -> Self {
        usize::try_from(n.0).unwrap()
    }
}

impl FromStr for Numeric {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(u) = s.parse::<u32>() {
            return Ok(Numeric(u));
        }
        let (value_part, suffix) = s.trim().split_at(
            s.trim()
                .find(|c: char| !c.is_numeric() && c != '.')
                .unwrap_or(s.len()),
        );
        let base: u32 = value_part
            .parse()
            .map_err(|_| Error::invalid_data(format!("Invalid numeric value '{}'", value_part)))?;

        let multiplier = match suffix.to_ascii_lowercase().as_str() {
            "k" => 1_000,
            "m" => 1_000_000,
            "g" => 1_000_000_000,
            "" => 1,
            v => {
                return Err(Error::invalid_data(format!(
                    "Invalid suffix '{}' in numeric value",
                    v
                )));
            }
        };

        let val = base
            .checked_mul(multiplier)
            .ok_or_else(|| Error::invalid_data(format!("Numeric value '{}' is too large", s)))?;

        Ok(Numeric(val))
    }
}

impl<'de> Deserialize<'de> for Numeric {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NumericVariant {
            Int(u32),
            Str(String),
        }
        let n = NumericVariant::deserialize(deserializer)?;
        match n {
            NumericVariant::Int(i) => Ok(Numeric(i)),
            NumericVariant::Str(s) => {
                let parsed = s.parse::<Numeric>().map_err(serde::de::Error::custom)?;
                Ok(parsed)
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GDuration(Duration);

impl FromStr for GDuration {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(usecs) = s.parse::<u64>() {
            return Ok(GDuration(Duration::from_secs(usecs)));
        }
        if let Ok(fsecs) = s.parse::<f64>() {
            if fsecs < 0.0 {
                return Err(Error::invalid_data("Duration cannot be negative"));
            }
            return Ok(GDuration(Duration::from_secs_f64(fsecs)));
        }
        let dur = humantime::parse_duration(s).map_err(Error::invalid_data)?;
        Ok(GDuration(dur))
    }
}

impl GDuration {
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
    pub fn from_secs(secs: u64) -> Self {
        GDuration(Duration::from_secs(secs))
    }
}

impl From<GDuration> for Duration {
    fn from(hd: GDuration) -> Self {
        hd.0
    }
}

impl<'de> Deserialize<'de> for GDuration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum DurationVariant {
            Secs(u64),
            SecsFloat(f64),
            Str(String),
        }
        let d = DurationVariant::deserialize(deserializer)?;
        match d {
            DurationVariant::Secs(s) => Ok(GDuration(Duration::from_secs(s))),
            DurationVariant::SecsFloat(f) => {
                if f < 0.0 {
                    return Err(serde::de::Error::custom("Duration cannot be negative"));
                }
                Ok(GDuration(Duration::from_secs_f64(f)))
            }
            DurationVariant::Str(s) => {
                let dur = humantime::parse_duration(&s).map_err(serde::de::Error::custom)?;
                Ok(GDuration(dur))
            }
        }
    }
}
