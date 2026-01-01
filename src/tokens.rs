use std::{
    cmp::max,
    path::{Path, PathBuf},
};

use crate::{
    ConfigCheckIssue, Error, Result,
    gate::worker::Context,
    keys::generate_signing_key,
    storage::Storage,
    util::{GDuration, get_cookie},
};
use base64::prelude::*;
use bma_ts::Timestamp;
use http::HeaderMap;
use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::{PublicKey, ecdsa::SigningKey, elliptic_curve::JwkEcKey};
use pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const TOKEN_COOKIE_NAME_PREFIX: &str = "gateryx_auth_";
pub const DEFAULT_TOKEN_COOKIE_NAME: &str = "token";

fn default_token_cookie_name() -> String {
    DEFAULT_TOKEN_COOKIE_NAME.to_string()
}

const JWKS_PATH: &str = "/.well-known/jwks.json";

fn max_bearer_expire() -> GDuration {
    GDuration::from_secs(86400 * 365) // 7 days
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[zeroize(skip)]
    key_file: PathBuf,
    #[zeroize(skip)]
    expire: GDuration,
    #[zeroize(skip)]
    #[serde(default = "max_bearer_expire")]
    max_bearer_expire: GDuration,
    pub domain: Option<String>,
    #[serde(default = "default_token_cookie_name")]
    pub cookie: String,
}

impl Config {
    pub fn canonicalize_path(&mut self, work_dir: &Path) {
        if !self.key_file.is_absolute() {
            self.key_file = work_dir.join(&self.key_file);
        }
    }
    pub fn check(&self, config_dir: &Path) -> Vec<ConfigCheckIssue> {
        let mut issues = Vec::new();
        let key_path = if self.key_file.is_absolute() {
            self.key_file.clone()
        } else {
            config_dir.join(&self.key_file)
        };
        if !key_path.exists() {
            issues.push(ConfigCheckIssue::Warning(format!(
                "Token key file path does not exist: {}",
                key_path.display()
            )));
        }
        issues
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl Claims {
    pub fn to_view(&self) -> ClaimsView {
        ClaimsView {
            sub: self.sub.clone(),
            iat: Timestamp::from_secs(self.iat),
            exp: Timestamp::from_secs(self.exp),
            apps: self.apps.clone(),
            groups: self.groups.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClaimsView {
    pub sub: String,
    pub iat: Timestamp,
    pub exp: Timestamp,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub enum ValidationResponse {
    Valid { claims: ClaimsView, token_s: String },
    Invalid,
}

pub fn get_token_from_cookie_header(headers: &HeaderMap, context: &Context) -> Option<String> {
    get_cookie(headers, &context.token_cookie_name)
}

pub fn extract_token_from_headers(
    headers: &mut HeaderMap,
    allow_app_tokens: bool,
    context: &Context,
) -> Option<String> {
    macro_rules! process_auth_header {
        ($auth_header:expr, $token_str: expr) => {
            let Ok(auth_str) = $auth_header.to_str() else {
                continue;
            };
            let (auth_kind, auth_value) = match auth_str.split_once(' ') {
                Some((k, v)) => (k.to_lowercase(), v.trim()),
                None => continue,
            };
            if auth_kind == "bearer" {
                $token_str = Some(auth_value.to_string());
            }
            if auth_kind == "basic" {
                let Ok(decoded) = BASE64_STANDARD.decode(auth_value) else {
                    continue;
                };
                let Ok(decoded_str) = String::from_utf8(decoded) else {
                    continue;
                };
                if let Some((_, password)) = decoded_str.split_once(':') {
                    $token_str = Some(password.to_string());
                }
            }
        };
    }
    if allow_app_tokens {
        let mut token_str = None;
        for auth_header in headers.get_all(&context.headers.authorization) {
            process_auth_header!(auth_header, token_str);
        }
        headers.remove(&context.headers.authorization);
        if token_str.is_some() {
            return token_str;
        }
        for auth_header in headers.get_all(http::header::AUTHORIZATION) {
            process_auth_header!(auth_header, token_str);
        }
        headers.remove(http::header::AUTHORIZATION);
        if token_str.is_some() {
            return token_str;
        }
    }
    get_cookie(headers, &context.token_cookie_name)
}

#[derive(Serialize, Deserialize)]
pub struct Public {
    issuer_uri: Option<String>,
    jwks_uri: Option<String>,
    pem: String,
    openid_configuration: String,
    jwks: Jwks,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Jwks {
    iss: Option<String>,
    sub: Option<String>,
    iat: u64,
    keys: Vec<JwkEcKey>,
}

impl Public {
    pub fn public_pem(&self) -> &str {
        &self.pem
    }
    pub fn jwks_path(&self) -> Option<&'static str> {
        if self.jwks_uri.is_some() {
            Some(JWKS_PATH)
        } else {
            None
        }
    }
    pub fn openid_configuration(&self) -> &str {
        &self.openid_configuration
    }
    pub fn jwks(&self) -> Jwks {
        let mut jwks = self.jwks.clone();
        jwks.iat = Timestamp::now().as_secs();
        jwks
    }
}

pub struct Factory {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiration_seconds: u64,
    max_bearer_expire_seconds: u64,
    issuer_uri: Option<String>,
    jwks_uri: Option<String>,
    public_key: PublicKey,
    public_pem: String,
    openid_configuration: String,
}

impl Factory {
    pub fn to_public(&self) -> Public {
        Public {
            issuer_uri: self.issuer_uri.clone(),
            jwks_uri: self.jwks_uri.clone(),
            pem: self.public_pem.clone(),
            openid_configuration: self.openid_configuration.clone(),
            jwks: Jwks {
                iss: self.issuer_uri.clone(),
                sub: self.issuer_uri.clone(),
                iat: Timestamp::now().as_secs(),
                keys: vec![self.public_key.to_jwk()],
            },
        }
    }
    pub async fn init(config: &Config, system_host: Option<&str>) -> Result<Self> {
        info!(path = %config.key_file.display(), "Loading token key");
        if !config.key_file.exists() {
            warn!("File does not exist. Generating new token key");
            generate_signing_key(Some(&config.key_file)).await?;
        }
        let jwt_key_pem = Zeroizing::new(
            tokio::fs::read_to_string(&config.key_file)
                .await
                .map_err(|e| Error::Io(format!("Failed to read token key file: {}", e)))?,
        );
        let signing_key = SigningKey::from_pkcs8_pem(&jwt_key_pem).map_err(|e| {
            Error::crypto(format!(
                "Failed to parse token key file as PKCS#8 PEM: {}",
                e
            ))
        })?;
        let encoding_key = EncodingKey::from_ec_der(
            signing_key
                .to_pkcs8_der()
                .map_err(|e| {
                    Error::crypto(format!("Failed to encode token key as PKCS#8 DER: {}", e))
                })?
                .as_bytes(),
        );
        let public_key: PublicKey = signing_key.verifying_key().into();

        let public_pem = public_key.to_public_key_pem(<_>::default()).map_err(|e| {
            Error::crypto(format!("Failed to encode token public key as PEM: {}", e))
        })?;

        let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(public_pem.as_bytes())
            .map_err(|e| Error::crypto(format!("Failed to parse token key for decode: {}", e)))?;
        let openid_configuration = serde_json::to_string(&serde_json::json!({
            "issuer": system_host.map(|s| format!("https://{}", s)),
            "jwks_uri": system_host.map(|s| format!("https://{}{}", s, JWKS_PATH)),
            "id_token_signing_alg_values_supported": ["ES256"],
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "claims_supported": ["sub", "iss", "exp", "iat"],
        }))?;
        Ok(Self {
            encoding_key,
            decoding_key,
            expiration_seconds: config.expire.as_secs(),
            max_bearer_expire_seconds: config.max_bearer_expire.as_secs(),
            issuer_uri: system_host.map(|s| format!("https://{}", s)),
            jwks_uri: system_host.map(|s| format!("https://{}/{}", s, JWKS_PATH)),
            public_key,
            public_pem,
            openid_configuration,
        })
    }
    pub fn max_expiration_seconds(&self) -> u64 {
        max(self.expiration_seconds, self.max_bearer_expire_seconds)
    }
    pub fn issue<S: AsRef<str>>(
        &self,
        sub: S,
        groups: Vec<String>,
        apps: Vec<String>,
        exp: Option<u64>,
    ) -> Result<(String, u64)> {
        if !apps.is_empty() {
            let Some(exp) = exp else {
                return Err(Error::failed("App tokens must have explicit expiration"));
            };
            if exp > self.max_bearer_expire_seconds {
                return Err(Error::failed(
                    "App token expiration exceeds maximum allowed",
                ));
            }
        }
        let exp = Timestamp::now().as_secs() + exp.unwrap_or(self.expiration_seconds);
        let claims = Claims {
            sub: sub.as_ref().to_string(),
            iat: Timestamp::now().as_secs(),
            exp,
            iss: self.issuer_uri.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            apps,
            groups,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
            &claims,
            &self.encoding_key,
        )
        .map_err(|e| Error::crypto(format!("Failed to encode token: {}", e)))?;
        Ok((token, exp))
    }
    pub async fn validate(
        &self,
        token_str: String,
        storage: &dyn Storage,
        allow_app_tokens: bool,
    ) -> ValidationResponse {
        let Ok(token) = jsonwebtoken::decode::<Claims>(
            &token_str,
            &self.decoding_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
        ) else {
            return ValidationResponse::Invalid;
        };
        if !token.claims.apps.is_empty() && !allow_app_tokens {
            debug!(user = %token.claims.sub, "App token not allowed");
            return ValidationResponse::Invalid;
        }
        if self.issuer_uri.as_deref() != token.claims.iss.as_deref() {
            debug!(expected_iss = ?self.issuer_uri, token_iss = ?token.claims.iss, "Token issuer mismatch");
            return ValidationResponse::Invalid;
        }
        // double check expiration
        if Timestamp::from_secs(token.claims.exp) < Timestamp::now() {
            debug!(user = %token.claims.sub, "Token is expired");
            return ValidationResponse::Invalid;
        }
        match storage
            .is_token_revoked(&token.claims.sub, Timestamp::from_secs(token.claims.iat))
            .await
        {
            Ok(true) => {
                debug!(user = %token.claims.sub, "Token is revoked");
                ValidationResponse::Invalid
            }
            Ok(false) => ValidationResponse::Valid {
                claims: token.claims.to_view(),
                token_s: token_str,
            },
            Err(e) => {
                error!(error = %e, "Failed to check token revocation");
                ValidationResponse::Invalid
            }
        }
    }
}
