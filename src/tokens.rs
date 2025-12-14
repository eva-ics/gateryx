use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

use crate::{
    ConfigCheckIssue, Error, Result,
    storage::Storage,
    util::{GDuration, get_cookie},
};
use bincode::{Decode, Encode};
use bma_ts::Timestamp;
use http::HeaderMap;
use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::{PublicKey, ecdsa::SigningKey, elliptic_curve::JwkEcKey};
use pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const TOKEN_COOKIE: &str = "gateryx_auth_token";
pub static TOKEN_COOKIE_WITH_EQ: LazyLock<String> = LazyLock::new(|| format!("{}=", TOKEN_COOKIE));
const JWKS_PATH: &str = "/.well-known/jwks.json";

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[zeroize(skip)]
    key_file: PathBuf,
    #[zeroize(skip)]
    expire: GDuration,
    pub domain: Option<String>,
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
            issues.push(ConfigCheckIssue::Error(format!(
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
}

impl Claims {
    pub fn to_view(&self) -> ClaimsView {
        ClaimsView {
            sub: self.sub.clone(),
            iat: Timestamp::from_secs(self.iat),
            exp: Timestamp::from_secs(self.exp),
        }
    }
}

#[derive(Clone, Encode, Decode)]
pub struct ClaimsView {
    pub sub: String,
    pub iat: Timestamp,
    pub exp: Timestamp,
}

#[derive(Encode, Decode)]
pub enum ValidationResponse {
    Valid { claims: ClaimsView, token_s: String },
    Invalid,
}
pub fn get_token_cookie(headers: &HeaderMap) -> Option<String> {
    get_cookie(headers, TOKEN_COOKIE)
}

#[derive(Encode, Decode)]
pub struct Public {
    issuer_uri: Option<String>,
    jwks_uri: Option<String>,
    pem: String,
    openid_configuration: String,
    jwks: Jwks,
}

#[derive(Encode, Decode, Serialize, Deserialize, Clone)]
pub struct Jwks {
    iss: Option<String>,
    sub: Option<String>,
    iat: u64,
    keys: Vec<JwkEcKeyPub>,
}

#[derive(Serialize, Deserialize, Clone)]
struct JwkEcKeyPub(JwkEcKey);

impl Encode for JwkEcKeyPub {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), bincode::error::EncodeError> {
        // TODO: Optimize to avoid double serialization (not urgent as serialized only once at
        // start)
        let jwk_json = serde_json::to_string(&self.0).map_err(|e| {
            bincode::error::EncodeError::OtherString(format!("Failed to serialize JWK: {}", e))
        })?;
        bincode::Encode::encode(&jwk_json, encoder)
    }
}

impl<Context> Decode<Context> for JwkEcKeyPub {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> std::result::Result<Self, bincode::error::DecodeError> {
        let jwk_json: String = bincode::Decode::decode(decoder)?;
        let jwk: JwkEcKey = serde_json::from_str(&jwk_json).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Failed to deserialize JWK: {}", e))
        })?;
        Ok(JwkEcKeyPub(jwk))
    }
}

bincode::impl_borrow_decode!(JwkEcKeyPub);

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
                keys: vec![JwkEcKeyPub(self.public_key.to_jwk())],
            },
        }
    }
    pub async fn init(config: &Config, system_host: Option<&str>) -> Result<Self> {
        info!(path = %config.key_file.display(), "Loading token key");
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
            issuer_uri: system_host.map(|s| format!("https://{}", s)),
            jwks_uri: system_host.map(|s| format!("https://{}/{}", s, JWKS_PATH)),
            public_key,
            public_pem,
            openid_configuration,
        })
    }
    pub fn expiration_seconds(&self) -> u64 {
        self.expiration_seconds
    }
    pub fn issue<S: AsRef<str>>(&self, sub: S) -> Result<(String, u64)> {
        let exp = Timestamp::now().as_secs() + self.expiration_seconds;
        let claims = Claims {
            sub: sub.as_ref().to_string(),
            iat: Timestamp::now().as_secs(),
            exp,
            iss: self.issuer_uri.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
            &claims,
            &self.encoding_key,
        )
        .map_err(|e| Error::crypto(format!("Failed to encode token: {}", e)))?;
        Ok((token, exp))
    }
    pub async fn validate(&self, token_str: String, storage: &dyn Storage) -> ValidationResponse {
        let Ok(token) = jsonwebtoken::decode::<Claims>(
            &token_str,
            &self.decoding_key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
        ) else {
            return ValidationResponse::Invalid;
        };
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
