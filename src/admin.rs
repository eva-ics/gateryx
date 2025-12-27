use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use http::{HeaderName, Request};
use http_body_util::{BodyExt as _, Full};
use httpsig_hyper::{
    MessageSignatureReq as _, RequestContentDigest as _,
    prelude::{HttpSignatureParams, PublicKey, SecretKey, message_component},
};
use hyper::body::{Bytes, Incoming};
use p256::{PublicKey as EcPublicKey, ecdsa::SigningKey};
use pkcs8::DecodePrivateKey as _;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    ConfigCheckIssue, Error, Result,
    authenticator::RandomSleeper,
    util::{AllowRemoteStrict, GDuration, synth_sleep},
};

const HEADER_CONTENT_DIGEST: HeaderName = HeaderName::from_static("content-digest");
const HEADER_SIGNATURE_INPUT: HeaderName = HeaderName::from_static("signature-input");
const HEADER_SIGNATURE: HeaderName = HeaderName::from_static("signature");

fn default_admin_max_time_diff() -> GDuration {
    GDuration::from_secs(300)
}

#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[zeroize(skip)]
    pub key_file: PathBuf,
    #[zeroize(skip)]
    pub allow: AllowRemoteStrict,
    #[serde(default = "default_admin_max_time_diff")]
    #[zeroize(skip)]
    pub max_time_diff: GDuration,
}

impl Config {
    pub fn new_client<P: AsRef<Path>>(key_file: P) -> Self {
        Self {
            key_file: key_file.as_ref().to_owned(),
            allow: <_>::default(),
            max_time_diff: default_admin_max_time_diff(),
        }
    }
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
                "Admin key file path does not exist: {}",
                key_path.display()
            )));
        }
        issues
    }
}

#[derive(Serialize, Deserialize)]
pub struct TransferredRequest {
    date_header: String,
    digest_header: String,
    signature_input_header: String,
    signature_header: String,
    body: Zeroizing<Vec<u8>>,
}

impl TransferredRequest {
    pub async fn create(http_req: Request<Incoming>, remote_ip: IpAddr) -> Result<Self> {
        let (parts, body) = http_req.into_parts();
        macro_rules! get_header {
            ($key: expr, $disp: expr) => {
                parts
                    .headers
                    .get($key)
                    .ok_or_else(|| Error::failed(format!("Missing {} header", $disp)))?
                    .to_str()
                    .map_err(|_| Error::failed(format!("Invalid {} header", $disp)))?
                    .to_string()
            };
        }
        let date_header = get_header!(http::header::DATE, "Date");
        let digest_header = get_header!(HEADER_CONTENT_DIGEST, "Content-Digest");
        let signature_input_header = get_header!(HEADER_SIGNATURE_INPUT, "Signature-Input");
        let signature_header = get_header!(HEADER_SIGNATURE, "Signature");
        let Ok(body_collected) = body.collect().await else {
            error!(ip = %remote_ip, "Failed to read RPC request body");
            return Err(Error::failed("Failed to read request body"));
        };
        let body_bytes = body_collected.to_bytes();
        Ok(Self {
            date_header,
            digest_header,
            signature_input_header,
            signature_header,
            body: Zeroizing::new(body_bytes.to_vec()),
        })
    }
}

pub struct Auth {
    secret_key: SecretKey,
    signature_params: HttpSignatureParams,
    verifiying_key: PublicKey,
    max_time_diff: Duration,
}

impl Auth {
    pub async fn init(config: &Config) -> Result<Self> {
        info!(path = %config.key_file.display(), "Loading admin key");
        let admin_key_pem = Zeroizing::new(
            tokio::fs::read_to_string(&config.key_file)
                .await
                .map_err(|e| Error::io(format!("Failed to read admin key file: {}", e)))?,
        );
        let signing_key = SigningKey::from_pkcs8_pem(&admin_key_pem).map_err(|e| {
            Error::crypto(format!(
                "Failed to parse token key file as PKCS#8 PEM: {}",
                e
            ))
        })?;
        let public_key: EcPublicKey = signing_key.verifying_key().into();
        let covered = [http::header::DATE, HEADER_CONTENT_DIGEST]
            .into_iter()
            .map(|v| message_component::HttpMessageComponentId::try_from(v.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::failed)?;
        let mut signature_params = HttpSignatureParams::try_new(&covered).map_err(Error::failed)?;
        let secret_key = SecretKey::EcdsaP256Sha256(signing_key.into());
        signature_params.set_key_info(&secret_key);

        Ok(Self {
            signature_params,
            secret_key,
            verifiying_key: PublicKey::EcdsaP256Sha256(public_key),
            max_time_diff: config.max_time_diff.into(),
        })
    }
    pub async fn parse_transferred_request(
        &self,
        req: TransferredRequest,
        remote_ip: IpAddr,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let TransferredRequest {
            date_header,
            digest_header,
            signature_input_header,
            signature_header,
            body,
        } = req;
        let Ok(time) = httpdate::parse_http_date(&date_header) else {
            synth_sleep().await;
            return Err(Error::access("Invalid Date header"));
        };
        let now = SystemTime::now();
        let elapsed = if now > time {
            now.duration_since(time).map_err(Error::failed)?
        } else {
            time.duration_since(now).map_err(Error::failed)?
        };
        if elapsed > self.max_time_diff {
            synth_sleep().await;
            return Err(Error::access("Request signature expired"));
        }
        let random_sleeper = RandomSleeper::new(10..50);
        let req: Request<Full<&[u8]>> = Request::builder()
            .header(http::header::DATE, date_header)
            .header(HEADER_CONTENT_DIGEST, digest_header)
            .header(HEADER_SIGNATURE_INPUT, signature_input_header)
            .header(HEADER_SIGNATURE, signature_header)
            .body(Full::new(body.as_slice()))
            .map_err(Error::failed)?;
        if let Err(e) = req
            .verify_message_signature(&self.verifiying_key, None)
            .await
        {
            synth_sleep().await;
            random_sleeper.sleep().await;
            error!(error = %e, ip = %remote_ip, "Admin signature verification failed");
            return Err(Error::access("Invalid signature"));
        }
        Ok(body)
    }
    pub async fn prepare_request(&self, req: Request<Bytes>) -> Result<Request<Bytes>> {
        let (mut parts, body) = req.into_parts();
        parts.headers.insert(
            http::header::DATE,
            httpdate::fmt_http_date(SystemTime::now())
                .parse()
                .map_err(Error::failed)?,
        );
        let body_orig = body.clone();
        let req = Request::from_parts(parts, Full::new(body));
        let mut req = req
            .set_content_digest(&httpsig_hyper::ContentDigestType::Sha256)
            .await
            .map_err(Error::failed)?;
        req.set_message_signature(&self.signature_params, &self.secret_key, None)
            .await
            .map_err(Error::failed)?;
        let (parts, _) = req.into_parts();
        Ok(Request::from_parts(parts, body_orig))
    }
}
