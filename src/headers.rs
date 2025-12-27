use http::HeaderName;
use serde::Deserialize;

use crate::{Error, Result};

fn default_jwt_assertion() -> String {
    "X-JWT-Assertion".to_string()
}

fn default_user() -> String {
    "X-Gateryx-User".to_string()
}

fn default_real_ip() -> String {
    "X-Real-IP".to_string()
}

fn default_via() -> String {
    "Via".to_string()
}

fn default_authorization() -> String {
    "X-Gateryx-Authorization".to_string()
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Headers {
    #[serde(default = "default_jwt_assertion")]
    jwt_assertion: String,
    #[serde(default = "default_user")]
    user: String,
    #[serde(default = "default_real_ip")]
    real_ip: String,
    #[serde(default = "default_authorization")]
    authorization: String,
    #[serde(default = "default_via")]
    via: String,
}

impl Default for Headers {
    fn default() -> Self {
        Headers {
            jwt_assertion: default_jwt_assertion(),
            user: default_user(),
            real_ip: default_real_ip(),
            authorization: default_authorization(),
            via: default_via(),
        }
    }
}

impl TryFrom<Headers> for WebHeaders {
    type Error = Error;

    fn try_from(value: Headers) -> Result<Self> {
        Ok(WebHeaders {
            jwt_assertion: HeaderName::from_bytes(value.jwt_assertion.as_bytes())
                .map_err(Error::invalid_data)?,
            user: HeaderName::from_bytes(value.user.as_bytes()).map_err(Error::invalid_data)?,
            real_ip: HeaderName::from_bytes(value.real_ip.as_bytes())
                .map_err(Error::invalid_data)?,
            authorization: HeaderName::from_bytes(value.authorization.as_bytes())
                .map_err(Error::invalid_data)?,
            via: HeaderName::from_bytes(value.via.as_bytes()).map_err(Error::invalid_data)?,
        })
    }
}

pub struct WebHeaders {
    pub jwt_assertion: HeaderName,
    pub user: HeaderName,
    pub real_ip: HeaderName,
    pub authorization: HeaderName,
    pub via: HeaderName,
}
