use core::fmt;

use bincode::{Decode, Encode};

pub enum ConfigCheckIssue {
    Warning(String),
    Error(String),
}

#[derive(thiserror::Error, Debug, Encode, Decode)]
pub enum Error {
    #[error("app already exists")]
    AppAlreadyExists,
    #[error("Host already exists")]
    HostAlreadyExists,
    #[error("IO error: {0}")]
    Io(String),
    #[error("Failed: {0}")]
    Failed(String),
    #[error("Crypto engine error: {0}")]
    Crypto(String),
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("{0}")]
    AccessDeniedMoreDataRequired(String),
    #[error("Method not found: {0}")]
    RpcMethodNotFound(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Resource not found: {0}")]
    NotFound(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Timeout")]
    Timeout,
}

impl From<busrt::rpc::RpcError> for Error {
    fn from(e: busrt::rpc::RpcError) -> Self {
        let Some(data) = e.data() else {
            return Error::Failed("Bus error".to_string());
        };
        let Ok((e, _)) = bincode::decode_from_slice(data, bincode::config::standard()) else {
            return Error::Failed("Unreadable bus error".to_string());
        };
        e
    }
}

impl From<Error> for busrt::rpc::RpcError {
    fn from(e: Error) -> Self {
        let Ok(data) = bincode::encode_to_vec(e, bincode::config::standard()) else {
            return busrt::rpc::RpcError::internal(None);
        };
        busrt::rpc::RpcError::new(0, Some(data))
    }
}

impl Error {
    pub fn failed<S: fmt::Display>(msg: S) -> Self {
        Error::Failed(msg.to_string())
    }
    pub fn invalid_data<S: fmt::Display>(msg: S) -> Self {
        Error::InvalidData(msg.to_string())
    }
    pub fn access<S: fmt::Display>(msg: S) -> Self {
        Error::AccessDenied(msg.to_string())
    }
    pub fn crypto<S: fmt::Display>(msg: S) -> Self {
        Error::Crypto(msg.to_string())
    }
    pub fn io<S: fmt::Display>(msg: S) -> Self {
        Error::Io(msg.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(_e: tokio::time::error::Elapsed) -> Self {
        Error::Timeout
    }
}

impl From<busrt::Error> for Error {
    fn from(e: busrt::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Database(e.to_string())
    }
}

impl From<sqlite::Error> for Error {
    fn from(e: sqlite::Error) -> Self {
        Error::Database(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidData(e.to_string())
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(e: bincode::error::EncodeError) -> Self {
        Error::InvalidData(e.to_string())
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(e: bincode::error::DecodeError) -> Self {
        Error::InvalidData(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::InvalidData(e.to_string())
    }
}

impl From<toml::ser::Error> for Error {
    fn from(e: toml::ser::Error) -> Self {
        Error::InvalidData(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<tokio_rustls::rustls::Error> for Error {
    fn from(e: tokio_rustls::rustls::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}
impl From<tokio_rustls::rustls::pki_types::pem::Error> for Error {
    fn from(e: tokio_rustls::rustls::pki_types::pem::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}
