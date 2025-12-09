use core::fmt;
use std::path::PathBuf;
use std::{net::IpAddr, path::Path};

use http::{Method, Request, Uri, Version};
use hyper::body::Incoming;
use tokio::fs::File;
use tokio::io::AsyncWriteExt as _;
use tracing::error;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use crate::gate;
use crate::ml::extractor::RequestMeta;

#[derive(Debug, PartialEq, Eq)]
struct FileId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,

    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_index: u64,
}

async fn get_file_id(path: &Path) -> std::io::Result<FileId> {
    let metadata = tokio::fs::metadata(path).await?;

    #[cfg(unix)]
    {
        Ok(FileId {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    #[cfg(windows)]
    {
        Ok(FileId {
            volume_serial_number: metadata.volume_serial_number(),
            file_index: ((metadata.file_index_high() as u64) << 32)
                | (metadata.file_index_low() as u64),
        })
    }
}

const LOGGER_CHANNEL_SIZE: usize = 1024;

pub type LogSender = async_channel::Sender<LogRecord>;
pub type MetaLogSender = async_channel::Sender<RequestMeta>;

pub struct LogRecord {
    ip: IpAddr,
    user: Option<String>,
    method: Method,
    tls: bool,
    host: String,
    uri: Uri,
    version: Version,
    status: u16,
    size: usize,
    referer: Option<String>,
    user_agent: Option<String>,
}

impl LogRecord {
    pub fn new(ip: IpAddr, req: &Request<Incoming>, tls: bool) -> Self {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let version = req.version();
        let referer = req
            .headers()
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .unwrap_or_default();
        Self {
            ip,
            user: None,
            method,
            tls,
            host,
            uri,
            version,
            status: 0,
            size: 0,
            referer,
            user_agent,
        }
    }
    pub fn set_user(&mut self, user: String) {
        self.user = Some(user);
    }
    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }
}

impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = if self.tls {
            format!("https://{}{}", self.host, self.uri)
        } else {
            format!("http://{}{}", self.host, self.uri)
        };
        write!(
            f,
            "{} - {} [{}] \"{} {} {:?}\" {} {} \"{}\" \"{}\"",
            self.ip,
            self.user.as_deref().unwrap_or("-"),
            chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z"),
            self.method,
            url,
            self.version,
            self.status,
            self.size,
            self.referer.as_deref().unwrap_or("-"),
            self.user_agent.as_deref().unwrap_or("-"),
        )
    }
}

struct LogFile {
    file: File,
    path: PathBuf,
    id: FileId,
}

impl LogFile {
    async fn create(path: &Path) -> std::io::Result<Self> {
        let file = File::options().create(true).append(true).open(path).await?;
        let id = get_file_id(path).await?;
        Ok(Self {
            file,
            path: path.to_owned(),
            id,
        })
    }
    async fn is_rotated(&self) -> std::io::Result<bool> {
        let current_id = match get_file_id(&self.path).await {
            Ok(id) => id,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File has been deleted
                return Ok(true);
            }
            Err(e) => return Err(e),
        };
        Ok(current_id != self.id)
    }
    fn write<'a>(&'a mut self, data: &'a [u8]) -> impl Future<Output = std::io::Result<()>> + 'a {
        self.file.write_all(data)
    }
}

pub struct Logger {
    path: PathBuf,
    log_file: Option<LogFile>,
}

impl Logger {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            log_file: None,
        }
    }
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        macro_rules! create_log_file {
        () => {
            match LogFile::create(&self.path).await {
                Ok(file) => self.log_file = Some(file),
                Err(e) => {
                        error!(path = %self.path.display(), error = %e, "Failed to open log file");
                        return Err(e);
                    }
                }
            };
        }
        if self.log_file.is_none() {
            create_log_file!();
        }
        match self.log_file.as_ref().unwrap().is_rotated().await {
            Ok(true) => {
                create_log_file!();
            }
            Ok(false) => {}
            Err(e) => {
                error!(path = %self.path.display(), error = %e, "Failed to check log file rotation");
                return Err(e);
            }
        }
        if let Err(e) = self.log_file.as_mut().unwrap().write(data).await {
            error!(path = %self.path.display(), error = %e, "Failed to write log record");
            return Err(e);
        }
        Ok(())
    }
}

pub fn spawn(master_client: gate::worker::Client) -> LogSender {
    const MAX_LOG_RECORD_SIZE: usize = 4096;
    let (tx, rx) = async_channel::bounded::<LogRecord>(LOGGER_CHANNEL_SIZE);
    tokio::spawn(async move {
        while let Ok(record) = rx.recv().await {
            let mut buf = record.to_string().into_bytes();
            if buf.len() > MAX_LOG_RECORD_SIZE {
                buf.truncate(MAX_LOG_RECORD_SIZE);
            }
            buf.push(b'\n');
            if let Err(e) = master_client.write_log_record(&buf).await {
                error!(error = %e, "Failed to send log record");
            }
        }
    });
    tx
}

pub fn spawn_meta(master_client: gate::worker::Client) -> MetaLogSender {
    const MAX_LOG_RECORD_SIZE: usize = 4096;
    let (tx, rx) = async_channel::bounded::<RequestMeta>(LOGGER_CHANNEL_SIZE);
    tokio::spawn(async move {
        while let Ok(record) = rx.recv().await {
            let mut buf = match serde_json::to_vec(&record) {
                Ok(b) => b,
                Err(e) => {
                    error!(error = %e, "Failed to serialize meta log record");
                    continue;
                }
            };
            if buf.len() > MAX_LOG_RECORD_SIZE {
                error!(error = "Meta log record too large, skipping");
                continue;
            }
            buf.push(b'\n');
            if let Err(e) = master_client.write_meta_log_record(&buf).await {
                error!(error = %e, "Failed to send meta log record");
            }
        }
    });
    tx
}
