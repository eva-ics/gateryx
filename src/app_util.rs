use std::path::{Path, PathBuf};

use hyper::Uri;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AppHostMap, ConfigCheckIssue, VAppMap, app::Config as AppConfig, vapp};

const UNDEFINED_PATH: PathBuf = PathBuf::new();

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AppConfigEntry {
    config: Option<AppConfig>,
    id: Option<String>,
    #[zeroize(skip)]
    path: Option<PathBuf>,
}

impl AppConfigEntry {
    pub fn new(config: AppConfig, id: Option<&str>, path: Option<&Path>) -> Self {
        Self {
            id: id.map(ToOwned::to_owned),
            config: Some(config),
            path: path.map(ToOwned::to_owned),
        }
    }
    pub fn check(&self, dir: &Path) -> Vec<ConfigCheckIssue> {
        let Some(ref config) = self.config else {
            return Vec::new();
        };
        config.check(dir, self.path.as_deref().unwrap_or(&UNDEFINED_PATH))
    }
}

pub fn add_apps(
    entries: Vec<AppConfigEntry>,
    config_dir: &Path,
    app_map: &AppHostMap,
    virtual_app_map: &mut VAppMap,
) -> Option<String> {
    let mut primary_system_host = None;
    let mut c = 0;
    for mut entry in entries {
        let Some(mut config) = entry.config.take() else {
            continue;
        };
        let id = entry.id.take();
        let path = entry.path.take().unwrap_or_else(|| UNDEFINED_PATH.clone());
        let id = id.unwrap_or_else(|| {
            c += 1;
            format!("App {}", c)
        });
        if config.name.is_empty() {
            config.name.clone_from(&id);
        }
        if let Some(v_id) = config.url.strip_prefix("gateryx://") {
            if v_id == vapp::System::id() {
                if primary_system_host.is_none() {
                    primary_system_host = config.hosts.first().cloned();
                } else {
                    warn!(path = %path.display(), "Multiple system virtual apps defined");
                }
                let v = vapp::System::create(config.remote.clone(), config.allow.clone());
                info!(path = %path.display(), id = v_id, "Loaded virtual app");
                virtual_app_map.add(config.hosts.clone(), v_id, v);
                continue;
            }
            if v_id == vapp::Plain::id() {
                let v = vapp::Plain::create(
                    config.remote.clone(),
                    config.settings.clone(),
                    config.allow.clone(),
                );
                info!(path = %path.display(), id = v_id, "Loaded virtual app");
                virtual_app_map.add(config.hosts.clone(), v_id, v);
                continue;
            }
            warn!(path = %path.display(), "Unknown virtual app URL scheme");
            continue;
        }
        if config.url.is_empty()
            && let Some(host) = config.hosts.first()
        {
            config.url = format!("https://{}/", host);
        }
        if let Some(ref icon) = config.icon {
            let icon_path: PathBuf = if icon.is_absolute() {
                icon.clone()
            } else {
                config_dir.join(icon)
            };
            match fs_err::read(&icon_path) {
                Ok(data) => {
                    config.icon_image = Some(data);
                }
                Err(e) => {
                    warn!(error = %e, path = %icon_path.display(), "Failed to read icon file");
                }
            }
        }
        match Uri::try_from(&config.remote) {
            Ok(u) => {
                if u.path() != "/" {
                    warn!(path = %path.display(), remote = %config.remote, "Remote URI must not contain path");
                }
            }
            Err(e) => {
                error!(error = %e, path = %path.display(), "Invalid remote URI");
                continue;
            }
        }
        if let Err(e) = app_map.add_sync(&id, config) {
            error!(error = %e, path = %path.display(), "Failed to add app config");
        } else {
            info!(name = %id, path = %path.display(), "Loaded app config");
        }
    }
    primary_system_host
}
