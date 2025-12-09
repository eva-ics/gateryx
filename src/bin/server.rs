use std::io::Write as _;
use std::{env, path::PathBuf};

use clap::Parser;
use fs_err::{read_dir, read_to_string};
use hyper::Uri;
use rustls::crypto::CryptoProvider;
use tracing::{error, info, warn};

use gateryx::{AppHostMap, Config, Error, Result, VAppMap, app::Config as AppConfig};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
struct Args {
    #[clap(short = 'c', long, default_value = "/etc/gateryx/config.toml")]
    config: PathBuf,
    #[clap(long, help = "Check configuration and exit")]
    check: bool,
    #[clap(long, help = "Print version and exit")]
    version: bool,
}

pub fn is_systemd() -> bool {
    env::var("INVOCATION_ID").is_ok_and(|v| !v.is_empty())
}

fn configure_logger() {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    if is_systemd() {
        builder.format(|buf, record| writeln!(buf, "{} {}", record.level(), record.args()));
    }
    builder.init();
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let args = Args::parse();
    if args.version {
        println!("gateryx {}", gateryx::VERSION);
        return Ok(());
    }
    gateryx::panic_handler::set();
    configure_logger();
    let mut config: Config = {
        let config_str = Zeroizing::new(read_to_string(&args.config)?);
        toml::from_str(&config_str)?
    };
    let config_path = args.config.canonicalize()?;
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut check_result = config.check(config_dir);
    let app_d_dir = config_dir.join("app.d");
    let mut app_configs = Vec::new();
    let app_config_entries = read_dir(&app_d_dir)?;
    let mut app_config_paths = Vec::new();
    for entry in app_config_entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            app_config_paths.push(path);
        }
    }
    app_config_paths.sort();
    for path in app_config_paths {
        let Some(app_id) = path.file_stem().and_then(|s| s.to_str()) else {
            error!(path = %path.display(), "Invalid app config file name");
            continue;
        };
        let app_config_str = read_to_string(&path)?;
        let app_config: AppConfig = match toml::from_str(&app_config_str) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, path = %path.display(), "Failed to parse app config");
                continue;
            }
        };
        app_configs.push((app_id.to_owned(), app_config, path));
    }
    for (_, app_config, path) in &app_configs {
        check_result.extend(app_config.check(config_dir, path));
    }
    let mut has_error = false;
    let mut has_warning = false;
    for issue in check_result {
        match issue {
            gateryx::ConfigCheckIssue::Warning(msg) => {
                warn!("CONFIG ISSUE: {}", msg);
                has_warning = true;
            }
            gateryx::ConfigCheckIssue::Error(msg) => {
                error!("CONFIG ISSUE: {}", msg);
                has_error = true;
            }
        }
    }
    if has_error {
        std::process::exit(1);
    }
    if args.check {
        if has_warning {
            std::process::exit(2);
        }
        info!("Configuration check passed");
        std::process::exit(0);
    }
    CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("Failed to install default crypto provider");
    config.canonicalize_path(config_dir);
    if config.listener.is_empty() {
        return Err(Error::invalid_data("No listeners configured"));
    }
    let app_map = AppHostMap::default();
    app_map.set_default_app(config.server.default_app.as_deref());
    let mut virtual_app_map = VAppMap::default();
    let mut primary_system_host = None;
    // read configs in toml from app.d
    for (app_id, mut app_config, path) in app_configs {
        if let Some(v_id) = app_config.url.strip_prefix("gateryx://") {
            if v_id == gateryx::vapp::System::id() {
                if primary_system_host.is_none() {
                    primary_system_host = app_config.hosts.first().cloned();
                } else {
                    warn!(name = %app_id, path = %path.display(), "Multiple system virtual apps defined");
                }
                let v = gateryx::vapp::System::create(app_config.remote);
                virtual_app_map.add(app_config.hosts, app_id, v);
                continue;
            }
            if v_id == gateryx::vapp::Plain::id() {
                let v = gateryx::vapp::Plain::create(app_config.remote, app_config.settings);
                virtual_app_map.add(app_config.hosts, app_id, v);
                continue;
            }
            warn!(name = %app_id, path = %path.display(), "Unknown virtual app URL scheme");
            continue;
        }
        if app_config.name.is_empty() {
            app_config.name.clone_from(&app_id);
        }
        if app_config.url.is_empty()
            && let Some(host) = app_config.hosts.first()
        {
            app_config.url = format!("https://{}/", host);
        }
        if let Some(ref icon) = app_config.icon {
            let icon_path: PathBuf = if icon.is_absolute() {
                icon.clone()
            } else {
                config_dir.join(icon)
            };
            match fs_err::read(&icon_path) {
                Ok(data) => {
                    app_config.icon_image = Some(data);
                }
                Err(e) => {
                    warn!(error = %e, path = %icon_path.display(), "Failed to read icon file");
                }
            }
        }
        match Uri::try_from(&app_config.remote) {
            Ok(u) => {
                if u.path() != "/" {
                    warn!(path = %path.display(), remote = %app_config.remote, "Remote URI must not contain path");
                }
            }
            Err(e) => {
                error!(error = %e, path = %path.display(), "Invalid remote URI");
                continue;
            }
        }
        if let Err(e) = app_map.add_sync(&app_id, app_config) {
            error!(error = %e, path = %path.display(), "Failed to add app config");
        } else {
            info!(name = %app_id, path = %path.display(), "Loaded app config");
        }
    }
    if !app_map.default_app_present() && config.server.default_app.is_some() {
        warn!(app = config.server.default_app, "Default app not found");
    }
    gateryx::run(config.into(), app_map, virtual_app_map, primary_system_host)
}
