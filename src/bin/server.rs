use std::io::Write as _;
use std::mem;
use std::path::Path;
use std::{env, path::PathBuf};

use clap::Parser;
use fs_err::{read_dir, read_to_string};
use gateryx::app_util::{self, AppConfigEntry};
use gateryx::setup::generate_default_config;
use rustls::crypto::CryptoProvider;
use serde::Deserialize as _;
use tracing::{error, info, warn};

use gateryx::{AppHostMap, Config, Error, Result, VAppMap, app::Config as AppConfig};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    #[clap(short = 'c', long, default_value = "/etc/gateryx/config.toml")]
    config: PathBuf,
    #[clap(long, help = "Check configuration and exit")]
    check: bool,
    #[clap(long, help = "Auto-generate configuration files/dirs if missing")]
    auto_generate_missing: bool,
    #[clap(long, help = "Launch as EVA ICS service)")]
    eva_svc: bool,
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

fn main() -> Result<()> {
    let args = Args::parse();
    if args.version {
        println!("gateryx {}", gateryx::VERSION);
        return Ok(());
    }
    if args.eva_svc {
        eva_sdk::service::svc_launch(run_eva_service).map_err(Error::failed)
    } else {
        gateryx::panic_handler::set();
        configure_logger();
        if !args.config.exists() && args.auto_generate_missing {
            warn!(path = %args.config.display(), "Config file does not exist, the default will be created");
            generate_default_config(&args.config)?;
        }
        let config: Config = {
            let config_str = Zeroizing::new(read_to_string(&args.config)?);
            toml::from_str(&config_str)?
        };
        let config_path = args.config.canonicalize()?;
        let config_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        run_server(config, config_dir, args.check)
    }
}

#[allow(clippy::cast_possible_wrap)]
async fn run_eva_service(mut initial: eva_common::services::Initial) -> eva_common::EResult<()> {
    use eva_sdk::prelude::*;

    struct Handlers {
        info: ServiceInfo,
    }

    #[async_trait]
    impl RpcHandlers for Handlers {
        async fn handle_call(&self, event: RpcEvent) -> RpcResult {
            let method = event.parse_method()?;
            svc_handle_default_rpc(method, &self.info)
        }
    }

    let config_dir = Path::new(initial.eva_dir()).join("runtime/gateryx");
    let config: Config = Config::deserialize(
        initial
            .take_config()
            .ok_or_else(|| Error::invalid_data("config not specified"))?,
    )?;
    let info = ServiceInfo::new("Bohemia Automation", env!("CARGO_PKG_VERSION"), "HTTP WAF");
    let handlers = Handlers { info };
    eapi_bus::init(&initial, handlers).await?;
    eapi_bus::init_logs(&initial)?;
    eapi_bus::mark_ready().await?;
    tracing::info!("Starting Gateryx service ({})", initial.id());
    let (tx_pid, rx_pid) = oneshot::channel();
    let h = tokio::task::spawn_blocking(move || {
        let pid = std::process::id();
        tx_pid.send(pid).ok();
        run_server(config, &config_dir, false).map_err(Error::failed)
    });
    let pid = rx_pid
        .await
        .map_err(|_| Error::failed("Failed to receive PID from server task"))?;
    tokio::select! {
        h = h => {
            h.map_err(Error::failed)??;
        }
        () = eapi_bus::block() => {
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
    }
    eapi_bus::block().await;
    eapi_bus::mark_terminating().await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_server(mut config: Config, config_dir: &std::path::Path, check: bool) -> Result<()> {
    let mut check_result = config.check(config_dir);
    let app_d_dir = config_dir.join("app.d");
    let mut app_config_entries: Vec<AppConfigEntry> = Vec::new();
    for app_config in mem::take(&mut config.app) {
        app_config_entries.push(AppConfigEntry::new(app_config, None, None));
    }
    let mut app_config_paths = Vec::new();
    if app_d_dir.exists() {
        let app_config_entries = read_dir(&app_d_dir)?;
        for entry in app_config_entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                app_config_paths.push(path);
            }
        }
        app_config_paths.sort();
    } else if config.app.is_empty() {
        warn!(
            app_d = %app_d_dir.display(),
            "No app.d directory found and no apps configured in the main config"
        );
    }
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
        app_config_entries.push(AppConfigEntry::new(app_config, Some(app_id), Some(&path)));
    }
    for entry in &app_config_entries {
        check_result.extend(entry.check(config_dir));
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
    if check {
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
    let primary_system_host = app_util::add_apps(
        app_config_entries,
        config_dir,
        &app_map,
        &mut virtual_app_map,
    );
    // read configs in toml from app.d
    if !app_map.default_app_present() && config.server.default_app.is_some() {
        warn!(app = config.server.default_app, "Default app not found");
    }
    gateryx::run(config.into(), app_map, virtual_app_map, primary_system_host)
}
