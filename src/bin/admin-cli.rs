use clap::Parser;
use colored::Colorize;
use fs_err::read_to_string;
use gateryx::{
    Config, Error, Result,
    admin::{self, Config as AdminConfig},
    app::AdminAppView,
    authenticator::{GroupInfo, UserInfo},
    rpc::{RpcRequest, RpcResponse, URI_RPC, URI_RPC_ADMIN},
    util::GDuration,
};
use http::Request;
use hyper::body::Bytes;
use prettytable::{Table, row};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};

const SERVER_TOML: &str = "/etc/gateryx/config.toml";

#[derive(Parser)]
struct Args {
    #[clap(short = 'c', long, default_value = "/etc/gateryx/client.toml")]
    config: PathBuf,
    #[clap(short = 's', long)]
    silent: bool,
    #[clap(short = 'j', long, help = "Output in JSON format")]
    json: bool,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    Test,
    #[clap(subcommand)]
    App(AppCommand),
    #[clap(subcommand)]
    Group(GroupCommand),
    #[clap(subcommand)]
    User(UserCommand),
    Version,
}

#[derive(Parser)]
enum AppCommand {
    List,
}

#[derive(Parser)]
enum UserCommand {
    List,
    Create(CreateUserCommand),
    Delete(DeleteUserCommand),
    Password(SetPasswordCommand),
    Invalidate(InvalidateCommand),
}

#[derive(Parser)]
enum GroupCommand {
    List,
    Create(CreateGroupCommand),
    Delete(DeleteGroupCommand),
    AddUser(AddUserToGroupCommand),
    RemoveUser(RemoveUserFromGroupCommand),
}

#[derive(Parser)]
struct CreateGroupCommand {
    #[clap()]
    group: String,
}

#[derive(Parser)]
struct DeleteGroupCommand {
    #[clap()]
    group: String,
}

#[derive(Parser)]
struct AddUserToGroupCommand {
    #[clap()]
    group: String,
    #[clap()]
    user: String,
}

#[derive(Parser)]
struct RemoveUserFromGroupCommand {
    #[clap()]
    group: String,
    #[clap()]
    user: String,
}

#[derive(Parser)]
struct CreateUserCommand {
    #[clap()]
    user: String,
    #[clap(short = 'r')]
    service: bool,
}

#[derive(Parser)]
struct DeleteUserCommand {
    #[clap()]
    user: String,
}

#[derive(Parser)]
struct SetPasswordCommand {
    #[clap()]
    user: String,
}

#[derive(Parser)]
struct InvalidateCommand {
    #[clap()]
    user: String,
}

pub struct RpcClient {
    req_id: u64,
    url: String,
    web_client: Client,
    admin_auth: Option<admin::Auth>,
}

impl RpcClient {
    async fn create(client_config: ClientConfig) -> Result<Self> {
        let admin_auth = if let Some(ref key_file) = client_config.key_file {
            Some(admin::Auth::init(&AdminConfig::new_client(key_file)).await?)
        } else {
            None
        };
        Ok(Self {
            req_id: 1,
            url: client_config.url,
            web_client: Client::builder()
                .timeout(client_config.timeout.into())
                .build()
                .map_err(Error::failed)?,
            admin_auth,
        })
    }
    fn next_id(&mut self) -> u64 {
        let id = self.req_id;
        if self.req_id == u64::MAX {
            self.req_id = 1;
        } else {
            self.req_id += 1;
        }
        id
    }
    pub async fn call<M: AsRef<str>, P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: M,
        params: P,
    ) -> Result<R> {
        let method = method.as_ref();
        let req = RpcRequest::create(self.next_id(), method, params)?;
        let body = serde_json::to_vec(&req)?;
        let url = if method.starts_with("admin.") {
            format!("{}{}", self.url, URI_RPC_ADMIN)
        } else {
            format!("{}{}", self.url, URI_RPC)
        };
        let mut http_req: Request<Bytes> = Request::post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(Bytes::from(body))
            .map_err(Error::failed)?;
        if method.starts_with("admin.") {
            if let Some(admin_auth) = &self.admin_auth {
                http_req = admin_auth.prepare_request(http_req).await?;
            } else {
                return Err(Error::failed(
                    "Admin authentication is not configured".to_string(),
                ));
            }
        }
        let r_req = reqwest::Request::try_from(http_req).map_err(Error::failed)?;
        let response = self
            .web_client
            .execute(r_req)
            .await
            .map_err(Error::failed)?;
        if response.status() != 200 {
            return Err(Error::failed(format!(
                "Unexpected response status: {}",
                response.status()
            )));
        }
        let rpc_response: RpcResponse = response.json().await.map_err(Error::failed)?;
        match rpc_response {
            RpcResponse::Result(rpc_result_response) => {
                let result: R = serde_json::from_value(rpc_result_response.result)?;
                Ok(result)
            }
            RpcResponse::Error(rpc_error_response) => {
                Err(Error::failed(rpc_error_response.error.to_string()))
            }
        }
    }
}

#[derive(Deserialize)]
struct Empty {}

#[derive(Deserialize)]
#[serde(untagged)]
enum ConfigVariant {
    Client(ClientConfig),
    Server(Box<Config>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    key_file: Option<PathBuf>,
    url: String,
    #[serde(default = "gateryx::util::default_timeout")]
    timeout: GDuration,
}

impl ClientConfig {
    fn canonicalize_path(&mut self, work_dir: &Path) {
        let Some(ref key_file) = self.key_file else {
            return;
        };
        if !key_file.is_absolute() {
            self.key_file = Some(work_dir.join(key_file));
        }
    }
}

impl TryFrom<ConfigVariant> for ClientConfig {
    type Error = Error;
    fn try_from(value: ConfigVariant) -> Result<Self> {
        match value {
            ConfigVariant::Client(mut c) => {
                c.url = c.url.trim_end_matches('/').to_owned();
                Ok(c)
            }
            ConfigVariant::Server(c) => {
                let Some(listener) = c.listener.first() else {
                    return Err(Error::failed("No listeners configured"));
                };
                let host = if listener.bind.starts_with("0.0.0.0:") {
                    let port = listener.bind.split_once(':').unwrap().1;
                    format!("127.0.0.1:{}", port)
                } else {
                    listener.bind.clone()
                };
                let proto = if listener.tls.is_some() {
                    "https"
                } else {
                    "http"
                };
                let url = format!("{}://{}", proto, host);
                let key_file = c
                    .admin
                    .as_ref()
                    .map(|admin_config| admin_config.key_file.clone());
                Ok(ClientConfig {
                    key_file,
                    url,
                    timeout: c.server.timeout,
                })
            }
        }
    }
}

fn create_table() -> Table {
    let mut table = Table::new();
    table.set_format(
        prettytable::format::FormatBuilder::new()
            .borders(' ')
            .column_separator(' ')
            .separator(
                prettytable::format::LinePosition::Title,
                prettytable::format::LineSeparator::new('-', '-', '-', '-'),
            )
            .build(),
    );
    table
}

#[allow(clippy::too_many_lines)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    if matches!(args.command, Command::Version) {
        println!("gateryx cli {}", gateryx::VERSION);
        return Ok(());
    }
    let mut config_path = args.config.clone();
    if !config_path.exists() {
        config_path = PathBuf::from(SERVER_TOML);
    }
    if !config_path.exists() {
        return Err(Error::failed(format!(
            "Config file not found (tried '{}', '{}')",
            args.config.display(),
            SERVER_TOML
        )));
    }
    let config_str = read_to_string(&config_path)?;
    let config: ConfigVariant = toml::from_str(&config_str)?;
    let config_dir = args
        .config
        .parent()
        .ok_or_else(|| Error::failed("Invalid config path".to_string()))?
        .canonicalize()?;
    let mut client_config = ClientConfig::try_from(config)?;
    client_config.canonicalize_path(&config_dir);
    let mut client = RpcClient::create(client_config).await?;
    macro_rules! ok {
        () => {
            if !args.silent {
                if args.json {
                    println!("null");
                } else {
                    println!("{}", "OK".green());
                }
            }
        };
    }
    macro_rules! to_json {
        ($data:expr) => {
            if args.json {
                let json = serde_json::to_string_pretty(&$data)?;
                println!("{}", json);
                return Ok(());
            }
        };
    }
    match args.command {
        Command::Version => {
            unreachable!();
        }
        Command::Test => {
            let _: Empty = client.call("admin.test", serde_json::json!({})).await?;
            ok!();
        }
        Command::App(app_cmd) => match app_cmd {
            AppCommand::List => {
                let apps: Vec<AdminAppView> = client.call("admin.app.list", ()).await?;
                to_json!(apps);
                let mut table = create_table();
                table.set_titles(row!["Name", "Tok", "Url", "Groups", "Hidden"]);
                for app in apps {
                    table.add_row(row![
                        app.name,
                        if app.allow_tokens { "Y" } else { "" },
                        app.url,
                        app.allow_groups.join(","),
                        if app.hidden { "Y" } else { "" },
                    ]);
                }
                table.printstd();
            }
        },
        Command::Group(group_cmd) => match group_cmd {
            GroupCommand::List => {
                let groups: Vec<GroupInfo> = client.call("admin.group.list", ()).await?;
                to_json!(groups);
                let mut table = create_table();
                table.set_titles(row!["Group", "Users"]);
                for group in groups {
                    table.add_row(row![group.name, group.users.join(",")]);
                }
                table.printstd();
            }
            GroupCommand::Create(CreateGroupCommand { group }) => {
                let params = serde_json::json!({ "group": group });
                let _: () = client.call("admin.group.create", params).await?;
                ok!();
            }
            GroupCommand::Delete(DeleteGroupCommand { group }) => {
                let params = serde_json::json!({ "group": group });
                let _: () = client.call("admin.group.delete", params).await?;
                ok!();
            }
            GroupCommand::AddUser(AddUserToGroupCommand { group, user }) => {
                let params = serde_json::json!({ "group": group,
                    "user": user
                });
                let _: () = client.call("admin.group.add_user", params).await?;
                ok!();
            }
            GroupCommand::RemoveUser(RemoveUserFromGroupCommand { group, user }) => {
                let params = serde_json::json!({ "group": group,
                    "user": user
                });
                let _: () = client.call("admin.group.remove_user", params).await?;
                ok!();
            }
        },
        Command::User(user_cmd) => match user_cmd {
            UserCommand::List => {
                let users: Vec<UserInfo> = client.call("admin.user.list", ()).await?;
                to_json!(users);
                let mut table = create_table();
                table.set_titles(row![
                    "User",
                    "Act",
                    "Kind",
                    "Groups",
                    "Created",
                    "Last Login"
                ]);
                for user in users {
                    table.add_row(row![
                        user.login,
                        if user.active == 0 { "" } else { "Y" },
                        user.kind,
                        user.groups.join(","),
                        user.created
                            .try_into_datetime_local()
                            .unwrap()
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        user.last_login
                            .try_into_datetime_local()
                            .unwrap()
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ]);
                }
                table.printstd();
            }
            UserCommand::Create(CreateUserCommand { user, service }) => {
                let password = if service {
                    String::new()
                } else {
                    rpassword::prompt_password(format!("Password for user '{}': ", user))?
                };
                let params = serde_json::json!({ "user": user,
                    "password": password
                });
                let _: () = client.call("admin.user.create", params).await?;
                ok!();
            }
            UserCommand::Delete(DeleteUserCommand { user }) => {
                let params = serde_json::json!({ "user": user });
                let _: () = client.call("admin.user.delete", params).await?;
                ok!();
            }
            UserCommand::Password(SetPasswordCommand { user }) => {
                let password =
                    rpassword::prompt_password(format!("Password for user '{}': ", user))?;
                let params = serde_json::json!({ "user": user,
                    "password": password
                });
                let _: () = client.call("admin.user.set_password", params).await?;
                ok!();
            }
            UserCommand::Invalidate(InvalidateCommand { user }) => {
                let params = serde_json::json!({
                    "user": user,
                });
                let _: () = client.call("admin.invalidate", params).await?;
                ok!();
            }
        },
    }

    Ok(())
}
