//! Simulates break-in attempts for tokens (auth + JWT) and admin API keys.
//!
//! Use to test breakin protection, captcha threshold, and rejection of invalid tokens/signatures.

use base64::prelude::*;
use clap::Parser;
use gateryx::rpc::{RpcRequest, URI_RPC, URI_RPC_ADMIN};
use rand::RngCore;
use reqwest::Client;
use serde_json::json;
use std::time::{Duration, Instant};

/// Random SHA-256-sized bytes (32) base64-encoded, in Content-Digest format.
fn random_content_digest_value() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("sha-256=:{}:", BASE64_STANDARD.encode(bytes))
}

/// Random ECDSA P-256 signature-sized bytes (64) base64-encoded, in Signature format.
fn random_signature_value() -> String {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("sig1=:{}:", BASE64_STANDARD.encode(bytes))
}

#[derive(Parser)]
#[command(about)]
struct Args {
    /// Base URL of the gateway (e.g. http://127.0.0.1:80 or https://gate.example.com)
    #[arg(short, long, default_value = "http://127.0.0.1:80")]
    url: String,

    /// Host header value (virtual host)
    #[arg(long)]
    host: Option<String>,

    /// Number of attempts to perform
    #[arg(short, long, default_value = "10")]
    count: u32,

    /// Delay in milliseconds between attempts (throttle)
    #[arg(short, long, default_value = "0")]
    delay_ms: u64,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Parser)]
enum Mode {
    /// Failed login attempts (wrong password) to trigger breakin protection / captcha
    Auth {
        /// Username to use in failed attempts
        #[arg(short, long, default_value = "attacker")]
        user: String,
    },

    /// Requests with invalid or missing token (gate.invalidate, gate.passkey.present, etc.)
    Token {
        /// Token-required RPC method to call
        #[arg(long, default_value = "gate.invalidate")]
        method: String,
        /// Send token as Bearer header instead of cookie
        #[arg(long)]
        bearer: bool,
    },

    /// Admin API requests with invalid or missing signature
    Admin {
        /// Attack variant: no_headers (omit signature headers), bad_signature (wrong sig), bad_body (tampered body)
        #[arg(long, default_value = "no_headers")]
        variant: AdminVariant,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum AdminVariant {
    /// Omit Date, Content-Digest, Signature-Input, Signature
    NoHeaders,
    /// Valid headers structure but wrong signature value
    BadSignature,
    /// Correct signature for one body, send different body
    BadBody,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let url = args.url.trim_end_matches('/');
    let delay = Duration::from_millis(args.delay_ms);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let host = args
        .host
        .as_deref()
        .unwrap_or_else(|| url.trim_start_matches("https://").trim_start_matches("http://"));

    match &args.mode {
        Mode::Auth { user } => run_auth(&client, url, host, user.clone(), args.count, delay).await,
        Mode::Token { method, bearer } => {
            run_token(&client, url, host, method, *bearer, args.count, delay).await
        }
        Mode::Admin { variant } => run_admin(&client, url, host, *variant, args.count, delay).await,
    }
}

async fn run_auth(
    client: &Client,
    base_url: &str,
    host: &str,
    user: String,
    count: u32,
    delay: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = format!("{}{}", base_url, URI_RPC);
    let body = RpcRequest::create(
        1u32,
        "gate.authenticate",
        json!({
            "auth": { "user": user, "password": "wrong_password_breakin_sim" },
            "set_auth_cookie": "no"
        }),
    )?;
    let body_bytes = serde_json::to_vec(&body)?;

    println!("Auth break-in: {} failed logins as user {:?} -> {}", count, user, rpc_url);

    let start = Instant::now();
    let mut ok = 0u32;
    let mut denied = 0u32;
    let mut other = 0u32;

    for i in 0..count {
        let resp = client
            .post(&rpc_url)
            .header("Host", host)
            .header("Content-Type", "application/json")
            .body(body_bytes.clone())
            .send()
            .await?;

        match resp.status().as_u16() {
            200 => {
                let text = resp.text().await?;
                if text.contains("Invalid") || text.contains("invalid") || text.contains("CAPTCHA") {
                    denied += 1;
                } else {
                    ok += 1;
                }
            }
            _ => other += 1,
        }

        if (i + 1) % 10 == 0 || i == count - 1 {
            eprint!("\r  {} attempts...", i + 1);
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    let elapsed = start.elapsed();
    println!(
        "\n  Done in {:?}: {} denied (expected), {} ok, {} other status",
        elapsed, denied, ok, other
    );
    Ok(())
}

async fn run_token(
    client: &Client,
    base_url: &str,
    host: &str,
    method: &str,
    bearer: bool,
    count: u32,
    delay: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = format!("{}{}", base_url, URI_RPC);

    // Params depend on method
    let params: serde_json::Value = if method == "gate.invalidate" || method == "gate.passkey.present" {
        json!({})
    } else if method == "gate.set_password" {
        json!({ "old_password": "x", "new_password": "y" })
    } else {
        json!({})
    };

    let body = RpcRequest::create(1u32, method, params)?;
    let body_bytes = serde_json::to_vec(&body)?;

    let invalid_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid";
    println!(
        "Token break-in: {} requests with invalid token to {} -> {}",
        count, method, rpc_url
    );

    let start = Instant::now();
    let mut denied = 0u32;
    let mut other = 0u32;

    for i in 0..count {
        let mut req = client
            .post(&rpc_url)
            .header("Host", host)
            .header("Content-Type", "application/json")
            .body(body_bytes.clone());

        if bearer {
            req = req.header("Authorization", format!("Bearer {}", invalid_token));
        } else {
            req = req.header("Cookie", format!("gateryx_auth_token={}", invalid_token));
        }

        let resp = req.send().await?;

        match resp.status().as_u16() {
            200 => {
                let text = resp.text().await?;
                if text.contains("Invalid") || text.contains("invalid") || text.contains("error") {
                    denied += 1;
                }
            }
            401 | 403 => denied += 1,
            _ => other += 1,
        }

        if (i + 1) % 10 == 0 || i == count - 1 {
            eprint!("\r  {} attempts...", i + 1);
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    let elapsed = start.elapsed();
    println!(
        "\n  Done in {:?}: {} denied/error (expected), {} other",
        elapsed, denied, other
    );
    Ok(())
}

async fn run_admin(
    client: &Client,
    base_url: &str,
    host: &str,
    variant: AdminVariant,
    count: u32,
    delay: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = format!("{}{}", base_url, URI_RPC_ADMIN);
    let body = RpcRequest::create(1u32, "admin.test", json!({}))?;
    let body_bytes = serde_json::to_vec(&body)?;

    let variant_name = match variant {
        AdminVariant::NoHeaders => "no_headers",
        AdminVariant::BadSignature => "bad_signature",
        AdminVariant::BadBody => "bad_body",
    };

    println!(
        "Admin break-in: {} requests (variant={}) -> {}",
        count, variant_name, rpc_url
    );

    let start = Instant::now();
    let mut denied = 0u32;
    let mut other = 0u32;

    for i in 0..count {
        let req = match variant {
            AdminVariant::NoHeaders => client
                .post(&rpc_url)
                .header("Host", host)
                .header("Content-Type", "application/json")
                .body(body_bytes.clone()),
            AdminVariant::BadSignature => client
                .post(&rpc_url)
                .header("Host", host)
                .header("Content-Type", "application/json")
                .header("Date", "Mon, 01 Jan 2020 00:00:00 GMT")
                .header("Content-Digest", random_content_digest_value())
                .header("Signature-Input", "sig1=();keyid=\"test\"")
                .header("Signature", random_signature_value())
                .body(body_bytes.clone()),
            AdminVariant::BadBody => {
                let tampered = json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "admin.user.list",
                    "params": {}
                });
                let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
                client
                    .post(&rpc_url)
                    .header("Host", host)
                    .header("Content-Type", "application/json")
                    .header("Date", "Mon, 01 Jan 2020 00:00:00 GMT")
                    .header("Content-Digest", random_content_digest_value())
                    .header("Signature-Input", "sig1=();keyid=\"test\"")
                    .header("Signature", random_signature_value())
                    .body(tampered_bytes)
            }
        };
        let resp = req.send().await?;

        match resp.status().as_u16() {
            200 => {
                let text = resp.text().await?;
                if text.contains("error") || text.contains("Invalid") || text.contains("signature") {
                    denied += 1;
                }
            }
            401 | 403 => denied += 1,
            _ => other += 1,
        }

        if (i + 1) % 10 == 0 || i == count - 1 {
            eprint!("\r  {} attempts...", i + 1);
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    let elapsed = start.elapsed();
    println!(
        "\n  Done in {:?}: {} denied/error (expected), {} other",
        elapsed, denied, other
    );
    Ok(())
}
