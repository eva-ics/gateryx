use std::{str::FromStr as _, time::Duration};

use async_trait::async_trait;
use bma_ts::Timestamp;
use log::LevelFilter;
use sqlx::{
    ConnectOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteSynchronous},
};
use sqlx::{Row, SqlitePool};
use webauthn_rs::prelude::Passkey;

use crate::{Error, Result, authenticator::UserInfo};

pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn create(config: &super::Config) -> Result<Self> {
        if !config.uri.starts_with("sqlite://") {
            return Err(Error::failed("Only sqlite storage is supported"));
        }
        let timeout = Duration::from_secs(config.timeout);
        let opts = SqliteConnectOptions::from_str(&config.uri)?
            .create_if_missing(true)
            .synchronous(SqliteSynchronous::Extra)
            .busy_timeout(timeout)
            .log_statements(LevelFilter::Trace)
            .log_slow_statements(LevelFilter::Warn, timeout);
        let pool = SqlitePoolOptions::new()
            // initialize all connections while in privileged mode
            //.min_connections(config.pool_size)
            .max_connections(config.pool_size)
            //.max_lifetime(None)
            //.idle_timeout(None)
            .acquire_timeout(timeout)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl super::Storage for Storage {
    async fn init(&self) -> Result<()> {
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                user VARCHAR PRIMARY KEY,
                not_before BIGINT,
                keep_until BIGINT
            );
            ",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS passkeys (
                user VARCHAR PRIMARY KEY,
                cred_id BLOB UNIQUE,
                data TEXT,
                created BIGINT,
                last_used BIGINT
            );
            ",
        )
        .execute(&self.pool)
        .await?;
        // create unique index on cred_id
        sqlx::query(
            r"
            CREATE UNIQUE INDEX IF NOT EXISTS idx_passkeys_cred_id
            ON passkeys (cred_id);
            ",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS users (
                user VARCHAR PRIMARY KEY,
                password_hash TEXT,
                active INTEGER,
                created BIGINT,
                last_login BIGINT
            );
            ",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn invalidate(&self, user: &str, record_expires: Duration) -> Result<()> {
        let now = Timestamp::now();
        let keep_until = now + record_expires;
        sqlx::query(
            r"
            INSERT OR REPLACE INTO revoked_tokens (user, not_before, keep_until)
            VALUES (?, ?, ?)
            ",
        )
        .bind(user)
        .bind(now)
        .bind(keep_until)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn is_token_revoked(&self, user: &str, t_issued: Timestamp) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM revoked_tokens
            WHERE user = ? and not_before > ?
            ",
        )
        .bind(user)
        .bind(t_issued)
        .fetch_one(&self.pool)
        .await?;
        if row.0 > 0 {
            return Ok(true);
        }
        Ok(false)
    }

    async fn cleanup(&self) -> Result<()> {
        let now = Timestamp::now();
        sqlx::query(
            r"
            DELETE FROM revoked_tokens
            WHERE keep_until < ?
            ",
        )
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn lookup_passkey(&self, cred_id: &[u8]) -> Result<Option<(String, Passkey)>> {
        let row = sqlx::query(
            r"
            SELECT user, data FROM passkeys
            WHERE cred_id = ?
            ",
        )
        .bind(cred_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let user: String = row.try_get("user")?;
        let data: String = row.try_get("data")?;
        let passkey = serde_json::from_str(&data)?;
        // set last_used timestamp
        let now = Timestamp::now();
        sqlx::query(
            r"
            UPDATE passkeys
            SET last_used = ?
            WHERE cred_id = ?
            ",
        )
        .bind(now)
        .bind(cred_id)
        .execute(&self.pool)
        .await?;
        Ok(Some((user, passkey)))
    }

    async fn save_passkey(&self, user: &str, passkey: Passkey) -> Result<()> {
        let passkey_serialized = serde_json::to_string(&passkey)?;
        let cred_id: &[u8] = passkey.cred_id();
        let now = Timestamp::now();
        sqlx::query(
            r"
            INSERT OR REPLACE INTO passkeys (user, cred_id, data, created, last_used)
            VALUES (?, ?, ?, ?, ?)
            ",
        )
        .bind(user)
        .bind(cred_id)
        .bind(passkey_serialized)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn has_passkey(&self, user: &str) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM passkeys
            WHERE user = ?
            ",
        )
        .bind(user)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 > 0)
    }

    async fn delete_passkey(&self, user: &str) -> Result<()> {
        sqlx::query(
            r"
            DELETE FROM passkeys
            WHERE user = ?
            ",
        )
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_user(&self, user: &str, password_hash: &str) -> Result<()> {
        let now = Timestamp::now();
        sqlx::query(
            r"
            INSERT OR REPLACE INTO users (user, password_hash, active, created, last_login)
            VALUES (?, ?, ?, ?, ?)
            ",
        )
        .bind(user)
        .bind(password_hash)
        .bind(1)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_user_password(&self, user: &str, password_hash: &str) -> Result<()> {
        sqlx::query(
            r"
            UPDATE users
            SET password_hash = ?
            WHERE user = ?
            ",
        )
        .bind(password_hash)
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_user(&self, user: &str) -> Result<()> {
        sqlx::query(
            r"
            DELETE FROM users
            WHERE user = ?
            ",
        )
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn lookup_user(&self, user: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            r"
            SELECT password_hash FROM users
            WHERE user = ? AND active = 1
            ",
        )
        .bind(user)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let password_hash: String = row.try_get("password_hash")?;
        Ok(Some(password_hash))
    }

    async fn touch_user(&self, user: &str) -> Result<()> {
        let now = Timestamp::now();
        sqlx::query(
            r"
            UPDATE users
            SET last_login = ?
            WHERE user = ?
            ",
        )
        .bind(now)
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<UserInfo>> {
        let rows = sqlx::query(
            r"
            SELECT user, active, created, last_login FROM users ORDER BY user ASC
            ",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut users = Vec::new();
        for row in rows {
            let user = UserInfo {
                login: row.try_get("user")?,
                active: u8::try_from(row.try_get::<i64, _>("active")?).unwrap_or_default(),
                created: row.try_get("created")?,
                last_login: row.try_get("last_login")?,
            };
            users.push(user);
        }
        Ok(users)
    }
}
