use std::{str::FromStr as _, time::Duration};

use async_trait::async_trait;
use bma_ts::Timestamp;
use log::LevelFilter;
use mini_moka::sync::Cache;
use sqlx::{
    ConnectOptions, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use webauthn_rs::prelude::Passkey;

use crate::{
    Error, Result,
    authenticator::{GroupInfo, UserInfo, UserKind},
};

pub struct Storage {
    pool: PgPool,
    revocation_cache: Cache<String, Option<Timestamp>>,
}

impl Storage {
    pub async fn create(config: &super::Config) -> Result<Self> {
        if !config.uri.starts_with("postgres://") {
            return Err(Error::failed("Only postgres storage is supported"));
        }

        let timeout = Duration::from(config.timeout);

        let opts = PgConnectOptions::from_str(&config.uri)?
            .log_statements(LevelFilter::Trace)
            .log_slow_statements(LevelFilter::Warn, timeout);

        let pool = PgPoolOptions::new()
            .max_connections(config.pool_size.into())
            .acquire_timeout(timeout)
            .connect_with(opts)
            .await?;

        let revocation_cache = Cache::builder()
            .max_capacity(65_535)
            .time_to_live(Duration::from_secs(1))
            .build();

        Ok(Self {
            pool,
            revocation_cache,
        })
    }

    async fn token_revocation_timestamp(&self, login: &str) -> Result<Option<Timestamp>> {
        if let Some(t) = self.revocation_cache.get(&login.to_owned()) {
            return Ok(t);
        }

        let row = sqlx::query(
            "
            SELECT not_before
            FROM revoked_tokens
            WHERE login = $1
            ",
        )
        .bind(login)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let not_before: Timestamp = row.try_get("not_before")?;
        self.revocation_cache
            .insert(login.to_owned(), Some(not_before));

        Ok(Some(not_before))
    }

    async fn group_users(&self, group: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "
            SELECT login
            FROM user_groups
            WHERE group_name = $1
            ORDER BY login ASC
            ",
        )
        .bind(group)
        .fetch_all(&self.pool)
        .await?;

        let mut users = Vec::new();
        for row in rows {
            users.push(row.try_get("login")?);
        }
        Ok(users)
    }
}

#[async_trait]
impl super::Storage for Storage {
    async fn init(&self) -> Result<()> {
        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                login TEXT PRIMARY KEY,
                not_before TIMESTAMPTZ NOT NULL,
                keep_until TIMESTAMPTZ NOT NULL,
                FOREIGN KEY (login) REFERENCES users(login) ON DELETE CASCADE
            )
            ",
        )
        .execute(&self.pool)
        .await?;

        // no foreign key for passkeys as they can exist without a user

        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS passkeys (
                login TEXT PRIMARY KEY,
                cred_id BYTEA UNIQUE NOT NULL,
                data TEXT NOT NULL,
                created TIMESTAMPTZ NOT NULL,
                last_used TIMESTAMPTZ NOT NULL,
            )
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS users (
                login TEXT PRIMARY KEY,
                password_hash TEXT,
                active BOOLEAN NOT NULL,
                created TIMESTAMPTZ NOT NULL,
                last_login TIMESTAMPTZ NOT NULL
            )
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS groups (
                name TEXT PRIMARY KEY
            )
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS user_groups (
                login TEXT NOT NULL,
                group_name TEXT NOT NULL,
                PRIMARY KEY (login, group_name),
                FOREIGN KEY (login) REFERENCES users(login) ON DELETE CASCADE,
                FOREIGN KEY (group_name) REFERENCES groups(name) ON DELETE CASCADE
            )
            ",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn user_groups(&self, login: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "
            SELECT group_name
            FROM user_groups
            WHERE login = $1
            ",
        )
        .bind(login)
        .fetch_all(&self.pool)
        .await?;

        let mut groups = Vec::new();
        for row in rows {
            groups.push(row.try_get("group_name")?);
        }
        Ok(groups)
    }

    async fn invalidate(&self, login: &str) -> Result<()> {
        let now = Timestamp::now();

        sqlx::query(
            "
            INSERT INTO revoked_tokens (login, not_before)
            VALUES ($1, $2, $3)
            ON CONFLICT (login) DO UPDATE
            SET not_before = EXCLUDED.not_before
            ",
        )
        .bind(login)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn is_token_revoked(&self, login: &str, issued_at: Timestamp) -> Result<bool> {
        let Some(not_before) = self.token_revocation_timestamp(login).await? else {
            return Ok(false);
        };
        Ok(issued_at < not_before)
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    async fn lookup_passkey(&self, cred_id: &[u8]) -> Result<Option<(String, Passkey)>> {
        let row = sqlx::query(
            "
            SELECT login, data
            FROM passkeys
            WHERE cred_id = $1
            ",
        )
        .bind(cred_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let login: String = row.try_get("login")?;
        let data: String = row.try_get("data")?;
        let passkey = serde_json::from_str(&data)?;

        let now = Timestamp::now();
        sqlx::query(
            "
            UPDATE passkeys
            SET last_used = $1
            WHERE cred_id = $2
            ",
        )
        .bind(now)
        .bind(cred_id)
        .execute(&self.pool)
        .await?;

        Ok(Some((login, passkey)))
    }

    async fn save_passkey(&self, login: &str, passkey: Passkey) -> Result<()> {
        let data = serde_json::to_string(&passkey)?;
        let cred_id = passkey.cred_id().to_vec();
        let now = Timestamp::now();

        sqlx::query(
            "
            INSERT INTO passkeys (login, cred_id, data, created, last_used)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (login) DO UPDATE
            SET cred_id = EXCLUDED.cred_id,
                data = EXCLUDED.data,
                last_used = EXCLUDED.last_used
            ",
        )
        .bind(login)
        .bind(cred_id)
        .bind(data)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn has_passkey(&self, login: &str) -> Result<bool> {
        let (count,): (i64,) = sqlx::query_as(
            "
            SELECT COUNT(*)
            FROM passkeys
            WHERE login = $1
            ",
        )
        .bind(login)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    async fn delete_passkey(&self, login: &str) -> Result<()> {
        sqlx::query(
            "
            DELETE FROM passkeys
            WHERE login = $1
            ",
        )
        .bind(login)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_user(&self, login: &str, password_hash: &str) -> Result<()> {
        let now = Timestamp::now();
        sqlx::query(
            "
            INSERT INTO users (login, password_hash, active, created, last_login)
            VALUES ($1, $2, TRUE, $3, $3)
            ON CONFLICT (login) DO UPDATE
            SET password_hash = EXCLUDED.password_hash,
                active = TRUE
            ",
        )
        .bind(login)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_user_password(&self, login: &str, password_hash: &str) -> Result<()> {
        sqlx::query(
            "
            UPDATE users
            SET password_hash = $1
            WHERE login = $2
            ",
        )
        .bind(password_hash)
        .bind(login)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_user(&self, login: &str) -> Result<()> {
        sqlx::query(
            "
            DELETE FROM users
            WHERE login = $1
            ",
        )
        .bind(login)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn lookup_user(&self, login: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "
            SELECT password_hash
            FROM users
            WHERE login = $1 AND active = TRUE
            ",
        )
        .bind(login)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.try_get("password_hash")).transpose()?)
    }

    async fn touch_user(&self, login: &str) -> Result<()> {
        let now = Timestamp::now();
        sqlx::query(
            "
            UPDATE users
            SET last_login = $1
            WHERE login = $2
            ",
        )
        .bind(now)
        .bind(login)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<UserInfo>> {
        let rows = sqlx::query(
            "
            SELECT login, password_hash, active, created, last_login
            FROM users
            ORDER BY login ASC
            ",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut users = Vec::new();
        for row in rows {
            let login: String = row.try_get("login")?;
            let password_hash: Option<String> = row.try_get("password_hash")?;
            let groups = self.user_groups(&login).await?;
            users.push(UserInfo {
                login,
                active: row.try_get::<bool, _>("active")?.into(),
                kind: if password_hash.is_some_and(|p| !p.is_empty()) {
                    UserKind::Reg
                } else {
                    UserKind::Svc
                },
                created: row.try_get("created")?,
                last_login: row.try_get("last_login")?,
                groups,
            });
        }
        Ok(users)
    }

    async fn list_groups(&self) -> Result<Vec<GroupInfo>> {
        let rows = sqlx::query(
            "
            SELECT name
            FROM groups
            ORDER BY name ASC
            ",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut groups = Vec::new();
        for row in rows {
            let name: String = row.try_get("name")?;
            let users = self.group_users(&name).await?;
            groups.push(GroupInfo { name, users });
        }
        Ok(groups)
    }

    async fn add_group(&self, group: &str) -> Result<()> {
        sqlx::query(
            "
            INSERT INTO groups (name)
            VALUES ($1)
            ON CONFLICT (name) DO NOTHING
            ",
        )
        .bind(group)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_group(&self, group: &str) -> Result<()> {
        sqlx::query(
            "
            DELETE FROM groups
            WHERE name = $1
            ",
        )
        .bind(group)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn add_user_to_group(&self, login: &str, group: &str) -> Result<()> {
        sqlx::query(
            "
            INSERT INTO user_groups (login, group_name)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            ",
        )
        .bind(login)
        .bind(group)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_user_from_group(&self, login: &str, group: &str) -> Result<()> {
        sqlx::query(
            "
            DELETE FROM user_groups
            WHERE login = $1 AND group_name = $2
            ",
        )
        .bind(login)
        .bind(group)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
