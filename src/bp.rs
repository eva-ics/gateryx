use std::{net::IpAddr, sync::Arc, time::Duration};

use bma_ts::Timestamp;
#[cfg(feature = "server")]
use captcha::{
    Captcha,
    filters::{Dots, Noise, Wave},
};
use parking_lot::Mutex;
#[cfg(feature = "server")]
use rand::Rng as _;
use serde::Deserialize;
use sqlite::Connection;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;

const CAPTCHA_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    max_records: usize,
    window: u32,
    ip_score: u64,
    user_score: u64,
    captcha_threshold: u64,
}

#[cfg(feature = "server")]
pub fn get_captcha_png(secret: &str) -> Option<Vec<u8>> {
    Captcha::new()
        .set_value(&secret.chars().collect::<Vec<char>>())
        .apply_filter(Noise::new(0.4))
        .apply_filter(Wave::new(2.0, 20.0).horizontal())
        .apply_filter(Wave::new(2.0, 20.0).vertical())
        .view(220, 120)
        .apply_filter(Dots::new(5))
        .as_png()
}

#[cfg(not(feature = "server"))]
pub fn get_captcha_png(_secret: &str) -> Option<Vec<u8>> {
    unimplemented!()
}

#[allow(unused)]
pub struct BreakinProtection {
    max_records: usize,
    window: Duration,
    db: Mutex<Connection>,
    ip_score: u64,
    user_score: u64,
    captcha_threshold: u64,
}

impl BreakinProtection {
    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config.max_records,
            Duration::from_secs(u64::from(config.window)),
            config.ip_score,
            config.user_score,
            config.captcha_threshold,
        )
    }
    #[allow(unused_variables)]
    pub fn new(
        max_records: usize,
        window: Duration,
        ip_score: u64,
        user_score: u64,
        captcha_threshold: u64,
    ) -> Self {
        let db = Connection::open(":memory:").unwrap();
        db.execute(
            "
            CREATE TABLE attempts (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
        ",
        )
        .unwrap();
        // create index for username/time
        db.execute("CREATE INDEX idx_username_timestamp ON attempts (username, timestamp)")
            .unwrap();
        db.execute(
            "
            CREATE TABLE captcha (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                value TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
        ",
        )
        .unwrap();
        db.execute("CREATE INDEX idx_captcha_ip ON captcha (ip)")
            .unwrap();
        Self {
            max_records,
            window,
            db: Mutex::new(db),
            ip_score,
            user_score,
            captcha_threshold,
        }
    }
    pub fn report_success(&self, ip_address: IpAddr, _username: &str) {
        let ip_str = ip_address.to_string();
        let db = self.db.lock();
        // delete all records for this ip/username
        let mut stmt = db
            .prepare("DELETE FROM attempts WHERE ip_address = ?")
            .unwrap();
        stmt.bind((1, ip_str.as_str())).unwrap();
        //stmt.bind((2, username)).unwrap();
        stmt.next().unwrap();
    }
    pub fn report_failure(&self, ip_address: IpAddr, username: &str) {
        let db = self.db.lock();
        let mut stmt = db.prepare("SELECT COUNT(*) FROM attempts").unwrap();
        stmt.next().unwrap();
        let num_records = usize::try_from(stmt.read::<i64, _>(0).unwrap()).unwrap();
        if num_records >= self.max_records {
            // delete oldest record
            let mut del_stmt = db
                .prepare("DELETE FROM attempts ORDER BY id ASC LIMIT ?")
                .unwrap();
            del_stmt
                .bind((1, i64::try_from(num_records - self.max_records).unwrap()))
                .unwrap();
            del_stmt.next().unwrap();
        }
        let timestamp = i64::try_from(Timestamp::now().as_secs()).unwrap();
        let mut stmt = db
            .prepare("INSERT INTO attempts (ip_address, username, timestamp) VALUES (?1, ?2, ?3)")
            .unwrap();
        let ip_str = ip_address.to_string();
        stmt.bind((1, ip_str.as_str())).unwrap();
        stmt.bind((2, username)).unwrap();
        stmt.bind((3, timestamp)).unwrap();
        stmt.next().unwrap();
    }
    #[cfg(feature = "server")]
    pub fn score(&self, ip_address: IpAddr, username: &str) -> u64 {
        let db = self.db.lock();
        // calculate score for ip
        let ip_str = ip_address.to_string();
        let mut ip_stmt = db
            .prepare("SELECT COUNT(*) FROM attempts WHERE ip_address = ?")
            .unwrap();
        ip_stmt.bind((1, ip_str.as_str())).unwrap();
        ip_stmt.next().unwrap();
        let ip_count = u64::try_from(ip_stmt.read::<i64, _>(0).unwrap()).unwrap();
        let ip_score = ip_count * self.ip_score;
        // calculate score for username
        let mut user_stmt = db
            .prepare("SELECT COUNT(*) FROM attempts WHERE username = ?")
            .unwrap();
        user_stmt.bind((1, username)).unwrap();
        user_stmt.next().unwrap();
        let user_count = u64::try_from(user_stmt.read::<i64, _>(0).unwrap()).unwrap();
        let user_score = user_count * self.user_score;
        ip_score + user_score
    }
    #[allow(clippy::unused_self)]
    #[cfg(not(feature = "server"))]
    pub fn verify_captcha(&self, _captcha_id: Uuid, _ip: IpAddr, _value: &str) -> Result<bool> {
        unimplemented!()
    }
    #[cfg(feature = "server")]
    pub fn verify_captcha(&self, captcha_id: Uuid, ip: IpAddr, value: &str) -> Result<bool> {
        let count = {
            let db = self.db.lock();
            let mut stmt = db.prepare(
                "SELECT COUNT(*) AS c FROM captcha WHERE id = ?1 AND ip = $2 AND value = ?3",
            )?;
            stmt.bind((1, captcha_id.to_string().as_str()))?;
            stmt.bind((2, ip.to_string().as_str()))?;
            stmt.bind((3, value.to_uppercase().as_str()))?;
            stmt.next()?;
            let c = stmt.read::<i64, _>(0)?;
            // delete the captcha after checking
            if c > 0 {
                let mut del_stmt = db.prepare("DELETE FROM captcha WHERE id = ?1")?;
                del_stmt.bind((1, captcha_id.to_string().as_str()))?;
                del_stmt.next()?;
            }
            c
        };
        Ok(count > 0)
    }
    #[allow(clippy::unused_self)]
    #[cfg(not(feature = "server"))]
    pub fn get_captcha_secret(
        &self,
        _captcha_id: Uuid,
        _ip_address: IpAddr,
    ) -> Result<Option<String>> {
        unimplemented!()
    }
    #[cfg(feature = "server")]
    pub fn get_captcha_secret(
        &self,
        captcha_id: Uuid,
        ip_address: IpAddr,
    ) -> Result<Option<String>> {
        let db = self.db.lock();
        let mut stmt = db.prepare("SELECT value FROM captcha WHERE id = ?1 AND ip = ?2")?;
        stmt.bind((1, captcha_id.to_string().as_str()))?;
        stmt.bind((2, ip_address.to_string().as_str()))?;
        stmt.next()?;
        let Ok(value) = stmt.read::<String, _>(0) else {
            return Ok(None);
        };
        Ok(Some(value))
    }
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    #[cfg(not(feature = "server"))]
    pub fn need_captcha(&self, _ip_address: IpAddr, _username: &str) -> Result<Option<Uuid>> {
        Ok(None)
    }
    #[cfg(feature = "server")]
    pub fn need_captcha(&self, ip_address: IpAddr, username: &str) -> Result<Option<Uuid>> {
        if self.score(ip_address, username) < self.captcha_threshold {
            return Ok(None);
        }
        let captcha_id = Uuid::new_v4();
        // random 6 alpha chars
        let supported = Captcha::new().supported_chars();
        // select 6 random chars
        let mut rng = rand::rng();
        let s: String = (0..4)
            .map(|_| {
                let idx = rng.random_range(0..supported.len());
                supported[idx]
            })
            .collect();
        let db = self.db.lock();
        let mut stmt =
            db.prepare("INSERT INTO captcha (id, ip, value, timestamp) VALUES (?1, ?2, ?3, ?4)")?;
        stmt.bind((1, captcha_id.to_string().as_str()))?;
        stmt.bind((2, ip_address.to_string().as_str()))?;
        stmt.bind((3, s.to_uppercase().as_str()))?;
        stmt.bind((4, i64::try_from(Timestamp::now().as_secs()).unwrap()))?;
        stmt.next()?;
        Ok(Some(captcha_id))
    }
    pub fn cleanup(&self) {
        let db = self.db.lock();
        let cutoff = Timestamp::now() - self.window;
        let mut stmt = db
            .prepare("DELETE FROM attempts WHERE timestamp < ?1")
            .unwrap();
        stmt.bind((1, i64::try_from(cutoff.as_secs()).unwrap()))
            .unwrap();
        stmt.next().unwrap();
        let captcha_cutoff = Timestamp::now() - CAPTCHA_TIMEOUT;
        let mut captcha_stmt = db
            .prepare("DELETE FROM captcha WHERE timestamp < ?1")
            .unwrap();
        captcha_stmt
            .bind((1, i64::try_from(captcha_cutoff.as_secs()).unwrap()))
            .unwrap();
        captcha_stmt.next().unwrap();
    }
    pub fn spawn_cleanup_worker(self: Arc<Self>, interval: Duration) {
        tokio::task::spawn_blocking(move || {
            loop {
                std::thread::sleep(interval);
                self.cleanup();
            }
        });
    }
}
