use std::{net::IpAddr, time::Duration};

use parking_lot::Mutex;
use serde::Deserialize;
use tracing::{error, warn};
use ttl_cache::TtlCache;
use url::Url;
use uuid::Uuid;
pub use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{DiscoverableAuthentication, PasskeyRegistration},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error, Result,
    authenticator::RandomSleeper,
    storage::Storage,
    util::{GDuration, Numeric},
};

fn default_timeout() -> GDuration {
    GDuration::from_secs(60)
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    #[zeroize(skip)]
    max_reg_challenges: Numeric,
    #[zeroize(skip)]
    max_auth_challenges: Numeric,
    #[zeroize(skip)]
    max_auth_challenges_per_ip: Option<Numeric>,
    #[serde(default = "default_timeout")]
    #[zeroize(skip)]
    timeout: GDuration,
    #[serde(default = "crate::util::default_true")]
    check_login_present: bool,
}

pub struct Factory {
    webauthn: Webauthn,
    reg_challenges: Mutex<TtlCache<String, PasskeyRegistration>>,
    login_challenges: Mutex<TtlCache<Base64UrlSafeData, (IpAddr, DiscoverableAuthentication)>>,
    timeout: Duration,
    check_login_present: bool,
    max_auth_challenges_per_ip: Option<usize>,
}

impl Factory {
    pub fn create<H>(system_hosts: &[H], config: &Config) -> Result<Self>
    where
        H: AsRef<str>,
    {
        let mut i = system_hosts.iter();
        let timeout = config.timeout.into();
        let primary_host = i
            .next()
            .ok_or(Error::invalid_data("no system hosts provided"))?
            .as_ref()
            .to_string();
        let rp_origin: Url =
            Url::parse(&format!("https://{}", primary_host)).map_err(Error::invalid_data)?;
        let webauthn = WebauthnBuilder::new(&primary_host, &rp_origin)
            .map_err(Error::invalid_data)?
            .rp_name(&primary_host)
            .timeout(timeout)
            .build()
            .map_err(Error::invalid_data)?;
        if i.next().is_some() {
            warn!(
                "Multiple system hosts are not supported for passkeys; Use {} only to manage/login with passkeys",
                primary_host
            );
        }
        Ok(Self {
            webauthn,
            reg_challenges: Mutex::new(TtlCache::new(config.max_reg_challenges.into())),
            login_challenges: Mutex::new(TtlCache::new(config.max_auth_challenges.into())),
            timeout,
            check_login_present: config.check_login_present,
            max_auth_challenges_per_ip: config.max_auth_challenges_per_ip.map(Into::into),
        })
    }
    pub fn need_check_login_present(&self) -> bool {
        self.check_login_present
    }
    pub fn start_authentication(&self, remote_ip: IpAddr) -> Result<RequestChallengeResponse> {
        if let Some(max_per_ip) = self.max_auth_challenges_per_ip {
            let count = self
                .login_challenges
                .lock()
                .iter()
                .filter(|(_, (ip, _))| *ip == remote_ip)
                .count();
            if count >= max_per_ip {
                return Err(Error::access("Too many authentication attempts"));
            }
        }
        let (challenge_response, passkey_authentication) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(Error::failed)?;
        let challenge = challenge_response.public_key.challenge.clone();
        self.login_challenges.lock().insert(
            challenge,
            (remote_ip, passkey_authentication),
            self.timeout,
        );
        Ok(challenge_response)
    }
    pub async fn finish_authentication(
        &self,
        challenge: &Base64UrlSafeData,
        auth: PublicKeyCredential,
        storage: &dyn Storage,
    ) -> Result<String> {
        let random_sleeper = RandomSleeper::new(100..200);
        let (_, passkey_authentication) = self
            .login_challenges
            .lock()
            .remove(challenge)
            .ok_or_else(|| Error::failed("no authentication in progress"))?;
        let (_, cred_id) = self
            .webauthn
            .identify_discoverable_authentication(&auth)
            .map_err(Error::failed)?;
        let Some((user, stored_passkey)) = storage.lookup_passkey(cred_id).await? else {
            random_sleeper.sleep().await;
            return Err(Error::access("No such passkey registered"));
        };
        let res = self
            .webauthn
            .finish_discoverable_authentication(
                &auth,
                passkey_authentication,
                &[stored_passkey.into()],
            )
            .map_err(Error::failed)?;
        random_sleeper.sleep().await;
        if !res.user_verified() {
            return Err(Error::access("Passkey authentication not verified"));
        }
        Ok(user)
    }
    pub fn start_registration(&self, user: &str) -> Result<CreationChallengeResponse> {
        let user_id = Uuid::new_v4();
        let (challenge_response, passkey_registration) = self
            .webauthn
            .start_passkey_registration(user_id, user, user, None)
            .map_err(Error::failed)?;
        self.reg_challenges
            .lock()
            .insert(user.to_string(), passkey_registration, self.timeout);
        Ok(challenge_response)
    }
    pub async fn finish_registration(
        &self,
        user: &str,
        reg: RegisterPublicKeyCredential,
        storage: &dyn Storage,
    ) -> Result<()> {
        let passkey_registration = self
            .reg_challenges
            .lock()
            .remove(user)
            .ok_or_else(|| Error::failed("no registration in progress"))?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg, &passkey_registration)
            .map_err(Error::failed)?;
        if let Err(e) = storage.save_passkey(user, passkey).await {
            error!(user, error = %e, "Failed to save passkey");
            return Err(e);
        }
        Ok(())
    }
}
