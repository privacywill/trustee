use chrono::{DateTime, Utc};
use jsonwebtoken::jwk::{self, Jwk};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
const DEFAULT_KEY_ALGORITHM: jwk::KeyAlgorithm = jwk::KeyAlgorithm::ES256;
use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{error, info};
use openssl::bn::{BigNum, BigNumContext};
use openssl::pkey::Private;
use tokio::time::interval;
#[derive(Clone)]
pub struct JwkWithKey {
    pub kid: String,
    pub _created_at: DateTime<Utc>,
    pub private_key: EcKey<Private>,
    pub jwk: Jwk,
}

#[derive(Clone)]
pub struct KeyManager {
    current: Arc<RwLock<JwkWithKey>>,
    previous: Arc<RwLock<Option<JwkWithKey>>>,
}

pub const DEFAULT_RATATIION_DURATION: u64 = 7;

impl KeyManager {
    // generate a ES256 jwk
    fn generate_key() -> Result<JwkWithKey> {
        let key_id = Uuid::new_v4().to_string();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let private_key = EcKey::generate(&group)?;

        let public_key = private_key.public_key();
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        public_key.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

        let common = jwk::CommonParameters {
            key_id: Some(key_id),
            public_key_use: Some(jwk::PublicKeyUse::Signature),
            key_algorithm: Some(DEFAULT_KEY_ALGORITHM),
            ..Default::default()
        };
        let algorithm = jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
            key_type: jwk::EllipticCurveKeyType::EC,
            curve: jwk::EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x.to_vec()),
            y: URL_SAFE_NO_PAD.encode(y.to_vec()),
        });
        let jwk = jwk::Jwk { common, algorithm };
        Ok(JwkWithKey {
            kid: Uuid::new_v4().to_string(),
            _created_at: Utc::now(),
            private_key: private_key,
            jwk: jwk,
        })
    }

    pub fn new() -> Result<Arc<Self>> {
        let key = Self::generate_key()?;
        Ok(Arc::new(KeyManager {
            current: Arc::new(RwLock::new(key)),
            previous: Arc::new(RwLock::new(None)),
        }))
    }

    pub async fn rotate(&self) -> Result<()> {
        let new_key = Self::generate_key()?;
        let mut prev = self.previous.write().await;
        let mut curr = self.current.write().await;
        *prev = Some(curr.clone());
        *curr = new_key;
        Ok(())
    }

    pub async fn get_current_key(&self) -> Result<EcKey<Private>> {
        Ok(self.current.read().await.private_key.clone())
    }

    pub async fn get_current_jwk(&self) -> Result<Jwk> {
        Ok(self.current.read().await.jwk.clone())
    }

    pub async fn get_current_kid(&self) -> String {
        self.current.read().await.kid.clone()
    }

    pub async fn get_jwks(&self) -> Vec<Jwk> {
        let mut res = vec![];
        res.push(self.current.read().await.jwk.clone());
        let prev = self.previous.read().await;
        if let Some(ref pk) = *prev {
            res.push(pk.jwk.clone())
        }
        res
    }

    pub fn start_rotation_task(self: Arc<Self>, period: std::time::Duration) {
        tokio::spawn(async move {
            let mut ticker = interval(period);
            loop {
                ticker.tick().await;
                if self.rotate().await.is_err() {
                    error!("failed to roate jwk!");
                    continue;
                }
                info!("jwk roated to {}", self.get_current_kid().await)
            }
        });
    }
}
