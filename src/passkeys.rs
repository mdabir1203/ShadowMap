use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_STORE_PATH: &str = "configs/passkeys.json";
const DEFAULT_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(120);

fn default_timestamp() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyConfigFile {
    credentials: Vec<PasskeyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyConfig {
    credential_id: String,
    label: Option<String>,
    algorithm: PasskeyAlgorithm,
    public_key: String,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default = "default_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(default)]
    last_used: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyAlgorithm {
    Ed25519,
    P256,
}

#[derive(Clone, Debug)]
pub struct PasskeyMetadata {
    pub credential_id: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct PasskeyLogin {
    pub credential_id: String,
    pub label: Option<String>,
    pub authenticated_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("failed to read passkey store: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse passkey store: {0}")]
    InvalidStore(String),
    #[error("passkey store path points to a directory")]
    StorePathIsDirectory,
    #[error("passkey credential `{0}` is unknown")]
    UnknownCredential(String),
    #[error("no active passkey challenge")]
    NoActiveChallenge,
    #[error("passkey challenge expired")]
    ChallengeExpired,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("no local passkey available for offline authentication")]
    NoLocalPasskey,
    #[error("passkey private key is missing or invalid")]
    InvalidPrivateKey,
    #[error("failed to persist passkey store: {0}")]
    Persistence(String),
}

impl From<serde_json::Error> for PasskeyError {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidStore(err.to_string())
    }
}

impl From<ring::error::Unspecified> for PasskeyError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::VerificationFailed
    }
}

#[derive(Clone, Debug)]
struct PasskeyRecord {
    credential_id: String,
    label: Option<String>,
    algorithm: PasskeyAlgorithm,
    public_key: Vec<u8>,
    private_key: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    last_used: Option<DateTime<Utc>>,
}

impl PasskeyRecord {
    fn verify(&self, challenge: &[u8], signature: &[u8]) -> Result<(), PasskeyError> {
        match self.algorithm {
            PasskeyAlgorithm::Ed25519 => {
                let verifier = UnparsedPublicKey::new(&signature::ED25519, &self.public_key);
                verifier
                    .verify(challenge, signature)
                    .map_err(|_| PasskeyError::VerificationFailed)
            }
            PasskeyAlgorithm::P256 => {
                let verifier =
                    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &self.public_key);
                verifier
                    .verify(challenge, signature)
                    .map_err(|_| PasskeyError::VerificationFailed)
            }
        }
    }

    fn metadata(&self) -> PasskeyMetadata {
        PasskeyMetadata {
            credential_id: self.credential_id.clone(),
            label: self.label.clone(),
            created_at: self.created_at,
            last_used: self.last_used,
        }
    }

    fn software_passkey(&self) -> Option<SoftwarePasskey> {
        let material = match (&self.algorithm, &self.private_key) {
            (PasskeyAlgorithm::Ed25519, Some(bytes)) => {
                Some(SoftwareKeyMaterial::Ed25519(bytes.clone()))
            }
            _ => None,
        }?;
        Some(SoftwarePasskey {
            credential_id: self.credential_id.clone(),
            label: self.label.clone(),
            algorithm: self.algorithm,
            material,
        })
    }

    fn to_config(&self) -> PasskeyConfig {
        PasskeyConfig {
            credential_id: self.credential_id.clone(),
            label: self.label.clone(),
            algorithm: self.algorithm,
            public_key: STANDARD_NO_PAD.encode(&self.public_key),
            private_key: self
                .private_key
                .as_ref()
                .map(|bytes| STANDARD_NO_PAD.encode(bytes)),
            created_at: self.created_at,
            last_used: self.last_used,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SoftwarePasskey {
    credential_id: String,
    label: Option<String>,
    algorithm: PasskeyAlgorithm,
    material: SoftwareKeyMaterial,
}

impl SoftwarePasskey {
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    pub fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>, PasskeyError> {
        match (&self.algorithm, &self.material) {
            (PasskeyAlgorithm::Ed25519, SoftwareKeyMaterial::Ed25519(pkcs8)) => {
                let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_slice())
                    .map_err(|_| PasskeyError::InvalidPrivateKey)?;
                Ok(key_pair.sign(challenge).as_ref().to_vec())
            }
            _ => Err(PasskeyError::InvalidPrivateKey),
        }
    }
}

#[derive(Clone, Debug)]
enum SoftwareKeyMaterial {
    Ed25519(Vec<u8>),
}

#[derive(Clone, Debug)]
struct ActiveChallenge {
    challenge: [u8; 32],
    issued_at: Instant,
}

impl ActiveChallenge {
    fn expired(&self, timeout: Duration) -> bool {
        self.issued_at.elapsed() > timeout
    }
}

#[derive(Debug)]
struct PasskeyStore {
    path: PathBuf,
    records: Vec<PasskeyRecord>,
}

impl PasskeyStore {
    fn load_or_initialize(path: impl AsRef<Path>) -> Result<Self, PasskeyError> {
        let path = path.as_ref();
        if path.is_dir() {
            return Err(PasskeyError::StorePathIsDirectory);
        }

        if path.exists() {
            let contents = fs::read_to_string(path)?;
            let config: PasskeyConfigFile = serde_json::from_str(&contents)?;
            return Self::from_config(path.to_path_buf(), config);
        }

        let config = Self::bootstrap_default_config();
        let store = Self::from_config(path.to_path_buf(), config.clone())?;
        store.persist_config(&config)?;
        Ok(store)
    }

    fn from_config(path: PathBuf, config: PasskeyConfigFile) -> Result<Self, PasskeyError> {
        let mut records = Vec::with_capacity(config.credentials.len());
        for entry in config.credentials {
            let public_key = STANDARD_NO_PAD
                .decode(entry.public_key.as_bytes())
                .map_err(|err| PasskeyError::InvalidStore(err.to_string()))?;
            let private_key = match entry.private_key {
                Some(ref value) => Some(
                    STANDARD_NO_PAD
                        .decode(value.as_bytes())
                        .map_err(|err| PasskeyError::InvalidStore(err.to_string()))?,
                ),
                None => None,
            };
            records.push(PasskeyRecord {
                credential_id: entry.credential_id,
                label: entry.label,
                algorithm: entry.algorithm,
                public_key,
                private_key,
                created_at: entry.created_at,
                last_used: entry.last_used,
            });
        }
        Ok(Self { path, records })
    }

    fn bootstrap_default_config() -> PasskeyConfigFile {
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            Ed25519KeyPair::generate_pkcs8(&rng).expect("system random should provide entropy");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .expect("generated key pair should be valid");

        let mut credential_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut credential_id_bytes);
        let credential_id = URL_SAFE_NO_PAD.encode(credential_id_bytes);

        let config = PasskeyConfig {
            credential_id,
            label: Some("Local development passkey".to_string()),
            algorithm: PasskeyAlgorithm::Ed25519,
            public_key: STANDARD_NO_PAD.encode(key_pair.public_key().as_ref()),
            private_key: Some(STANDARD_NO_PAD.encode(pkcs8_bytes.as_ref())),
            created_at: Utc::now(),
            last_used: None,
        };

        PasskeyConfigFile {
            credentials: vec![config],
        }
    }

    fn persist(&self) -> Result<(), PasskeyError> {
        let config = PasskeyConfigFile {
            credentials: self
                .records
                .iter()
                .map(|record| record.to_config())
                .collect(),
        };
        self.persist_config(&config)
    }

    fn persist_config(&self, config: &PasskeyConfigFile) -> Result<(), PasskeyError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let serialized = serde_json::to_string_pretty(config)?;
        fs::write(&self.path, serialized).map_err(|err| PasskeyError::Persistence(err.to_string()))
    }

    fn get_mut(&mut self, credential_id: &str) -> Option<&mut PasskeyRecord> {
        self.records
            .iter_mut()
            .find(|record| record.credential_id == credential_id)
    }

    fn first_metadata(&self) -> Option<PasskeyMetadata> {
        self.records.first().map(|record| record.metadata())
    }

    fn first_software_passkey(&self) -> Option<SoftwarePasskey> {
        self.records
            .iter()
            .find_map(|record| record.software_passkey())
    }
}

pub struct PasskeyAuthenticator {
    store: Mutex<PasskeyStore>,
    active_challenge: Mutex<Option<ActiveChallenge>>,
    challenge_timeout: Duration,
}

impl PasskeyAuthenticator {
    pub fn open_default() -> Result<Self, PasskeyError> {
        Self::new(DEFAULT_STORE_PATH)
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self, PasskeyError> {
        let store = PasskeyStore::load_or_initialize(path)?;
        Ok(Self {
            store: Mutex::new(store),
            active_challenge: Mutex::new(None),
            challenge_timeout: DEFAULT_CHALLENGE_TIMEOUT,
        })
    }

    pub fn begin_login(&self) -> Result<PasskeyChallenge, PasskeyError> {
        let mut challenge_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut challenge_bytes);
        let issued_at = Instant::now();
        let active = ActiveChallenge {
            challenge: challenge_bytes,
            issued_at,
        };

        let mut guard = self
            .active_challenge
            .lock()
            .expect("passkey challenge mutex poisoned");
        *guard = Some(active.clone());

        Ok(PasskeyChallenge {
            challenge: challenge_bytes,
            issued_at,
        })
    }

    pub fn complete_login(
        &self,
        credential_id: &str,
        signature: &[u8],
    ) -> Result<PasskeyLogin, PasskeyError> {
        let active = {
            let mut guard = self
                .active_challenge
                .lock()
                .expect("passkey challenge mutex poisoned");
            guard.take().ok_or(PasskeyError::NoActiveChallenge)?
        };

        if active.expired(self.challenge_timeout) {
            return Err(PasskeyError::ChallengeExpired);
        }

        let mut store = self.store.lock().expect("passkey store mutex poisoned");
        let login = {
            let record = store
                .get_mut(credential_id)
                .ok_or_else(|| PasskeyError::UnknownCredential(credential_id.to_string()))?;

            record.verify(&active.challenge, signature)?;

            let authenticated_at = Utc::now();
            record.last_used = Some(authenticated_at);
            PasskeyLogin {
                credential_id: record.credential_id.clone(),
                label: record.label.clone(),
                authenticated_at,
            }
        };
        store.persist()?;

        Ok(login)
    }

    pub fn authenticate_with_local(&self) -> Result<PasskeyLogin, PasskeyError> {
        let challenge = self.begin_login()?;
        let passkey = {
            let store = self.store.lock().expect("passkey store mutex poisoned");
            store
                .first_software_passkey()
                .ok_or(PasskeyError::NoLocalPasskey)?
        };
        let signature = passkey.sign(&challenge.challenge)?;
        self.complete_login(passkey.credential_id(), &signature)
    }

    pub fn primary_passkey(&self) -> Option<PasskeyMetadata> {
        let store = self.store.lock().expect("passkey store mutex poisoned");
        store.first_metadata()
    }
}

#[derive(Clone, Debug)]
pub struct PasskeyChallenge {
    pub challenge: [u8; 32],
    pub issued_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn authenticates_with_default_passkey() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!(
            "shadowmap_passkeys_test_{}_{:?}.json",
            std::process::id(),
            Instant::now()
        ));
        if path.exists() {
            fs::remove_file(&path).ok();
        }

        let authenticator = PasskeyAuthenticator::new(&path).expect("should create passkey store");
        let login = authenticator
            .authenticate_with_local()
            .expect("local authentication should succeed");
        assert_eq!(login.label, Some("Local development passkey".to_string()));
        assert!(path.exists());

        fs::remove_file(path).ok();
    }
}
