use std::fmt;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::preferences::{Language, StyleType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conf {
    pub theme: StyleType,
    pub language: Language,
    pub concurrency: usize,
    pub timeout: u64,
    pub retries: usize,
    pub last_domain: Option<String>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            theme: StyleType::Dark,
            language: Language::English,
            concurrency: 50,
            timeout: 10,
            retries: 3,
            last_domain: None,
        }
    }
}

impl Conf {
    fn path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recon_results")
            .join("shadowmap_gui_config.json")
    }

    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if content.trim().is_empty() {
                    Ok(Self::default())
                } else {
                    serde_json::from_str(&content).map_err(ConfigError::from)
                }
            }
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    Ok(Self::default())
                } else {
                    Err(ConfigError::Io(err))
                }
            }
        }
    }

    pub fn store(&self) -> Result<(), ConfigError> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Serde(serde_json::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "{}", err),
            ConfigError::Serde(err) => write!(f, "{}", err),
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        ConfigError::Serde(err)
    }
}

impl std::error::Error for ConfigError {}
