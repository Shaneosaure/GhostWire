//! Persistance de la configuration utilisateur.
//!
//! Stocke le chemin du dernier .conf.age utilisé dans
//! %APPDATA%\GhostWire\config.json.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserConfig {
    /// Dernier fichier .conf.age utilisé (chemin absolu).
    pub last_config_path: Option<PathBuf>,
    /// Dernier slot YubiKey utilisé.
    pub last_slot: Option<String>,
}

impl UserConfig {
    /// Charge la config depuis %APPDATA%\GhostWire\config.json.
    /// Retourne une config vide si le fichier n'existe pas.
    pub fn load() -> Self {
        match Self::try_load() {
            Ok(cfg) => {
                tracing::debug!("config utilisateur chargée : {cfg:?}");
                cfg
            }
            Err(e) => {
                tracing::debug!("pas de config utilisateur ({e}), valeurs par défaut");
                Self::default()
            }
        }
    }

    fn try_load() -> Result<Self> {
        let path = config_path()?;
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("lecture {path:?}"))?;
        let cfg: UserConfig =
            serde_json::from_str(&data).context("désérialisation config")?;
        Ok(cfg)
    }

    /// Sauve la config sur disque.
    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création {parent:?}"))?;
        }
        let data = serde_json::to_string_pretty(self).context("sérialisation")?;
        std::fs::write(&path, data).with_context(|| format!("écriture {path:?}"))?;
        tracing::debug!("config utilisateur sauvée : {path:?}");
        Ok(())
    }
}

fn config_path() -> Result<PathBuf> {
    let appdata = std::env::var("APPDATA").context("APPDATA non défini")?;
    Ok(PathBuf::from(appdata).join("GhostWire").join("config.json"))
}