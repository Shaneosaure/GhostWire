//! Type d'erreur unifié de la crate.
//!
//! On utilise `thiserror` pour avoir des variantes structurées exploitables
//! par les couches supérieures (UI, service), tout en restant compatibles
//! avec `anyhow` côté binaires.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),

    #[error("YubiKey : {0}")]
    YubiKey(#[from] yubikey::Error),

    #[error("Déchiffrement age : {0}")]
    AgeDecrypt(#[from] age::DecryptError),

    #[error("Configuration invalide : {0}")]
    Config(String),

    #[error("PIN incorrect ou slot vide")]
    BadPinOrSlot,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;