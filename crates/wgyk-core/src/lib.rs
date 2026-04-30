//! Cœur métier de WireGuard-YubiKey-Client : crypto, IPC et types partagés.

pub mod config;
pub mod crypto;
pub mod error;

pub use error::{Error, Result};