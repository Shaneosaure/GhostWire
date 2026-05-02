//! État partagé entre threads (IPC + UI).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub interface: String,
    pub address: String,
    pub peer_endpoint: String,
}

#[derive(Debug)]
pub struct UiState {
    pub tunnel: TunnelState,
    pub last_error: Option<String>,
    pub config_path: Option<PathBuf>,
    pub tunnel_info: Option<TunnelInfo>,
    /// Quand true, on ferme l'app dès que la déconnexion est confirmée.
    pub quit_after_disconnect: bool,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            tunnel: TunnelState::Disconnected,
            last_error: None,
            config_path: None,
            tunnel_info: None,
            quit_after_disconnect: false,
        }
    }
}

pub type SharedState = Arc<Mutex<UiState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(Mutex::new(UiState::new()))
}

#[derive(Debug, Clone)]
pub enum IpcResult {
    Connected { interface: String, address: String, peer_endpoint: String },
    Disconnected { interface: String },
    Error { message: String },
}