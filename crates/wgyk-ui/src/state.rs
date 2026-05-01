//! État partagé entre le tray et les fenêtres egui.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
}

impl TunnelState {
    pub fn label(self) -> &'static str {
        match self {
            TunnelState::Disconnected => "Disconnected",
            TunnelState::Connecting   => "Connecting…",
            TunnelState::Connected    => "Connected",
        }
    }
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
    /// Action demandée par le tray, à traiter au prochain frame egui.
    pub pending_action: Option<PendingAction>,
}

#[derive(Debug, Clone)]
pub enum PendingAction {
    /// Affiche la fenêtre principale.
    ShowWindow,
    /// Quitte complètement l'application.
    Quit,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            tunnel: TunnelState::Disconnected,
            last_error: None,
            config_path: None,
            tunnel_info: None,
            pending_action: None,
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