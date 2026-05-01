//! État partagé entre le thread tray et les éventuelles fenêtres PIN.

use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
}

pub type SharedState = Arc<Mutex<UiState>>;

#[derive(Debug)]
pub struct UiState {
    pub tunnel: TunnelState,
    pub last_error: Option<String>,
    pub config_path: Option<std::path::PathBuf>,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            tunnel: TunnelState::Disconnected,
            last_error: None,
            config_path: None,
        }
    }
}

pub fn new_shared_state() -> SharedState {
    Arc::new(Mutex::new(UiState::new()))
}