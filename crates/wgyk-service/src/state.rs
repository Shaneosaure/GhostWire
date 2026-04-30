//! État global du service : tunnels actifs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::tunnel::Tunnel;

/// Tunnels actifs, indexés par nom d'interface (ex: "GhostWire").
pub type TunnelMap = Arc<Mutex<HashMap<String, Tunnel>>>;

pub fn new_tunnel_map() -> TunnelMap {
    Arc::new(Mutex::new(HashMap::new()))
}