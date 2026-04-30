//! Types de messages échangés entre le client UI et le service Windows.
//!
//! Sérialisés en JSON length-prefixed sur le Named Pipe.
//! Tous les champs sensibles (PIN) sont des `String` ici — c'est le
//! service qui les reçoit et les zeroize immédiatement après usage.

use serde::{Deserialize, Serialize};

/// Requêtes envoyées par le client (UI ou CLI) vers le service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Établit un tunnel WireGuard.
    Connect {
        /// Chemin vers le fichier `.conf.age` sur le disque.
        config_path: String,
        /// Slot PIV YubiKey (ex: "r1", "authentication").
        slot: String,
        /// PIN YubiKey — zeroizé par le service dès usage.
        pin: String,
    },

    /// Coupe le tunnel actif.
    Disconnect {
        /// Nom de l'interface à couper (ex: "GhostWire").
        /// None = coupe tous les tunnels.
        interface: Option<String>,
    },

    /// Retourne l'état de tous les tunnels actifs.
    Status,

    /// Ping de sanité — le service répond `Pong`.
    Ping,
}

/// Réponses envoyées par le service vers le client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Tunnel établi avec succès.
    Connected {
        interface: String,
        address: String,
        peer_endpoint: String,
    },

    /// Tunnel coupé avec succès.
    Disconnected {
        interface: String,
    },

    /// État actuel des tunnels.
    Status {
        tunnels: Vec<TunnelStatus>,
    },

    /// Réponse au Ping.
    Pong,

    /// Une erreur s'est produite côté service.
    Error {
        message: String,
    },
}

/// Informations sur un tunnel actif.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub interface: String,
    pub address: String,
    pub peer_endpoint: String,
    pub connected: bool,
}