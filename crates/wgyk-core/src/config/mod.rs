//! Représentation interne d'une configuration WireGuard, parsée depuis
//! le format INI standard `wg-quick`.
//!
//! Le but de ce module est uniquement de transformer une `&str` (le
//! plaintext déchiffré qu'on tient dans un `SecretString`) en types
//! Rust strictement typés, prêts à être consommés par le wrapper
//! `wireguard-nt`. Aucune logique réseau ici, aucun appel externe.
//!
//! Sécurité :
//! - La clé privée est encapsulée dans `Secret<[u8; 32]>` qui zeroize
//!   à la destruction. Elle n'est ni `Debug` ni `Display`.
//! - Les clés publiques (peers) ne sont PAS marquées secrètes : ce sont
//!   des identifiants publics par construction du protocole WireGuard.
//! - Le parser ne fait aucune E/S : il prend `&str`, rend `WgConfig`.
pub mod parser;

use std::net::SocketAddr;

use ipnet::IpNet;
use secrecy::{CloneableSecret, SecretBox};
use zeroize::Zeroize;

pub type WgKeyBytes = [u8; 32];

/// Clé privée WireGuard — zeroizée au drop, jamais affichée.
#[derive(Clone, Zeroize)]
pub struct WgPrivateKey(pub WgKeyBytes);

impl WgPrivateKey {
    pub fn as_bytes(&self) -> &WgKeyBytes {
        &self.0
    }
}

// Trait marker : autorise SecretBox<WgPrivateKey> à être cloné.
// secrecy 0.10 : le bound est `Clone + Zeroize`, qu'on a déjà via le derive.
impl CloneableSecret for WgPrivateKey {}

/// Section `[Interface]`.
#[derive(Clone)]
pub struct InterfaceConfig {
    pub private_key: SecretBox<WgPrivateKey>,
    pub addresses: Vec<IpNet>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
    pub dns: Vec<std::net::IpAddr>,
}

// Debug manuel : on ne révèle JAMAIS la clé privée.
impl std::fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceConfig")
            .field("private_key", &"<redacted>")
            .field("addresses", &self.addresses)
            .field("listen_port", &self.listen_port)
            .field("mtu", &self.mtu)
            .field("dns", &self.dns)
            .finish()
    }
}

/// Section `[Peer]`.
#[derive(Clone)]
pub struct PeerConfig {
    pub public_key: WgKeyBytes,
    pub preshared_key: Option<SecretBox<WgPrivateKey>>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<EndpointSpec>,
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("public_key", &hex_bytes(&self.public_key))
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "<redacted>"))
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

fn hex_bytes(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Endpoint : adresse résolue ou hostname à résoudre.
#[derive(Clone, Debug)]
pub enum EndpointSpec {
    Resolved(SocketAddr),
    Hostname { host: String, port: u16 },
}

/// Config complète d'un tunnel.
#[derive(Clone, Debug)]
pub struct WgConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

pub use parser::{parse, ConfigError};