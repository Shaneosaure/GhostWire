//! Wrapper safe autour de `wireguard-nt 0.5`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use secrecy::ExposeSecret;
use wireguard_nt::{Adapter, SetInterface, SetPeer};

use wgyk_core::config::{EndpointSpec, WgConfig};

const ADAPTER_NAME: &str = "GhostWire";
const ADAPTER_POOL: &str = "GhostWire";

pub struct Tunnel {
    _adapter: Adapter,
}

pub fn start_tunnel(config: &WgConfig) -> Result<Tunnel> {
    let dll_path = find_wireguard_dll()?;
    tracing::info!(?dll_path, "chargement wireguard.dll");

    let wg = unsafe { wireguard_nt::load_from_path(&dll_path) }
        .context("impossible de charger wireguard.dll")?;

    wireguard_nt::set_logger(&wg, Some(wireguard_nt::default_logger));

    let adapter = match Adapter::open(&wg, ADAPTER_NAME) {
        Ok(a) => {
            tracing::info!("adaptateur GhostWire existant réutilisé");
            a
        }
        Err(_) => {
            tracing::info!("création de l'adaptateur GhostWire…");
            Adapter::create(&wg, ADAPTER_POOL, ADAPTER_NAME, None)
                .context("Adapter::create échoué")?
        }
    };

    let private_key: [u8; 32] = *config
        .interface
        .private_key
        .expose_secret()
        .as_bytes();

    let peers = config
        .peers
        .iter()
        .map(build_set_peer)
        .collect::<Result<Vec<_>>>()?;

    let set_iface = SetInterface {
        listen_port: config.interface.listen_port,
        public_key:  None,
        private_key: Some(private_key),
        peers,
    };

    adapter
        .set_config(&set_iface)
        .context("set_config wireguard-nt échoué")?;

    tracing::info!("configuration WireGuard poussée dans le kernel");

    // set_default_route configure d'un coup :
    //  - les adresses IP de l'interface
    //  - les routes pour tous les AllowedIPs des peers
    //  - le MTU correct
    //  - l'activation de la couche media
    adapter
        .set_default_route(&config.interface.addresses, &set_iface)
        .context("set_default_route échoué")?;

    tracing::info!("routes et adresses configurées par wireguard-nt");

    // Active explicitement l'interface (passage à Status: Up).
    adapter.up().context("adapter.up() échoué")?;

    tracing::info!("tunnel GhostWire actif ✓");
    Ok(Tunnel { _adapter: adapter })
}

fn build_set_peer(p: &wgyk_core::config::PeerConfig) -> Result<SetPeer> {
    let endpoint: SocketAddr = match &p.endpoint {
        None => return Err(anyhow!("peer sans endpoint — non supporté en mode client")),
        Some(EndpointSpec::Resolved(addr)) => *addr,
        Some(EndpointSpec::Hostname { host, port }) => {
            let addr = format!("{host}:{port}")
                .to_socket_addrs()
                .with_context(|| format!("résolution DNS {host}:{port} échouée"))?
                .next()
                .ok_or_else(|| anyhow!("aucune adresse pour {host}:{port}"))?;
            tracing::info!("DNS résolu : {host}:{port} → {addr}");
            addr
        }
    };

    let preshared_key: Option<[u8; 32]> = p
        .preshared_key
        .as_ref()
        .map(|s| *s.expose_secret().as_bytes());

    Ok(SetPeer {
        public_key:    Some(p.public_key),
        preshared_key,
        endpoint,
        keep_alive:    p.persistent_keepalive,
        allowed_ips:   p.allowed_ips.clone(),
    })
}

fn find_wireguard_dll() -> Result<PathBuf> {
    // 1. À côté du binaire en cours d'exécution (production + service SYSTEM).
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("wireguard.dll");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 2. assets/wireguard-nt/ relatif au CWD (développement depuis CLI).
    let dev = PathBuf::from("assets/wireguard-nt/wireguard.dll");
    if dev.exists() {
        return Ok(dev);
    }

    // 3. Même dossier que le binaire + sous-dossier wireguard-nt (layout release).
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.parent()
            .map(|p| p.join("wireguard-nt").join("wireguard.dll"))
            .unwrap_or_default();
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "wireguard.dll introuvable — \
         place-la à côté du binaire ou dans assets/wireguard-nt/"
    ))
}
