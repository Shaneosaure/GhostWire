//! CLI de diagnostic : déchiffre un `.conf.age` via YubiKey et affiche le
//! résultat *en mode debug uniquement*. C'est l'outil qu'on utilise pour
//! valider le moteur cryptographique avant d'avoir le service Windows.
//!
//! Sous-commandes :
//!   * `wgyk probe`               — liste les YubiKeys détectées
//!   * `wgyk decrypt <path>`      — déchiffre un fichier .conf.age en RAM

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretString};
use yubikey::piv::SlotId;

use wgyk_core::config::EndpointSpec;

#[derive(Parser)]
#[command(
    name = "wgyk",
    about = "WireGuard-YubiKey-Client : CLI de diagnostic",
    version,
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Déchiffre un fichier client.conf.age en RAM et affiche un résumé.
    Decrypt {
        /// Chemin vers le fichier .conf.age
        path: PathBuf,

        /// Slot PIV à utiliser (par défaut : authentication = 9a)
        #[arg(long, value_enum, default_value_t = Slot::Authentication)]
        slot: Slot,

        /// Affiche la config en clair sur stdout. À UTILISER UNIQUEMENT pour
        /// déboguer ; ne JAMAIS rediriger vers un fichier.
        #[arg(long)]
        show_plaintext: bool,
    },
    /// Déchiffre puis parse en WgConfig — affiche un résumé safe.
    /// Ne révèle JAMAIS la clé privée.
    Inspect {
        /// Chemin vers le fichier .conf.age
        path: PathBuf,

        #[arg(long, value_enum, default_value_t = Slot::R1)]
        slot: Slot,
    },

    /// Établit un tunnel WireGuard (nécessite droits admin).
    Connect {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Slot::R1)]
        slot: Slot,
    },

    /// Liste les YubiKeys détectées via PC/SC.
    Probe,
}

#[derive(Copy, Clone, ValueEnum)]
enum Slot {
    /// Slot 9a — authentification (standard PIV)
    Authentication,
    /// Slot 9c — signature numérique
    Signature,
    /// Slot 9d — gestion de clés
    KeyManagement,
    /// Slot 9e — authentification carte
    CardAuth,
    /// Slot retired R1 (0x82) — typique pour age-plugin-yubikey
    R1,
    R2, R3, R4, R5, R6, R7, R8, R9, R10,
    R11, R12, R13, R14, R15, R16, R17, R18, R19, R20,
}

impl From<Slot> for SlotId {
    fn from(s: Slot) -> Self {
        use yubikey::piv::RetiredSlotId::*;
        match s {
            Slot::Authentication => SlotId::Authentication,
            Slot::Signature      => SlotId::Signature,
            Slot::KeyManagement  => SlotId::KeyManagement,
            Slot::CardAuth       => SlotId::CardAuthentication,
            Slot::R1  => SlotId::Retired(R1),
            Slot::R2  => SlotId::Retired(R2),
            Slot::R3  => SlotId::Retired(R3),
            Slot::R4  => SlotId::Retired(R4),
            Slot::R5  => SlotId::Retired(R5),
            Slot::R6  => SlotId::Retired(R6),
            Slot::R7  => SlotId::Retired(R7),
            Slot::R8  => SlotId::Retired(R8),
            Slot::R9  => SlotId::Retired(R9),
            Slot::R10 => SlotId::Retired(R10),
            Slot::R11 => SlotId::Retired(R11),
            Slot::R12 => SlotId::Retired(R12),
            Slot::R13 => SlotId::Retired(R13),
            Slot::R14 => SlotId::Retired(R14),
            Slot::R15 => SlotId::Retired(R15),
            Slot::R16 => SlotId::Retired(R16),
            Slot::R17 => SlotId::Retired(R17),
            Slot::R18 => SlotId::Retired(R18),
            Slot::R19 => SlotId::Retired(R19),
            Slot::R20 => SlotId::Retired(R20),
        }
    }
}

fn main() -> Result<()> {
    // Logs : par défaut info, mais wgyk_core en debug pour tracer la crypto.
    // Tu peux surcharger via `$env:RUST_LOG = "trace"` avant de lancer.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,wgyk_core=debug")
            }),
        )
        .with_target(false)
        .init();

    match Cli::parse().cmd {
        Cmd::Probe => cmd_probe(),
        Cmd::Decrypt { path, slot, show_plaintext } => {
            cmd_decrypt(path, slot.into(), show_plaintext)
        },
        Cmd::Connect { path, slot } => cmd_connect(path, slot.into()),
        Cmd::Inspect { path, slot } => cmd_inspect(path, slot.into())
    }
}

fn cmd_probe() -> Result<()> {
    let yk = yubikey::YubiKey::open()
        .context("aucune YubiKey détectée — vérifie le service SCardSvr")?;

    println!("✓ YubiKey détectée");
    println!("  Série      : {}", yk.serial());
    println!("  Firmware   : {}", yk.version());
    Ok(())
}

fn cmd_decrypt(path: PathBuf, slot: SlotId, show_plaintext: bool) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("fichier introuvable : {}", path.display());
    }

    // Lecture du PIN sans écho terminal. `rpassword` zeroize le buffer
    // interne, et `SecretString` zeroize la copie qu'on en fait.
    let pin = rpassword::prompt_password("PIN YubiKey : ")
        .context("lecture du PIN échouée")?;
    let pin = SecretString::new(pin);

    let cfg = wgyk_core::crypto::decrypt_config(&path, pin, slot)
        .context("déchiffrement échoué — mauvais PIN ? mauvaise slot ?")?;

    let plaintext = cfg.expose_secret();
    println!("✓ Config déchiffrée : {} octets en RAM.", plaintext.len());

    if show_plaintext {
        println!("\n--- BEGIN CONFIG (DEBUG ONLY) ---");
        println!("{plaintext}");
        println!("--- END CONFIG ---");
    } else {
        // Aperçu sans fuite : on ne montre que les noms de section et le
        // nombre de peers, jamais les clés.
        let sections: Vec<&str> = plaintext
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('[') && l.ends_with(']'))
            .collect();

        let peer_count = sections.iter().filter(|s| **s == "[Peer]").count();
        let has_iface  = sections.iter().any(|s| *s == "[Interface]");

        println!("  Sections   : {sections:?}");
        println!("  Interface  : {}", if has_iface { "✓" } else { "✗ MANQUANTE" });
        println!("  Peers      : {peer_count}");
        println!();
        println!("Pour voir le contenu complet (déconseillé) :");
        println!("  wgyk decrypt {} --show-plaintext", path.display());
    }

    Ok(())
}

fn cmd_inspect(path: PathBuf, slot: SlotId) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("fichier introuvable : {}", path.display());
    }
    let pin = rpassword::prompt_password("PIN YubiKey : ")
        .context("lecture du PIN échouée")?;
    let pin = SecretString::new(pin);

    let plaintext = wgyk_core::crypto::decrypt_config(&path, pin, slot)
        .context("déchiffrement échoué")?;

    let cfg = wgyk_core::config::parse(plaintext.expose_secret())
        .context("parsing INI WireGuard échoué")?;

    println!("✓ Config valide ({} octets en RAM, parsée).", plaintext.expose_secret().len());
    println!();
    println!("[Interface]");
    println!("  PrivateKey  : <32 octets, scellés>");
    println!(
        "  Address     : {}",
        cfg.interface
            .addresses
            .iter()
            .map(|a: &ipnet::IpNet| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(p) = cfg.interface.listen_port {
        println!("  ListenPort  : {p}");
    }
    if let Some(m) = cfg.interface.mtu {
        println!("  MTU         : {m}");
    }
    if !cfg.interface.dns.is_empty() {
        println!(
            "  DNS         : {}",
            cfg.interface
                .dns
                .iter()
                .map(|d: &std::net::IpAddr| d.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    for (i, peer) in cfg.peers.iter().enumerate() {
        println!();
        println!("[Peer #{}]", i + 1);
        println!(
            "  PublicKey   : {}…  (fingerprint)",
            hex_short(&peer.public_key)
        );
        println!(
            "  AllowedIPs  : {}",
            peer.allowed_ips
                .iter()
                .map(|a: &ipnet::IpNet| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(ep) = &peer.endpoint {
            match ep {
                EndpointSpec::Resolved(addr) => {
                    println!("  Endpoint    : {addr} (résolu)")
                }
                EndpointSpec::Hostname { host, port } => {
                    println!("  Endpoint    : {host}:{port} (DNS à résoudre)")
                }
            }
        }
        if let Some(k) = peer.persistent_keepalive {
            println!("  Keepalive   : {k}s");
        }
        if peer.preshared_key.is_some() {
            println!("  PSK         : <présente, scellée>");
        }
    }

    Ok(())
}

fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn cmd_connect(path: PathBuf, slot: SlotId) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("fichier introuvable : {}", path.display());
    }

    let pin = rpassword::prompt_password("PIN YubiKey : ")
        .context("lecture du PIN")?;
    let pin = SecretString::new(pin);

    // 1. Déchiffrement
    let plaintext = wgyk_core::crypto::decrypt_config(&path, pin, slot)
        .context("déchiffrement échoué")?;

    // 2. Parsing
    let cfg = wgyk_core::config::parse(plaintext.expose_secret())
        .context("parsing WireGuard échoué")?;

    println!("✓ Config parsée — établissement du tunnel…");

    // 3. Tunnel kernel
    let _tunnel = wgyk_service::tunnel::start_tunnel(&cfg)
        .context("impossible d'établir le tunnel")?;

    println!("✓ Tunnel GhostWire actif !");
    for addr in &cfg.interface.addresses {
        println!("  Adresse locale : {addr}");
    }
    for peer in &cfg.peers {
        if let Some(ep) = &peer.endpoint {
            match ep {
                wgyk_core::config::EndpointSpec::Resolved(a) =>
                    println!("  Peer endpoint  : {a}"),
                wgyk_core::config::EndpointSpec::Hostname { host, port } =>
                    println!("  Peer endpoint  : {host}:{port}"),
            }
        }
    }

    println!("\nCtrl+C pour arrêter le tunnel.");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}