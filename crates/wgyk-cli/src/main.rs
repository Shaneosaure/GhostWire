//! CLI de diagnostic et client du service GhostWire.
//!
//! Sous-commandes locales (sans service) :
//!   * `wgyk probe`               — liste les YubiKeys détectées
//!   * `wgyk decrypt <path>`      — déchiffre un fichier .conf.age en RAM
//!   * `wgyk inspect <path>`      — déchiffre + parse, affichage redacté
//!   * `wgyk connect <path>`      — tunnel direct (ADMIN requis)
//!
//! Sous-commandes via le service Windows (utilisateur normal) :
//!   * `wgyk service-ping`        — test de connectivité
//!   * `wgyk service-status`      — liste les tunnels actifs
//!   * `wgyk service-connect`     — établit un tunnel via le service
//!   * `wgyk service-disconnect`  — coupe le tunnel actif

use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretString};
use yubikey::piv::SlotId;

use wgyk_core::config::EndpointSpec;
use wgyk_core::ipc::{
    messages::{Request, Response},
    read_message, write_message, PIPE_NAME,
};

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
    /// Liste les YubiKeys détectées via PC/SC.
    Probe,

    /// Déchiffre un fichier client.conf.age en RAM et affiche un résumé.
    Decrypt {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Slot::Authentication)]
        slot: Slot,
        /// Affiche la config en clair sur stdout. UNIQUEMENT pour debug.
        #[arg(long)]
        show_plaintext: bool,
    },

    /// Déchiffre puis parse en WgConfig — affiche un résumé safe.
    Inspect {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Slot::R1)]
        slot: Slot,
    },

    /// Établit un tunnel WireGuard directement (NÉCESSITE droits admin).
    Connect {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Slot::R1)]
        slot: Slot,
    },

    /// Établit un tunnel via le service (PAS d'admin requis).
    /// Le service doit être installé et démarré.
    ServiceConnect {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Slot::R1)]
        slot: Slot,
    },

    /// Coupe le tunnel actif via le service.
    ServiceDisconnect,

    /// Affiche l'état des tunnels actifs côté service.
    ServiceStatus,

    /// Test de connectivité avec le service (ping/pong).
    ServicePing,
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
        Cmd::Decrypt { path, slot, show_plaintext } =>
            cmd_decrypt(path, slot.into(), show_plaintext),
        Cmd::Inspect { path, slot } =>
            cmd_inspect(path, slot.into()),
        Cmd::Connect { path, slot } =>
            cmd_connect(path, slot.into()),
        Cmd::ServiceConnect { path, slot } =>
            cmd_service_connect(path, slot.into()),
        Cmd::ServiceDisconnect => cmd_service_disconnect(),
        Cmd::ServiceStatus     => cmd_service_status(),
        Cmd::ServicePing       => cmd_service_ping(),
    }
}

// ── Commandes locales ─────────────────────────────────────────────────

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

    let pin = rpassword::prompt_password("PIN YubiKey : ")
        .context("lecture du PIN échouée")?;
    let pin = SecretString::new(pin.into());

    let cfg = wgyk_core::crypto::decrypt_config(&path, pin, slot)
        .context("déchiffrement échoué — mauvais PIN ? mauvaise slot ?")?;

    let plaintext = cfg.expose_secret();
    println!("✓ Config déchiffrée : {} octets en RAM.", plaintext.len());

    if show_plaintext {
        println!("\n--- BEGIN CONFIG (DEBUG ONLY) ---");
        println!("{plaintext}");
        println!("--- END CONFIG ---");
    } else {
        let sections: Vec<&str> = plaintext
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('[') && l.ends_with(']'))
            .collect();

        let peer_count = sections.iter().filter(|s| **s == "[Peer]").count();
        let has_iface  = sections.contains(&"[Interface]");

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
    let pin = SecretString::new(pin.into());

    let plaintext = wgyk_core::crypto::decrypt_config(&path, pin, slot)
        .context("déchiffrement échoué")?;

    let cfg = wgyk_core::config::parse(plaintext.expose_secret())
        .context("parsing INI WireGuard échoué")?;

    println!(
        "✓ Config valide ({} octets en RAM, parsée).",
        plaintext.expose_secret().len()
    );
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
                EndpointSpec::Resolved(addr) =>
                    println!("  Endpoint    : {addr} (résolu)"),
                EndpointSpec::Hostname { host, port } =>
                    println!("  Endpoint    : {host}:{port} (DNS à résoudre)"),
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

fn cmd_connect(path: PathBuf, slot: SlotId) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("fichier introuvable : {}", path.display());
    }

    let pin = rpassword::prompt_password("PIN YubiKey : ")
        .context("lecture du PIN")?;
    let pin = SecretString::new(pin.into());

    let plaintext = wgyk_core::crypto::decrypt_config(&path, pin, slot)
        .context("déchiffrement échoué")?;

    let cfg = wgyk_core::config::parse(plaintext.expose_secret())
        .context("parsing WireGuard échoué")?;

    println!("✓ Config parsée — établissement du tunnel…");

    let _tunnel = wgyk_service::tunnel::wg_nt::start_tunnel(&cfg)
        .context("impossible d'établir le tunnel")?;

    println!("✓ Tunnel GhostWire actif !");
    for addr in &cfg.interface.addresses {
        println!("  Adresse locale : {addr}");
    }
    for peer in &cfg.peers {
        if let Some(ep) = &peer.endpoint {
            match ep {
                EndpointSpec::Resolved(a) =>
                    println!("  Peer endpoint  : {a}"),
                EndpointSpec::Hostname { host, port } =>
                    println!("  Peer endpoint  : {host}:{port}"),
            }
        }
    }

    println!("\nCtrl+C pour arrêter le tunnel.");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

// ── Client IPC (Named Pipe) ───────────────────────────────────────────

/// Ouvre une connexion au pipe du service. Retourne reader + writer.
fn open_service_pipe() -> Result<(BufReader<std::fs::File>, BufWriter<std::fs::File>)> {
    let pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)
        .with_context(|| {
            format!(
                "impossible d'ouvrir le pipe {PIPE_NAME} — \
                 le service GhostWireService est-il démarré ?\n\
                 Lancer : wgyk-service start"
            )
        })?;
    let pipe_clone = pipe.try_clone().context("clone du pipe échoué")?;
    Ok((BufReader::new(pipe), BufWriter::new(pipe_clone)))
}

/// Envoie une requête au service, attend la réponse.
fn ipc_call(request: Request) -> Result<Response> {
    let (mut reader, mut writer) = open_service_pipe()?;
    write_message(&mut writer, &request).context("envoi requête échoué")?;
    let response: Response = read_message(&mut reader).context("lecture réponse échouée")?;
    Ok(response)
}

fn cmd_service_ping() -> Result<()> {
    println!("→ Ping du service…");
    match ipc_call(Request::Ping)? {
        Response::Pong => {
            println!("✓ Pong — le service répond.");
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("erreur service : {message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

fn cmd_service_status() -> Result<()> {
    match ipc_call(Request::Status)? {
        Response::Status { tunnels } => {
            if tunnels.is_empty() {
                println!("Aucun tunnel actif.");
            } else {
                println!("Tunnels actifs :");
                for t in tunnels {
                    println!(
                        "  • {} — {}",
                        t.interface,
                        if t.connected { "✓" } else { "✗" }
                    );
                }
            }
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("erreur service : {message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

fn cmd_service_connect(path: PathBuf, slot: SlotId) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("fichier introuvable : {}", path.display());
    }

    let pin = rpassword::prompt_password("PIN YubiKey : ")
        .context("lecture du PIN échouée")?;

    let slot_str = slot_to_string(&slot)?;

    // Le service tourne dans son propre CWD — il faut lui passer un chemin absolu.
    let abs_path = std::fs::canonicalize(&path)
        .context("impossible de résoudre le chemin absolu")?;

    println!("→ Demande de connexion au service…");
    let request = Request::Connect {
        config_path: abs_path.to_string_lossy().to_string(),
        slot: slot_str,
        pin, // Le service zeroize côté SYSTEM
    };

    match ipc_call(request)? {
        Response::Connected { interface, address, peer_endpoint } => {
            println!("✓ Tunnel '{interface}' établi.");
            println!("  Adresse : {address}");
            println!("  Peer    : {peer_endpoint}");
            println!();
            println!("Pour couper : wgyk service-disconnect");
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("connexion échouée : {message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

fn cmd_service_disconnect() -> Result<()> {
    println!("→ Déconnexion…");
    match ipc_call(Request::Disconnect { interface: None })? {
        Response::Disconnected { interface } => {
            println!("✓ Tunnel '{interface}' coupé.");
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("déconnexion échouée : {message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Convertit un `SlotId` en chaîne attendue par le service.
fn slot_to_string(slot: &SlotId) -> Result<String> {
    use yubikey::piv::RetiredSlotId::*;
    Ok(match slot {
        SlotId::Authentication       => "authentication".to_string(),
        SlotId::Signature            => "signature".to_string(),
        SlotId::KeyManagement        => "key-management".to_string(),
        SlotId::CardAuthentication   => "card-auth".to_string(),
        SlotId::Retired(r) => match r {
            R1=>"r1", R2=>"r2", R3=>"r3", R4=>"r4", R5=>"r5",
            R6=>"r6", R7=>"r7", R8=>"r8", R9=>"r9", R10=>"r10",
            R11=>"r11", R12=>"r12", R13=>"r13", R14=>"r14", R15=>"r15",
            R16=>"r16", R17=>"r17", R18=>"r18", R19=>"r19", R20=>"r20",
        }.to_string(),
        _ => anyhow::bail!("slot non supportée"),
    })
}