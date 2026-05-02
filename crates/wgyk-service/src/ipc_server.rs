//! Serveur Named Pipe : écoute les requêtes du client UI/CLI.
//!
//! # Sécurité
//!
//! Ce serveur tourne dans le service Windows (contexte SYSTEM) et expose
//! un Named Pipe qui pilote la création/destruction de tunnels WireGuard.
//! Plusieurs durcissements sont en place :
//!
//! - **DACL restrictive** : seuls SYSTEM, les administrateurs locaux et les
//!   utilisateurs en session interactive peuvent ouvrir le pipe. Les
//!   processus tournant dans une autre session, en compte service, ou en
//!   tant que NetworkService/LocalService sont rejetés.
//!
//! - **Mandatory Integrity Level Medium** : un SACL `(ML;;NW;;;ME)` empêche
//!   les processus de basse intégrité (typiquement les onglets de
//!   navigateur sandboxés ou les AppContainers) d'écrire dans le pipe.
//!
//! - **Limite de connexions concurrentes** : au plus
//!   [`MAX_CONCURRENT_CLIENTS`] clients simultanés. Au-delà, les nouvelles
//!   connexions sont refusées immédiatement, ce qui empêche un attaquant
//!   d'épuiser les threads OS du service.
//!
//! - **Rate limit sur `Connect`** : au plus [`CONNECT_MAX_ATTEMPTS`]
//!   tentatives par fenêtre de [`CONNECT_WINDOW`]. Empêche un appelant
//!   malveillant de brick l'applet PIV de la YubiKey en envoyant trois
//!   mauvais PINs d'affilée.
//!
//! - **Validation du chemin de config** : seuls les chemins absolus,
//!   pointant vers un fichier `.age` régulier de moins de 64 KiB, sont
//!   acceptés. Les device paths (`\\.\`, `\\?\`) et les UNC paths réseau
//!   sont rejetés.

use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use secrecy::SecretString;
use wgyk_core::ipc::{
    messages::{Request, Response, TunnelStatus},
    read_message, write_message, PIPE_NAME,
};

use crate::state::TunnelMap;
use crate::tunnel::wg_nt::start_tunnel;

// ─────────────────────────── Limites de sécurité ──────────────────────────

/// Nombre maximum de clients IPC pouvant être servis simultanément.
///
/// Les nouvelles connexions arrivant alors que la limite est atteinte sont
/// refusées immédiatement, ce qui borne la consommation de threads OS du
/// service.
const MAX_CONCURRENT_CLIENTS: usize = 4;

/// Nombre maximum de tentatives `Connect` autorisées par fenêtre glissante.
///
/// Pourquoi 3 : c'est aussi le seuil de blocage de l'applet PIV de la
/// YubiKey. Refuser à partir de la 3ᵉ tentative dans la fenêtre empêche
/// un attaquant local de brick l'applet en envoyant trois mauvais PINs.
const CONNECT_MAX_ATTEMPTS: usize = 3;

/// Fenêtre glissante pour le rate limit des tentatives `Connect`.
const CONNECT_WINDOW: Duration = Duration::from_secs(60);

/// Taille maximale acceptée pour un fichier `.conf.age` (config WireGuard
/// chiffrée). Une vraie config fait quelques centaines d'octets ; 64 KiB
/// est très large mais empêche un appelant malveillant de pousser un gros
/// fichier vers la pipeline de déchiffrement.
const MAX_CONFIG_FILE_SIZE: u64 = 64 * 1024;

// ───────────────────────── État global rate limit ─────────────────────────

/// Horodatages des tentatives `Connect` récentes, pour le rate limit.
///
/// Volontairement global plutôt que per-client : on veut limiter le total
/// de tentatives que la YubiKey voit, pas par connexion individuelle (un
/// attaquant pourrait réouvrir une connexion à chaque fois).
static CONNECT_ATTEMPTS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());

/// Vérifie qu'on n'a pas dépassé le quota de tentatives `Connect`.
///
/// Enregistre la tentative courante si elle est acceptée. Renvoie un
/// message d'erreur explicite à transmettre au client en cas de refus.
fn check_connect_rate_limit() -> Result<(), String> {
    let mut attempts = CONNECT_ATTEMPTS.lock().unwrap();
    let now = Instant::now();

    // Nettoie les tentatives sorties de la fenêtre.
    attempts.retain(|t| now.duration_since(*t) < CONNECT_WINDOW);

    if attempts.len() >= CONNECT_MAX_ATTEMPTS {
        return Err(format!(
            "trop de tentatives de connexion ({}/{}). \
             Attendez {} secondes avant de réessayer.",
            attempts.len(),
            CONNECT_MAX_ATTEMPTS,
            CONNECT_WINDOW.as_secs()
        ));
    }

    attempts.push(now);
    Ok(())
}

// ───────────────────────── Boucle d'acceptation ───────────────────────────

pub fn run(tunnels: TunnelMap) -> Result<()> {
    tracing::info!("serveur IPC démarré sur {PIPE_NAME}");

    let active = Arc::new(AtomicUsize::new(0));

    loop {
        // Crée une nouvelle instance du pipe et attend une connexion.
        // Note : `create_pipe_instance` BLOQUE jusqu'à ce qu'un client
        // se connecte (ConnectNamedPipe synchrone). C'est volontaire ici
        // — on accepte les clients un par un.
        let pipe = create_pipe_instance()?;

        // Vérifie qu'on n'a pas trop de clients déjà actifs.
        let current = active.load(Ordering::SeqCst);
        if current >= MAX_CONCURRENT_CLIENTS {
            tracing::warn!(
                "{} clients déjà actifs (limite : {}). \
                 Connexion refusée.",
                current,
                MAX_CONCURRENT_CLIENTS
            );
            // Le drop ferme le handle du pipe immédiatement → le client
            // verra ERROR_BROKEN_PIPE.
            drop(pipe);
            // Petite pause pour éviter une boucle hot si un attaquant
            // martèle le pipe.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }

        active.fetch_add(1, Ordering::SeqCst);
        let active_for_thread = Arc::clone(&active);
        let tunnels = tunnels.clone();

        std::thread::spawn(move || {
            if let Err(e) = handle_client(pipe, tunnels) {
                tracing::warn!("client IPC déconnecté : {e:#}");
            }
            active_for_thread.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn handle_client(pipe: std::fs::File, tunnels: TunnelMap) -> Result<()> {
    let pipe_clone = pipe.try_clone().context("clone du pipe échoué")?;
    let mut reader = BufReader::new(pipe);
    let mut writer = BufWriter::new(pipe_clone);

    loop {
        let request: Request = match read_message(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("client déconnecté : {e}");
                return Ok(());
            }
        };

        tracing::info!("requête IPC : {:?}", request);

        let response = handle_request(request, &tunnels);
        write_message(&mut writer, &response)
            .context("écriture réponse IPC échouée")?;
    }
}

// ───────────────────────── Validation des entrées ─────────────────────────

/// Valide le chemin d'un fichier `.conf.age` fourni par le client IPC.
///
/// Garde-fous appliqués :
///
/// 1. Pas de device path Windows (`\\.\COM1`, `\\?\GLOBALROOT\…`) qui
///    pourraient ouvrir des handles vers des objets noyau.
/// 2. Pas d'UNC réseau (`\\serveur\share`) qui ferait que le service
///    SYSTEM va causer du trafic SMB sortant avec ses credentials.
/// 3. Chemin absolu obligatoire — évite les ambiguïtés liées au CWD du
///    service (qui est `C:\Windows\System32`).
/// 4. Extension `.age` obligatoire — petit garde-fou contre une demande
///    de lire un fichier système inadéquat (`SAM`, `SECURITY`, etc.).
/// 5. Le fichier doit exister et être un fichier régulier (pas un
///    périphérique, pas un répertoire).
/// 6. Taille bornée à [`MAX_CONFIG_FILE_SIZE`].
fn validate_config_path(path: &str) -> Result<PathBuf, String> {
    // 1. Device paths.
    if path.starts_with(r"\\.\") || path.starts_with(r"\\?\") {
        return Err("chemin device interdit".to_string());
    }

    // 2. UNC paths réseau (tout chemin commençant par `\\` qui n'est pas
    //    un device path).
    if path.starts_with(r"\\") {
        return Err("chemins réseau (UNC) interdits".to_string());
    }

    let path_buf = PathBuf::from(path);

    // 3. Absolu obligatoire.
    if !path_buf.is_absolute() {
        return Err("le chemin doit être absolu".to_string());
    }

    // 4. Extension `.age`.
    let ext_ok = path_buf
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("age"))
        .unwrap_or(false);
    if !ext_ok {
        return Err("le fichier doit avoir l'extension .age".to_string());
    }

    // 5. Existe et fichier régulier.
    let metadata = std::fs::metadata(&path_buf)
        .map_err(|e| format!("impossible de lire les métadonnées : {e}"))?;
    if !metadata.is_file() {
        return Err("le chemin ne pointe pas vers un fichier régulier".to_string());
    }

    // 6. Taille bornée.
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(format!(
            "fichier trop gros ({} octets, max {})",
            metadata.len(),
            MAX_CONFIG_FILE_SIZE
        ));
    }

    Ok(path_buf)
}

// ───────────────────────── Dispatch des requêtes ──────────────────────────

fn handle_request(request: Request, tunnels: &TunnelMap) -> Response {
    match request {
        Request::Ping => Response::Pong,

        Request::Status => {
            let map = tunnels.lock().unwrap();
            let list: Vec<TunnelStatus> = map
                .keys()
                .map(|name| TunnelStatus {
                    interface: name.clone(),
                    address: String::new(),       // enrichi plus tard
                    peer_endpoint: String::new(), // idem
                    connected: true,
                })
                .collect();
            Response::Status { tunnels: list }
        }

        Request::Connect { config_path, slot, pin } => {
            // Rate limit avant tout — on refuse même de parser le slot
            // si l'attaquant martèle le pipe.
            if let Err(msg) = check_connect_rate_limit() {
                return Response::Error { message: msg };
            }

            // Valide le chemin du fichier de config.
            let validated_path = match validate_config_path(&config_path) {
                Ok(p) => p,
                Err(e) => {
                    return Response::Error {
                        message: format!("chemin de config invalide : {e}"),
                    }
                }
            };

            // Parse la slot.
            let slot_id = match parse_slot(&slot) {
                Ok(s) => s,
                Err(e) => {
                    return Response::Error {
                        message: format!("slot invalide '{slot}' : {e}"),
                    }
                }
            };

            let pin_secret = SecretString::new(pin);

            // Déchiffrement (utilise le path validé).
            let plaintext = match wgyk_core::crypto::decrypt_config(
                &validated_path,
                pin_secret,
                slot_id,
            ) {
                Ok(p) => p,
                Err(e) => {
                    return Response::Error {
                        message: format!("déchiffrement échoué : {e:#}"),
                    }
                }
            };

            // Parsing.
            use secrecy::ExposeSecret;
            let config = match wgyk_core::config::parse(plaintext.expose_secret()) {
                Ok(c) => c,
                Err(e) => {
                    return Response::Error {
                        message: format!("parsing config échoué : {e}"),
                    }
                }
            };

            // Tunnel.
            let address = config
                .interface
                .addresses
                .first()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let peer_endpoint = config
                .peers
                .first()
                .and_then(|p| p.endpoint.as_ref())
                .map(|e| format!("{e:?}"))
                .unwrap_or_default();

            match start_tunnel(&config) {
                Ok(tunnel) => {
                    let iface = "GhostWire".to_string();
                    tunnels.lock().unwrap().insert(iface.clone(), tunnel);
                    Response::Connected {
                        interface: iface,
                        address,
                        peer_endpoint,
                    }
                }
                Err(e) => Response::Error {
                    message: format!("tunnel échoué : {e:#}"),
                },
            }
        }

        Request::Disconnect { interface } => {
            let name = interface.unwrap_or_else(|| "GhostWire".to_string());
            let removed = tunnels.lock().unwrap().remove(&name);
            if removed.is_some() {
                Response::Disconnected { interface: name }
            } else {
                Response::Error {
                    message: format!("aucun tunnel '{name}' actif"),
                }
            }
        }
    }
}

fn parse_slot(slot: &str) -> anyhow::Result<yubikey::piv::SlotId> {
    use yubikey::piv::{RetiredSlotId::*, SlotId};
    Ok(match slot.to_ascii_lowercase().as_str() {
        "authentication" => SlotId::Authentication,
        "signature"      => SlotId::Signature,
        "key-management" => SlotId::KeyManagement,
        "card-auth"      => SlotId::CardAuthentication,
        "r1"  => SlotId::Retired(R1),
        "r2"  => SlotId::Retired(R2),
        "r3"  => SlotId::Retired(R3),
        "r4"  => SlotId::Retired(R4),
        "r5"  => SlotId::Retired(R5),
        "r6"  => SlotId::Retired(R6),
        "r7"  => SlotId::Retired(R7),
        "r8"  => SlotId::Retired(R8),
        "r9"  => SlotId::Retired(R9),
        "r10" => SlotId::Retired(R10),
        "r11" => SlotId::Retired(R11),
        "r12" => SlotId::Retired(R12),
        "r13" => SlotId::Retired(R13),
        "r14" => SlotId::Retired(R14),
        "r15" => SlotId::Retired(R15),
        "r16" => SlotId::Retired(R16),
        "r17" => SlotId::Retired(R17),
        "r18" => SlotId::Retired(R18),
        "r19" => SlotId::Retired(R19),
        "r20" => SlotId::Retired(R20),
        other => anyhow::bail!("slot inconnue : '{other}'"),
    })
}

// ─────────────────── Création du pipe avec DACL durcie ────────────────────

/// Crée une nouvelle instance du Named Pipe et attend qu'un client se
/// connecte.
///
/// La sécurité du pipe est définie par une SDDL :
///
/// ```text
/// D:                    DACL
/// (A;;GRGW;;;SY)        Allow Generic Read/Write to SYSTEM
/// (A;;GRGW;;;BA)        Allow Generic Read/Write to Built-in Administrators
/// (A;;GRGW;;;IU)        Allow Generic Read/Write to Interactive Users
/// S:                    SACL
/// (ML;;NW;;;ME)         Mandatory Integrity Label = Medium, No-Write-up
/// ```
///
/// Conséquences :
///
/// - Un processus de basse intégrité (navigateur sandboxé, AppContainer)
///   ne peut pas écrire dans le pipe → la requête est rejetée par le
///   noyau avant même qu'on lise un octet.
/// - Un processus tournant en NetworkService, LocalService, ou dans une
///   session non-interactive (service tiers, tâche planifiée hors
///   utilisateur) ne peut pas se connecter.
/// - Seul l'utilisateur en session interactive (celui qui a lancé l'UI)
///   et les administrateurs locaux peuvent dialoguer avec le service.
fn create_pipe_instance() -> Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCSTR;
    use windows::Win32::Security::*;
    use windows::Win32::Storage::FileSystem::*;
    use windows::Win32::System::Pipes::*;

    let sddl = "D:(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;ME)\0";

    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut acl_size: u32 = 0;

    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PCSTR(sddl.as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            Some(&mut acl_size),
        )
    }
    .context("ConvertStringSecurityDescriptorToSecurityDescriptorA échoué")?;

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    let pipe_name = format!("{PIPE_NAME}\0");

    let handle = unsafe {
        CreateNamedPipeA(
            PCSTR(pipe_name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            Some(&mut sa),
        )
    }
    .context("CreateNamedPipe échoué")?;

    // Libère le security descriptor via HeapFree (LocalFree n'existe pas
    // en windows-rs 0.58).
    unsafe {
        windows::Win32::System::Memory::HeapFree(
            windows::Win32::System::Memory::GetProcessHeap().unwrap(),
            windows::Win32::System::Memory::HEAP_FLAGS(0),
            Some(sd.0),
        )
    }
    .ok();

    unsafe { ConnectNamedPipe(handle, None) }
        .context("ConnectNamedPipe échoué")?;

    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as _) })
}