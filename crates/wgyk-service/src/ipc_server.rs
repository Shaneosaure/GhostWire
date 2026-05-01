//! Serveur Named Pipe : écoute les requêtes du client UI/CLI.

use std::io::{BufReader, BufWriter};

use anyhow::{Context, Result};
use secrecy::SecretString;
use wgyk_core::ipc::{
    messages::{Request, Response, TunnelStatus},
    read_message, write_message, PIPE_NAME,
};

use crate::state::TunnelMap;
use crate::tunnel::wg_nt::start_tunnel;

pub fn run(tunnels: TunnelMap) -> Result<()> {
    tracing::info!("serveur IPC démarré sur {PIPE_NAME}");

    loop {
        // Crée une nouvelle instance du pipe et attend une connexion.
        let pipe = create_pipe_instance()?;

        // Clone la map pour le thread client.
        let tunnels = tunnels.clone();

        std::thread::spawn(move || {
            if let Err(e) = handle_client(pipe, tunnels) {
                tracing::warn!("client IPC déconnecté : {e:#}");
            }
        });
    }
}

fn handle_client(
    pipe: std::fs::File,
    tunnels: TunnelMap,
) -> Result<()> {
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

fn handle_request(request: Request, tunnels: &TunnelMap) -> Response {
    match request {
        Request::Ping => Response::Pong,

        Request::Status => {
            let map = tunnels.lock().unwrap();
            let list = map
                .keys()
                .map(|name| TunnelStatus {
                    interface: name.clone(),
                    address: String::new(),
                    peer_endpoint: String::new(),
                    connected: true,
                })
                .collect();
            Response::Status { tunnels: list }
        }

        Request::Connect { config_path, slot, pin } => {
            // Parse la slot.
            let slot_id = match parse_slot(&slot) {
                Ok(s) => s,
                Err(e) => return Response::Error {
                    message: format!("slot invalide '{slot}' : {e}"),
                },
            };

            let pin_secret = SecretString::new(pin);

            // Déchiffrement.
            let plaintext = match wgyk_core::crypto::decrypt_config(
                &config_path,
                pin_secret,
                slot_id,
            ) {
                Ok(p) => p,
                Err(e) => return Response::Error {
                    message: format!("déchiffrement échoué : {e:#}"),
                },
            };

            // Parsing.
            use secrecy::ExposeSecret;
            let config = match wgyk_core::config::parse(plaintext.expose_secret()) {
                Ok(c) => c,
                Err(e) => return Response::Error {
                    message: format!("parsing config échoué : {e}"),
                },
            };

            // Tunnel.
            let address = config.interface.addresses
                .first()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let peer_endpoint = config.peers.first()
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
fn create_pipe_instance() -> Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCSTR;
    use windows::Win32::Storage::FileSystem::*;
    use windows::Win32::System::Pipes::*;
    use windows::Win32::Security::*;

    // SDDL : "D:(A;;GRGW;;;WD)" = Allow (Generic Read + Generic Write) to Everyone.
    // "WD" = World (Everyone) — suffisant pour un pipe local.
    // En production on affinerait à "BU" (BUILTIN\Users) mais ça nécessite
    // ConvertStringSecurityDescriptorToSecurityDescriptor qui est plus verbeux.
    let sddl = "D:(A;;GRGW;;;WD)\0";

    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut acl_size: u32 = 0;

    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PCSTR(sddl.as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            Some(&mut acl_size),
        )
    }.context("ConvertStringSecurityDescriptorToSecurityDescriptorA échoué")?;

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
    }.context("CreateNamedPipe échoué")?;

    // Libère le security descriptor via HeapFree (LocalFree n'existe pas en windows 0.58).
    unsafe {
        windows::Win32::System::Memory::HeapFree(
            windows::Win32::System::Memory::GetProcessHeap().unwrap(),
            windows::Win32::System::Memory::HEAP_FLAGS(0),
            Some(sd.0),
        )
    }.ok();

    unsafe { ConnectNamedPipe(handle, None) }
        .context("ConnectNamedPipe échoué")?;

    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as _) })
}