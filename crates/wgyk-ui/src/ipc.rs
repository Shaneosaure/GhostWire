//! Client IPC vers le service GhostWire.
//!
//! Wrapper minimal pour ne pas dupliquer le code entre tray et dialogue PIN.

use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter};

use anyhow::{Context, Result};

use wgyk_core::ipc::{
    messages::{Request, Response},
    read_message, write_message, PIPE_NAME,
};

/// Envoie une requête au service, attend la réponse.
pub fn call(request: Request) -> Result<Response> {
    let pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)
        .with_context(|| format!("pipe {PIPE_NAME} introuvable — service démarré ?"))?;

    let pipe_clone = pipe.try_clone().context("clone du pipe échoué")?;
    let mut reader = BufReader::new(pipe);
    let mut writer = BufWriter::new(pipe_clone);

    write_message(&mut writer, &request).context("envoi requête échoué")?;
    let response: Response = read_message(&mut reader).context("lecture réponse échouée")?;
    Ok(response)
}

/// Vérifie que le service répond.
pub fn ping() -> Result<()> {
    match call(Request::Ping)? {
        Response::Pong => Ok(()),
        Response::Error { message } => anyhow::bail!("service erreur : {message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

/// Coupe le tunnel actif.
pub fn disconnect() -> Result<String> {
    match call(Request::Disconnect { interface: None })? {
        Response::Disconnected { interface } => Ok(interface),
        Response::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

/// Établit un tunnel.
pub fn connect(config_path: &str, slot: &str, pin: String) -> Result<(String, String, String)> {
    let req = Request::Connect {
        config_path: config_path.to_string(),
        slot: slot.to_string(),
        pin,
    };
    match call(req)? {
        Response::Connected { interface, address, peer_endpoint } =>
            Ok((interface, address, peer_endpoint)),
        Response::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}

/// Récupère le status des tunnels actifs.
pub fn status() -> Result<Vec<wgyk_core::ipc::messages::TunnelStatus>> {
    match call(Request::Status)? {
        Response::Status { tunnels } => Ok(tunnels),
        Response::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("réponse inattendue : {other:?}"),
    }
}