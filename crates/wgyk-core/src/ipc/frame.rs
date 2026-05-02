//! Encodage des messages sur le Named Pipe : length-prefixed JSON.
//!
//! Format : [u32 LE : longueur du payload] [payload JSON UTF-8]
//!
//! Simple, sans dépendance async — compatible avec les I/O synchrones
//! des Named Pipes Windows en mode message.

use std::io::{Read, Write};

use anyhow::{anyhow, Context, Result};
use serde::{de::DeserializeOwned, Serialize};

/// Longueur maximale d'un message.
///
/// Nos messages réels font < 2 KiB (le plus gros est `Connect` avec un path
/// Windows long, ou `Status` avec plusieurs tunnels). 64 KiB laisse 30× de
/// marge — assez pour absorber l'évolution future du protocole, pas assez
/// pour permettre une attaque par allocation excessive.
const MAX_FRAME_SIZE: u32 = 64 * 1024;

/// Écrit un message sérialisé en JSON sur `writer`.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<()> {
    let payload = serde_json::to_vec(msg).context("sérialisation JSON échouée")?;
    let len = payload.len() as u32;

    if len > MAX_FRAME_SIZE {
        return Err(anyhow!("message trop grand : {len} > {MAX_FRAME_SIZE}"));
    }

    writer
        .write_all(&len.to_le_bytes())
        .context("écriture longueur frame échouée")?;
    writer
        .write_all(&payload)
        .context("écriture payload frame échouée")?;
    writer.flush().context("flush pipe échoué")?;
    Ok(())
}

/// Lit un message sérialisé en JSON depuis `reader`.
pub fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .context("lecture longueur frame échouée")?;
    let len = u32::from_le_bytes(len_buf);

    if len > MAX_FRAME_SIZE {
        return Err(anyhow!("frame trop grande : {len} > {MAX_FRAME_SIZE}"));
    }
    if len == 0 {
        return Err(anyhow!("frame vide reçue"));
    }

    let mut payload = vec![0u8; len as usize];
    reader
        .read_exact(&mut payload)
        .context("lecture payload frame échouée")?;

    serde_json::from_slice(&payload).context("désérialisation JSON échouée")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::messages::{Request, Response};

    #[test]
    fn roundtrip_request() {
        let req = Request::Connect {
            config_path: "test.conf.age".into(),
            slot: "r1".into(),
            pin: "123456".into(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();
        let decoded: Request = read_message(&mut buf.as_slice()).unwrap();
        assert!(matches!(decoded, Request::Connect { .. }));
    }

    #[test]
    fn roundtrip_response() {
        let resp = Response::Pong;
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();
        let decoded: Response = read_message(&mut buf.as_slice()).unwrap();
        assert!(matches!(decoded, Response::Pong));
    }

    #[test]
    fn roundtrip_error() {
        let resp = Response::Error {
            message: "quelque chose a raté".into(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();
        let decoded: Response = read_message(&mut buf.as_slice()).unwrap();
        assert!(matches!(decoded, Response::Error { .. }));
    }
}