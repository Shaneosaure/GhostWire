//! GhostWire UI — tray icon + dialogue PIN.
//!
//! Tourne en utilisateur normal. Toute opération privilégiée passe par
//! le service Windows via Named Pipe (voir wgyk_core::ipc).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ipc;
mod state;
mod tray;

use anyhow::Result;

fn main() -> Result<()> {
    // En debug, on garde la console pour voir les logs.
    // En release, l'attribut `windows_subsystem = "windows"` la supprime.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wgyk_ui=debug")),
        )
        .with_target(false)
        .init();

    tracing::info!("GhostWire UI démarrée");

    tray::run()
}