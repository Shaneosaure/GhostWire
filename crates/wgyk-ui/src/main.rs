//! GhostWire UI — fenêtre principale + dialogues egui.
//!
//! Tourne en utilisateur normal — toute opération privilégiée passe
//! par le service GhostWireService via Named Pipe.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod ipc;
mod state;

use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wgyk_ui=debug")),
        )
        .with_target(false)
        .init();

    tracing::info!("GhostWire UI démarrée");

    if let Err(e) = ipc::ping() {
        tracing::warn!("service injoignable au démarrage : {e}");
    } else {
        tracing::info!("✓ Service GhostWire joignable");
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("GhostWire")
            .with_inner_size([400.0, 380.0])
            .with_resizable(false),
        ..Default::default()
    };
    eframe::run_native(
        "GhostWire",
        options,
        Box::new(|cc| Ok(Box::new(app::GhostWireApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe run_native échoué : {e}"))
}