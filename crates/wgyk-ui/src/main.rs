//! GhostWire UI — tray icon + dialogues egui.
//!
//! Architecture : `eframe` héberge la boucle d'événements principale,
//! le tray Windows y est rattaché. Les fenêtres PIN/settings sont des
//! viewports egui ouverts à la demande.
//!
//! Tourne en utilisateur normal — toute opération privilégiée passe
//! par le service GhostWireService via Named Pipe.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ipc;
mod state;
mod tray;

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

    // Vérifie que le service répond.
    if let Err(e) = ipc::ping() {
        tracing::warn!("service injoignable au démarrage : {e}");
    } else {
        tracing::info!("✓ Service GhostWire joignable");
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("GhostWire")
            .with_inner_size([400.0, 280.0])
            .with_resizable(false)
            .with_taskbar(true),
        ..Default::default()
    };
    eframe::run_native(
        "GhostWire",
        options,
        Box::new(|cc| Ok(Box::new(app::GhostWireApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe run_native échoué : {e}"))
}