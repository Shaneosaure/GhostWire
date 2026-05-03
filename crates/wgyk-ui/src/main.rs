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

    let icon = load_icon();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 480.0])
            .with_min_inner_size([400.0, 360.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "GhostWire",
        native_options,
        Box::new(|cc| Ok(Box::new(crate::app::GhostWireApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe run_native échoué : {e}"))
}

fn load_icon() -> egui::IconData {
    // L'icône est embed via winresource dans build.rs (pour l'exe).
    // Pour la fenêtre runtime, on charge un PNG depuis les assets.
    // Si tu veux, fournis aussi un PNG 256x256 dans assets/icons/app.png
    let bytes = include_bytes!("../../../assets/icons/app.png");
    let image = image::load_from_memory(bytes)
        .expect("failed to decode app icon")
        .into_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}