//! Tray icon GhostWire avec menu contextuel.

use anyhow::{Context, Result};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};

use crate::ipc;
use crate::state::{new_shared_state, SharedState, TunnelState};

pub fn run() -> Result<()> {
    let state = new_shared_state();

    // Vérifie que le service est joignable au démarrage.
    match ipc::ping() {
        Ok(()) => tracing::info!("✓ Service GhostWire joignable"),
        Err(e) => tracing::warn!("Service injoignable : {e}"),
    }

    // Construit le menu contextuel.
    let menu = Menu::new();
    let item_connect = MenuItem::new("Connect…", true, None);
    let item_disconnect = MenuItem::new("Disconnect", false, None);
    let item_status = MenuItem::new("Status", true, None);
    let item_quit = MenuItem::new("Quit", true, None);

    menu.append(&item_connect)?;
    menu.append(&item_disconnect)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_status)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_quit)?;

    // IDs pour le dispatch dans la boucle d'événements.
    let id_connect = item_connect.id().clone();
    let id_disconnect = item_disconnect.id().clone();
    let id_status = item_status.id().clone();
    let id_quit = item_quit.id().clone();

    // Crée le tray avec une icône embarquée.
    let icon = load_icon();
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("GhostWire — Disconnected")
        .with_icon(icon)
        .build()
        .context("construction tray icon échouée")?;

    tracing::info!("Tray GhostWire démarré — clic droit sur l'icône");

    // Boucle d'événements Windows minimaliste.
    // tray-icon utilise le message loop natif Windows.
    let menu_channel = MenuEvent::receiver();
    let _tray_channel = TrayIconEvent::receiver();

    // Sur Windows, il faut une boucle de messages pour que le tray réponde.
    use winit::event_loop::{ControlFlow, EventLoop};
    let event_loop = EventLoop::builder()
        .build()
        .context("event loop winit échoué")?;
    event_loop.set_control_flow(ControlFlow::Wait);

    event_loop.run(move |_event, elwt| {
        // Pump les événements de menu (non-bloquant).
        if let Ok(event) = menu_channel.try_recv() {
            match event.id {
                id if id == id_connect => {
                    tracing::info!("Menu : Connect");
                    handle_connect(&state, &item_connect, &item_disconnect);
                }
                id if id == id_disconnect => {
                    tracing::info!("Menu : Disconnect");
                    handle_disconnect(&state, &item_connect, &item_disconnect);
                }
                id if id == id_status => {
                    tracing::info!("Menu : Status");
                    handle_status(&state);
                }
                id if id == id_quit => {
                    tracing::info!("Menu : Quit");
                    elwt.exit();
                }
                _ => {}
            }
        }
    })?;

    Ok(())
}

fn handle_connect(state: &SharedState, btn_connect: &MenuItem, btn_disconnect: &MenuItem) {
    // Pour l'instant : choisit un fichier .conf.age, demande PIN console, lance.
    // Le dialogue PIN egui sera ajouté à l'étape 4b.
    let path = match rfd::FileDialog::new()
        .add_filter("Config WireGuard chiffrée", &["age"])
        .set_title("Choisir un fichier .conf.age")
        .pick_file()
    {
        Some(p) => p,
        None => {
            tracing::info!("aucun fichier sélectionné");
            return;
        }
    };

    // Pour l'instant on prompte le PIN dans la console.
    // Ça sera remplacé par une fenêtre egui à l'étape 4b.
    let pin = match rpassword_prompt() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("PIN non fourni : {e}");
            return;
        }
    };

    {
        let mut s = state.lock().unwrap();
        s.tunnel = TunnelState::Connecting;
        s.config_path = Some(path.clone());
    }

    let path_str = path.to_string_lossy().to_string();
    match ipc::connect(&path_str, "r1", pin) {
        Ok((iface, addr, peer)) => {
            tracing::info!("✓ tunnel '{iface}' établi : {addr} → {peer}");
            let mut s = state.lock().unwrap();
            s.tunnel = TunnelState::Connected;
            s.last_error = None;
            btn_connect.set_enabled(false);
            btn_disconnect.set_enabled(true);
        }
        Err(e) => {
            tracing::error!("connexion échouée : {e:#}");
            let mut s = state.lock().unwrap();
            s.tunnel = TunnelState::Disconnected;
            s.last_error = Some(e.to_string());
        }
    }
}

fn handle_disconnect(state: &SharedState, btn_connect: &MenuItem, btn_disconnect: &MenuItem) {
    match ipc::disconnect() {
        Ok(iface) => {
            tracing::info!("✓ tunnel '{iface}' coupé");
            let mut s = state.lock().unwrap();
            s.tunnel = TunnelState::Disconnected;
            btn_connect.set_enabled(true);
            btn_disconnect.set_enabled(false);
        }
        Err(e) => {
            tracing::error!("déconnexion échouée : {e:#}");
            let mut s = state.lock().unwrap();
            s.last_error = Some(e.to_string());
        }
    }
}

fn handle_status(state: &SharedState) {
    let s = state.lock().unwrap();
    tracing::info!("État : {:?}", s.tunnel);
    if let Some(err) = &s.last_error {
        tracing::warn!("Dernière erreur : {err}");
    }
}

/// Prompt PIN console — temporaire pour 4a, remplacé par egui en 4b.
fn rpassword_prompt() -> anyhow::Result<String> {
    use std::io::{self, Write};
    print!("PIN YubiKey : ");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Génère une icône simple (placeholder rouge/vert).
fn load_icon() -> tray_icon::Icon {
    // Icône 16x16 RGBA — gris foncé pour l'instant.
    let size = 16;
    let mut rgba = Vec::with_capacity(size * size * 4);
    for _ in 0..(size * size) {
        rgba.extend_from_slice(&[60, 60, 80, 255]); // gris-bleu
    }
    tray_icon::Icon::from_rgba(rgba, size as u32, size as u32)
        .expect("création icône échouée")
}