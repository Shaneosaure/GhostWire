//! Tray icon minimal : Afficher / Quitter + double-clic.

use anyhow::{Context, Result};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder, TrayIconEvent,
};

use crate::state::{PendingAction, SharedState};

pub struct TrayHandle {
    pub _tray: TrayIcon,
    pub id_show: MenuId,
    pub id_quit: MenuId,
}

pub fn build() -> Result<TrayHandle> {
    let menu = Menu::new();
    let item_show = MenuItem::new("Afficher GhostWire", true, None);
    let item_quit = MenuItem::new("Quitter", true, None);

    menu.append(&item_show)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_quit)?;

    let id_show = item_show.id().clone();
    let id_quit = item_quit.id().clone();

    let icon = make_icon([60, 60, 80, 255]);
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("GhostWire VPN")
        .with_icon(icon)
        .build()
        .context("construction tray icon échouée")?;

    Ok(TrayHandle { _tray: tray, id_show, id_quit })
}

/// Pompe les événements menu ET double-clic tray.
pub fn poll_events(handle: &TrayHandle, state: &SharedState) {
    // Événements menu
    let menu_rx = MenuEvent::receiver();
    while let Ok(event) = menu_rx.try_recv() {
        let action = match &event.id {
            id if *id == handle.id_show => Some(PendingAction::ShowWindow),
            id if *id == handle.id_quit => Some(PendingAction::Quit),
            _ => None,
        };
        if let Some(a) = action {
            state.lock().unwrap().pending_action = Some(a);
        }
    }

    // Double-clic sur l'icône tray
    let tray_rx = TrayIconEvent::receiver();
    while let Ok(event) = tray_rx.try_recv() {
        if matches!(event, TrayIconEvent::DoubleClick { .. }) {
            state.lock().unwrap().pending_action = Some(PendingAction::ShowWindow);
        }
    }
}

fn make_icon(rgba_color: [u8; 4]) -> tray_icon::Icon {
    let size = 16u32;
    let rgba: Vec<u8> = (0..size * size).flat_map(|_| rgba_color).collect();
    tray_icon::Icon::from_rgba(rgba, size, size).expect("icône échouée")
}