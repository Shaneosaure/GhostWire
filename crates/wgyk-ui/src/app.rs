//! Application eframe — fenêtre principale GhostWire.
//!
//! Comportement de fermeture :
//! - Croix sans tunnel actif → ferme directement
//! - Croix avec tunnel actif → popup de confirmation
//!   - Déconnecter et Quitter : coupe puis ferme
//!   - Quitter en laissant le tunnel actif : ferme l'UI, tunnel continue
//!   - Annuler : reste sur l'app

use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui;

use crate::config::UserConfig;
use crate::ipc;
use crate::state::{
    new_shared_state, IpcResult, SharedState, TunnelInfo, TunnelState,
};

pub struct GhostWireApp {
    state: SharedState,

    // Dialogue PIN inline
    show_pin_dialog: bool,
    pin_buffer: String,
    pin_focus_requested: bool,
    pending_config_path: Option<std::path::PathBuf>,

    // IPC async
    ipc_tx: Sender<IpcResult>,
    ipc_rx: Receiver<IpcResult>,

    // Configuration utilisateur persistée
    user_config: UserConfig,
    selected_config: Option<std::path::PathBuf>,

    // Popup de confirmation de fermeture (tunnel actif)
    show_quit_confirm: bool,
}

impl GhostWireApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let state = new_shared_state();
        let user_config = UserConfig::load();

        let selected_config = user_config.last_config_path
            .as_ref()
            .filter(|p| p.exists())
            .cloned();

        if let Some(p) = &selected_config {
            tracing::info!("dernier fichier rechargé : {p:?}");
        }

        let (ipc_tx, ipc_rx) = mpsc::channel();

        // Détection d'un tunnel déjà actif au démarrage.
        match ipc::status() {
            Ok(tunnels) if !tunnels.is_empty() => {
                let t = &tunnels[0];
                tracing::info!("tunnel déjà actif détecté : '{}'", t.interface);
                let mut s = state.lock().unwrap();
                s.tunnel = TunnelState::Connected;
                s.tunnel_info = Some(TunnelInfo {
                    interface: t.interface.clone(),
                    address: "(tunnel pré-existant)".to_string(),
                    peer_endpoint: "(repris au démarrage)".to_string(),
                });
            }
            Ok(_) => tracing::debug!("aucun tunnel actif"),
            Err(e) => tracing::warn!("status check échoué : {e}"),
        }

        // Thread de repaint pour réveiller eframe (réponse IPC notamment).
        let ctx_clone = cc.egui_ctx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            ctx_clone.request_repaint();
        });

        Self {
            state,
            show_pin_dialog: false,
            pin_buffer: String::new(),
            pin_focus_requested: false,
            pending_config_path: None,
            ipc_tx,
            ipc_rx,
            user_config,
            selected_config,
            show_quit_confirm: false,
        }
    }

    // ── IPC async ─────────────────────────────────────────────────────

    fn do_connect(&mut self, pin: String) {
        let path = match self.pending_config_path.take() {
            Some(p) => p,
            None => return,
        };
        let path_str = path.to_string_lossy().to_string();
        {
            let mut s = self.state.lock().unwrap();
            s.tunnel = TunnelState::Connecting;
            s.config_path = Some(path);
        }
        let tx = self.ipc_tx.clone();
        std::thread::spawn(move || {
            let result = match ipc::connect(&path_str, "r1", pin) {
                Ok((iface, addr, peer)) => IpcResult::Connected {
                    interface: iface,
                    address: addr,
                    peer_endpoint: peer,
                },
                Err(e) => IpcResult::Error { message: e.to_string() },
            };
            let _ = tx.send(result);
        });
    }

    fn do_disconnect(&mut self) {
        let tx = self.ipc_tx.clone();
        std::thread::spawn(move || {
            let result = match ipc::disconnect() {
                Ok(iface) => IpcResult::Disconnected { interface: iface },
                Err(e) => IpcResult::Error { message: e.to_string() },
            };
            let _ = tx.send(result);
        });
    }

    fn poll_ipc_results(&mut self) {
        while let Ok(result) = self.ipc_rx.try_recv() {
            match result {
                IpcResult::Connected { interface, address, peer_endpoint } => {
                    tracing::info!("✓ tunnel '{interface}' : {address}");
                    let mut s = self.state.lock().unwrap();
                    s.tunnel = TunnelState::Connected;
                    s.last_error = None;
                    s.tunnel_info = Some(TunnelInfo { interface, address, peer_endpoint });
                }
                IpcResult::Disconnected { interface } => {
                    tracing::info!("✓ tunnel '{interface}' coupé");
                    let mut s = self.state.lock().unwrap();
                    s.tunnel = TunnelState::Disconnected;
                    s.tunnel_info = None;
                    s.last_error = None;
                    let should_quit = s.quit_after_disconnect;
                    drop(s);
                    if should_quit {
                        tracing::info!("Quit après déconnexion");
                        std::process::exit(0);
                    }
                }
                IpcResult::Error { message } => {
                    tracing::error!("IPC erreur : {message}");
                    let mut s = self.state.lock().unwrap();
                    s.tunnel = TunnelState::Disconnected;
                    s.last_error = Some(message);
                }
            }
        }
    }

    // ── Gestion de la fermeture ──────────────────────────────────────

    /// Intercepte la croix de fenêtre. Renvoie true si on doit afficher la popup.
    fn handle_close_request(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.viewport().close_requested()) {
            return;
        }

        let tunnel_state = self.state.lock().unwrap().tunnel;
        if tunnel_state == TunnelState::Connected {
            // Tunnel actif → annule la fermeture, affiche la popup.
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.show_quit_confirm = true;
        }
        // Sinon, on laisse eframe fermer naturellement.
    }

    // ── Rendu ─────────────────────────────────────────────────────────

    fn render_main_window(&mut self, ctx: &egui::Context) {
        let (tunnel_state, tunnel_info, last_error) = {
            let s = self.state.lock().unwrap();
            (s.tunnel, s.tunnel_info.clone(), s.last_error.clone())
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(16.0);

            // ── Statut ───────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                let (color, label) = match tunnel_state {
                    TunnelState::Disconnected => (egui::Color32::from_rgb(180, 60, 60),  "● Disconnected"),
                    TunnelState::Connecting   => (egui::Color32::from_rgb(200, 160, 0),  "● Connecting…"),
                    TunnelState::Connected    => (egui::Color32::from_rgb(60, 180, 80),  "● Connected"),
                };
                ui.colored_label(color, egui::RichText::new(label).size(18.0).strong());
            });

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(12.0);

            // ── Infos tunnel ─────────────────────────────────────────
            if let Some(info) = &tunnel_info {
                egui::Grid::new("info")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Interface :");
                        ui.strong(&info.interface);
                        ui.end_row();
                        ui.label("Adresse :");
                        ui.strong(&info.address);
                        ui.end_row();
                        ui.label("Peer :");
                        ui.label(&info.peer_endpoint);
                        ui.end_row();
                    });
            } else if tunnel_state == TunnelState::Disconnected {
                ui.add_space(4.0);
                ui.label("Aucun tunnel actif.");
            }

            if let Some(err) = &last_error {
                ui.add_space(8.0);
                ui.colored_label(egui::Color32::RED, format!("Erreur : {err}"));
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(12.0);

            // ── Sélection du fichier ─────────────────────────────────
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label("Configuration :");
                if let Some(p) = &self.selected_config {
                    let name = p.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "?".into());
                    ui.strong(name);
                } else {
                    ui.colored_label(egui::Color32::from_rgb(180, 100, 100),
                        "Aucun fichier sélectionné");
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                let label = if self.selected_config.is_some() {
                    "Changer de fichier…"
                } else {
                    "Choisir un fichier .conf.age…"
                };
                if ui.button(label).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Config WireGuard chiffrée", &["age"])
                        .set_title("Choisir un fichier .conf.age")
                        .pick_file()
                    {
                        self.selected_config = Some(p.clone());
                        self.user_config.last_config_path = Some(p);
                        let _ = self.user_config.save();
                    }
                }
            });

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(12.0);

            // ── Boutons / formulaire PIN ─────────────────────────────
            if self.show_pin_dialog {
                self.render_pin_form(ui);
            } else {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    let can_connect    = tunnel_state == TunnelState::Disconnected;
                    let can_disconnect = tunnel_state == TunnelState::Connected;

                    if ui.add_enabled(
                        can_connect && self.selected_config.is_some(),
                        egui::Button::new("🔒  Connect").min_size([120.0, 36.0].into()),
                    ).clicked() {
                        if let Some(path) = self.selected_config.clone() {
                            self.pending_config_path = Some(path);
                            self.pin_buffer.clear();
                            self.show_pin_dialog = true;
                            self.pin_focus_requested = true;
                        }
                    }

                    ui.add_space(8.0);

                    if ui.add_enabled(
                        can_disconnect,
                        egui::Button::new("🔓  Disconnect").min_size([120.0, 36.0].into()),
                    ).clicked() {
                        self.do_disconnect();
                    }
                });
            }

            ui.add_space(8.0);
        });

        // Popup au-dessus du panel principal.
        if self.show_quit_confirm {
            self.render_quit_confirm(ctx);
        }
    }

    fn render_pin_form(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("PIN YubiKey").strong());
            ui.add_space(6.0);

            let response = ui.add(
                egui::TextEdit::singleline(&mut self.pin_buffer)
                    .password(true)
                    .desired_width(200.0)
                    .hint_text("Entrez votre PIN…"),
            );

            if self.pin_focus_requested {
                response.request_focus();
                self.pin_focus_requested = false;
            }

            let enter_pressed = response.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                && !self.pin_buffer.is_empty();

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let ok = ui.add_enabled(
                    !self.pin_buffer.is_empty(),
                    egui::Button::new("OK"),
                ).clicked();

                let cancel = ui.button("Annuler").clicked();

                if ok || enter_pressed {
                    self.show_pin_dialog = false;
                    let pin = std::mem::take(&mut self.pin_buffer);
                    self.do_connect(pin);
                } else if cancel {
                    self.show_pin_dialog = false;
                    self.pin_buffer.clear();
                    self.pending_config_path = None;
                }
            });
            ui.add_space(4.0);
        });
    }

    fn render_quit_confirm(&mut self, ctx: &egui::Context) {
        let mut should_close       = false;
        let mut should_disco_quit  = false;
        let mut should_keep_tunnel = false;

        egui::Window::new("Quitter GhostWire")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Un tunnel est actuellement actif.").strong());
                ui.add_space(8.0);
                ui.label("Que voulez-vous faire ?");
                ui.add_space(16.0);

                ui.vertical_centered(|ui| {
                    if ui.add_sized([260.0, 32.0],
                        egui::Button::new("🔌  Déconnecter et quitter")
                    ).clicked() {
                        should_disco_quit = true;
                    }
                    ui.add_space(6.0);
                    if ui.add_sized([260.0, 32.0],
                        egui::Button::new("✓  Quitter en laissant le tunnel actif")
                    ).clicked() {
                        should_keep_tunnel = true;
                    }
                    ui.add_space(6.0);
                    if ui.add_sized([260.0, 32.0],
                        egui::Button::new("Annuler")
                    ).clicked() {
                        should_close = true;
                    }
                });
                ui.add_space(8.0);
            });

        if should_close {
            self.show_quit_confirm = false;
        } else if should_disco_quit {
            self.show_quit_confirm = false;
            self.do_disconnect();
            self.state.lock().unwrap().quit_after_disconnect = true;
        } else if should_keep_tunnel {
            tracing::info!("Quit, tunnel conservé en arrière-plan");
            std::process::exit(0);
        }
    }
}

impl eframe::App for GhostWireApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_close_request(ctx);
        self.poll_ipc_results();
        self.render_main_window(ctx);
    }
}