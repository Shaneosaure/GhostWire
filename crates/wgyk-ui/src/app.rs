//! Application eframe — fenêtre principale + tray icon.

use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui;
use windows::Win32::Foundation::HWND;

use crate::ipc;
use crate::state::{
    new_shared_state, IpcResult, PendingAction, SharedState, TunnelInfo, TunnelState,
};
use crate::tray::{self, TrayHandle};

pub struct GhostWireApp {
    state: SharedState,
    tray: Option<TrayHandle>,
    show_pin_dialog: bool,
    pin_buffer: String,
    pin_focus_requested: bool,
    pending_config_path: Option<std::path::PathBuf>,
    ipc_tx: Sender<IpcResult>,
    ipc_rx: Receiver<IpcResult>,
    hwnd: Option<HWND>,
}

impl GhostWireApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let state = new_shared_state();

        let tray = match tray::build() {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!("tray non construit : {e:#}");
                None
            }
        };

        let (ipc_tx, ipc_rx) = mpsc::channel();

        let ctx_clone = cc.egui_ctx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            ctx_clone.request_repaint();
        });

        Self {
            state,
            tray,
            show_pin_dialog: false,
            pin_buffer: String::new(),
            pin_focus_requested: false,
            pending_config_path: None,
            ipc_tx,
            ipc_rx,
            hwnd: None,
        }
    }

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

    fn process_tray_events(&mut self, ctx: &egui::Context) {
        let action = self.state.lock().unwrap().pending_action.take();
        match action {
            None => {}
            Some(PendingAction::ShowWindow) => {
                if let Some(hwnd) = self.hwnd {
                    show_hwnd(hwnd);
                }
            }
            Some(PendingAction::Quit) => {
                tracing::info!("Quit");
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn render_main_window(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if let Some(hwnd) = self.hwnd {
                hide_hwnd(hwnd);
            }
        }

        let (tunnel_state, tunnel_info, last_error) = {
            let s = self.state.lock().unwrap();
            (s.tunnel, s.tunnel_info.clone(), s.last_error.clone())
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(16.0);

            ui.horizontal(|ui| {
                ui.add_space(8.0);
                let (color, label) = match tunnel_state {
                    TunnelState::Disconnected => (egui::Color32::from_rgb(180, 60, 60), "● Disconnected"),
                    TunnelState::Connecting   => (egui::Color32::from_rgb(200, 160, 0), "● Connecting…"),
                    TunnelState::Connected    => (egui::Color32::from_rgb(60, 180, 80), "● Connected"),
                };
                ui.colored_label(color, egui::RichText::new(label).size(18.0).strong());
            });

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(12.0);

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

            if self.show_pin_dialog {
                self.render_pin_form(ui);
            } else {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    let can_connect    = tunnel_state == TunnelState::Disconnected;
                    let can_disconnect = tunnel_state == TunnelState::Connected;

                    if ui.add_enabled(
                        can_connect,
                        egui::Button::new("🔒  Connect").min_size([120.0, 36.0].into()),
                    ).clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Config WireGuard chiffrée", &["age"])
                            .set_title("Choisir un fichier .conf.age")
                            .pick_file()
                        {
                            self.pending_config_path = Some(p);
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
}

impl eframe::App for GhostWireApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.hwnd.is_none() {
            self.hwnd = find_hwnd();
            tracing::debug!("HWND capturé : {:?}", self.hwnd);
        }

        if let Some(tray) = &self.tray {
            tray::poll_events(tray, &self.state);
        }
        self.poll_ipc_results();
        self.process_tray_events(ctx);
        self.render_main_window(ctx);
    }
}

fn find_hwnd() -> Option<HWND> {
    use windows::Win32::UI::WindowsAndMessaging::FindWindowA;
    use windows::core::PCSTR;
    unsafe {
        let title = "GhostWire\0";
        FindWindowA(PCSTR::null(), PCSTR(title.as_ptr())).ok()
    }
}

fn show_hwnd(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{
        SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };
    unsafe {
        let _ = ShowWindow(hwnd, SW_RESTORE);
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn hide_hwnd(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
    unsafe {
        let _ = ShowWindow(hwnd, SW_HIDE);
    }
}