//! Lifecycle SCM (Service Control Manager) Windows.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode,
        ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
    service::{ServiceAccess, ServiceInfo, ServiceStartType, ServiceErrorControl},
};

use crate::ipc_server;
use crate::state::new_tunnel_map;

const SERVICE_NAME: &str = "GhostWireService";
const SERVICE_DISPLAY: &str = "GhostWire VPN Service";
const SERVICE_DESC: &str =
    "Gère les tunnels WireGuard de GhostWire. Ne pas arrêter manuellement.";

/// Macro windows-service : enregistre le point d'entrée SCM.
define_windows_service!(ffi_service_main, service_main);

/// Appelé par Windows quand le service démarre.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service terminé avec erreur : {e:#}");
    }
}

fn run_service() -> Result<()> {
    use std::sync::mpsc;

    let tunnels = new_tunnel_map();
    let tunnels_for_handler = tunnels.clone();

    // Canal pour signaler l'arrêt depuis le handler SCM vers la boucle principale.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop => {
                tracing::info!("SCM → Stop reçu");
                // Coupe tous les tunnels actifs (Drop nettoie le kernel).
                tunnels_for_handler.lock().unwrap().clear();
                // Signale à la boucle principale qu'il faut sortir.
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("enregistrement handler SCM échoué")?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    })?;

    // Démarre le serveur IPC dans un thread dédié.
    let tunnels_for_ipc = tunnels.clone();
    std::thread::spawn(move || {
        if let Err(e) = ipc_server::run(tunnels_for_ipc) {
            tracing::error!("serveur IPC terminé avec erreur : {e:#}");
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    tracing::info!("service GhostWire démarré ✓");

    // Boucle principale : attend le signal d'arrêt SCM.
    // recv() bloque jusqu'à ce que le handler envoie sur le canal.
    let _ = shutdown_rx.recv();

    tracing::info!("arrêt du service en cours…");

    // Signale au SCM que le service s'arrête proprement.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    Ok(())
}

/// Installe le service dans le SCM Windows. Nécessite admin.
pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE,
    ).context("impossible d'ouvrir le SCM")?;

    let exe = std::env::current_exe()
        .context("impossible de trouver le chemin de l'exécutable")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None,   // None = LocalSystem (SYSTEM)
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .context("création du service échouée")?;

    service
        .set_description(SERVICE_DESC)
        .context("définition description service échouée")?;

    println!("✓ Service '{SERVICE_NAME}' installé.");
    println!("  Démarrez avec : wgyk-service start");
    Ok(())
}

/// Désinstalle le service.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    ).context("impossible d'ouvrir le SCM")?;

    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP)
        .context("service introuvable — déjà désinstallé ?")?;

    // Tente d'arrêter avant de supprimer.
    let _ = service.stop();
    std::thread::sleep(Duration::from_secs(1));

    service.delete().context("suppression du service échouée")?;
    println!("✓ Service '{SERVICE_NAME}' désinstallé.");
    Ok(())
}

/// Démarre le service via le SCM.
pub fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    ).context("impossible d'ouvrir le SCM")?;

    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .context("service introuvable — installez-le d'abord")?;

    service.start(&[] as &[&str]).context("démarrage du service échoué")?;
    println!("✓ Service '{SERVICE_NAME}' démarré.");
    Ok(())
}

/// Arrête le service via le SCM.
pub fn stop() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    ).context("impossible d'ouvrir le SCM")?;

    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("service introuvable")?;

    service.stop().context("arrêt du service échoué")?;
    println!("✓ Service '{SERVICE_NAME}' arrêté.");
    Ok(())
}

/// Point d'entrée appelé par Windows (via `service_dispatcher`).
pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("impossible de démarrer le dispatcher SCM")
}