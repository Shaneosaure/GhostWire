//! Point d'entrée du service Windows GhostWire.
//!
//! Usage :
//!   wgyk-service install    — installe le service dans le SCM
//!   wgyk-service uninstall  — supprime le service
//!   wgyk-service start      — démarre le service
//!   wgyk-service stop       — arrête le service
//!   wgyk-service run        — appelé par Windows (ne pas lancer manuellement)

mod tunnel;
mod service;
mod ipc_server;
mod state;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wgyk_service=debug")),
        )
        .with_target(false)
        .init();

    let arg = std::env::args().nth(1).unwrap_or_default();

    match arg.as_str() {
        "install"   => service::install().context("installation du service échouée"),
        "uninstall" => service::uninstall().context("désinstallation du service échouée"),
        "start"     => service::start().context("démarrage du service échoué"),
        "stop"      => service::stop().context("arrêt du service échoué"),
        "run"       => service::run().context("exécution du service échouée"),
        other => {
            eprintln!("Usage: wgyk-service <install|uninstall|start|stop|run>");
            eprintln!("Argument inconnu : '{other}'");
            std::process::exit(1);
        }
    }
}