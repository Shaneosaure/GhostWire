//! IPC entre le service SYSTEM et le client utilisateur via Named Pipe.
//!
//! Nom du pipe : `\\.\pipe\GhostWireService`
//! Protocole   : JSON length-prefixed (voir `frame.rs`)

pub mod frame;
pub mod messages;

pub use messages::{Request, Response, TunnelStatus};
pub use frame::{read_message, write_message};

/// Nom complet du Named Pipe Windows.
pub const PIPE_NAME: &str = r"\\.\pipe\GhostWireService";