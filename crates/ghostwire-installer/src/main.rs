//! Crate de packaging pour GhostWire.
//!
//! Ce binaire ne fait rien à l'exécution — il existe uniquement pour
//! servir de cible à `cargo wix`, qui génère le MSI à partir du
//! workspace. Le vrai installeur est défini dans `wix/main.wxs`.

fn main() {
    eprintln!("ghostwire-installer is a packaging crate.");
    eprintln!("Run `cargo wix -p ghostwire-installer` to build the MSI.");
    std::process::exit(1);
}