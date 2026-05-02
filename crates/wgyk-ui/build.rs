//! Embed l'icône Windows dans le binaire wgyk-ui.exe.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/icons/app.ico");
        res.set("ProductName", "GhostWire");
        res.set("FileDescription", "GhostWire VPN Client");
        res.set("LegalCopyright", "Copyright (C) Shane");
        res.compile().expect("failed to compile Windows resources");
    }
}