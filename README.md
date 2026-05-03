# GhostWire

<p align="center">
  <img src="assets/icons/app.png" alt="GhostWire" width="180" />
</p>

<p align="center">
  <i>A native Rust WireGuard client for Windows that keeps your private key
  on a YubiKey — and never on your disk.</i>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"></a>
  <a href="#status"><img src="https://img.shields.io/badge/release-v0.2.0-brightgreen" alt="Release: v0.2.0"></a>
  <a href="https://github.com/Shaneosaure/GhostWire/releases"><img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue" alt="Platform: Windows"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.95%2B-orange?logo=rust" alt="Rust 1.95+"></a>
  <a href="https://blog.rust-lang.org/"><img src="https://img.shields.io/badge/edition-2024-orange" alt="Rust Edition 2024"></a>
</p>

GhostWire is an open-source Windows VPN client that bridges three things
that should have always belonged together: the **WireGuard kernel driver**
(`wireguard-nt`), a **hardware-bound identity** (YubiKey PIV), and the
**`age` encryption format**. The encrypted configuration is decrypted in
RAM and pushed straight to the kernel — no plaintext ever lives on disk,
no external binaries are spawned, no PowerShell scripts in sight.

## Why

The current state of running WireGuard with a YubiKey-protected key on
Windows is grim: you write a PowerShell script that calls `age.exe` to
decrypt your config, drops the plaintext to disk, hands it to
`wireguard.exe /installtunnelservice`, then races to delete the file
before something reads it. That window of vulnerability is small, but it
exists every time you connect — which kind of defeats the point of using
a hardware token in the first place.

GhostWire closes that window by treating the cryptographic core as a
single in-process pipeline: read ciphertext → ask YubiKey to unwrap →
parse INI in memory → push to kernel. That's it. The plaintext config
lives in a `SecretBox` that's automatically zeroized when the scope
ends, the YubiKey's private key never leaves the chip, and no byte of
your real configuration is ever flushed to a filesystem.

## Project goals (the three rules)

GhostWire is built around three non-negotiable rules:

1. **Zero disk writes.** The encrypted `.conf.age` is the only file
   touched. Decryption happens in RAM. The plaintext config goes
   directly into WireGuard's kernel API. No temporary files, ever.
2. **No external binaries.** No `Command::new("age.exe")`, no
   `Command::new("wireguard.exe")`. Every cryptographic and networking
   primitive comes from a Rust crate compiled into the binary.
3. **Polite UAC.** The privileged work runs in a Windows service
   (`SYSTEM` context, network rights). The PIN dialog and main window
   run as the regular user. They communicate over a hardened named
   pipe — so connecting to a tunnel doesn't trigger a UAC popup
   every time.

## Status

**v0.2.0 — Rust 2024 modernization.** Full upgrade to the Rust 2024
edition (MSRV 1.95), modernized cryptographic stack (`secrecy 0.10`,
`age 0.11`), and a refreshed UI built on `eframe`/`egui 0.34` with the
new `logic` / `ui` separation pattern. Built on the security-hardened
foundation of v0.1.1.

What's implemented today:

### Core functionality

- ✅ **YubiKey PIV decryption** of `age`-encrypted WireGuard configs in RAM,
  with full `piv-p256` protocol implementation (no plugin, no subprocess).
- ✅ **Native INI parser** for WireGuard configs, with strict typing and
  `SecretBox`-wrapped private keys.
- ✅ **`wireguard-nt` integration** that establishes a real kernel-mode
  tunnel: handshake, routing, MTU, IP assignment all configured via the
  native API.
- ✅ **Windows service** (`wgyk-service`) running as `SYSTEM`, managing
  tunnel lifecycle independently of the UI, with proper SCM signal
  handling for graceful shutdown.
- ✅ **Hardened named-pipe IPC** between UI and service — see
  [Security](#security-notes) below for details.
- ✅ **Native GUI** (`wgyk-ui`) with `egui`/`eframe` 0.34 showing tunnel
  status, stats, and connect/disconnect controls — no UAC required
  for daily use.
- ✅ **Configuration persistence** — last-used `.conf.age` is remembered
  across launches.
- ✅ **Resume state** — UI detects a tunnel already active at startup
  (e.g. left running between sessions) and shows it as connected.
- ✅ **Graceful shutdown** — closing the window with an active tunnel
  prompts to disconnect, keep alive in background, or cancel.
- ✅ **Explicit secret drop order** — the connection flow uses an
  explicit scope to guarantee `SecretBox<>` instances holding plaintext
  config and parsed credentials are zeroized before the response is
  returned to the client. Robust under both Rust 2021 and 2024 drop
  semantics.

### Packaging & distribution

- ✅ **MSI installer** (WiX v7) with automatic service registration,
  custom branding, Start menu shortcut with icon, and clean uninstall.
- ✅ **Application icon** embedded in `wgyk-ui.exe` and shown in
  Add/Remove Programs.
- ✅ **Custom EULA** displayed during installation (GPL-3.0-or-later).
- ✅ **Automated CI/CD** — every `vX.Y.Z` git tag triggers a GitHub
  Actions workflow that builds the MSI on `windows-latest`, computes
  its SHA256, and publishes a release with both files.
- ✅ **Diagnostic CLI** (`wgyk`) with `probe`, `decrypt`, `inspect`,
  `connect`, and service-control subcommands.

### Planned for future releases

- Code signing (Authenticode) of the MSI to remove SmartScreen warnings
- Auto-update mechanism for the application
- Multiple-config management with quick switching from the UI
- Visual feedback during YubiKey touch wait (currently the UI freezes
  briefly while the user is expected to touch the device)
- In-app log viewer surfacing service-side `tracing` events

## Recent updates

- **v0.2.0** (May 2026) — Migration to Rust Edition 2024 (MSRV 1.95).
  Codebase modernized via `cargo fix --edition` and `cargo clippy --fix`,
  with explicit drop-order control for secrets in the IPC handler. Zero
  warnings in release build.
- **v0.1.3** (May 2026) — UI framework upgrade: `eframe`/`egui` 0.29 →
  0.34, adopting the new `App::ui` required method and `logic` provided
  method for cleaner separation of state updates and rendering.
- **v0.1.2** (May 2026) — Cryptographic stack refresh: `secrecy` 0.8 →
  0.10 (`Secret<T>` → `SecretBox<T>`, `CloneableSecret` impl restored),
  `age` 0.10 → 0.11 (opaque `Decryptor`, `FileKey::init_with_mut`).
  Plus `thiserror 2`, `windows 0.62`, `windows-service 0.8`, `rfd 0.17`.
- **v0.1.1** (May 2026) — IPC hardening: restricted DACL, Mandatory
  Integrity Label, concurrency limit, Connect rate limit, config path
  validation. Custom branding integrated into the MSI installer
  (icon, banner, dialog).
- **v0.1.0** (May 2026) — First functional release. End-to-end
  pipeline working: YubiKey decryption → kernel tunnel. MSI installer
  produced and distributed via GitHub Releases.

## How it works (cryptographic pipeline)

GhostWire implements the `piv-p256` stanza protocol of
[`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey)
natively — meaning it speaks the same wire format, but without the
plugin or any subprocess.

```text
                 ┌──────────────────┐
client.conf.age ─┤ Read ciphertext  │  (only disk I/O of the runtime)
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ age::Decryptor   │
                 └────────┬─────────┘
                          │  per stanza
                          ▼
              ┌─────────────────────────┐
              │ YubiKeyIdentity::       │
              │   unwrap_p256_stanza    │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  PIV ECDH (hardware)    │   ← PIN + touch (policy-dep.)
              │  on YubiKey via PC/SC   │
              └────────────┬────────────┘
                           │ shared secret (32B)
                           ▼
              ┌─────────────────────────┐
              │  HKDF-SHA256            │
              │  salt = ephem_c‖slot_c  │
              │  label = "piv-p256"     │
              └────────────┬────────────┘
                           │ wrap key (32B)
                           ▼
              ┌─────────────────────────┐
              │  ChaCha20-Poly1305      │
              │  nonce = 12×0x00        │
              └────────────┬────────────┘
                           │ file key (16B)
                           ▼
              ┌─────────────────────────┐
              │  age STREAM decrypt     │
              └────────────┬────────────┘
                           │
                           ▼
                   SecretBox<String>
                  (zeroized on drop)
                           │
                           ▼
              ┌─────────────────────────┐
              │  WireGuard INI parser   │
              └────────────┬────────────┘
                           │ WgConfig (typed)
                           ▼
              ┌─────────────────────────┐
              │ wireguard-nt::          │
              │   set_config            │
              │   set_default_route     │
              │   up                    │
              └────────────┬────────────┘
                           │
                           ▼
                Kernel WireGuard tunnel
                  (handshake + traffic)
```

The private key never leaves the YubiKey: only the ECDH input
(ephemeral public key, 65 bytes uncompressed SEC-1) goes in, and only
the shared secret (32 bytes, the X coordinate) comes out. Even on a
fully compromised machine, an attacker who steals `client.conf.age`
cannot decrypt it without physical possession of your YubiKey *and*
your PIN *and* (depending on policy) a physical touch.

## Architecture

GhostWire is a Cargo workspace with five crates:

| Crate                  | Role                                            | Privilege   |
|------------------------|-------------------------------------------------|-------------|
| `wgyk-core`            | Crypto, INI parser, IPC types                   | (library)   |
| `wgyk-service`         | Windows service: tunnel lifecycle, kernel calls | `SYSTEM`    |
| `wgyk-ui`              | Native GUI window (eframe/egui)                 | user        |
| `wgyk-cli`             | Diagnostic CLI                                  | user/admin  |
| `ghostwire-installer`  | MSI installer packaging crate                   | (build only)|

Only `wgyk-core` knows about cryptography. The service invokes it for
decryption (with the PIN forwarded by the UI through the named pipe)
and pushes the resulting `WgConfig` to `wireguard-nt`. The UI never
touches keys, never speaks PC/SC.

The UI and service are decoupled: closing the GUI does not stop the
tunnel, and the GUI can be relaunched at any time to reconnect to the
running service and pick up the current state.

## Installation (recommended)

Download the latest `GhostWire-x.y.z-x64.msi` from the
[Releases page](https://github.com/Shaneosaure/GhostWire/releases) and
double-click to install. Windows will display a SmartScreen warning
because the installer is not yet code-signed — click **More info** then
**Run anyway**.

The installer:

- Copies binaries to `C:\Program Files\GhostWire\`
- Registers and starts the Windows service `GhostWireService`
- Creates a Start menu shortcut "GhostWire"

After installation, search for "GhostWire" in the Start menu and launch
the application. The first run will prompt you to select a `.conf.age`
file — the choice is remembered for subsequent launches.

To uninstall, use the standard Windows **Settings → Apps → Installed
apps → GhostWire → Uninstall**. The service is stopped and removed
automatically.

### Verifying the download

Each release ships with a `.sha256` companion file. To verify:

```powershell
Get-FileHash GhostWire-0.2.0-x64.msi -Algorithm SHA256
# Compare with the value in GhostWire-0.2.0-x64.msi.sha256
```

## Building from source

Requirements:

- **Rust 1.95 or newer** (Edition 2024)
- Windows 10/11 (PC/SC service `SCardSvr` enabled — default)
- A YubiKey 5 series (firmware ≥ 5.2) with PIV support
- An `age` identity provisioned on a retired PIV slot (R1–R20)
- The signed `wireguard.dll` from
  [git.zx2c4.com/wireguard-nt](https://git.zx2c4.com/wireguard-nt/about/)
  placed in `assets/wireguard-nt/wireguard.dll`
- For building the MSI: [WiX Toolset v7](https://wixtoolset.org/) installed
  via `dotnet tool install --global wix` (requires .NET SDK 6.0+)

```powershell
git clone https://github.com/Shaneosaure/GhostWire.git
cd GhostWire
cargo build --workspace --release
```

The `wireguard.dll` is *not* committed to the repository — see
[`assets/wireguard-nt/README.md`](assets/wireguard-nt/README.md) for
how to obtain the signed driver from upstream.

## Building the MSI

Once the workspace is built and `wireguard.dll` is in place:

```powershell
# One-time setup: install WiX extensions
wix extension add --global WixToolset.UI.wixext/7.0.0
wix extension add --global WixToolset.Util.wixext/7.0.0

# Copy the driver next to the release binaries
Copy-Item assets\wireguard-nt\wireguard.dll target\release\wireguard.dll

# Build the MSI
cd crates\ghostwire-installer\wix
wix build -arch x64 `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -o ..\..\..\target\wix\GhostWire-0.2.0-x64.msi `
    main.wxs
cd ..\..\..
```

The MSI is produced at `target\wix\GhostWire-0.2.0-x64.msi` (~3.6 MB).

For automated builds, every git tag matching `v*` triggers a GitHub
Actions workflow that performs the same steps on a fresh
`windows-latest` runner and publishes the resulting MSI as a release
asset — see [`.github/workflows/release.yml`](.github/workflows/release.yml).

## Manual service installation (development)

If you're developing without building the MSI, the service can be
installed manually. From an elevated PowerShell:

```powershell
# Copy the WireGuard driver next to the service binary
Copy-Item assets\wireguard-nt\wireguard.dll target\release\wireguard.dll

# Install and start the service
target\release\wgyk-service.exe install
target\release\wgyk-service.exe start
```

Once installed, the GUI runs as a normal user — no UAC prompts.

## Using the GUI

```powershell
target\release\wgyk-ui.exe
```

The window shows current tunnel status, lets you select a `.conf.age`
file (the choice is remembered), connect with PIN entry, and
disconnect. If a tunnel is already active when the GUI launches, it
is detected and displayed.

Closing the window with a tunnel active prompts to either disconnect
cleanly or leave the tunnel running in the background.

## Using the CLI

The CLI exposes the full pipeline as discrete subcommands so each
layer can be tested independently. The CLI binary is named `wgyk.exe`.

```powershell
# Probe — list connected YubiKeys
wgyk probe

# Decrypt only — exercises the YubiKey + age stack
wgyk decrypt path\to\client.conf.age --slot r1

# Inspect — decrypt + parse INI, show a redacted config summary
wgyk inspect path\to\client.conf.age --slot r1

# Standalone connect — full pipeline without the service
# *** Requires running PowerShell as Administrator ***
wgyk connect path\to\client.conf.age --slot r1

# Service-mediated commands (no admin required)
wgyk service-ping
wgyk service-status
wgyk service-connect path\to\client.conf.age --slot r1
wgyk service-disconnect
```

`--slot` accepts `authentication`, `signature`, `key-management`,
`card-auth`, or `r1`–`r20`. `age-plugin-yubikey` identities live in
the retired slots by default (typically `r1`).

While a tunnel is active, it can be inspected with the standard tools:

```powershell
wg show GhostWire
Get-NetAdapter -Name GhostWire
ping <peer-internal-ip>
```

## Provisioning a YubiKey

GhostWire decrypts files that were encrypted with an existing
`age-plugin-yubikey` identity. Provisioning the identity itself is a
one-shot operation outside the runtime path of GhostWire and — by
design — uses Yubico's official tools:

```powershell
# Install the official tools (one-time)
scoop install age age-plugin-yubikey

# Generate a new PIV identity in retired slot R1
age-plugin-yubikey --generate

# List your YubiKey identities and their recipients
age-plugin-yubikey --list

# Encrypt a WireGuard config to your YubiKey recipient
age -r age1yubikey1...your-recipient... -o client.conf.age client.conf
```

This is the **only** moment external binaries are involved — and only
to set up the hardware identity. Once the identity exists, GhostWire's
runtime never invokes them.

## Security notes

GhostWire's threat model assumes an attacker may have unprivileged
local code execution on the same machine, but does not have physical
access to the YubiKey. Several layers of defense narrow what such an
attacker can achieve.

### Cryptographic core

- `SecretBox<T>` (from the [`secrecy 0.10`](https://crates.io/crates/secrecy)
  crate) wraps both the decrypted config and the WireGuard private
  key; both are zeroized automatically when dropped.
- The PIN is collected via password field in the GUI (or `rpassword`
  in the CLI), wrapped in `SecretString` from input to use, and sent
  over the named pipe to the service for the duration of one
  connection attempt only.
- **Explicit drop ordering** in the IPC connection handler: the
  decrypted plaintext and parsed config are processed inside an inner
  scope that closes before the tunnel handle is stored or the response
  is sent. This guarantees secrets are zeroized before any response
  reaches the client, regardless of the surrounding control flow or
  Rust edition (2021 vs 2024).
- Touch and PIN policies are honored by the YubiKey itself — GhostWire
  cannot bypass them, only forward what the user provides.
- A 64 KiB upper bound is enforced on decrypted plaintext to mitigate
  malicious or corrupted input.
- The `Debug` impl of internal config types redacts secrets (shown as
  `<redacted>`) so they cannot leak through error logs.

### IPC hardening (v0.1.1)

The named pipe between the user-facing UI and the `SYSTEM`-context
service is the primary attack surface for local privilege escalation.
It is hardened along five axes:

- **Restricted DACL.** Only `SYSTEM`, `Built-in Administrators`, and
  `Interactive Users` can open the pipe. Service accounts
  (`NetworkService`, `LocalService`), other-session processes, and
  unauthenticated callers are rejected by the kernel before any byte
  is read.
- **Mandatory Integrity Level.** A SACL of `(ML;;NW;;;ME)` blocks
  processes running below Medium integrity (e.g. sandboxed browser
  tabs, AppContainers) from writing to the pipe.
- **Concurrency limit.** At most four simultaneous client connections;
  excess connections are dropped immediately, preventing OS-thread
  exhaustion attacks against the service.
- **`Connect` rate limit.** Three attempts per 60-second sliding window
  — globally, not per-client. This matches the YubiKey's PIV PIN
  retry counter and prevents an attacker from bricking the applet
  with three deliberately wrong PINs.
- **Config path validation.** The `config_path` argument must be
  absolute, point to a regular file with a `.age` extension and a
  size below 64 KiB, with no UNC or device-namespace prefixes
  (`\\?\`, `\\.\`).

### DLL loading

The `wireguard.dll` driver is loaded via an absolute path resolved
from `std::env::current_exe()` rather than the Windows DLL search
order. Even if an attacker were able to plant a malicious
`wireguard.dll` somewhere on `%PATH%`, the service would not pick
it up.

### Frame size

The IPC framing layer rejects any message header declaring a payload
larger than 64 KiB *before* allocating the receive buffer, preventing
memory-exhaustion attacks against the service.

### Out of scope (yet)

- The MSI installer is **not yet code-signed** — Windows SmartScreen
  will display a warning at install time. Code signing is planned for
  a future release once a certificate is available.
- This project has not been independently audited. Treat it as
  beta-quality until that is no longer true.

## Development & testing

The parser and crypto layers have unit tests that don't require any
hardware:

```powershell
cargo test -p wgyk-core --lib
```

The full crypto integration test (which decrypts a real `.age`
fixture against a physical YubiKey) is `#[ignore]`d by default:

```powershell
$env:WGYK_TEST_PIN = "your-piv-pin"
cargo test -p wgyk-core -- --ignored
```

CI runs only the non-hardware tests; nothing in this repository
assumes a YubiKey is plugged into the build agent.

The `ghostwire-installer` binary requires UAC elevation to run its
test suite (it interacts with WiX/MSI tooling). To run the full
workspace test suite, launch PowerShell as Administrator:

```powershell
cargo test --workspace
```

## License

GhostWire is licensed under the GNU General Public License v3.0 or
later — the same family as upstream WireGuard. See [`LICENSE`](LICENSE).

The `wireguard.dll` driver, when redistributed alongside built
binaries, is covered by its own license — see
[git.zx2c4.com/wireguard-nt/about](https://git.zx2c4.com/wireguard-nt/about/).

## Acknowledgements

GhostWire would not exist without the work of:

- [Filippo Valsorda](https://filippo.io/) — `age` and the plugin protocol
- [Jack Grigg (`str4d`)](https://github.com/str4d) — `age-plugin-yubikey`
  and `yubikey-rs`
- The [`wireguard-nt`](https://crates.io/crates/wireguard-nt) crate
  maintainers for the safe Rust bindings to the kernel driver
- The [`eframe`/`egui`](https://github.com/emilk/egui) team — for an
  immediate-mode GUI library that makes Rust desktop apps actually fun
- The [WiX Toolset](https://wixtoolset.org/) team — for making MSI
  authoring something a single developer can actually do
- Jason A. Donenfeld and the WireGuard team — for the protocol, the
  kernel driver, and setting the bar for what a VPN should look like

GhostWire is not affiliated with Yubico or any of the projects above.