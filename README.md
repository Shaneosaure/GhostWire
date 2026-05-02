# GhostWire

> A native Rust WireGuard client for Windows that keeps your private key
> on a YubiKey — and never on your disk.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Release: v0.1.0](https://img.shields.io/badge/release-v0.1.0-brightgreen)](#status)

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
lives in a `SecretString` that's automatically zeroized when the scope
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
   run as the regular user. They communicate over a named pipe with a
   strict DACL — so connecting to a tunnel doesn't trigger a UAC popup
   every time.

## Status

**v0.1.0 — first functional release.** A real WireGuard tunnel can be
established, hardware-authenticated, with handshake and encrypted
traffic flowing — all from a native Rust application packaged as a
single MSI installer. No external runtime dependencies.

What's implemented today:

- ✅ **YubiKey PIV decryption** of `age`-encrypted WireGuard configs in RAM,
  with full `piv-p256` protocol implementation (no plugin, no subprocess).
- ✅ **Native INI parser** for WireGuard configs, with strict typing and
  `Secret<>`-wrapped private keys.
- ✅ **`wireguard-nt` integration** that establishes a real kernel-mode
  tunnel: handshake, routing, MTU, IP assignment all configured via the
  native API.
- ✅ **Windows service** (`wgyk-service`) running as `SYSTEM`, managing
  tunnel lifecycle independently of the UI, with proper SCM signal
  handling for graceful shutdown.
- ✅ **Named-pipe IPC** between UI and service with DACL restricting
  access to local users.
- ✅ **Native GUI** (`wgyk-ui`) with `egui`/`eframe` showing tunnel
  status, stats, and connect/disconnect controls — no UAC required
  for daily use.
- ✅ **Configuration persistence** — last-used `.conf.age` is remembered
  across launches.
- ✅ **Resume state** — UI detects a tunnel already active at startup
  (e.g. left running between sessions) and shows it as connected.
- ✅ **Graceful shutdown** — closing the window with an active tunnel
  prompts to disconnect, keep alive in background, or cancel.
- ✅ **MSI installer** (WiX v7) with automatic service registration,
  Start menu shortcut, and clean uninstall.
- ✅ **Diagnostic CLI** (`wgyk`) with `probe`, `decrypt`, `inspect`,
  `connect`, and service-control subcommands.

Planned for future releases:

1. Code signing (Authenticode) of the MSI to remove SmartScreen warnings.
2. Custom EULA in the installer (currently shows placeholder text).
3. Application icon (`.ico`) for the executable and Add/Remove Programs.
4. Auto-update mechanism for the application.
5. Multiple-config management with quick switching from the UI.

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
                   SecretString
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

## Building from source

Requirements:

- Rust 1.78 or newer
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
wix extension add WixToolset.UI.wixext/7.0.0
wix extension add WixToolset.Util.wixext/7.0.0

# Build the MSI
cd crates\ghostwire-installer\wix
wix build -arch x64 `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -o ..\..\..\target\wix\GhostWire-0.1.0-x64.msi `
    main.wxs
cd ..\..\..
```

The MSI is produced at `target\wix\GhostWire-0.1.0-x64.msi` (~3.6 MB).

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

- `SecretString` (from the [`secrecy`](https://crates.io/crates/secrecy)
  crate) wraps both the decrypted config and the WireGuard private
  key; both are zeroized automatically when dropped.
- The PIN is collected via password field in the GUI (or `rpassword`
  in the CLI), wrapped in `SecretString` from input to use, and sent
  over the named pipe to the service for the duration of one
  connection attempt only.
- The named pipe DACL grants `GR;GW` to the local users group only.
- Touch and PIN policies are honored by the YubiKey itself — GhostWire
  cannot bypass them, only forward what the user provides.
- A 64 KiB upper bound is enforced on decrypted plaintext to mitigate
  malicious or corrupted input.
- The `Debug` impl of internal config types redacts secrets (shown as
  `<redacted>`) so they cannot leak through error logs.
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