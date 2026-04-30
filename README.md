# GhostWire

> A native Rust WireGuard client for Windows that keeps your private key
> on a YubiKey — and never on your disk.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)](#status)

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
   (`SYSTEM` context, network rights). The PIN dialog and tray icon
   run as the regular user. They communicate over a named pipe with a
   strict DACL — so connecting to a tunnel doesn't trigger a UAC popup
   every time.

## Status

**Working end-to-end VPN client.** A real WireGuard tunnel can be
established, hardware-authenticated, with handshake and encrypted
traffic flowing — all from a single Rust binary.

What's implemented today:

- ✅ **YubiKey PIV decryption** of `age`-encrypted WireGuard configs in RAM,
  with full `piv-p256` protocol implementation (no plugin, no subprocess).
- ✅ **Native INI parser** for WireGuard configs, with strict typing and
  `Secret<>`-wrapped private keys.
- ✅ **`wireguard-nt` integration** that establishes a real kernel-mode
  tunnel: handshake, routing, MTU, IP assignment all configured via the
  native API.
- ✅ **Diagnostic CLI** (`wgyk`) with `probe`, `decrypt`, `inspect`, and
  `connect` subcommands — useful both for development and as a smoke test.
- ✅ **Workspace structure** ready to host the Windows service and tray UI.

What's not yet implemented (planned, in this order):

1. Windows service (`wgyk-service`) — SCM lifecycle, runs as `SYSTEM`
   so the user-facing UI doesn't need administrator rights.
2. Named-pipe IPC with DACL-restricted access between UI and service.
3. Tray icon + PIN entry dialog (`wgyk-ui`).
4. Disconnect / reconnect commands and tunnel state persistence.
5. WiX installer (MSI) that registers the service.

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

GhostWire is a Cargo workspace with four crates:

| Crate           | Role                                            | Privilege          |
|-----------------|-------------------------------------------------|--------------------|
| `wgyk-core`     | Crypto, INI parser, IPC types                   | (library)          |
| `wgyk-service`  | Windows service: tunnel lifecycle, kernel calls | `SYSTEM` (planned) |
| `wgyk-ui`       | Tray icon + PIN dialog                          | user (planned)     |
| `wgyk-cli`      | Diagnostic CLI (no service, no UI)              | admin (today)      |

Only `wgyk-core` knows about cryptography. The service will invoke it
for decryption (with the PIN forwarded by the UI through the named
pipe) and push the resulting `WgConfig` to `wireguard-nt`. The UI
never touches keys, never speaks PC/SC.

## Building

Requirements:

- Rust 1.78 or newer
- Windows 10/11 (PC/SC service `SCardSvr` enabled — default)
- A YubiKey 5 series (firmware ≥ 5.2) with PIV support
- An `age` identity provisioned on a retired PIV slot (R1–R20)
- The signed `wireguard.dll` from
  [git.zx2c4.com/wireguard-nt](https://git.zx2c4.com/wireguard-nt/about/)
  placed in `assets/wireguard-nt/wireguard.dll`

```powershell
git clone https://gitea.safcert/shane/GhostWire.git
cd GhostWire
cargo build --workspace
```

The `wireguard.dll` is *not* committed to the repository — see
[`assets/wireguard-nt/README.md`](assets/wireguard-nt/README.md) for
how to obtain the signed driver from upstream.

## Using the CLI

The CLI exposes the full pipeline as discrete subcommands so each
layer can be tested independently.

```powershell
# Probe — list connected YubiKeys
cargo run -p wgyk-cli -- probe

# Decrypt only — exercises the YubiKey + age stack
cargo run -p wgyk-cli -- decrypt path\to\client.conf.age --slot r1

# Inspect — decrypt + parse INI, show a redacted config summary
cargo run -p wgyk-cli -- inspect path\to\client.conf.age --slot r1

# Connect — full pipeline: decrypt + parse + kernel tunnel
# *** Requires running PowerShell as Administrator ***
cargo run -p wgyk-cli -- connect path\to\client.conf.age --slot r1
```

`--slot` accepts `authentication`, `signature`, `key-management`,
`card-auth`, or `r1`–`r20`. `age-plugin-yubikey` identities live in
the retired slots by default (typically `r1`).

While `connect` is running, the tunnel can be inspected with the
standard tools:

```powershell
wg show GhostWire
Get-NetAdapter -Name GhostWire
ping <peer-internal-ip>
```

`Ctrl+C` cleanly tears down the tunnel and removes the network
adapter (handled by the `Drop` impl on `Tunnel`).

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
- The PIN is read with [`rpassword`](https://crates.io/crates/rpassword)
  (no terminal echo) and wrapped in `SecretString` from input to use.
- Touch and PIN policies are honored by the YubiKey itself — GhostWire
  cannot bypass them, only forward what the user provides.
- A 64 KiB upper bound is enforced on decrypted plaintext to mitigate
  malicious or corrupted input.
- The `Debug` impl of internal config types redacts secrets (shown as
  `<redacted>`) so they cannot leak through error logs.
- This project has not been independently audited. Treat it as
  alpha-quality until that is no longer true.

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
- Jason A. Donenfeld and the WireGuard team — for the protocol, the
  kernel driver, and setting the bar for what a VPN should look like

GhostWire is not affiliated with Yubico or any of the projects above.