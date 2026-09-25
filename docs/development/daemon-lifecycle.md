# Production Daemon Lifecycle Contract

This document is the authoritative V1 lifecycle contract for the local
KiCad MCP Pro Gateway daemon. It applies to the Tauri desktop application, the
CLI/daemon archive distribution, upgrades, and uninstall.

## Supported model: packaged sidecar, not an OS service

Gateway V1 does **not** install a systemd unit, launchd daemon, or Windows
service. Installing an OS service would create a second lifecycle owner and is
not required for the supported desktop distribution.

| Supported target | Package model | Packaged daemon location | Lifecycle owner |
|---|---|---|---|
| Linux `x86_64-unknown-linux-gnu` | Tauri `.deb` | Package-owned `/usr/bin` directory beside `kicad-mcp-gateway-desktop` | Tauri desktop while open; packaged sibling CLI for headless start/stop |
| macOS `aarch64-apple-darwin` | Tauri `.dmg` containing `KiCad MCP Pro Gateway.app` | `KiCad MCP Pro Gateway.app/Contents/MacOS/`, beside the desktop executable | Same as Linux |
| Windows `x86_64-pc-windows-msvc` | Tauri `.msi` | Package install directory beside `kicad-mcp-gateway-desktop.exe` | Same as Linux |

The Tauri build stages the daemon at
`apps/desktop/src-tauri/bin/kicad-mcp-gateway-daemon-<target-triple>`. The
`externalBin` entry, build script, and Rust sidecar name must remain aligned.
A release build never searches `PATH`, accepts a daemon path from the UI, or
falls back to a daemon outside the package.

CLI release archives contain `kicad-mcp-gateway` and
`kicad-mcp-gateway-daemon` as siblings. The CLI likewise starts only that
packaged sibling.

## Stable data and endpoint locations

The daemon and clients resolve the same configuration through
`companion-core`. Desktop launches always override transport mode to
`disabled`; a development/mock transport setting cannot escape into a desktop
process.

| Target | Default data directory (`dirs::data_dir()`) |
|---|---|
| Linux | `$XDG_DATA_HOME/kicad-mcp-gateway`, otherwise `~/.local/share/kicad-mcp-gateway` |
| macOS | `~/Library/Application Support/kicad-mcp-gateway` |
| Windows | `%APPDATA%\kicad-mcp-gateway` (Roaming) |

The directory contains `config.toml`, `gateway.db`, the advisory
`gateway.lock`, checkpoints/audit state, and the optional `daemon.stopped`
lifecycle hand-off marker. `GATEWAY_DATA_DIR` may select a different stable
directory; all clients and the daemon must use the same value.

The device private key is **not** in this directory. It remains in the native
OS secret store under `dev.oaslananka.kicad-mcp-pro-gateway.device-key`.

IPC is a Unix-domain socket on Linux/macOS and a named pipe on Windows. Its
name is derived from the canonical data-directory selection. Gateway never
falls back to TCP, a public listener, or a second endpoint.

## Ownership and state transitions

### Desktop

1. The first lifecycle request removes an old `daemon.stopped` marker and
   adopts supervision for this desktop session.
2. It probes only the endpoint derived from the configured data directory.
3. If no daemon is present, it spawns only Tauri's configured packaged sidecar.
4. Startup is serialized in-process. A bounded three-attempt launch and a
   watchdog with 2-to-30-second backoff recover from crashes.
5. Every privileged desktop IPC request performs the identity handshake on the
   same connection before forwarding the request.

The desktop does not shut the daemon down during an ordinary window close, so
the headless CLI can still inspect or stop it. OS logout/reboot terminates it.
Reopening the desktop re-adopts the lifecycle.

### CLI

- `kicad-mcp-gateway daemon start` is idempotent and starts only the packaged
  sibling.
- `daemon stop` writes `daemon.stopped` before requesting shutdown. This tells
  an open desktop watchdog not to race the user's explicit stop. A failed stop
  clears the marker and resumes desktop supervision.
- `daemon restart` performs the same stop/start hand-off without allowing two
  processes to own `gateway.lock`.
- `daemon status` fails for a wrong product/protocol or a stale version rather
  than treating it as stopped.

A new desktop session, CLI `start`, or CLI `restart` clears the explicit-stop
marker. This is the ownership hand-off between the two supported launchers.

### Daemon authority and duplicate detection

Before opening/migrating SQLite or creating device state, the daemon takes an
exclusive advisory lock on `gateway.lock`. A second daemon for the same data
directory exits with `STORAGE_ANOTHER_INSTANCE_RUNNING`; deleting a stale lock
file is neither necessary nor sufficient because the OS lock follows the live
process handle.

The local IPC readiness response contains:

- stable product ID `kicad-mcp-gateway`;
- local IPC contract version;
- packaged daemon version;
- a random per-process instance ID.

A client rejects a wrong product, protocol, or version. A structurally valid
older Gateway daemon may receive only the explicit shutdown request; the client
waits for its endpoint to disappear before launching the packaged replacement.
A wrong-product or wrong-protocol endpoint receives no lifecycle or privileged
request, and no alternate endpoint is tried.

## Crash recovery and authorization invariants

Crash recovery restarts only the process. It never recreates or rewinds policy
state:

- sessions, approvals, audit records, device identity, and workspace grants
  remain in the stable data directory / native key store;
- revoked and expired sessions remain terminal after restart;
- the restarted process has a new instance ID but the same device identity;
- database migration and audit persistence must succeed before the daemon
  begins serving IPC.

`apps/daemon/tests/lifecycle.rs` exercises identity, duplicate rejection,
abrupt listener loss, restart, and persisted revocation on the Linux, macOS,
and Windows Rust CI matrix.

## Update and rollback behavior

The daemon, desktop Cargo package, and `tauri.conf.json` must carry the same
version. `pnpm sidecar:release` rejects version drift before compiling.

On update:

1. The installer replaces the desktop and its same-version sidecar.
2. The next desktop/CLI start validates product and IPC contract.
3. A verified older Gateway daemon is stopped gracefully.
4. The endpoint must disappear before the packaged daemon is launched.
5. The existing data directory is reused; schema migrations run under the
   single-instance lock before IPC readiness.

Do not delete `gateway.db` during an update. A rollback to an older daemon must
use an installer/CLI archive with that older version and a database backup
appropriate to that release; forward-only schema compatibility is not assumed.

## Uninstall and complete removal

1. Run `kicad-mcp-gateway daemon stop` before uninstalling.
2. The OS package uninstaller removes the desktop and bundled daemon. The CLI
   archive has no installer; delete the extracted archive directory.
3. User data is deliberately preserved at the stable data directory across
   uninstall and reinstall.
4. A complete wipe requires deleting that directory and the native-key-store
   entry separately. Removing only the binaries is not a data wipe.

The socket/lock file may remain as a harmless filesystem entry after an
abnormal exit; the OS advisory lock and listener availability determine whether
a daemon is actually running.

## Failure UX

Desktop lifecycle failures are rendered in the status screen without daemon
stderr or secret material. CLI errors identify whether the endpoint is absent,
structurally incompatible, stale, locked, or failed readiness. Typical safe
messages include:

- `Refusing local endpoint: ... No alternate endpoint or process will be used.`
- `Packaged Gateway daemon is missing or invalid ... Reinstall Gateway.`
- `Gateway daemon was stopped explicitly from the CLI ...`

A raw sidecar stderr stream is never copied into the UI. This avoids creating a
secret-bearing log channel; detailed diagnostics must use a sanitized local
reproduction with `RUST_LOG` and no configuration secrets.

## Automated and clean-machine evidence

`.github/workflows/ci.yml` provides the reproducible matrix:

| Evidence | Linux | macOS | Windows |
|---|---|---|---|
| Native daemon lifecycle/IPC integration test | Ubuntu runner | macOS runner | Windows runner |
| Packaged desktop artifact | `.deb` | `.dmg` | `.msi` |
| Packaged sidecar verification | `verify:sidecar` | `verify:sidecar` | `verify:sidecar` |
| Failure UX component test | `StatusScreen.test.tsx` | Same source build | Same source build |
| Downloadable evidence | `desktop-<target>` CI artifact | Same | Same |

Local Linux packaging reproduction:

```bash
cd apps/desktop
pnpm install --frozen-lockfile
pnpm sidecar:release
pnpm tauri build --bundles deb
pnpm verify:sidecar
cargo test --manifest-path src-tauri/Cargo.toml --all-targets --locked
```

For final release evidence, repeat the package matrix on fresh supported OS
machines. Capture one screenshot of the first-launch Ready state, one
screenshot of a safe failure banner, and a redacted lifecycle log excerpt.
Before attaching evidence, remove pairing codes, device fingerprints, data
paths containing usernames, config values, tokens, and process arguments.
