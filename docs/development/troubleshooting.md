# Gateway Production Troubleshooting Guide

This guide provides actionable steps for diagnosing and resolving runtime issues across the Gateway daemon, desktop frontend, and IPC layer.

## 1. Daemon Startup & Process Lifecycle

### Symptoms
- Desktop app reports a packaged-daemon/startup failure.
- CLI commands return a readiness, version, or local endpoint error.

### Diagnostics
1. **Check the validated lifecycle state:**
   ```bash
   kicad-mcp-gateway daemon status
   ```
   A missing endpoint, wrong product/protocol, stale packaged version, and
   duplicate data-directory owner are distinct results.
2. **Check the process without treating a filename match as readiness:**
   ```bash
   pgrep -af kicad-mcp-gateway-daemon
   ```
3. **Capture sanitized daemon stderr:** the daemon does not create a log
   directory. Run the packaged CLI/daemon from a terminal with `RUST_LOG=info`
   and redact config values, tokens, device fingerprints, and usernames.
4. **Check the single-instance owner:** `gateway.lock` is an advisory OS lock,
   not a PID file. Its presence alone does not mean a daemon is running; use
   `daemon status` or the process list.
5. **Check explicit CLI stop state:** `<data_dir>/daemon.stopped` pauses an
   open desktop watchdog. Run `kicad-mcp-gateway daemon start` or reopen the
   desktop to hand supervision back.

See [daemon-lifecycle.md](daemon-lifecycle.md) for the full ownership and
update contract.

## 2. IPC Sockets & Connectivity

### Symptoms
- `IPC socket error`, `Broken pipe`, or an identity-handshake failure.

### Diagnostics
- **Linux / macOS (domain sockets):** the endpoint is derived from the selected
  Gateway data directory; do not connect to a guessed `/tmp` path.
- **Windows (named pipes):** the endpoint is derived from the same data
  directory and is not configured through `GATEWAY_IPC_ENDPOINT`.
- Gateway has no TCP fallback. A wrong product/protocol/version fails closed;
  it never causes another executable or endpoint to be launched.

## 3. Keychain & Secure Storage

### Symptoms
- Device key loading failure or "Keychain service unavailable" error on Linux/macOS.

### Diagnostics
- **Linux:** Ensure `dbus` and `secret-service` / `gnome-keychain` or `kwallet` are active. Fallback test mode is used in headless CI environments.
- **macOS:** Ensure Keychain access is granted for the app identifier `dev.oaslananka.kicad-mcp-gateway`.

## 4. WebView / GTK Integration (Linux)

### Symptoms
- Desktop UI fails to launch or crashes with GTK / WebKitGTK errors.

### Diagnostics
- Ensure WebKit2GTK dependencies are installed:
  `sudo apt install libwebkit2gtk-4.1-0` (or `libwebkit2gtk-4.0-37`).

## 5. Core MCP Detection & Config Parsing

### Symptoms
- Daemon status reports `core_reachable = false`.

### Diagnostics
1. Confirm `kicad-mcp-pro` HTTP server is running at `http://127.0.0.1:3334/mcp`.
2. Test loopback endpoint directly:
   ```bash
   curl -i http://127.0.0.1:3334/mcp
   ```
3. Check `<data_dir>/config.toml` for syntax or address typos.

## 6. Uninstall & Data Retention Policy

1. Run `kicad-mcp-gateway daemon stop` before removing the application.
2. **Application binaries:** the OS package uninstaller removes the desktop and
   packaged sidecar. A CLI archive is removed by deleting its extracted
   directory.
3. **Local application data:** preserved by default at `<data_dir>` (config,
   database, audit/checkpoint state, lifecycle marker). The device private key
   remains separately in the OS key store.
4. **Complete wipe:** delete `<data_dir>` and the native-key-store entry
   `dev.oaslananka.kicad-mcp-pro-gateway.device-key`. Removing binaries alone
   is not a data wipe.

Default paths and rollback/update details are documented in
[daemon-lifecycle.md](daemon-lifecycle.md).
