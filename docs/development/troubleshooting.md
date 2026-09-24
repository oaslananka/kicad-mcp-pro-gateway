# Companion Production Troubleshooting Guide

This guide provides actionable steps for diagnosing and resolving runtime issues across the Companion daemon, desktop frontend, and IPC layer.

## 1. Daemon Startup & Process Lifecycle

### Symptoms
- Desktop app reports "Daemon Unavailable" or "Connection Refused".
- CLI commands return socket connection errors.

### Diagnostics
1. **Check if daemon process is running:**
   ```bash
   pgrep -af companion-daemon
   ```
2. **Inspect daemon log output:**
   - Linux / macOS: `~/.local/share/kicad-mcp-companion/logs/` or stdout.
   - Windows: `%LOCALAPPDATA%\kicad-mcp-companion\logs\`
3. **Verify single-instance lock file:**
   - Check if stale lockfile exists at `<data_dir>/companion-daemon.lock`.

## 2. IPC Sockets & Connectivity

### Symptoms
- `IPC socket error` or `Broken pipe` during command execution.

### Diagnostics
- **Linux / macOS (Domain Sockets):**
  Verify domain socket permissions at `/tmp/kicad-mcp-companion-<hash>.sock` or user runtime dir.
- **Windows (Named Pipes):**
  Verify named pipe `\\.\pipe\kicad-mcp-companion-<hash>` is accessible without administrator elevation.

## 3. Keychain & Secure Storage

### Symptoms
- Device key loading failure or "Keychain service unavailable" error on Linux/macOS.

### Diagnostics
- **Linux:** Ensure `dbus` and `secret-service` / `gnome-keychain` or `kwallet` are active. Fallback test mode is used in headless CI environments.
- **macOS:** Ensure Keychain access is granted for `com.kicad-mcp.companion`.

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

- **Application Binaries:** Removed by OS package manager / installer.
- **Local Application Data:** Preserved by default at `<data_dir>` (database, audit logs, device identity) to prevent accidental data loss across upgrades.
- **Complete Wipe:** Manually delete `<data_dir>` (`~/.local/share/kicad-mcp-companion` or `%LOCALAPPDATA%\kicad-mcp-companion`).
