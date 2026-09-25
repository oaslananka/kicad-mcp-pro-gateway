# Companion → Gateway Identity Migration & Compatibility Decision

The repository and product were renamed from **KiCad MCP Pro Companion**
(`kicad-mcp-pro-companion`) to **KiCad MCP Pro Gateway**
(`kicad-mcp-pro-gateway`). This document is the compatibility/migration
decision that the rename requires: renaming persisted data directories,
service names, bundle identifiers, or binaries can break upgrades, so every
such rename and its rationale is recorded here.

## Decision

**The rename ships before any release exists, so it is migration-safe by
construction.**

The project is pre-alpha and unreleased: `main` has never published a GitHub
Release, installer, or signed binary (see README "Project Status & Maturity"
and [SECURITY.md](../../SECURITY.md) "Supported versions"). There is no
installed population to migrate and no supported upgrade path to preserve,
so all user-visible identity is renamed in one change instead of carrying a
split Companion/Gateway identity into V1.

Consequences:

- **No automatic migration is implemented, and none is required for any
  supported install — there are none.**
- A developer checkout created *before* this change keeps working only after
  a manual move (below), or by starting fresh.
- If a stable release ever renames these surfaces again, that rename must
  ship with an automatic migration or a compatibility fallback, because
  releases will then have installed users.

## Renamed surfaces (before → after)

| Surface | Before | After |
|---|---|---|
| Repository / public & security links | `https://github.com/oaslananka/kicad-mcp-pro-companion` | `https://github.com/oaslananka/kicad-mcp-pro-gateway` |
| Product name (docs, CLI banner, UI, window title) | `KiCad MCP Pro Companion` | `KiCad MCP Pro Gateway` |
| CLI binary / package | `kicad-mcp-companion` / `kicad-mcp-companion-cli` | `kicad-mcp-gateway` / `kicad-mcp-gateway-cli` |
| Daemon binary / package | `kicad-mcp-companion-daemon` (both) | `kicad-mcp-gateway-daemon` (both) |
| Desktop binary / package / npm name | `kicad-mcp-companion-desktop` | `kicad-mcp-gateway-desktop` |
| Tauri `productName` / bundle identifier | `KiCad MCP Pro Companion` / `dev.oaslananka.kicad-mcp-companion` | `KiCad MCP Pro Gateway` / `dev.oaslananka.kicad-mcp-gateway` |
| Desktop sidecar binary | `companion-daemon-<target-triple>` | `kicad-mcp-gateway-daemon-<target-triple>` |
| Default data directory | `<data>/kicad-mcp-companion` (`~/.local/share/…`, `%LOCALAPPDATA%\…`) | `<data>/kicad-mcp-gateway` |
| Database / single-instance lock | `companion.db`, `companion.lock` | `gateway.db`, `gateway.lock` |
| Per-workspace checkpoint directory | `<workspace>/.companion-checkpoints` | `<workspace>/.gateway-checkpoints` |
| IPC socket / named pipe | `kicad-mcp-companion-<hash>.sock`, `\\.\pipe\kicad-mcp-companion-<hash>` | `kicad-mcp-gateway-<hash>.sock`, `\\.\pipe\kicad-mcp-gateway-<hash>` |
| Keyring service label | `dev.oaslananka.kicad-mcp-pro-companion.device-key` | `dev.oaslananka.kicad-mcp-pro-gateway.device-key` |
| Environment variables | `COMPANION_DATA_DIR`, `COMPANION_LOG_LEVEL`, `COMPANION_CORE_BRIDGE_ENDPOINT`, `COMPANION_TRANSPORT_MODE` | `GATEWAY_DATA_DIR`, `GATEWAY_LOG_LEVEL`, `GATEWAY_CORE_BRIDGE_ENDPOINT`, `GATEWAY_TRANSPORT_MODE`; local IPC is always derived from the data directory and has no endpoint override |
| MCP `clientInfo.name` sent to kicad-mcp-pro | `kicad-mcp-pro-companion` | `kicad-mcp-pro-gateway` |
| Release archive / GitHub Release title | `kicad-mcp-companion-<tag>-<target>.tar.gz` | `kicad-mcp-gateway-<tag>-<target>.tar.gz` |

## Manual migration for a pre-1.0 source checkout (optional)

Nothing below is required for a supported install; it only preserves local
history from a checkout built before this change.

1. Stop the daemon.
2. Move the data directory:
   `mv ~/.local/share/kicad-mcp-companion ~/.local/share/kicad-mcp-gateway`
   (Windows: `%LOCALAPPDATA%`).
3. Rename state files inside it: `companion.db` → `gateway.db`,
   `companion.lock` → `gateway.lock`.
4. In each authorized workspace, rename `.companion-checkpoints` →
   `.gateway-checkpoints`.
5. Rename exported `COMPANION_*` variables to the supported `GATEWAY_*` set in
   shell/environment configuration. V1 has no endpoint override and installs no
   OS service unit.
6. Expect to re-pair: the device private key lives in the OS key store under
   the old service label, so the gateway recreates device identity under the
   new label and existing remote pairings must be redone.

The simplest and recommended option for an unreleased checkout is to delete
the old data directory and start fresh.

## Deliberately unchanged

- **Internal crate and Rust identifiers**: packages such as
  `companion-core` / `companion-protocol` and types such as `CompanionConfig`
  / `CompanionError` are internal code identifiers. They appear in no
  shipped artifact, doc title, or public link, and renaming them would be
  large cosmetic churn for no user-visible benefit.
- **Historical records under `docs/superpowers/`** keep their original
  filenames, paths, and text so the design history stays verifiable and
  existing links keep resolving. Each affected record carries a banner
  explaining that it uses the former product name.
- **Upstream `kicad-mcp-pro` and KiCad** are separate projects and are not
  renamed, modified, or absorbed by this repository.

## Verifying the migration

```bash
# Current-product identifier search: only internal crate/type names,
# historical records, and this document may match.
grep -rIn -i "companion" --exclude-dir=.git --exclude-dir=target .

# Public / security links resolve to the Gateway repository
grep -rIn "github.com/oaslananka" --exclude-dir=.git .

# Artifact identity comes from packaging metadata
grep -n "productName\|identifier\|externalBin" apps/desktop/src-tauri/tauri.conf.json
grep -n "^name =\|^\[\[bin\]\]" apps/cli/Cargo.toml apps/daemon/Cargo.toml apps/desktop/src-tauri/Cargo.toml
```
