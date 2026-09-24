# Gateway Canonical Compatibility Matrix

This document defines the authoritative compatibility and platform support contract for KiCad MCP Pro Gateway.

## Platform & Architecture Support

| OS | Architecture | Gateway Status | CI / Validation Level | Installers Produced |
|---|---|---|---|---|
| **Linux** | `x86_64` (GNU) | **SUPPORTED** | CI-Validated (Ubuntu 22.04 / 24.04) | AppImage / `.deb` (Target) |
| **Linux** | `aarch64` / ARM64 | **PLANNED** | Unvalidated | N/A |
| **macOS** | `aarch64` (Apple Silicon) | **SUPPORTED** | CI-Validated (macOS 14/15) | DMG / `.app` (Target) |
| **macOS** | `x86_64` (Intel) | **UNSUPPORTED** | Unsupported / No runner | N/A |
| **Windows** | `x86_64` (MSVC) | **SUPPORTED** | CI-Validated (Windows Server 2022 / 2025) | MSI / NSIS (Target) |
| **Windows** | `arm64` (ARM64) | **PLANNED** | Unvalidated | N/A |

## Component Dependencies & Compatibility

| Component | Target / Version Range | Policy / Notes |
|---|---|---|
| **KiCad** | 10.0.x (Primary), 8.x (Deprecated) | Required local EDA environment; 10.0.6 latest verified |
| **kicad-mcp-pro** | `main` @ `f641a92596ab7adc1e134287578b1ae5ff9580ad` | Pinned upstream tool snapshot (387 tools, mcp-server-v3.35.0) |
| **Gateway Protocol** | Version `1.0.0` | Shared IPC envelope & binary framing codec |
| **Rust MSRV** | 1.88.0 | Enforced in CI across all crates |
| **Node.js / pnpm** | Node 20+ / pnpm 9 | Frontend desktop app runtime & package manager |
| **Product identity** | Companion → Gateway, pre-1.0 | Renamed before the first release; no installed population to migrate — see [identity-migration.md](../development/identity-migration.md) |

## Architecture Decisions Rationale

1. **macOS Intel (`x86_64`):** Explicitly unsupported. Apple Silicon (`aarch64`) represents current and future macOS target hardware.
2. **Linux & Windows ARM64:** Marked as **PLANNED**. Build tools compile, but cross-compilation and native hardware QA remain open post-V1 items.
3. **No Unvalidated Support:** A target is marked `SUPPORTED` only when native CI builds and runs automated test suites on that platform.
