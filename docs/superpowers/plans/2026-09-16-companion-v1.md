# KiCad MCP Pro Companion V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the local trust-boundary core of KiCad MCP Pro Companion —
device identity, workspace authorization, capability/risk policy, session
lifecycle, daemon + CLI + local IPC, a local kicad-mcp-pro MCP bridge, a mock
transport, audit, and checkpoints — fully tested against a mock relay and a
mock kicad-mcp-pro server, plus a minimal Tauri desktop shell.

**Architecture:** Rust workspace of small, single-responsibility crates
(`crates/*`) consumed by three binaries (`apps/daemon`, `apps/cli`,
`apps/desktop`). The daemon is the only privileged process; CLI and desktop
are thin local-IPC clients. See
`docs/superpowers/specs/2026-09-16-companion-v1-design.md` for the full
domain model this plan implements against.

**Tech Stack:** Rust (tokio, serde, thiserror/anyhow, tracing, clap,
rusqlite, ed25519-dalek, reqwest, interprocess), Tauri 2 + React + TypeScript
+ Vite for the desktop shell.

**Spec:** `docs/superpowers/specs/2026-09-16-companion-v1-design.md`

## Global Constraints

- Rust-first; no arbitrary shell/filesystem access is ever modeled as a
  capability (project principle, non-negotiable).
- No inbound internet-facing port; local IPC only, outbound-only cloud
  transport.
- No `unwrap()`/`expect()` in request/security-handling code paths.
- `cargo clippy --workspace --all-targets -- -D warnings` must stay clean
  after every task.
- Private key material: `SecretStore` only, never SQLite, never logs, never
  IPC/CLI output.
- Every workspace path check uses canonical-root containment, never
  `path.starts_with(root_string)`.
- Unknown tool / unknown capability → deny, no fallback allow.
- `anyhow` only inside `apps/*/src/main.rs`; library crates use `thiserror`.
- Deterministic time via the `Clock` trait everywhere expiry/backoff logic
  exists — no `sleep`-based expiry tests.

---

## Phase 0 — Repository Foundation

### Task 0.1: Workspace scaffold, toolchain, formatting, licensing

**Files:**
- Create: `Cargo.toml` (workspace root, `resolver = "2"`, members list)
- Create: `rust-toolchain.toml` (stable channel pin, `components =
  ["rustfmt", "clippy"]`)
- Create: `.editorconfig`, `.gitignore` (must ignore `target/`,
  `node_modules/`, `*.db`, `.env`, `apps/desktop/dist`, `apps/desktop/src-tauri/target`)
- Create: `LICENSE` (MIT, matching kicad-mcp-pro's license choice)
- Create: `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`
- Create: `.env.example` (non-secret dev config placeholders only)
- Modify: `README.md` (full rewrite per spec §"Documentation / README" in
  the original product prompt — see Task 0.3)

**Interfaces:** none (no code yet).

- [ ] **Step 1:** Write `Cargo.toml` workspace root with `[workspace]
  members = ["apps/daemon", "apps/cli", "crates/*"]` and
  `[workspace.package] version = "0.1.0" edition = "2021"`.
- [ ] **Step 2:** Write `rust-toolchain.toml` pinning `channel = "stable"`.
- [ ] **Step 3:** Write `.editorconfig`, `.gitignore`, `LICENSE`,
  `SECURITY.md` (vulnerability reporting contact + supported versions +
  disclosure policy), `CONTRIBUTING.md` (dev setup, TDD expectation, commit
  style), `CHANGELOG.md` (Keep a Changelog format, `## [0.1.0] - Unreleased`
  section).
- [ ] **Step 4:** Write `.env.example` with `COMPANION_DATA_DIR=`,
  `COMPANION_LOG_LEVEL=info`, `COMPANION_CORE_BRIDGE_ENDPOINT=http://127.0.0.1:3334/mcp`,
  `COMPANION_TRANSPORT_MODE=mock`, all commented as non-secret examples.
- [ ] **Step 5:** Run `git status` and confirm no crate directories exist
  yet (workspace `members` will fail to resolve until Task 1.1 adds a real
  crate) — leave `Cargo.toml` members as `["crates/core"]` only for now,
  widen in later tasks as each crate is created.
- [ ] **Step 6: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .editorconfig .gitignore LICENSE SECURITY.md CONTRIBUTING.md CHANGELOG.md .env.example
git commit -m "chore: initialize repository foundation"
```

### Task 0.2: Design docs

Already written in this session:
`docs/architecture/{system-overview,component-boundaries,session-lifecycle,data-flow}.md`,
`docs/security/{threat-model,trust-boundaries,secure-storage}.md`,
`docs/protocol/README.md`, `docs/development/testing.md`,
`docs/superpowers/specs/2026-09-16-companion-v1-design.md`, this file.

- [ ] **Step 1:** `git add docs/` and commit:

```bash
git commit -m "docs: define companion v1 architecture, security model, and plan"
```

### Task 0.3: README rewrite

**Files:**
- Modify: `README.md`

- [ ] **Step 1:** Write the full README per the structure: one-sentence
  description, why Companion exists, relationship to kicad-mcp-pro,
  architecture (link to `docs/architecture/system-overview.md`), security
  model (link to threat model), current status (honest — nothing runnable
  yet at this task), quick start for developers, CLI examples (from spec
  §7/CLI section, marked "planned" until Phase 5 lands), development mock
  mode, what is NOT supported yet (the out-of-scope list), roadmap
  (Phase 0–10), contributing, security reporting (link `SECURITY.md`).
- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README as project entry point"
```

### Task 0.4: CI foundation

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:** none yet — job will fail until Task 1.1 adds a real crate;
that's expected and acceptable since Task 0.4 lands before Task 1.1's commit
in the same working session, not before a push that's expected to pass.

- [ ] **Step 1:** Write `ci.yml` with a `rust` job (matrix
  `ubuntu-latest`/`windows-latest`/`macos-latest`) running
  `cargo fmt --all -- --check`, then
  `cargo clippy --workspace --all-targets -- -D warnings`, then
  `cargo test --workspace`, and a separate `security` job running
  `cargo install cargo-audit --locked` + `cargo audit`. Frontend job is
  added in Task 9.1 once `apps/desktop` exists (a job referencing a
  nonexistent `apps/desktop/package.json` would fail CI on every commit
  until then).
- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add rust workspace pipeline"
```

---

## Phase 1 — Domain + Storage

### Task 1.1: `crates/core` — typed IDs, error taxonomy, Clock

**Files:**
- Create: `crates/core/Cargo.toml` (deps: `serde`, `ulid`, `time`,
  `thiserror`, `serde_json`)
- Create: `crates/core/src/lib.rs`
- Create: `crates/core/src/ids.rs`
- Create: `crates/core/src/error.rs`
- Create: `crates/core/src/clock.rs`
- Test: `crates/core/src/ids.rs` (inline `#[cfg(test)] mod tests`)
- Test: `crates/core/src/clock.rs` (inline)

**Interfaces:**
- Produces: `pub struct DeviceId(Ulid)` ... through `CheckpointId` (via the
  `typed_id!` macro in `ids.rs`), each with `fn new() -> Self`,
  `impl Display`, `impl FromStr`, `impl Serialize/Deserialize`.
- Produces: `pub trait CompanionError: std::error::Error { fn code(&self)
  -> &'static str; fn retryable(&self) -> bool; fn context(&self) ->
  serde_json::Value { serde_json::Value::Null } }`
- Produces: `pub trait Clock: Send + Sync { fn now(&self) ->
  time::OffsetDateTime; }`, `pub struct SystemClock;`, and (feature
  `test-util`) `pub struct FakeClock { .. }` with `fn advance(&self,
  d: time::Duration)`.

- [ ] **Step 1: Write failing tests** in `crates/core/src/ids.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_round_trips_through_display_and_fromstr() {
        let id = DeviceId::new();
        let s = id.to_string();
        assert!(s.starts_with("dev_"));
        let parsed: DeviceId = s.parse().expect("valid id parses");
        assert_eq!(id, parsed);
    }

    #[test]
    fn distinct_id_types_are_not_interchangeable_at_compile_time() {
        // compile-time assertion via type system: this test just documents
        // that DeviceId and WorkspaceId are structurally distinct types.
        fn takes_device_id(_: DeviceId) {}
        let d = DeviceId::new();
        takes_device_id(d);
    }

    #[test]
    fn ids_sort_lexically_by_creation_order() {
        let a = DeviceId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = DeviceId::new();
        assert!(a.to_string() < b.to_string());
    }
}
```

and in `crates/core/src/clock.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_advances_deterministically() {
        let clock = FakeClock::new_at(time::OffsetDateTime::UNIX_EPOCH);
        let t0 = clock.now();
        clock.advance(time::Duration::seconds(60));
        let t1 = clock.now();
        assert_eq!(t1 - t0, time::Duration::seconds(60));
    }
}
```

- [ ] **Step 2:** Run `cargo test -p companion-core` — expect compile
  failure (crate doesn't exist yet).
- [ ] **Step 3:** Implement `ids.rs` with a `typed_id!` macro generating
  each ID newtype over `ulid::Ulid`, `error.rs` with the `CompanionError`
  trait, `clock.rs` with `Clock`/`SystemClock`/`FakeClock`, and `lib.rs`
  re-exporting all three modules plus the domain structs from spec §3.4–3.7
  (`Session`, `SessionStatus`, `Capability`, `CapabilitySet`,
  `CapabilityProfile`, `RiskLevel`, `WorkspaceAuthorization`,
  `OperationRequest`, `OperationResult`, `AuditEvent`,
  `ApprovalRequest`/`ApprovalDecision`, `TransportState`,
  `CoreConnectionState`) as plain data types with no behavior yet (behavior
  lands in `sessions`/`policy`/`workspace` crates in later phases).
- [ ] **Step 4:** Run `cargo test -p companion-core -- --nocapture` —
  expect PASS.
- [ ] **Step 5:** Run `cargo clippy -p companion-core --all-targets -- -D
  warnings` — fix until clean.
- [ ] **Step 6:** Add `"crates/core"` to workspace `Cargo.toml` members if
  not already covered by the `crates/*` glob; run `cargo fmt --all`.
- [ ] **Step 7: Commit**

```bash
git add crates/core Cargo.toml Cargo.lock
git commit -m "feat(core): add typed ids, error taxonomy, and clock abstraction"
```

### Task 1.2: `crates/core` — configuration model

**Files:**
- Create: `crates/core/src/config.rs`
- Test: inline `#[cfg(test)] mod tests` in `config.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub struct CompanionConfig { pub data_dir: PathBuf, pub
  log_level: String, pub core_bridge_endpoint: Url, pub transport_mode:
  TransportMode, pub ipc_endpoint: IpcEndpoint }` and `pub fn
  load(cli_overrides: CliOverrides) -> Result<CompanionConfig, ConfigError>`
  implementing precedence CLI flags > env (`COMPANION_*`) > file
  (`<data_dir>/config.toml`, but `data_dir` itself must come from
  CLI/env/default first) > defaults.

- [ ] **Step 1: Write failing tests** covering: defaults when nothing is
  set; env var overrides default; CLI override beats env; malformed
  `core_bridge_endpoint` URL produces `ConfigError::InvalidEndpoint` (typed,
  not a panic); non-loopback endpoint is accepted at parse time (the
  loopback-only enforcement is `core-bridge`'s job per spec §8, not
  config's).
- [ ] **Step 2:** Run tests, confirm failure (module doesn't exist).
- [ ] **Step 3:** Implement `config.rs` using `std::env` reads plus a small
  manual precedence resolver (no need for a heavyweight config crate given
  the small surface — see Global Constraints on avoiding unnecessary deps).
- [ ] **Step 4:** Run tests, confirm PASS; `cargo clippy -p companion-core
  --all-targets -- -D warnings`.
- [ ] **Step 5: Commit**

```bash
git add crates/core/src/config.rs
git commit -m "feat(core): add layered configuration model"
```

### Task 1.3: `crates/storage` — schema, migrations, connection lifecycle

**Files:**
- Create: `crates/storage/Cargo.toml` (deps: `rusqlite` with `bundled`
  feature, `rusqlite_migration`, `companion-core`, `thiserror`, `tracing`)
- Create: `crates/storage/migrations/0001_init.sql` (tables: `device`,
  `workspaces`, `sessions`, `approvals`, `audit_events`, `settings`,
  `checkpoints` — columns per spec §4/§3)
- Create: `crates/storage/src/lib.rs`
- Create: `crates/storage/src/connection.rs`
- Create: `crates/storage/src/migrations.rs`
- Test: `crates/storage/tests/migrations.rs`
- Test: `crates/storage/tests/single_instance.rs`

**Interfaces:**
- Consumes: `companion_core::{DeviceId, WorkspaceId, ...}` for typed
  query params where practical (row mapping still goes through
  `rusqlite::Row`, converted to typed IDs at the boundary).
- Produces: `pub struct Storage { .. }` with `pub fn open(data_dir:
  &Path) -> Result<Storage, StorageError>` (creates dir if missing, opens
  SQLite file, runs pending migrations inside a transaction, acquires an
  exclusive advisory lock file for single-instance enforcement) and `pub fn
  connection(&self) -> &Mutex<rusqlite::Connection>`.
- Produces: `StorageError::{DbUnreadable, MigrationFailed,
  AnotherInstanceRunning, Io}`.

- [ ] **Step 1: Write failing tests**: `migrations.rs` asserts a fresh
  `Storage::open` on a temp dir creates all expected tables (query
  `sqlite_master`); re-opening the same dir is idempotent (no migration
  re-run error); opening a deliberately corrupted file (write garbage bytes
  first) returns `StorageError::DbUnreadable`, not a panic.
  `single_instance.rs` asserts a second `Storage::open` on the same
  `data_dir` while the first handle is still alive returns
  `StorageError::AnotherInstanceRunning`, and that dropping the first
  handle allows a subsequent open to succeed.
- [ ] **Step 2:** Run `cargo test -p companion-storage`, confirm failure.
- [ ] **Step 3:** Implement `0001_init.sql`, `connection.rs` (lock file via
  `fs4`/`fs2` advisory file lock on `<data_dir>/companion.lock`),
  `migrations.rs` (wraps `rusqlite_migration::Migrations`), `lib.rs`
  wiring `Storage::open`.
- [ ] **Step 4:** Run tests, confirm PASS. `cargo clippy -p
  companion-storage --all-targets -- -D warnings`.
- [ ] **Step 5: Commit**

```bash
git add crates/storage Cargo.toml Cargo.lock
git commit -m "feat(storage): add sqlite schema, migrations, and single-instance guard"
```

---

## Phase 2 — Identity

### Task 2.1: `crates/identity` — SecretStore trait + in-memory test adapter

**Files:**
- Create: `crates/identity/Cargo.toml` (deps: `ed25519-dalek`, `rand_core`
  (OS RNG), `zeroize`, `companion-core`, `thiserror`)
- Create: `crates/identity/src/secret_store.rs`
- Create: `crates/identity/src/secret_store/memory.rs` (behind
  `#[cfg(any(test, feature = "test-util"))]`)
- Test: `crates/identity/src/secret_store/memory.rs` inline tests

**Interfaces:**
- Produces: `pub struct SigningKeyMaterial(SecretVec<u8>)` with a manual
  `impl fmt::Debug` printing `"SigningKeyMaterial(REDACTED)"` and
  `#[derive(Zeroize)] #[zeroize(drop)]` on the inner bytes.
- Produces: `pub trait SecretStore: Send + Sync { fn store_device_key(&self,
  device_id: &DeviceId, key: &SigningKeyMaterial) -> Result<(),
  SecretStoreError>; fn load_device_key(&self, device_id: &DeviceId) ->
  Result<Option<SigningKeyMaterial>, SecretStoreError>; fn
  delete_device_key(&self, device_id: &DeviceId) -> Result<(),
  SecretStoreError>; }`

- [ ] **Step 1: Write failing tests**: `InMemorySecretStore` round-trips
  store→load; `load_device_key` on an unknown id returns `Ok(None)`, not an
  error; `delete_device_key` then `load_device_key` returns `Ok(None)`;
  `format!("{:?}", key_material)` does **not** contain any byte of the
  actual key (assert the debug string equals the literal redacted string).
- [ ] **Step 2:** Run tests, confirm failure.
- [ ] **Step 3:** Implement `SigningKeyMaterial`, `SecretStore` trait,
  `InMemorySecretStore` (a `Mutex<HashMap<DeviceId, SigningKeyMaterial>>`).
- [ ] **Step 4:** Run tests, confirm PASS; clippy clean.
- [ ] **Step 5: Commit**

```bash
git add crates/identity
git commit -m "feat(identity): add secret store abstraction and in-memory test adapter"
```

### Task 2.2: `crates/identity` — Windows DPAPI adapter

**Files:**
- Create: `crates/identity/src/secret_store/windows_dpapi.rs` (behind
  `#[cfg(target_os = "windows")]`, deps: `windows` crate,
  `Win32_Security_Cryptography` feature for `CryptProtectData`/
  `CryptUnprotectData`)
- Test: `crates/identity/tests/windows_dpapi.rs` (`#[cfg(target_os =
  "windows")]`)

**Interfaces:**
- Consumes: `SecretStore`, `SigningKeyMaterial` from Task 2.1.
- Produces: `pub struct DpapiSecretStore { store_dir: PathBuf }` (encrypted
  blobs written under `<data_dir>/secrets/<device_id>.bin` using
  `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`, decrypted with
  `CryptUnprotectData`; the DPAPI call is scoped to the current Windows
  user, matching "OS secure storage" intent).

- [ ] **Step 1: Write failing tests**: store→load round trip on a temp
  dir; a blob written by `DpapiSecretStore` is not valid UTF-8/plaintext
  key bytes when read raw from disk (assert the raw file bytes do not equal
  the plaintext key bytes); missing file → `Ok(None)`.
- [ ] **Step 2:** Run (Windows CI runner / local Windows dev machine),
  confirm failure.
- [ ] **Step 3:** Implement using the `windows` crate's `CryptProtectData`/
  `CryptUnprotectData` FFI wrappers; on any Win32 error, map to
  `SecretStoreError::Backend` with the Win32 error code in context (no
  panic).
- [ ] **Step 4:** Run, confirm PASS; clippy clean.
- [ ] **Step 5: Commit**

```bash
git add crates/identity/src/secret_store/windows_dpapi.rs crates/identity/tests/windows_dpapi.rs
git commit -m "feat(identity): add windows dpapi secret store adapter"
```

### Task 2.3: `crates/identity` — device identity lifecycle + fingerprint

**Files:**
- Create: `crates/identity/src/device.rs`
- Test: `crates/identity/tests/device_lifecycle.rs`

**Interfaces:**
- Consumes: `SecretStore` (Task 2.1/2.2), `companion_storage::Storage`
  (Task 1.3) for non-secret metadata persistence, `companion_core::{DeviceId,
  DeviceIdentity, DevicePublicKey, DeviceFingerprint}`.
- Produces: `pub trait DeviceIdentityStore { fn load(&self) ->
  Result<Option<DeviceIdentity>, IdentityError>; fn create(&self,
  display_name: &str) -> Result<DeviceIdentity, IdentityError>; fn
  public_identity(&self) -> Result<Option<DeviceIdentity>, IdentityError>;
  fn sign(&self, message: &[u8]) -> Result<Signature, IdentityError>; }`
  and `pub struct SqliteDeviceIdentityStore<S: SecretStore> { .. }`
  implementing it.

- [ ] **Step 1: Write failing tests** in `device_lifecycle.rs` (using
  `InMemorySecretStore` + an in-memory/temp `Storage`): `load()` on a fresh
  store returns `Ok(None)`; `create("dev-machine")` then `load()` returns
  `Some` with matching `device_id`/`public_key`/non-empty
  `fingerprint`; calling `create` a second time returns
  `IdentityError::AlreadyExists` rather than silently overwriting; `sign(msg)`
  then verifying against `public_identity().public_key` succeeds via
  `ed25519_dalek::Verifier`; the fingerprint is deterministic for the same
  public key (compute twice, assert equal) and differs between two distinct
  generated identities.
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement `device.rs`: `create` generates an Ed25519
  keypair via `SigningKey::generate(&mut OsRng)`, stores the private key via
  `SecretStore::store_device_key`, stores public metadata via `Storage`
  (`device` table), computes fingerprint as a grouped hex encoding of
  `blake3`/`sha256` of the public key bytes (pick one, document the choice
  in a doc comment — no invented crypto, just a mature hash for a
  human-readable label). `sign` loads the private key from `SecretStore`
  each call rather than caching it in a long-lived plaintext field.
- [ ] **Step 4:** Run, confirm PASS; clippy clean.
- [ ] **Step 5: Commit**

```bash
git add crates/identity/src/device.rs crates/identity/tests/device_lifecycle.rs
git commit -m "feat(identity): add device identity lifecycle and fingerprinting"
```

---

## Phase 3 — Workspaces + Policy

### Task 3.1: `crates/workspace` — canonical path boundary enforcement

**Files:**
- Create: `crates/workspace/Cargo.toml` (deps: `companion-core`,
  `thiserror`, `dunce` (Windows canonical-path normalization), `time`)
- Create: `crates/workspace/src/boundary.rs`
- Create: `crates/workspace/src/lib.rs`
- Test: `crates/workspace/tests/boundary.rs`

**Interfaces:**
- Produces: `pub struct WorkspaceAuthorization { pub workspace_id:
  WorkspaceId, pub display_name: String, pub canonical_root: PathBuf, pub
  created_at: OffsetDateTime, pub enabled: bool }` with `pub fn new(
  display_name: String, root: &Path) -> Result<Self, WorkspaceError>`
  (canonicalizes `root`, rejects relative paths, rejects nonexistent paths).
- Produces: `pub trait WorkspaceBoundary { fn resolve_within(&self,
  requested: &Path) -> Result<PathBuf, WorkspaceError>; }` implemented for
  `WorkspaceAuthorization`.
- Produces: `WorkspaceError::{RelativeRoot, RootNotFound, PathEscapesRoot,
  SymlinkEscapesRoot}`.

- [ ] **Step 1: Write failing tests** — the full matrix from spec §6, e.g.:

```rust
#[test]
fn path_inside_root_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let resolved = ws.resolve_within(&dir.path().join("sub/file.kicad_pro"));
    assert!(resolved.is_ok());
}

#[test]
fn sibling_directory_with_prefix_collision_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let evil = parent.path().join("project-evil");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evil).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let resolved = ws.resolve_within(&evil.join("file"));
    assert!(matches!(resolved, Err(WorkspaceError::PathEscapesRoot)));
}

#[test]
fn traversal_sequence_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    std::fs::create_dir_all(&root).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let escape = root.join("..").join("project-evil").join("file");
    let resolved = ws.resolve_within(&escape);
    assert!(matches!(resolved, Err(WorkspaceError::PathEscapesRoot)));
}

#[cfg(unix)]
#[test]
fn symlink_escaping_root_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let outside = parent.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let resolved = ws.resolve_within(&root.join("link").join("file"));
    assert!(matches!(resolved, Err(WorkspaceError::SymlinkEscapesRoot)));
}

#[test]
fn mixed_separators_normalize_to_same_result_as_native_separators() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let mixed = format!("{}/sub\\file.kicad_pro", dir.path().display());
    assert!(ws.resolve_within(Path::new(&mixed)).is_ok());
}

#[test]
fn relative_root_is_rejected_at_construction() {
    let result = WorkspaceAuthorization::new("proj".into(), Path::new("relative/dir"));
    assert!(matches!(result, Err(WorkspaceError::RelativeRoot)));
}
```

- [ ] **Step 2:** Run `cargo test -p companion-workspace`, confirm failure.
- [ ] **Step 3:** Implement `boundary.rs`: canonicalize root at
  construction (`dunce::canonicalize` for sane Windows `\\?\` handling);
  `resolve_within` canonicalizes the requested path's *existing* ancestor
  and re-joins remaining components (so it works for paths that don't exist
  yet, e.g. a file about to be created), resolves any symlinks encountered,
  then checks `Path::components()` containment against `canonical_root`
  component-by-component — never `str::starts_with`.
- [ ] **Step 4:** Run tests, confirm PASS on the current platform; note
  Windows-specific cases run in CI's `windows-latest` matrix leg. Clippy
  clean.
- [ ] **Step 5: Commit**

```bash
git add crates/workspace
git commit -m "feat(workspace): add canonical workspace path boundary enforcement"
```

### Task 3.2: `crates/policy` — tool registry (capability/risk types live in `companion-core`, see note above)

**Files:**
- Create: `crates/policy/Cargo.toml` (deps: `companion-core`, `thiserror`,
  `serde`, `toml`)
- Create: `crates/policy/src/tool_registry.rs`
- Create: `crates/policy/assets/tool_registry.toml` (tool name →
  capability/risk table; seeded from kicad-mcp-pro's documented tool list at
  `docs/tools-reference.generated.md`, expanded during Phase 6 when the real
  bridge is built against the live tool list)
- Test: `crates/policy/tests/capability.rs`
- Test: `crates/policy/tests/tool_registry.rs`

**Interfaces:**
- Produces: `Capability`, `CapabilitySet`, `CapabilityProfile` per spec
  §3.2, with `impl CapabilityProfile { fn effective_capabilities(&self) ->
  CapabilitySet }`.
- Produces: `RiskLevel` per spec §3.3.
- Produces: `pub trait ToolCapabilityResolver { fn resolve(&self, tool_name:
  &str) -> Option<(Capability, RiskLevel)>; }` and `pub struct
  TomlToolRegistry { .. }` loading `assets/tool_registry.toml` at build
  time via `include_str!` + validated with `#[test]` that every entry
  parses to a known `Capability` (fails the build's test suite, not
  silently, if the asset is malformed).

- [ ] **Step 1: Write failing tests**: `CapabilityProfile::Inspect`
  contains `project.read`/`schematic.read`/etc. but not
  `schematic.write`/`manufacturing.export`;
  `CapabilityProfile::Design.effective_capabilities()` is a strict superset
  of `Inspect`'s and still excludes `manufacturing.export`;
  `CapabilityProfile::Manufacturing` includes `manufacturing.export`;
  `TomlToolRegistry::resolve("schematic.add_symbol")` returns a known
  `(Capability, RiskLevel)` pair for a seeded fixture entry;
  `resolve("totally_unknown_tool")` returns `None`.
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement `capability.rs` (fixed profile-expansion table
  matching spec §3.2 exactly), `risk.rs`, `tool_registry.toml` seeded with
  at least: `project.read_metadata`→(`project.read`,Low),
  `schematic.read`→(`schematic.read`,Low),
  `schematic.add_symbol`→(`schematic.write`,Normal),
  `pcb.read`→(`pcb.read`,Low), `erc.run`→(`erc.run`,Normal),
  `drc.run`→(`drc.run`,Normal), `manufacturing.export_gerber`→
  (`manufacturing.export`,High) — exact upstream names reconciled against
  kicad-mcp-pro's tool reference doc in Task 6.2 once the live bridge is
  wired up; this task's fixture names are clearly marked
  `# placeholder pending Phase 6 reconciliation` in the TOML file comments,
  which is not a design placeholder (the mechanism is fully implemented and
  tested) but an acknowledged data-freshness note.
- [ ] **Step 4:** Run tests, confirm PASS; clippy clean.
- [ ] **Step 5: Commit**

```bash
git add crates/policy/src/capability.rs crates/policy/src/risk.rs crates/policy/src/tool_registry.rs crates/policy/assets crates/policy/tests/capability.rs crates/policy/tests/tool_registry.rs crates/policy/Cargo.toml
git commit -m "feat(policy): add capability model, risk levels, and tool registry"
```

### Task 3.3: `crates/policy` — deterministic policy engine

**Files:**
- Create: `crates/policy/src/engine.rs`
- Test: `crates/policy/tests/engine.rs`

**Note (decided during Phase 1 implementation, amending spec §3.2):**
`Capability`, `CapabilitySet`, `CapabilityProfile`, and `RiskLevel` are
owned by `companion-core` (they are shared domain vocabulary referenced by
`Session` itself), not redefined in `crates/policy`. `crates/policy`
imports them from `companion_core` and adds only the
`ToolCapabilityResolver`/registry and the evaluation engine. Task 3.2 below
is updated accordingly: it produces the tool registry only, not the
capability/risk types.

**Interfaces:**
- Consumes: `companion_core::{Session, SessionStatus, OperationRequest,
  Capability, CapabilitySet, CapabilityProfile, RiskLevel}`,
  `companion_workspace::WorkspaceAuthorization`,
  `ToolCapabilityResolver` (Task 3.2), `companion_core::Clock`.
- Produces: `pub enum PolicyDecision { Allow, Deny { reason: DenyReason },
  RequireApproval { reason: ApprovalReason, risk: RiskLevel } }`,
  `pub enum DenyReason { SessionNotActive, SessionExpired, SessionRevoked,
  WorkspaceNotAuthorized, PathEscapesWorkspace, UnknownTool,
  CapabilityNotGranted, MalformedRequest }`, `pub struct
  PolicyEngine<R: ToolCapabilityResolver> { resolver: R }` with `pub fn
  evaluate(&self, request: &OperationRequest, session: &Session, workspace:
  &WorkspaceAuthorization, clock: &dyn Clock) -> PolicyDecision`.

- [ ] **Step 1: Write failing tests**, one per rule in spec §3.5 / data-flow
  steps 4–10, each as an independent `#[test]` with a minimal fixture
  builder (`fn active_session(clock: &FakeClock) -> Session { .. }` helper
  in the test module):
  - `denies_when_session_not_active` (status `Connected`)
  - `denies_when_session_expired` (status `Active`, `expires_at` in the
    past per `FakeClock`)
  - `denies_when_session_revoked`
  - `denies_when_workspace_not_in_session_workspace_ids`
  - `denies_when_path_escapes_workspace` (uses `crates/workspace`'s
    boundary check via the `WorkspaceAuthorization` passed in)
  - `denies_unknown_tool_with_no_fallback_allow`
  - `denies_when_capability_not_in_effective_capabilities` (known tool,
    but session's profile is `Inspect` and tool maps to `schematic.write`)
  - `requires_approval_for_high_risk_operation_even_with_capability_granted`
    (session has `Manufacturing` profile, tool maps to
    `manufacturing.export`/High)
  - `allows_low_risk_known_tool_within_authorized_workspace_with_capability`
  - `manufacturing_capability_is_never_implied_by_design_profile` (session
    profile `Design`, tool maps to `manufacturing.export` → Deny
    `CapabilityNotGranted`, not Allow)
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement `engine.rs` as an ordered sequence of pure
  checks exactly matching data-flow.md steps 4–10, returning at the first
  failing check.
- [ ] **Step 4:** Run tests, confirm PASS; clippy clean.
- [ ] **Step 5: Commit**

```bash
git add crates/policy/src/engine.rs crates/policy/tests/engine.rs
git commit -m "feat(policy): add deterministic policy evaluation engine"
```

---

## Phase 4 — Session Engine

Concrete scope (full step-by-step detail added when this phase begins,
following the Task 3.3 template):

- `crates/sessions/src/state_machine.rs`: `Session::transition(&self, event:
  SessionEvent, clock: &dyn Clock) -> Result<Session, SessionError>`
  implementing every row of the transition table in
  `docs/architecture/session-lifecycle.md` plus a regression test per
  explicit non-transition (reconnect never resurrects `Active`; `Revoked`/
  `Expired` reject all further events).
- `crates/sessions/src/approvals.rs`: `ApprovalRequest`/`ApprovalDecision`
  handling feeding `PendingApproval → Active`.
- `crates/sessions/src/repository.rs`: persistence of sessions/approvals via
  `companion-storage`.
- Tests: full state table coverage (`crates/sessions/tests/transitions.rs`),
  TTL expiry under `FakeClock`, revoke-then-reconnect-still-denied
  (integration test combined with a `MockTransport` stub).

## Phase 5 — Local IPC + Daemon

Concrete scope:
- `crates/protocol/src/ipc.rs`: typed request/response DTOs enumerated in
  spec §7.
- `apps/daemon/src/main.rs`, `apps/daemon/src/lifecycle.rs` (startup order:
  storage → identity → policy/workspace load → session engine → core-bridge
  → transport → IPC server), `apps/daemon/src/ipc_server.rs` (named
  pipe/Unix socket via `interprocess`), `apps/daemon/src/single_instance.rs`
  (reuses `crates/storage`'s lock file), signal handling
  (`tokio::signal::ctrl_c` + platform SIGTERM where applicable) for clean
  shutdown.
- `apps/cli/src/main.rs` + one module per command group (`device.rs`,
  `pair.rs`, `workspace.rs`, `session.rs`, `audit.rs`, `status.rs`) using
  `clap` derive, all going through an `IpcClient` in `crates/protocol`.
- Tests: CLI⇄daemon integration tests spawning a real daemon process against
  a temp data dir; `--verbose` output asserted to never contain secret
  material.

## Phase 6 — Core Bridge

Concrete scope:
- `crates/core-bridge/src/client.rs`: `initialize`/`tools/list`/`tools/call`
  per spec §8, loopback allow-list enforcement, timeout, typed error
  mapping, correlation id passthrough.
- `tests/fixtures/mock_mcp_server`: a minimal Streamable HTTP server
  implementing the same three methods for integration tests.
- Task 6.2 reconciles `crates/policy/assets/tool_registry.toml` against
  kicad-mcp-pro's live `tools/list` response / `docs/tools-reference.generated.md`,
  replacing the Phase 3 placeholder names with the real upstream tool names.
- Tests: policy→core-bridge integration (allow → real call proxied; deny →
  never reaches core-bridge, asserted via a call-count spy).

## Phase 7 — Transport Abstraction

Concrete scope:
- `crates/transport/src/lib.rs`: `Transport` trait per spec §10.
- `crates/transport/src/mock.rs`: scriptable `MockTransport`.
- `crates/transport/src/reconnect.rs`: `ReconnectingTransport<T>` with
  exponential backoff + jitter per spec §10 parameters.
- `crates/protocol/src/envelope.rs`: the versioned envelope from
  `docs/protocol/README.md`.
- Tests: reconnect never busy-loops (bounded call count under `FakeClock`
  within a bounded wall interval), envelope rejects unknown
  `message_type`/oversized payload/mismatched major `protocol_version`.

## Phase 8 — Audit + Checkpoints

Concrete scope:
- `crates/audit/src/lib.rs`: `AuditEvent` creation/query over
  `companion-storage`, one write per policy decision + one update per
  execution outcome (spec §3.7).
- `crates/checkpoints/src/lib.rs`: `create`/`list`/`restore`/`delete` per
  spec §11, atomic metadata write (temp file + rename), disk-space note in
  `docs/architecture/` addendum.
- Tests: audit record exists for every Allow/Deny/RequireApproval; no
  secret/full-source-dump fields in audit rows; checkpoint restore rejects
  mismatched root explicitly; checkpoint dir never included in its own
  snapshot (no infinite recursion).

## Phase 9 — Desktop

Concrete scope:
- `apps/desktop/src-tauri`: Tauri 2 shell whose Rust commands are thin
  forwarders to the daemon's local IPC client (`crates/protocol`), never
  embedding policy logic.
- `apps/desktop/src`: React + TS + Vite screens per spec §12 (Status,
  Device, Pairing, Workspaces, Sessions incl. approval dialog, Activity,
  Settings), matching the mockups in the original product brief.
- CI: add the frontend job (`pnpm install --frozen-lockfile`, typecheck,
  lint, test, build) to `.github/workflows/ci.yml`, now that
  `apps/desktop/package.json` exists.
- Manual verification: run `pnpm tauri dev` against a locally running
  daemon in mock-transport mode and walk the approval dialog flow by hand,
  in addition to automated tests.

## Phase 10 — E2E

Concrete scope:
- `tests/e2e_vertical_slice.rs`: automates the full 23-step scenario from
  the product brief (fake KiCad MCP server → daemon → mock relay → pending
  session → CLI approve → low-risk operation → audit → high-risk operation
  → pending approval → allow-once → revoke → reconnect → denied), using the
  mock transport and mock MCP server built in earlier phases.
- Final pass over the Security Review Checklist (README) with a
  one-line disposition per item, referencing the test that proves it.
- Final verification commands (`cargo fmt --all -- --check`, `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and
  the frontend equivalents) run and their exact output captured in the
  final report.

---

## Execution note

Phases 0–3 above are specified to full bite-sized step granularity because
they are executed immediately following this plan's creation. Phases 4–10
are specified with concrete file paths, types/signatures, and required
tests; each phase's tasks are expanded to the same full step-by-step
template (failing test → run → implement → run → commit) in place, in this
file, immediately before that phase's work begins — this file is the living
plan of record, not a snapshot.
