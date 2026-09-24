# KiCad MCP Pro Companion — V1 Design Spec

Status: approved architectural direction (see project principles below).
This spec is the source of truth the implementation plan
(`docs/superpowers/plans/2026-09-16-companion-v1.md`) argues from.

## 1. Problem and scope

Companion is the trusted local runtime between remote/cloud AI agents and a
user's local kicad-mcp-pro installation. Full rationale in
[`docs/architecture/system-overview.md`](../../architecture/system-overview.md).
This spec covers V1: everything needed for the local trust boundary to work
end-to-end against a **mock** relay/cloud, with real device identity, real
SQLite persistence, a real policy engine, and a real (client-only) local MCP
bridge to kicad-mcp-pro. The hosted cloud control plane is out of scope
(see project principle 13).

## 2. Workspace layout

```
kicad-mcp-pro-companion/
  Cargo.toml                 # workspace root
  rust-toolchain.toml
  apps/
    daemon/                  # apps/daemon — authoritative local runtime binary
    cli/                     # apps/cli — kicad-mcp-companion clap binary
    desktop/                 # apps/desktop — Tauri + React shell (Phase 9)
  crates/
    protocol/                # wire types: envelope, pairing/session DTOs, IPC DTOs
    core/                    # typed IDs, domain model, error taxonomy, Clock
    identity/                # device keypair, SecretStore, fingerprint
    workspace/                # WorkspaceAuthorization + path boundary enforcement
    policy/                  # Capability/Profile/Risk + PolicyEngine
    sessions/                # session state machine
    storage/                  # SQLite + migrations
    audit/                    # structured audit trail
    transport/                # Transport trait + mock transport + backoff
    core-bridge/               # MCP Streamable HTTP client to kicad-mcp-pro
    checkpoints/               # local safe-snapshot subsystem
  docs/
  tests/fixtures/
  scripts/
  .github/workflows/
```

## 3. Domain model (owned by `crates/core`)

### 3.1 Typed IDs

All IDs are newtypes wrapping a ULID string (`ulid` crate) — sortable,
unique, no raw `String`/`Uuid` passed where a specific ID type is meant.

```rust
macro_rules! typed_id { ($name:ident, $prefix:literal) => { /* newtype over Ulid, Display as "<prefix>_<ulid>", FromStr, Serialize/Deserialize */ } }

typed_id!(DeviceId,      "dev");
typed_id!(AccountId,     "acct");
typed_id!(WorkspaceId,   "ws");
typed_id!(SessionId,     "sess");
typed_id!(TaskId,        "task");
typed_id!(OperationId,   "op");
typed_id!(CheckpointId,  "chk");
```

`DeviceIdentity { device_id: DeviceId, public_key: DevicePublicKey, fingerprint: DeviceFingerprint, display_name: String, created_at: OffsetDateTime }`.
`DevicePublicKey(pub [u8; 32])` (Ed25519). `DeviceFingerprint(String)` —
derived, display-only, never used as a security check by itself.

### 3.2 Capability model

```rust
pub struct Capability(&'static str); // interned, e.g. "schematic.write"
pub struct CapabilitySet(BTreeSet<Capability>);
pub enum CapabilityProfile { Inspect, Design, Manufacturing, Custom(CapabilitySet) }
```

Known capability namespace (V1, extendable via the tool→capability
registry, never invented ad hoc by the policy engine):
`project.read`, `schematic.read`, `schematic.write`, `pcb.read`,
`pcb.write`, `erc.run`, `drc.run`, `validation.run`,
`manufacturing.read`, `manufacturing.export`, `workspace.read`.

Profile expansion (fixed table, unit-tested):
- `Inspect` → `{project.read, schematic.read, pcb.read, validation.run,
  erc.run, drc.run, workspace.read}`
- `Design` → `Inspect` ∪ `{schematic.write, pcb.write}` — **never** includes
  `manufacturing.export`.
- `Manufacturing` → `Design` ∪ `{manufacturing.read, manufacturing.export}`.
- `Custom(set)` → exactly `set`, intersected with what the account/device
  relationship allows (future cloud concern; V1 treats it as the full set).

### 3.3 Risk model

```rust
pub enum RiskLevel { Low, Normal, High, Critical }
```

Fixed classification table (owned by `crates/policy`, keyed by capability +
operation shape), e.g. `project.read`→Low, `schematic.write`(single
symbol)→Normal, `manufacturing.export`→High, any destructive batch
mutation→High, data-exfiltration-shaped operations→Critical (denied by
default), arbitrary shell → not a capability at all, forbidden.

### 3.4 Session

```rust
pub struct Session {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub remote_principal: String,          // opaque, cloud-supplied label
    pub workspace_ids: BTreeSet<WorkspaceId>,
    pub capability_profile: CapabilityProfile,
    pub effective_capabilities: CapabilitySet,
    pub task_scope: String,
    pub issued_at: OffsetDateTime,
    pub approved_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    pub risk_policy_version: u32,
    pub approval_policy: ApprovalPolicy,
    pub status: SessionStatus,
}
pub enum SessionStatus { Unpaired, Paired, Disconnected, Connected, PendingApproval, Active, Suspended, Expired, Revoked }
```

Transition table and every explicit non-transition: see
[`docs/architecture/session-lifecycle.md`](../../architecture/session-lifecycle.md).
Implemented as `Session::transition(&self, event: SessionEvent, clock: &dyn Clock) -> Result<Session, SessionError>` — pure, returns a new `Session`, never mutates in place, so illegal transitions are compile-time-impossible to skip-test.

### 3.5 Policy evaluation

```rust
pub struct OperationRequest {
    pub operation_id: OperationId,
    pub session_id: SessionId,
    pub workspace_id: WorkspaceId,
    pub tool_name: String,          // as named by kicad-mcp-pro's MCP tool registry
    pub target_path: Option<PathBuf>,
    pub requested_at: OffsetDateTime,
}

pub enum PolicyDecision {
    Allow,
    Deny { reason: DenyReason },
    RequireApproval { reason: ApprovalReason, risk: RiskLevel },
}

pub trait PolicyEngine {
    fn evaluate(
        &self,
        request: &OperationRequest,
        session: &Session,
        workspace: &WorkspaceAuthorization,
        clock: &dyn Clock,
    ) -> PolicyDecision;
}
```

Evaluation order matches [`docs/architecture/data-flow.md`](../../architecture/data-flow.md)
steps 4–10 exactly and is implemented as an ordered list of pure rule
functions so each rule is independently unit-testable.

### 3.6 Workspace

```rust
pub struct WorkspaceAuthorization {
    pub workspace_id: WorkspaceId,
    pub display_name: String,
    pub canonical_root: PathBuf,   // canonicalized at authorization time
    pub created_at: OffsetDateTime,
    pub enabled: bool,
}

pub trait WorkspaceBoundary {
    fn resolve_within(&self, requested: &Path) -> Result<PathBuf, WorkspaceError>;
}
```

`resolve_within` canonicalizes `requested`, resolves symlinks, and checks
component-wise containment under `canonical_root` — never a string-prefix
check. See spec §6 for the exact test matrix.

### 3.7 Audit

```rust
pub struct AuditEvent {
    pub operation_id: OperationId,
    pub timestamp: OffsetDateTime,
    pub session_id: Option<SessionId>,
    pub workspace_id: Option<WorkspaceId>,
    pub remote_principal: Option<String>,
    pub requested_tool: String,
    pub capability: Option<Capability>,
    pub risk: Option<RiskLevel>,
    pub policy_result: PolicyResultKind,   // Allow/Deny/RequireApproval
    pub approval_decision: Option<ApprovalDecisionKind>,
    pub execution_status: ExecutionStatus, // NotExecuted/Success/Failed
    pub error_class: Option<String>,
    pub duration_ms: Option<u64>,
}
```

### 3.8 Errors

`thiserror`-based per-crate error enums with stable string codes
(`IDENTITY_*`, `PAIRING_*`, `SESSION_*`, `POLICY_*`, `WORKSPACE_*`,
`TRANSPORT_*`, `CORE_*`, `STORAGE_*`, `CHECKPOINT_*`, `IPC_*`). Each carries
`{ code: &'static str, message: String (safe/user-facing), retryable: bool,
context: serde_json::Value (non-sensitive only) }` via a shared
`CompanionError` trait so CLI/IPC surfaces render them uniformly.
`anyhow` is used only at `apps/*` binary boundaries (`main.rs`), never
inside library crates.

### 3.9 Clock

```rust
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}
pub struct SystemClock;
#[cfg(any(test, feature = "test-util"))]
pub struct FakeClock { /* interior-mutable instant, advance(Duration) */ }
```

## 4. Storage (`crates/storage`)

SQLite via `rusqlite` (bundled) with migrations via `rusqlite_migration`
(embedded, no external migration server). Tables (V1): `device`,
`workspaces`, `sessions`, `approvals`, `audit_events`, `settings`,
`checkpoints`. Migrations live at `crates/storage/migrations/NNNN_*.sql` and
run automatically on daemon startup inside a transaction; a failed migration
aborts startup with a typed `STORAGE_MIGRATION_FAILED` error rather than
modifying data further. Corrupt/unreadable DB files produce
`STORAGE_DB_UNREADABLE` with the underlying SQLite error preserved in
context, never a panic.

## 5. Identity (`crates/identity`)

Ed25519 via `ed25519-dalek` + `rand_core::OsRng`. `SecretStore` trait (see
[`docs/security/secure-storage.md`](../../security/secure-storage.md)) with
a Windows DPAPI adapter (`windows` crate,
`CryptProtectData`/`CryptUnprotectData` or `Windows.Security.Cryptography.DataProtection`)
as the V1 production adapter, and an `InMemorySecretStore` gated behind
`#[cfg(any(test, feature = "test-util"))]`.

```rust
pub trait DeviceIdentityStore {
    fn load(&self) -> Result<Option<DeviceIdentity>, IdentityError>;
    fn create(&self, display_name: &str) -> Result<DeviceIdentity, IdentityError>;
    fn public_identity(&self) -> Result<Option<DeviceIdentity>, IdentityError>;
    fn sign(&self, message: &[u8]) -> Result<Signature, IdentityError>;
}
```

## 6. Workspace path boundary — required test matrix

Implemented in `crates/workspace/src/boundary.rs`, tested in
`crates/workspace/tests/boundary.rs` (Windows-specific cases behind
`#[cfg(windows)]`, POSIX-specific behind `#[cfg(unix)]`):

1. `C:\project\sub\file.kicad_pro` inside `C:\project` → Ok.
2. `C:\project-evil\file` against root `C:\project` → Err (prefix
   collision without separator must not pass).
3. `C:\project\..\project-evil\file` → Err (traversal).
4. `C:\project\sub\..\..\..\Windows\System32\evil` → Err.
5. A symlink inside `C:\project` pointing outside it → Err at resolution
   time (resolve target, then re-check containment).
6. Mixed separators `C:/project/sub\\file` → normalized then checked, same
   result as case 1.
7. Unicode-confusable path segments (e.g. combining characters,
   NFC vs NFD forms of the same visual name) → compared post-normalization;
   a segment that only *looks* like `project` but isn't byte-identical after
   normalization is rejected, not fuzzy-matched.
8. Relative root config value is rejected at `WorkspaceAuthorization`
   construction time — roots are always stored canonical/absolute.

## 7. Local IPC (`crates/protocol` DTOs + `apps/daemon` server + `apps/cli`/`apps/desktop` clients)

Named pipe on Windows (`\\.\pipe\kicad-mcp-companion`), Unix domain socket
elsewhere (`$XDG_RUNTIME_DIR` or app data dir), via the `interprocess` crate.
No public TCP listener in any configuration; a `127.0.0.1`-bound HTTP
fallback is defined in `crates/protocol` but not wired up as default in V1.
Local API surface (request/response DTOs in `crates/protocol::ipc`):
`Status`, `PairingStatus`, `BeginPairing`, `ListSessions`,
`ApproveSession{session_id}`, `DenySession{session_id}`,
`PauseSession{session_id}`, `ResumeSession{session_id}`,
`RevokeSession{session_id}`, `ListWorkspaces`,
`AuthorizeWorkspace{path,display_name}`, `RemoveWorkspace{workspace_id}`,
`AuditSummary{filter}`, `DaemonShutdown`.

## 8. Core bridge (`crates/core-bridge`)

`reqwest`-based MCP Streamable HTTP client. Default endpoint
`http://127.0.0.1:3334/mcp`, configurable, but the crate refuses to connect
to any non-loopback/non-explicitly-allow-listed host by default
(`CORE_BRIDGE_ENDPOINT_NOT_ALLOWED`). Implements `initialize`, `tools/list`,
`tools/call` per kicad-mcp-pro's documented contract (protocol version
`2025-11-25` at time of writing; sends
`Accept: application/json, text/event-stream`, echoes
`MCP-Protocol-Version`, honors `MCP-Session-Id` when the server returns one).
Per-call timeout (default 30s, configurable), typed error mapping
(`CORE_TIMEOUT`, `CORE_UNREACHABLE`, `CORE_PROTOCOL_ERROR`,
`CORE_TOOL_ERROR`), correlation id passthrough for audit. A mock server
(`tests/fixtures/mock_mcp_server`) implements the same three methods for
integration tests.

## 9. Tool → capability mapping (`crates/policy::tool_registry`)

Data-driven table (`crates/policy/src/tool_registry.rs`, backed by an
embedded TOML/JSON asset validated at compile time via a build-time test)
mapping kicad-mcp-pro tool name → `(Capability, RiskLevel)`. Unknown tool
name → `PolicyDecision::Deny { reason: DenyReason::UnknownTool }`, never a
fallback allow. The exact upstream tool name list is confirmed against
kicad-mcp-pro's `docs/tools-reference.generated.md` before the mapping is
finalized in the Phase 6 task.

## 10. Transport (`crates/transport`)

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self) -> Result<(), TransportError>;
    async fn disconnect(&self) -> Result<(), TransportError>;
    async fn send(&self, envelope: Envelope) -> Result<(), TransportError>;
    async fn receive(&self) -> Result<Envelope, TransportError>;
    fn state(&self) -> CoreConnectionState;
    async fn health(&self) -> TransportHealth;
}
```

V1 ships `MockTransport` (deterministic, in-memory, scriptable for tests)
and `ReconnectingTransport<T>` decorator implementing exponential backoff
with jitter (`base=250ms, factor=2.0, max=30s, jitter=±20%`), capped retry
count configurable, never a busy loop. No production cloud transport is
implemented in this repository (see project principle 13/15).

## 11. Checkpoints (`crates/checkpoints`)

V1 strategy: copy-on-checkpoint of the authorized workspace root into
`<data_dir>/checkpoints/<workspace_id>/<checkpoint_id>/`, excluding the
checkpoints directory itself (no recursive self-snapshot), with an atomic
metadata write (write-temp-then-rename). `create`, `list`, `restore`,
`delete` per workspace; restore requires the workspace to currently match
the checkpoint's recorded root (fails explicitly rather than guessing on
mismatch). No automatic pruning that deletes all history silently — cleanup
policy is explicit and documented, defaulting to "never delete without an
explicit command."

## 12. Desktop (`apps/desktop`, Phase 9)

Tauri 2 + React + TypeScript + Vite. Talks only to the daemon's local IPC
(via a thin Tauri command layer that forwards typed requests, never embeds
policy logic in TypeScript). Screens: Status, Device, Pairing, Workspaces,
Sessions (incl. approval dialog), Activity/Audit, Settings. Full screen
content per the product spec's mockups.

## 13. CI

`.github/workflows/ci.yml`: matrix `{ubuntu-latest, windows-latest,
macos-latest}` running `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`; a separate frontend job once `apps/desktop` has a
frontend; a `cargo audit` (or `cargo deny`) job. Live-KiCad tests are a
separate, manually-triggered workflow, never part of the default gate.

## 14. Explicit non-goals for V1

Everything in the prompt's "OUT OF SCOPE FOR THIS INITIAL IMPLEMENTATION"
list: production hosted cloud, billing, accounts DB, teams/SSO, real-time
collaboration/CRDT, cloud project storage, GitHub sync, mobile app,
production ChatGPT pairing, cloud-hosted KiCad/inference, arbitrary
shell/filesystem access, unattended manufacturing automation.
