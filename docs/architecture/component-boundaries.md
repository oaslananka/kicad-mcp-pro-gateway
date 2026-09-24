# Component Boundaries

## Three-project boundary

| Project | Owns | Does NOT own |
|---|---|---|
| `kicad-mcp-pro` (external, unmodified) | What can be done inside KiCad: schematic/PCB tools, ERC/DRC, manufacturing export, MCP tool surface | Who may invoke it, from where, under what authorization |
| `kicad-mcp-pro-gateway` (this repo) | Device identity, pairing (client side), session lifecycle, workspace authorization, capability policy, risk classification, approvals, audit, checkpoints, secure transport (client side) | KiCad domain logic of any kind; the hosted cloud control plane |
| Future private cloud service | Accounts, device registry, hosted relay, cloud workspaces, billing, collaboration/teams | The local trust boundary — it is always treated as **untrusted input** by Gateway |

Gateway must never grow KiCad-specific tool logic. If a change requires
knowing *how* to edit a schematic, it belongs in kicad-mcp-pro. If a change
requires knowing *whether* a request is allowed, it belongs in Gateway.

## Internal crate/app boundaries

```
apps/desktop  --local IPC-->  apps/daemon  --HTTP(loopback)-->  kicad-mcp-pro
apps/cli      --local IPC-->  apps/daemon
```

- **`apps/desktop`** (Tauri + React) never talks to the cloud and never talks
  to kicad-mcp-pro directly. It only talks to the daemon's local IPC API.
- **`apps/cli`** never talks to the cloud or kicad-mcp-pro directly either,
  and never re-implements authorization logic — it is a thin client over the
  same local IPC API the desktop app uses.
- **`apps/daemon`** is the single authoritative local runtime. All privileged
  decisions happen here.

### Crate responsibilities

| Crate | Responsibility | Must not do |
|---|---|---|
| `protocol` | Wire types shared across daemon/CLI/desktop IPC and the future cloud transport: envelopes, versioning, pairing/session DTOs | No business logic, no I/O |
| `core` | Strongly-typed domain IDs/models, error taxonomy, `Clock` abstraction | No I/O, no KiCad knowledge |
| `identity` | Device keypair generation, secure-storage abstraction, fingerprinting, signing | No session/workspace logic |
| `workspace` | Authorized workspace records, canonical path boundary enforcement | No capability/risk logic |
| `policy` | Capability/profile/risk model, `ToolCapabilityResolver`, deterministic policy evaluator | No I/O, no network, no KiCad tool implementations |
| `sessions` | Session state machine, TTL, approvals, revoke/pause/resume | No transport, no policy decisions (consumes `policy`) |
| `storage` | SQLite persistence + migrations for all non-secret state | No secret material ever written in plaintext |
| `audit` | Structured audit event creation/query on top of `storage` | No policy decisions |
| `transport` | Transport trait, mock transport, protocol envelope, reconnect/backoff | No vendor-specific cloud implementation (future work) |
| `core-bridge` | Adapter to the local kicad-mcp-pro MCP endpoint only | No arbitrary/public network targets, no KiCad domain logic |
| `checkpoints` | Local safe-snapshot create/list/restore for authorized workspaces | No distributed revision graph (future work) |

Each crate has exactly one reason to change. If a change touches two
unrelated reasons, that is a signal the boundary is wrong.

## Why the daemon is authoritative

The desktop UI and CLI are both untrusted-adjacent from the daemon's point of
view: neither is allowed to short-circuit policy evaluation, and both must
observe the same state the daemon owns. This guarantees a single code path
for "is this operation allowed," which is the property the whole security
model depends on. See [trust-boundaries.md](../security/trust-boundaries.md).
