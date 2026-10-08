# KiCad MCP Pro Gateway

KiCad MCP Pro Gateway is the trusted local runtime that securely connects
authorized remote AI agents and cloud services to a user's local
[KiCad MCP Pro](https://github.com/oaslananka/kicad-mcp-pro) environment.

> KiCad MCP Pro knows how to operate KiCad.
> KiCad MCP Pro Gateway decides whether a remote actor is allowed to ask it to.

## Project Status & Maturity

**Current Status:** Pre-alpha / Unreleased Local Vertical Slice.

The release-candidate engineering pipeline is implemented, but pipeline readiness is
not evidence that an actual Gateway RC or stable release has been qualified.
The current release record remains a **conditional go**: stable promotion still
requires an exact tagged RC with signing/provenance evidence, clean-machine
qualification on every supported platform, live macOS/Windows KiCad + MCP
evidence, and human release-owner authorization. See
[the V1 sign-off record](docs/development/v1-stable-signoff.md).

Release management, security automation, and target architecture support are
documented in:
- [Compatibility Matrix](docs/architecture/compatibility-matrix.md)
- [Security Automation & Governance](docs/development/security-automation.md)
- [Release Architecture & Engineering](docs/development/release.md)
- [Companion → Gateway Identity Migration & Compatibility Decision](docs/development/identity-migration.md)
- [Production Daemon Lifecycle Contract](docs/development/daemon-lifecycle.md)
- [Private Cloud Relay Authenticated Heartbeat Pilot](docs/development/cloud-relay-pilot.md) — opt-in development transport; remote MCP remains unavailable

## Why Gateway exists

kicad-mcp-pro exposes a rich MCP tool surface for driving KiCad from AI
agents, reachable locally over Streamable HTTP. That's the right shape for
"what can be done inside KiCad." It is not, by itself, an answer to "which
remote agent, from where, for how long, with which permissions, is allowed
to ask for it." Gateway is a separate project that answers exactly that
question, sitting between remote/cloud AI agents and the local kicad-mcp-pro
installation as a deny-by-default policy boundary.

## Relationship to kicad-mcp-pro

| | Owns |
|---|---|
| [kicad-mcp-pro](https://github.com/oaslananka/kicad-mcp-pro) | What can be done inside KiCad — schematic/PCB tools, ERC/DRC, manufacturing export |
| **kicad-mcp-pro-gateway** (this repo) | Who may ask for it, from where, to which workspace, for how long, under which permissions, through which trusted local session |
| Future private cloud service | Accounts, cloud device registry, hosted relay, cloud workspaces, billing, collaboration |

Gateway never re-implements KiCad domain logic and never modifies
kicad-mcp-pro. It talks to it purely as an MCP client over
`http://127.0.0.1:3334/mcp` (configurable) — see
[`docs/protocol/README.md`](docs/protocol/README.md).

## Architecture

```
ChatGPT / Claude / Web / Agent
             |
     KiCad MCP Cloud (future, not in this repo)
             |
       encrypted OUTBOUND connection
             |
   +--------------------+
   |   Gateway Daemon   |  <-- DENY-BY-DEFAULT POLICY BOUNDARY
   +--------------------+      - Device identity / pairing
             |                 - Workspace path isolation
             |                 - Session & capability scope
             |                 - Audit logging & checkpoints
             v
   Local KiCad MCP Pro (http://127.0.0.1:3334/mcp)
             |
      Local KiCad 10.0.x
```

## Security Invariants

1. **Fail-closed default:** Any unclassified or unknown MCP tool is denied.
2. **Loopback-only core:** `kicad-mcp-pro` is exposed only to localhost.
3. **Workspace containment:** All operations are constrained to approved workspace root paths.
4. **Explicit approvals:** High-risk operations (e.g., manufacturing export, irreversible edits) require explicit user approval.
5. **Session revocation:** Revoked or expired sessions immediately stop processing requests.
