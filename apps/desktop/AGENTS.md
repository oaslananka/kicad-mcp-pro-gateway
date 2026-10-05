# Desktop Application Instructions

These instructions apply to `apps/desktop/**` and supplement the repository root `AGENTS.md`.

## Boundary

The desktop is a local client and lifecycle owner for the packaged Gateway daemon sidecar. It does
not own authorization policy, talk to the cloud directly, or call `kicad-mcp-pro` directly.

Read first:

- `docs/development/daemon-lifecycle.md`
- `docs/architecture/component-boundaries.md`
- `docs/security/secure-storage.md`
- `docs/development/testing.md`
- `docs/development/release.md`
- `apps/desktop/src-tauri/vendor/compat/README.md`

## IPC-only authority boundary

Privileged desktop operations go through the daemon's local IPC API.

- Do not add a direct cloud or core-bridge execution path from the UI/Tauri shell.
- Do not add TCP fallback for local IPC.
- Preserve the identity handshake before privileged forwarding: product ID, local IPC contract
  version, packaged daemon version, and process instance identity.
- Wrong-product, wrong-protocol, or incompatible endpoints fail closed; do not probe alternate
  privileged endpoints.

The desktop may render safe authorization/risk evidence but must not receive raw operation arguments
or credentials merely to improve explanations.

## Packaged daemon lifecycle

Production builds use the packaged sidecar.

- Do not search `PATH` for a replacement daemon.
- Do not accept a daemon path from the UI.
- Keep `externalBin`, sidecar staging scripts, binary name, target triple, and packaging layout
  synchronized.
- Preserve single-daemon ownership and the CLI/desktop explicit-stop handoff.
- Bounded restart/watchdog behavior must not create multiple daemon owners.

Release version parity across the root/daemon workspace version, desktop Cargo package, desktop `package.json`, and `tauri.conf.json` is mandatory. A release-version change must also refresh the affected Cargo lockfiles before locked CI/package builds.

## Vendored Tauri/GTK compatibility set

`apps/desktop/src-tauri/vendor/compat/` is reviewed security compatibility code, not disposable
generated/vendor output.

Do not casually delete, replace, or regenerate it.

The current set intentionally:

- removes the vulnerable `glib 0.18` resolution while preserving Tauri's package constraints;
- contains reviewed API compatibility patches;
- hardens null native-pointer handling;
- normalizes native cookies to `Secure=true`.

Any update/removal requires upstream provenance review, MSRV/stable checks, OSV verification, and the
security guarantees documented in its README.

## UI and secret handling

- Never display raw daemon stderr as user-facing diagnostics.
- Do not log or render private keys, tokens, pairing codes, credentials, sensitive paths, config
  values, or process arguments.
- Failure UI should identify bounded product/protocol/lifecycle states rather than dump internal
  errors.
- User-selected paths remain untrusted and do not bypass daemon workspace policy.

## Verification

For frontend/Tauri changes:

```bash
cd apps/desktop
pnpm install --frozen-lockfile
pnpm audit
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm sidecar:dev
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

For package/lifecycle changes also run the appropriate sidecar release/verification and Tauri
packaging path from `docs/development/daemon-lifecycle.md`.

## Definition of done

A desktop change is complete only when IPC-only authority, endpoint identity, sidecar lifecycle,
version parity, vendored compatibility security, secret-safe UX, tests, and package evidence remain
aligned.
