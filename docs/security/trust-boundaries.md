# Trust Boundaries

## Boundary map

```
 UNTRUSTED                  TRUST BOUNDARY                   TRUSTED
 ───────────                ──────────────                   ───────
 Cloud relay  ───outbound TLS───▶ [transport crate] ───▶ daemon core
 Remote agent                                              (policy, sessions,
 (via cloud)                                                workspace, audit)
                                                                  │
                                                                  ▼
                                                          [core-bridge crate]
                                                                  │
                                                     loopback-only, allow-list
                                                                  ▼
                                                          kicad-mcp-pro (local)


 Desktop UI ──local IPC (named pipe / Unix socket)──▶ daemon local API
 CLI        ──local IPC (named pipe / Unix socket)──▶ daemon local API
```

## Rules that hold at every boundary crossing

1. **Cloud → transport**: everything received is untrusted input. It is
   validated (envelope shape, size, protocol version) before it is allowed
   to reference any domain type.
2. **transport → daemon core**: a message is only ever turned into a
   `Session`/`OperationRequest` lookup; it is never allowed to construct or
   mutate a `Session` directly. Session state changes only happen through
   the state machine's own transition functions.
3. **daemon core → core-bridge**: the daemon only calls core-bridge after a
   policy `Allow`. core-bridge itself additionally refuses any endpoint that
   is not loopback/local by default — even if the daemon were misconfigured,
   core-bridge is a second gate against reaching an arbitrary network host.
4. **Desktop/CLI → daemon local API**: this boundary is trusted-local (same
   machine, same user), but it is still not allowed to skip policy — the
   local API only exposes operations that are themselves policy-safe
   (status, approve/deny, pause/resume/revoke, workspace CRUD, audit read).
   It has no "run arbitrary tool" verb.
5. **daemon → SQLite**: only non-secret state crosses this boundary. Private
   key material never does (see [secure-storage.md](secure-storage.md)).

## Authentication vs. authorization — kept explicitly separate

These are three different, non-substitutable facts, and the codebase must
never conflate them:

- **Transport authentication**: proves *which device* is on the other end of
  the pipe. Established by the transport handshake.
- **Pairing**: proves the device is *known and trusted* by the account.
  Established once, persists until revoked.
- **Active session with effective capabilities**: proves *this specific
  remote principal, right now, for this workspace and task scope, is allowed
  to invoke this specific operation*. Established per-session, expires,
  can be revoked, and is re-checked on every operation.

A device being paired does not imply an active session. An active transport
connection does not imply an active session. An active session does not
imply unrestricted tool access — it implies exactly its effective
capabilities, subject to per-operation risk/approval checks.

## Process boundary note

The daemon is the only process that holds device private key material in
memory. The desktop UI and CLI processes never receive private key material
through the local API, under any verbosity setting.
