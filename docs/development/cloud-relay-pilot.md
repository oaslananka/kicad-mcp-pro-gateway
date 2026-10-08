# Private Cloud Relay — authenticated transport pilot

**Status (2026-10-08):** Authenticated Gateway device-to-relay heartbeat
connection is implemented and demonstrated against the separate private
`oaslananka/kicad-mcp-cloud-relay` service. **This is NOT a production
remote-agent MCP service.** No remote agent can open a grant, forward a tool
call, or issue a verified principal over this lane. The legacy mock transport
continues to cover local policy tests.

## Product ownership

- This public repository owns the local Gateway daemon, the OS-secret-store
  device identity, `GATEWAY_TRANSPORT_MODE=relay`, outbound WebSocket client,
  core MCP bridge, desktop IPC, local policy, audit, grants and workspace safety.
- The **separate private repository** owns the HTTP/WebSocket listener, the
  owner-managed enrolled *public-key* allowlist, remote ingress and any future
  account/OAuth backend. Do not move cloud accounts, enrollment keys, or backend
  credentials into the public desktop repository.

## Opt-in, fail-closed transport

`GATEWAY_TRANSPORT_MODE` continues to default to `disabled`. The
experimental `relay` mode requires `GATEWAY_RELAY_URL` (or `relay_url` in
the Gateway config). Only `wss://…/v1/device/connect` with normal WebPKI
certificate validation, or literal `ws://127.0.0.1:PORT/v1/device/connect`
and `ws://[::1]:PORT/v1/device/connect` **for local encrypted SSH tunneling**
are accepted. HTTP, cleartext remote WS, URL-embedded credentials, query
tokens, and unsupported paths fail configuration loading.

On the WebSocket connection the server gives a 256-bit random nonce. The
client signs exactly
`kicad-mcp-cloud-relay/auth/v1\n<device_id>\n<base64url_nonce>`
using the existing OS-secured Ed25519 device identity. The server validates
this against a **previously enrolled public key** before announcing `ready`.
The client only accepts `ready` for its exact device ID. Unexpected commands,
principal claims, and privileged outgoing payloads fail closed; heartbeat
is the only accepted traffic.

A working device connection means **transport connected**, not *cloud account
paired*, *remote actor verified*, or *authorized to run KiCad operations*.
Status and PairingStatus report `paired=false` until a real durable
production pairing flow exists. The desktop currently **always forces
transport disabled when launching a sidecar**, even with a configured
`relay_url`: this pilot must be started explicitly as a headless daemon, not
silently enabled on user desktops.

## Local-only end-to-end rehearsal

1. Build both CLI and daemon siblings on the same revision:
   `cargo build --locked -p kicad-mcp-gateway-cli -p kicad-mcp-gateway-daemon`.
2. Run the cloud service bound to `127.0.0.1:18788`, with an explicitly
   enrolled device public key and no public Internet listeners.
3. Forward the cloud port over authenticated private SSH:
   `ssh -N -L 127.0.0.1:18788:127.0.0.1:18788 <verified-host>`.
4. With the same local Gateway data directory containing the matching
   OS-secret-store identity, start the compiled daemon with
   `GATEWAY_TRANSPORT_MODE=relay` and
   `GATEWAY_RELAY_URL=ws://127.0.0.1:18788/v1/device/connect`.
5. `target/debug/kicad-mcp-gateway status` should show
   `Transport connectivity: Connected`, `paired: false`, and zero
   grants absent a local user approval. `device status` still truthfully
   reports unpaired. The cloud must refuse an invalid signature and a
   second concurrent device connection.

## Required before any public remote MCP operation

- Owner-authenticated, rate-limited, auditable production device enrollment
  and revocation; persistent device registry and public WSS/TLS deployment.
- MCP Streamable HTTP and provider-compatible OAuth/OIDC authentication with
  audience checks; explicit authenticated principal and client IDs.
- **Locally verified**, request-bound principal claims (issuer, audience,
  expiry, nonce, account/agent/device binding). Relay labels alone are
  untrusted; never populate `VerifiedPrincipal` from unsigned JSON.
- Durable replay protection across restarts, idempotency, per-actor
  backpressure/rate limits and audit provenance.
- Complete local grant, workspace and effect-aware policy tests and remote
  abuse-case coverage. Do not add shortcuts that bypass
  `remote_processor` or directly expose the loopback KiCad MCP port.
- Clean-machine packaging/QA and distinct release-owner approval. Existing
  `v1.0.0-rc1` source/CI run evidence predates this transport change and
  must NOT be represented as CI evidence for the new merge SHA.
