# Cloud Web device association status v1

This is **display-only** Cloud Web account association, not verified remote
actor identity, Relay transport enrollment, local Gateway permission or an MCP
tool authorization. A paired device can execute **zero** remote tools solely
because this check succeeds.

On a local Gateway `Status` or `PairingStatus` IPC request, the daemon uses its
existing secure-store Ed25519 identity to sign a short-lived status proof.
It issues `GET https://kicad-mcp-pro.oaslananka.dev/api/devices` with four
headers: `X-Kicad-Device-Id`, `X-Kicad-Timestamp` (Unix seconds),
`X-Kicad-Nonce` (two fresh ULIDs, 52 uppercase Crockford-base32 characters)
and `X-Kicad-Signature` (base64url Ed25519 signature without padding).
The signed bytes are UTF-8, with no trailing newline:

```
kicad-mcp-cloud-web/device-status/v1\nGET\n/api/devices\n{device_id}\n{timestamp}\n{nonce}
```

Every `\n` above denotes **one** ASCII LF byte. The proof includes the exact
method, path, device, time and nonce. It cannot be substituted for the separate
`kicad-mcp-cloud-web/pair/v1` one-time enrollment proof. Cloud Web verifies the
Ed25519 signature against the previously owner-approved database public key;
it rejects missing/ambiguous headers, timestamps outside ±60 seconds, unknown
keys, and already-consumed `(device_id, nonce)` tuples, with durable unique
nonce storage. An authenticated but revoked key receives `paired: false`.

A successful status reply is exactly
`{"paired":true|false,"device_id":"...","can_execute_tools":false}`.
The daemon rejects unexpected keys, a mismatched device ID, any assertion that
`can_execute_tools` is true, redirects, non-200 HTTP responses and oversized
responses. TLS certificate/hostname verification remains mandatory. The fixed
host is not caller-configurable; requests are bounded to 850 ms. Network,
secure-store or database failures produce the existing fail-closed
`paired: false` IPC value. Thus that value may mean **unavailable**, not proof
that the owner deliberately revoked the device; no cached `true` is kept.

This status query does **not** synchronize the Cloud Relay allowlist, establish
Relay device presence, grant workspace access, authenticate an OAuth user or
permit remote `tools/call`. Any future remote-operation path must independently
verify the signed remote principal, active Relay channel, durable replay state,
workspace grants, risk and pre-execution audit as specified in the security
contracts. Do not use `paired` as an authorization predicate.
