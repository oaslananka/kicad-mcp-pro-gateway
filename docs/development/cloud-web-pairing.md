# Owner-approved Cloud Device Pairing (Linux-first)

This is the user-account link, not authorization for ChatGPT or KiCad tools.

1. Sign into https://kicad-mcp-pro.oaslananka.dev with GitHub.
2. Open Cihazlar, choose + Linux cihazı eşleştir, copy the 10-minute code.
3. On the Linux computer with the same Gateway daemon build, run:

       kicad-mcp-gateway device cloud-pair YOUR_ONE_TIME_CODE

4. The CLI proves the compatible local daemon identity through the established
   IPC channel. The daemon signs only the domain-separated pairing message
   using its existing native OS-keyring Ed25519 device key. The CLI sends
   this signed public proof to the fixed HTTPS Cloud Web service.
5. Confirm the displayed fingerprint in Cihazlar. Until explicit approval
   the device is only awaiting approval; once approved, it is listed as
   paired_offline until actual authenticated Cloud Relay activity is linked.

The signing message is three ASCII lines joined with LF:
   kicad-mcp-cloud-web/pair/v1
   <device_id>
   <code>

The browser owns the one-time high-entropy code. Never paste private keys,
GitHub tokens or Doppler secrets into the dashboard or CLI. The CLI rejects
all redirects and pins HTTPS to the application's public production host.
The local daemon IPC contract is version 6, so older daemons cannot silently
accept new requests. Upgrade CLI/daemon together. The original local
mock-only Gateway pair command remains a separate development flow.

Pairing does not grant workspace access, remote tools, or MCP operations.
The remote public /mcp service remains deliberately unavailable until
principal attestation, Cloud Relay forwarding and owner-local approvals exist.
