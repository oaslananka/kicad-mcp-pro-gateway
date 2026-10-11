# Owner-approved Cloud Device Pairing (Linux-first)

This is the user-account link, not authorization for ChatGPT or KiCad tools.

1. Sign into https://kicad-mcp-pro.oaslananka.dev with GitHub.
2. Open Cihazlar, choose + Linux cihazı eşleştir, copy the 10-minute code.
3. **Preferred desktop flow (Gateway desktop + compatible daemon IPC v7):**
   - Open the Gateway desktop application and choose **Kurulum → Cihaz**.
   - Paste the invitation code and choose **Cihaz kanıtını gönder**.
   - The desktop calls the **local daemon IPC only**. The daemon signs the
     same domain-separated CloudPairingProof used by the CLI, then sends the
     public proof to the fixed HTTPS Cloud Web endpoint with redirects
     forbidden and a bounded timeout. No key material, browser cookies,
     project paths or authenticated remote tool grants are transmitted.
   - The Cloud Web owner **must still compare the fingerprint and approve**
     the pending request. A successful submit response is not an approval.

   If using a CLI-only installation, run on the Linux device:

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
The local daemon IPC contract is version 7: the extra submit action
belongs to the daemon, not the Tauri shell. Older daemons cannot silently
accept new requests. Upgrade CLI/daemon together. The original local
mock-only Gateway pair command remains a separate development flow.

Pairing does not grant workspace access, remote tools, or MCP operations.
The remote public /mcp service remains deliberately unavailable until
principal attestation, Cloud Relay forwarding and owner-local approvals exist.

## Three-step first-run desktop workflow

1. **Cihaz:** Sign in to Cloud Web with GitHub, request the 10-minute code,
   paste it into Gateway Desktop > Kurulum, submit the signed proof via local
   IPC, compare the device fingerprint and explicitly approve in Cloud Web.
2. **ChatGPT:** This is currently **disabled**. The desktop displays the
   future /mcp URL and explains the OAuth/Relay/Gateway gate; it must not
   claim success or ask the user to create a non-functional connector.
3. **Proje:** Use the native OS directory picker (or enter a local path) in
   the desktop. The existing IPC AuthorizeWorkspace command and daemon
   containment policy decide whether to register the selected root; the
   picker choice is not authorization evidence. The operation does not send
   files to Cloud Web or grant ChatGPT read access. Workspaces can be revoked
   from the existing Workspaces screen.

Current packaging is pre-alpha; this source change does not create a signed
installer or evidence a live Windows/macOS KiCad release.
