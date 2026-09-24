# Security Policy

KiCad MCP Pro Companion is a security boundary by design: it decides
whether a remote AI agent or cloud service may operate on a user's local
KiCad MCP Pro installation. Its threat model is documented in
[`docs/security/threat-model.md`](docs/security/threat-model.md) and its
trust boundaries in
[`docs/security/trust-boundaries.md`](docs/security/trust-boundaries.md).

## Supported versions

This project is currently in pre-alpha / pre-1.0 (`0.x`) unreleased development. All security fixes land on `main`. Once stable releases are published, security updates will target the latest active minor release.

| Version | Supported | Status |
|---|---|---|
| `main` (unreleased) | ✅ | Active Development |
| Pre-alpha | ❌ | No published release binaries yet |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository
(Security tab → "Report a vulnerability"), or open a
[GitHub Security Advisory](https://github.com/oaslananka/kicad-mcp-pro-companion/security/advisories/new).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce, or a minimal proof of concept.
- Whether the issue affects the local trust boundary (session/workspace/
  capability enforcement, secret storage) or the transport layer.

We aim to acknowledge reports within 5 business days. Disclosure timing is
coordinated with the reporter; we ask for a reasonable window to ship a fix
before public disclosure.
