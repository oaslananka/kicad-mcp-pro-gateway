---
name: Compatibility Refresh
about: Periodic review of KiCad, protocol, OS, and tool snapshot compatibility matrix
title: 'docs: refresh canonical compatibility matrix for [quarter/release]'
labels: docs, compatibility
assignees: ''
---

## Scope
- [ ] Record the reviewed kicad-mcp-pro release tag and immutable commit SHA.
- [ ] Verify upstream `compatibility.yaml` at that SHA before updating KiCad claims.
- [ ] Update supported KiCad ranges, OS/architectures, core protocol lanes, and release artifacts in `docs/architecture/compatibility-matrix.md`.
- [ ] Download that commit's `docs/tools-reference.generated.md` and run `reconcile-tool-registry` to regenerate `crates/policy/assets/upstream_tool_snapshot.toml`.
- [ ] Review the reconciliation report; unclassified tools must remain fail-closed until separately authorized.
- [ ] Run `cargo test -p companion-policy` and the relevant workspace checks.
- [ ] Attach live KiCad/MCP reconciliation evidence for every combination promoted to live-validated status.
- [ ] Synchronize `README.md` and release documentation with the canonical matrix.

Do not promote an untested OS/architecture, KiCad line, or live-core
combination. Do not automatically mirror an upstream release: the pinned SHA,
compatibility contract, policy reconciliation, and evidence must be reviewed
together.
