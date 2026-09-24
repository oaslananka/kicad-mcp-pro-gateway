---
name: Security Exception Follow-up
about: Track time-bound OSV / dependency security advisory exceptions
title: 'security: re-evaluate temporary OSV exception for [crate]'
labels: security, dependencies
assignees: ''
---

## Exception Summary
- **Advisory ID:** `RUSTSEC-202X-XXXX`
- **Affected Crate / Path:**
- **Current Expiry Date:** `YYYY-MM-DD`
- **Configuration File:** `apps/desktop/src-tauri/osv-scanner.toml`

## Re-evaluation Tasks
- [ ] Check if upstream patch or non-vulnerable release is available.
- [ ] Attempt dependency upgrade in local tree.
- [ ] Verify if security invariant / threat exposure has changed.
- [ ] Remove exception from `osv-scanner.toml` OR extend expiry with explicit documented reason.
