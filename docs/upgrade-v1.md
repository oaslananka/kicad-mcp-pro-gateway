# V1 Upgrade, Upgrade, and Rollback Strategy

This document defines the approved upgrade path for desktop, daemon, configuration, database, identity, and persisted security state.

- **Upgrade Order**: ‑*Configuration/Data dir → Media Formats → Db schema → identity → daemon binary → service names*.
- **Failure Detection**: If the daemon cannot start with the new binary or configuration, the startup fails and the old daemon remains active.
- **Rollback**: On failure, the system retains the previous binary and configuration, restoring any persisted data from the previous state. No data is written to the new location until the upgrade succeeds.
- **Security**: Revoked or expired grants remain revoked after upgrade or rollback. Identity data is never persisted in plaintext.

For detailed testing scripts, see the `tests` directory and the CI matrix described in `docs/architecture/compatibility-matrix.md`.
