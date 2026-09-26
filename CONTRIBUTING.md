# Contributing

Thanks for your interest in KiCad MCP Pro Gateway. This project is a
security boundary, so contributions are held to a higher testing bar than a
typical feature repo — see [`docs/development/testing.md`](docs/development/testing.md)
before opening a PR that touches `crates/policy`, `crates/sessions`,
`crates/workspace`, or `crates/identity`.

## Development setup

Prerequisites: a stable Rust toolchain (pinned via `rust-toolchain.toml`,
installed automatically by `rustup` on first build), and, once
`apps/desktop` exists, Node.js + pnpm for the frontend.

```bash
git clone https://github.com/oaslananka/kicad-mcp-pro-gateway.git
cd kicad-mcp-pro-gateway
cp .env.example .env
cargo build --workspace
cargo test --workspace
```

## Workflow

1. Prefer TDD: write the failing test before the implementation,
   especially for anything in the policy/session/workspace/identity crates.
2. Run before every commit:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
3. Keep crates single-responsibility (see
   [`docs/architecture/component-boundaries.md`](docs/architecture/component-boundaries.md)).
   Do not add KiCad domain logic to this repository — that belongs in
   [kicad-mcp-pro](https://github.com/oaslananka/kicad-mcp-pro).
4. No `unwrap()`/`expect()` in request/security-handling paths. No secret
   material in logs, `Debug` output, CLI output, or IPC responses.
5. Commit messages follow Conventional Commits
   (`feat(scope): ...`, `fix(scope): ...`, `docs: ...`, `test: ...`,
   `chore: ...`), one logical change per commit.

## Pull requests

- Reference the design doc / plan task your change implements where
  applicable (`docs/superpowers/specs/`, `docs/superpowers/plans/`).
- Include tests for new behavior and for any bug fixed.
- CI must be green: `cargo fmt`, `cargo clippy -D warnings`,
  `cargo test --workspace`, and (once applicable) the frontend checks.

## Static analysis dispositions

- This repository has no analyzer-suppression configuration, and none may be
  added to clear a finding. Fix the code behind a finding. When a finding is
  demonstrably inapplicable instead, record the determination here and pin it
  with a test, so the next reader has evidence rather than a silence.
- Hosted static analysis runs its Transact-SQL (SQL Server) rules over every
  `.sql` file, including the SQLite migrations in `crates/storage/migrations/`.
  It annotates those files for a mandatory identifier-quoting session option
  near the top of the file and for a compression clause on every `CREATE
  TABLE`. Neither feature exists in SQLite, and each is a syntax error that
  aborts the migration — so satisfying the annotation would make the daemon
  fail closed at startup instead of running. These annotations are
  dispositions, never defects: do not add the construct, and do not silence
  the analyzer.
  `sql_server_only_ddl_is_rejected_rather_than_added_to_a_sqlite_migration`
  in `crates/storage/tests/migrations.rs` pins that boundary, and each
  migration's header states its dialect.

## Reporting security issues

Do not file a public issue — see [`SECURITY.md`](SECURITY.md).
