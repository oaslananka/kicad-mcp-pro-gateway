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

## Reporting security issues

Do not file a public issue — see [`SECURITY.md`](SECURITY.md).
