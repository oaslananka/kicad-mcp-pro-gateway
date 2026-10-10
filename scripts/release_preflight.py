#!/usr/bin/env python3
"""Read-only checks before creating an irreversible, protected v* release tag.

This command never creates a tag, uploads credentials, triggers CI or publishes.
It checks names of environment secrets, NEVER their values. A passing result
cannot establish certificate validity or prove a signed release will succeed.
"""

from __future__ import annotations

import json
import plistlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPOSITORY = "oaslananka/kicad-mcp-pro-gateway"
ENVIRONMENT = "release-signing"
REQUIRED_SECRETS = frozenset(
    {
        "APPLE_API_ISSUER",
        "APPLE_API_KEY",
        "APPLE_API_PRIVATE_KEY",
        "APPLE_CERTIFICATE",
        "APPLE_CERTIFICATE_PASSWORD",
        "WINDOWS_CERTIFICATE",
        "WINDOWS_CERTIFICATE_PASSWORD",
        "WINDOWS_CERTIFICATE_THUMBPRINT",
    }
)
REQUIRED_WORKFLOWS = ("ci.yml", "e2e-live.yml", "osv-full.yml")


class PreflightError(Exception):
    """Prerequisite could not be verified without a mutation."""


def invoke(*args: str, allow_404: bool = False) -> str | None:
    try:
        result = subprocess.run(
            args, check=False, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError(f"unable to execute {args[0]}") from exc
    if result.returncode:
        if allow_404 and "HTTP 404" in result.stderr:
            return None
        raise PreflightError(f"command failed: {args[0]} {args[1] if len(args) > 1 else ''}")
    return result.stdout.strip()


def missing_secret_names(existing: set[str]) -> list[str]:
    return sorted(REQUIRED_SECRETS - existing)


def source_version_errors(root: Path) -> tuple[str, list[str]]:
    errors: list[str] = []
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    canonical = workspace["workspace"]["package"]["version"]
    desktop = tomllib.loads(
        (root / "apps/desktop/src-tauri/Cargo.toml").read_text()
    )["package"]["version"]
    js = json.loads((root / "apps/desktop/package.json").read_text())["version"]
    tauri = json.loads(
        (root / "apps/desktop/src-tauri/tauri.conf.json").read_text()
    )
    if len({canonical, desktop, js, tauri["version"]}) != 1:
        errors.append("workspace, desktop Cargo, JS and Tauri versions must match")
    daemon = tomllib.loads((root / "apps/daemon/Cargo.toml").read_text())
    if daemon["package"].get("version") != {"workspace": True}:
        errors.append("daemon must inherit the workspace package version")
    if canonical == "1.0.0-rc1":
        wix = tauri["bundle"]["windows"]["wix"]["version"]
        if wix != "0.99.1":
            errors.append("RC1 Windows MSI ProductVersion must be 0.99.1")
        mac = plistlib.loads(
            (root / "apps/desktop/src-tauri/Info.plist").read_bytes()
        )
        for field in ("CFBundleShortVersionString", "CFBundleVersion"):
            if mac.get(field) != "0.99.1":
                errors.append(f"RC1 macOS {field} must be 0.99.1")
    elif re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", canonical):
        # A final stable source must not retain the lower, RC-only package
        # identity; otherwise in-place upgrades may be rejected by the OS.
        wix = tauri.get("bundle", {}).get("windows", {}).get("wix", {}).get("version")
        if wix is not None and wix != canonical:
            errors.append("stable Windows MSI version override must match stable version")
        mac_path = root / "apps/desktop/src-tauri/Info.plist"
        if mac_path.is_file():
            mac = plistlib.loads(mac_path.read_bytes())
            for field in ("CFBundleShortVersionString", "CFBundleVersion"):
                if mac.get(field) != canonical:
                    errors.append(f"stable macOS {field} must match stable version")
    else:
        errors.append("only the qualified RC1 or a numeric stable version is supported")
    return canonical, errors


def preflight(root: Path) -> list[str]:
    issues: list[str] = []
    if invoke("git", "branch", "--show-current") != "main":
        issues.append("checkout must be on main")
    if invoke("git", "status", "--porcelain"):
        issues.append("working tree must be clean")
    sha = invoke("git", "rev-parse", "HEAD")
    remote_sha = invoke(
        "gh", "api", f"repos/{REPOSITORY}/branches/main",
        "--jq", ".commit.sha",
    )
    if sha != remote_sha:
        issues.append("local HEAD does not match protected remote main")
    actor = invoke("gh", "api", "user", "--jq", ".login")
    git_name = invoke("git", "config", "user.name")
    git_email = invoke("git", "config", "user.email")
    if actor != REPOSITORY.split("/")[0] or git_name != actor or not git_email:
        issues.append("authenticated GitHub actor and local git identity must match repository owner")

    version, errors = source_version_errors(root)
    issues.extend(errors)
    tag = f"v{version}"
    existing_tag = invoke(
        "gh", "api", f"repos/{REPOSITORY}/git/ref/tags/{tag}",
        allow_404=True,
    )
    if existing_tag is not None:
        issues.append(f"tag {tag} already exists (protected; never overwrite it)")

    env = json.loads(
        invoke("gh", "api", f"repos/{REPOSITORY}/environments/{ENVIRONMENT}")
        or "{}"
    )
    reviewers = {
        reviewer.get("reviewer", {}).get("login")
        for rule in env.get("protection_rules", [])
        if rule.get("type") == "required_reviewers"
        for reviewer in rule.get("reviewers", [])
    }
    if REPOSITORY.split("/")[0] not in reviewers:
        issues.append("release-signing environment must retain owner reviewer approval")

    secret_json = invoke(
        "gh", "secret", "list", "--repo", REPOSITORY,
        "--env", ENVIRONMENT, "--json", "name",
    )
    existing = {item["name"] for item in json.loads(secret_json or "[]")}
    # Only print names from the source-controlled, fixed allowlist. Never
    # forward any string returned by GitHub's secrets API into diagnostics.
    for expected_name in sorted(REQUIRED_SECRETS):
        if expected_name not in existing:
            issues.append("missing release-signing secret: " + expected_name)

    for workflow in REQUIRED_WORKFLOWS:
        run_id = invoke(
            "gh", "run", "list", "--repo", REPOSITORY,
            "--commit", sha, "--workflow", workflow,
            "--event", "push", "--status", "success",
            "--limit", "1", "--json", "databaseId",
            "--jq", ".[0].databaseId // empty",
        )
        if not run_id or not run_id.isdecimal():
            issues.append(f"no successful exact-source push run for {workflow}")
    return issues


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        issues = preflight(root)
    except (PreflightError, KeyError, ValueError, OSError):
        # Do not log exception payloads; CLI errors may include sensitive data.
        print("RELEASE PREFLIGHT BLOCKED: unable to verify prerequisites.")
        return 1
    if issues:
        # Only constant diagnostics: never print strings derived from GitHub
        # secret metadata, including values inadvertently echoed by a caller.
        print("RELEASE PREFLIGHT BLOCKED (no tag created).")
        print("Check main/HEAD, source versions, CI, protected tag and environment.")
        print("Check the eight required secret names under release-signing.")
        print("No secret values, tag, workflow or release were modified.")
        return 1
    print("RELEASE PREFLIGHT: required source gates and signing secret NAMES are present.")
    print("Certificate validity, notarization and actual signing remain unverified.")
    print("No tag, workflow or release was created.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
