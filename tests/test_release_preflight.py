"""Offline tests: release preflight never creates tags or accesses secret values."""

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release_preflight.py"
SPEC = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class ReleasePreflightTests(unittest.TestCase):
    def test_expected_signing_secret_inventory(self):
        self.assertEqual(
            preflight.missing_secret_names(set()),
            sorted(preflight.REQUIRED_SECRETS),
        )
        self.assertEqual(
            preflight.missing_secret_names(set(preflight.REQUIRED_SECRETS)),
            [],
        )
        self.assertEqual(
            preflight.missing_secret_names({"APPLE_API_KEY", "UNRELATED_SECRET"}),
            sorted(preflight.REQUIRED_SECRETS - {"APPLE_API_KEY"}),
        )

    def test_workspace_versions_and_rc_native_metadata(self):
        version, errors = preflight.source_version_errors(SCRIPT.parents[1])
        self.assertEqual(version, "1.0.0-rc1")
        self.assertEqual(errors, [])

    def test_complete_ci_with_missing_secrets_blocks_without_mutation(self):
        commands = []
        sha = "a" * 40

        def fake(*args, allow_404=False):
            commands.append(args)
            if args[:2] == ("git", "branch"):
                return "main"
            if args[:2] == ("git", "status"):
                return ""
            if args[:3] == ("git", "rev-parse", "HEAD"):
                return sha
            if args[:3] == ("git", "config", "user.name"):
                return "oaslananka"
            if args[:3] == ("git", "config", "user.email"):
                return "info@oaslananka.dev"
            if args[:3] == ("gh", "api", "user"):
                return "oaslananka"
            if args[:3] == ("gh", "api", "repos/oaslananka/kicad-mcp-pro-gateway/branches/main"):
                return sha
            if args[:3] == ("gh", "api", "repos/oaslananka/kicad-mcp-pro-gateway/git/ref/tags/v1.0.0-rc1"):
                self.assertTrue(allow_404)
                return None
            if args[:3] == ("gh", "api", "repos/oaslananka/kicad-mcp-pro-gateway/environments/release-signing"):
                return '{"protection_rules":[{"type":"required_reviewers","reviewers":[{"reviewer":{"login":"oaslananka"}}]}]}'
            if args[:3] == ("gh", "secret", "list"):
                self.assertIn("--env", args)
                return "[]"
            if args[:3] == ("gh", "run", "list"):
                self.assertIn("--commit", args)
                self.assertEqual(args[args.index("--commit") + 1], sha)
                return "12345678"
            self.fail(f"unexpected command: {args}")

        with patch.object(preflight, "invoke", side_effect=fake):
            errors = preflight.preflight(SCRIPT.parents[1])
        self.assertEqual(
            errors,
            [
                "missing release-signing secret: " + name
                for name in sorted(preflight.REQUIRED_SECRETS)
            ],
        )
        self.assertFalse(any(c[:3] == ("gh", "release", "create") for c in commands))
        self.assertFalse(any(c[:2] in (("git", "push"), ("git", "tag")) for c in commands))
        self.assertFalse(any(c[:3] == ("gh", "secret", "set") for c in commands))

    def test_existing_tag_blocks_even_with_configured_secret_names(self):
        sha = "a" * 40

        def fake(*args, allow_404=False):
            if args[:2] == ("git", "branch"):
                return "main"
            if args[:2] == ("git", "status"):
                return ""
            if args[:3] == ("git", "rev-parse", "HEAD"):
                return sha
            if args[:3] == ("git", "config", "user.name"):
                return "oaslananka"
            if args[:3] == ("git", "config", "user.email"):
                return "info@oaslananka.dev"
            if args[:3] == ("gh", "api", "user"):
                return "oaslananka"
            if args[:3] == ("gh", "api", "repos/oaslananka/kicad-mcp-pro-gateway/branches/main"):
                return sha
            if args[:3] == ("gh", "api", "repos/oaslananka/kicad-mcp-pro-gateway/git/ref/tags/v1.0.0-rc1"):
                return '{"ref":"refs/tags/v1.0.0-rc1"}'
            if args[:3] == ("gh", "api", "repos/oaslananka/kicad-mcp-pro-gateway/environments/release-signing"):
                return '{"protection_rules":[{"type":"required_reviewers","reviewers":[{"reviewer":{"login":"oaslananka"}}]}]}'
            if args[:3] == ("gh", "secret", "list"):
                return json.dumps([{"name": name} for name in preflight.REQUIRED_SECRETS])
            if args[:3] == ("gh", "run", "list"):
                return "12345678"
            self.fail(f"unexpected command: {args}")

        with patch.object(preflight, "invoke", side_effect=fake):
            issues = preflight.preflight(SCRIPT.parents[1])
        self.assertEqual(issues, ["tag v1.0.0-rc1 already exists (protected; never overwrite it)"])


if __name__ == "__main__":
    unittest.main()
