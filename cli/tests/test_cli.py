"""CLI tests. No network: provisioning is exercised against a fake transport."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli"))
sys.path.insert(0, str(ROOT / "core"))

from dracla_cli.config import (                                   # noqa: E402
    Confirmation, ProjectConfig, Recipient, Scope,
)
from dracla_cli.errors import CliError                            # noqa: E402
from dracla_cli.main import build_parser, _install_links          # noqa: E402
from dracla_cli.seed import RECONCILE_WORKFLOW                    # noqa: E402


def good_config(**kw) -> ProjectConfig:
    base = dict(
        slug="acme",
        recipient=Recipient("Acme Foundation", "legal@acme.org"),
        scope=Scope(orgs=["acme"]),
        privacy_policy_url="https://acme.org/privacy",
        retention_statement="Evidence is retained after revocation.",
        confirmations=[Confirmation("read", "I have read the agreement")],
    )
    base.update(kw)
    return ProjectConfig(**base)                                  # type: ignore[arg-type]


class TestConfigValidation(unittest.TestCase):

    def test_a_good_config_validates(self):
        good_config().validate()

    def test_recipient_is_required(self):
        """REQ-CONFIG-2: the legal recipient may not be assumed from the org."""
        with self.assertRaises(CliError):
            good_config(recipient=Recipient("  ", "x@y.z")).validate()

    def test_privacy_policy_is_required(self):
        """REQ-SEC-3: the signing page must link to it before acceptance."""
        with self.assertRaises(CliError):
            good_config(privacy_policy_url="").validate()

    def test_retention_statement_is_required(self):
        """REQ-SEC-7: signing must explain evidence is retained after revocation."""
        with self.assertRaises(CliError):
            good_config(retention_statement="").validate()

    def test_empty_scope_is_rejected(self):
        with self.assertRaises(CliError):
            good_config(scope=Scope()).validate()

    def test_duplicate_confirmation_ids_rejected(self):
        with self.assertRaises(CliError):
            good_config(confirmations=[
                Confirmation("a", "one"), Confirmation("a", "two")]).validate()

    def test_bad_slugs_rejected(self):
        for slug in ("A", "x", "has space", "-lead", "x" * 40, "UPPER"):
            with self.subTest(slug=slug), self.assertRaises(CliError):
                good_config(slug=slug).validate()

    def test_scope_matching(self):
        """Scope is evaluated, so its semantics need to be exact (DR-007)."""
        s = Scope(orgs=["acme"], repos=["labs/widget"])
        self.assertTrue(s.covers("acme/anything"))
        self.assertTrue(s.covers("labs/widget"))
        self.assertFalse(s.covers("labs/other"))
        self.assertFalse(s.covers("acme-evil/x"), "prefix must not match an org")


class TestConfigSerialization(unittest.TestCase):

    def test_round_trip(self):
        cfg = good_config()
        again = ProjectConfig.from_dict(json.loads(cfg.to_json()))
        self.assertEqual(again.to_json(), cfg.to_json())

    def test_committed_form_is_resolved_and_stable(self):
        """What lands in the repo must be inert: no interpolation, no defaults."""
        text = good_config().to_json()
        self.assertNotIn("${", text, "no unresolved interpolation may be committed")
        self.assertNotIn("defaults:", text)
        self.assertEqual(text, good_config().to_json(), "output must be stable")
        self.assertTrue(text.endswith("\n"))

    def test_unknown_schema_version_refused(self):
        doc = json.loads(good_config().to_json())
        doc["schema_version"] = 99
        with self.assertRaises(CliError):
            ProjectConfig.from_dict(doc)

    def test_repo_names_follow_the_slug(self):
        """Naming keys on the slug so a second recipient does not collide (§5.5)."""
        cfg = good_config(slug="projx")
        self.assertEqual(cfg.records_repo("acme"), "acme/projx-cla-records")
        self.assertEqual(cfg.coverage_repo("acme"), "acme/projx-cla-coverage")


class TestGeneratedWorkflow(unittest.TestCase):
    """DR-013: this workflow holds a cross-repo write key and reads signer data."""

    def setUp(self):
        self.body = RECONCILE_WORKFLOW % {
            "version": "0.0.1", "coverage_repo": "acme/acme-cla-coverage"}

    def test_declares_least_privilege_permissions(self):
        self.assertIn("permissions:", self.body)
        self.assertIn("contents: read", self.body)
        self.assertNotIn("contents: write", self.body,
                         "the reconciler must not be able to rewrite canonical")

    def test_no_event_data_interpolated_into_run_or_env(self):
        """A ${{ }} expansion of a signer field would be command execution."""
        offenders = [
            line for line in self.body.splitlines()
            if "${{" in line and "secrets." not in line and not line.lstrip().startswith("#")
        ]
        self.assertEqual(offenders, [], f"unsafe interpolation: {offenders}")

    def test_schedule_is_daily(self):
        """§9.2: minutes bill to the adopter's org; hourly costs 39-78%."""
        crons = [l for l in self.body.splitlines() if "cron:" in l]
        self.assertEqual(len(crons), 1)
        fields = crons[0].split('"')[1].split()
        self.assertEqual(fields[2:], ["*", "*", "*"], "must be once per day")

    def test_has_a_concurrency_group(self):
        """Two replays racing would write conflicting projections."""
        self.assertIn("concurrency:", self.body)

    def test_pins_its_own_version(self):
        self.assertIn('pip install "dracla==${DRACLA_VERSION}"', self.body)
        self.assertIn("0.0.1", self.body)


class TestCliSurface(unittest.TestCase):

    def test_install_requires_the_legally_significant_options(self):
        parser = build_parser()
        for missing in ("--recipient", "--privacy-policy", "--owner", "--slug"):
            argv = ["install", "--owner", "o", "--slug", "s", "--recipient", "r",
                    "--contact", "c", "--privacy-policy", "p"]
            idx = argv.index(missing)
            del argv[idx:idx + 2]
            with self.subTest(missing=missing), self.assertRaises(SystemExit):
                parser.parse_args(argv)

    def test_install_links_point_at_github_consent(self):
        links = _install_links("acme")
        self.assertIn("github.com/apps/dracla-records/installations/new", links)
        self.assertIn("github.com/apps/dracla-enforcer/installations/new", links)
        self.assertIn("state=acme", links)

    def test_no_installer_app_is_referenced(self):
        """D11: provisioning is the CLI, never a third App."""
        self.assertNotIn("dracla-installer", _install_links("acme"))


class TestLayering(unittest.TestCase):

    def test_core_does_not_import_hydra(self):
        """Composition is a client concern; core receives a resolved dict (§6.9)."""
        for path in (ROOT / "core" / "dracla").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in ("import hydra", "from hydra", "omegaconf"):
                self.assertNotIn(token, text,
                                 f"{path.name} must not depend on Hydra")


if __name__ == "__main__":
    unittest.main()
