"""Tests for `dracla install` (§6.10.6).

Grouped by the property being protected rather than by module, because every
finding that mattered in the removed implementation was a seam between modules
that were individually plausible.
"""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
for extra in (ROOT / "cli", ROOT / "core", ROOT / "cli" / "tests"):
    sys.path.insert(0, str(extra))

from fake import FakeAdmin                                            # noqa: E402
from dracla.githost import FakeGitHost                                # noqa: E402

from dracla_cli.admin import Repo                                     # noqa: E402
from dracla_cli.config import resolve                                 # noqa: E402
from dracla_cli.errors import CliError                                # noqa: E402
from dracla_cli.install import (                                      # noqa: E402
    COVERAGE_REF, EVENTS_BRANCH, EVENTS_REF, InstallFailed, Result,
    preflight, run,
)
from dracla_cli import main as main_mod                               # noqa: E402
from dracla_cli.errors import Aborted                                 # noqa: E402
from dracla_cli.main import build_parser, install_links               # noqa: E402
from dracla_cli.workflow import (                                     # noqa: E402
    RECONCILE, RECONCILE_IMPLEMENTED, WORKFLOW_PATH, render,
)

CFG = resolve(["github.org=acme"])
# A personal account the fake viewer actually owns. The exemption is for
# YOUR OWN account; installing into someone else's is refused, so these
# must not share CFG's org.
OWN_CFG = resolve(["github.org=test-user"])


def do_run(admin, host=None, cfg=None, **kw):
    """Drive run() with fakes. Hosts come from the admin seam, as in production.

    Supplies a confirm callback explicitly. It used to omit one, which run()
    read as consent — so most of the suite exercised a provisioning path with
    the confirmation absent, and the bypass looked normal because the tests
    depended on it.
    """
    cfg = cfg or CFG
    host = host or admin.host_for(cfg.records_repo)
    kw.setdefault("confirm", lambda warnings=(): None)
    out = run(admin, cfg, version="0.0.1", records_host=host,
              coverage_host=admin.host_for(cfg.coverage_repo), **kw)
    return out, host


def dry(overrides):
    return resolve(["github.org=acme", *overrides])


class TestConfig(unittest.TestCase):
    """Composition is Hydra's, so these test the contract, not a parser.

    An earlier version of this CLI hand-rolled dotlist parsing and merging. It
    mangled quoted commas and nested lists, and validated only top-level keys.
    Hydra's Compose API is used instead; what remains worth asserting is how the
    CLI *behaves* at the boundary.
    """

    def test_org_is_required(self):
        with self.assertRaises(CliError) as ctx:
            resolve([])
        self.assertIn("github.org", str(ctx.exception))

    def test_slug_defaults_to_org(self):
        """§5.5: the prefix IS the recipient slug, defaulted by interpolation."""
        cfg = resolve(["github.org=hydra-ecosystem"])
        self.assertEqual(cfg.records_repo,
                         "hydra-ecosystem/hydra-ecosystem-cla-records")

    def test_second_recipient_is_a_value_not_a_new_shape(self):
        """The deferred multi-recipient case costs nothing later."""
        cfg = resolve(["github.org=foundation", "recipient.slug=projx"])
        self.assertEqual(cfg.records_repo, "foundation/projx-cla-records")
        self.assertEqual(cfg.coverage_repo, "foundation/projx-cla-coverage")

    def test_unknown_keys_rejected(self):
        """Struct mode: a mistyped key must fail, not be silently ignored."""
        with self.assertRaises(CliError):
            resolve(["github.org=acme", "recipient.name=Someone"])

    def test_malformed_override_is_reported(self):
        with self.assertRaises(CliError):
            resolve(["github.org"])

    def test_hydra_grammar_is_available(self):
        """Quoting and nesting my hand-rolled parser got wrong."""
        cfg = resolve(["github.org=acme", "recipient.slug='projx'"])
        self.assertEqual(cfg.slug, "projx")


class TestOrgPermissionGate(unittest.TestCase):
    """§6.10.4: this blocks. A warning would leave REQ-SEC-2 quietly untrue."""

    def test_read_default_blocks(self):
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        self.assertIn("every member", str(ctx.exception))

    def test_there_is_no_override(self):
        """§6.10.4: the dedicated organization is required, not preferred.

        An override would only let someone install into the wrong organization
        by accident, and there is no legitimate reason to decline in an
        organization created for this purpose.
        """
        with self.assertRaises(CliError):
            preflight(FakeAdmin(base_permission="read"), CFG)
        import inspect
        from dracla_cli import install as install_mod
        self.assertNotIn("accept_org_read",
                         inspect.getsource(install_mod.preflight))

    def test_the_remedy_offered_is_one_that_exists(self):
        """Base permissions are a floor: repository settings can raise a
        member's access but never lower it. Telling the operator to 'restrict
        the repositories yourself' would be something nobody can do."""
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        hint = ctx.exception.hint or ""
        self.assertIn("cannot be fixed on the repository", hint)
        self.assertNotIn("restrict", hint)

    def test_the_hint_offers_a_different_owner_as_an_option(self):
        """Installing where members are not already readers is a real fix,
        unlike restricting the repository, which is not possible."""
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        self.assertIn("github.org=", ctx.exception.hint or "")

    def test_none_is_silent(self):
        self.assertEqual(preflight(FakeAdmin(base_permission="none"), CFG), [])

    def test_user_account_has_no_org_default(self):
        self.assertEqual(
            preflight(FakeAdmin(owner_type="User"), OWN_CFG), [])

    def test_someone_elses_personal_account_is_refused(self):
        """The exemption is for your own account. `acme` is not test-user."""
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(owner_type="User"), CFG)
        self.assertIn("belonging to someone else", str(ctx.exception.hint or "")
                      + str(ctx.exception))

    def test_existing_public_repo_blocks(self):
        admin = FakeAdmin(existing={
            "acme/acme-cla-records": Repo("acme/acme-cla-records", False, "events", False)})
        with self.assertRaises(CliError):
            preflight(admin, CFG)


class TestDryRunWritesNothing(unittest.TestCase):
    """The one output whose entire purpose is to be trustworthy."""

    def test_no_writes_at_all(self):
        admin = FakeAdmin()
        out, host = do_run(admin, cfg=dry(["dry_run=true"]))
        self.assertEqual(admin.writes, [], "no administration write")
        self.assertIsNone(host.head(EVENTS_REF), "no ref may be created")
        cov = admin.host_for(CFG.coverage_repo)
        self.assertIsNone(cov.head(COVERAGE_REF), "coverage untouched too")

    def test_does_not_claim_to_have_created(self):
        out, _ = do_run(FakeAdmin(), cfg=dry(["dry_run=true"]))
        self.assertEqual(out.created, [])
        self.assertEqual(len(out.would_create), 2)

    def test_real_run_reports_what_it_created(self):
        out, _ = do_run(FakeAdmin())
        self.assertEqual(len(out.created), 2)
        self.assertEqual(out.would_create, [])


class TestBranchLayout(unittest.TestCase):
    """§6.10.1: everything the reconciler reads is on the branch it checks out."""

    def test_events_is_the_first_ref_and_becomes_default(self):
        admin = FakeAdmin()
        out, host = do_run(admin)
        self.assertIsNotNone(host.head(EVENTS_REF))
        self.assertIsNone(host.head("refs/heads/main"),
                          "no main should ever exist; repos are created empty")
        self.assertIn(("set_default_branch", f"{CFG.records_repo}:{EVENTS_BRANCH}"),
                      admin.writes)

    def test_workflow_lands_on_events(self):
        _, host = do_run(FakeAdmin())
        self.assertTrue(host.exists(EVENTS_REF, WORKFLOW_PATH))

    def test_bootstrap_carries_no_events(self):
        """§6.10.1: the branch begins with bootstrap commits and no events.

        Two, not one: the Git Data API refuses on an empty repository, so the
        first commit must go through the Contents API, which writes one path per
        commit. REQ-REC-3's one-event-per-commit rule governs what follows.
        """
        _, host = do_run(FakeAdmin())
        history = host.history(EVENTS_REF)
        self.assertEqual(len(history), 2, "README, then the workflow")
        self.assertTrue(host.exists(EVENTS_REF, WORKFLOW_PATH))
        self.assertTrue(host.exists(EVENTS_REF, "README.md"))

        paths = set(history[-1].tree)
        self.assertFalse([p for p in paths if p.startswith("events/")],
                         "bootstrap must contain no event files")

    def test_coverage_projection_is_initialized(self):
        """§5.3 defines a layout; install creates what the enforcer reads."""
        admin = FakeAdmin()
        do_run(admin)
        cov = admin.host_for(CFG.coverage_repo)
        self.assertTrue(cov.exists(COVERAGE_REF, "inflight.json"))
        self.assertTrue(cov.exists(COVERAGE_REF, "source.json"))

    def test_repos_are_created_empty(self):
        """auto_init would make `main`, needing demotion and deletion."""
        import inspect
        from dracla_cli import admin as admin_mod
        src = inspect.getsource(admin_mod.GitHubAdmin.create_repo)
        self.assertIn('"auto_init": False', src)


class TestInstallDefersToThePortal(unittest.TestCase):
    """§6.10.3: install collects one thing and writes nothing else."""

    def test_no_project_config_is_written(self):
        _, host = do_run(FakeAdmin())
        self.assertFalse(host.exists(EVENTS_REF, "config/project.json"))

    def test_no_agreement_is_written(self):
        _, host = do_run(FakeAdmin())
        paths = set(host.history(EVENTS_REF)[-1].tree)
        self.assertFalse([p for p in paths if p.startswith("agreements/")])

    def test_no_deploy_key_is_created(self):
        """A write-capable credential nothing consumes is a live credential."""
        admin = FakeAdmin()
        do_run(admin)
        self.assertFalse([w for w in admin.writes if "key" in w[0].lower()])

    def test_install_takes_only_the_org(self):
        parser = build_parser()
        args = parser.parse_args(["install", "github.org=acme"])
        self.assertEqual(args.overrides, ["github.org=acme"])


class TestIdempotence(unittest.TestCase):

    def test_second_run_creates_nothing(self):
        admin = FakeAdmin()
        do_run(admin)
        before = list(admin.writes)
        out, _ = do_run(admin)
        self.assertEqual(out.created, [])
        self.assertEqual(admin.writes, before, "re-run must not write again")

    def test_identical_workflow_is_left_alone(self):
        admin = FakeAdmin()
        do_run(admin)
        out, _ = do_run(admin)
        results = {s.what: s.result for s in out.steps}
        self.assertEqual(results["workflow"], Result.UNCHANGED)


class TestWorkflowIsRunnable(unittest.TestCase):
    """The defect that shipped last time: a workflow calling a missing command."""

    def _invoked_commands(self, body: str) -> set[str]:
        found = set()
        for line in body.splitlines():
            s = line.strip()
            if s.startswith("run:") and "dracla " in s:
                rest = s.split("dracla ", 1)[1].split()
                if rest and not rest[0].startswith("-"):
                    found.add(rest[0])
        return found

    def _known_commands(self) -> set[str]:
        known = set()
        for action in build_parser()._actions:
            if getattr(action, "choices", None):
                known.update(action.choices)
        return known

    def test_seeded_workflow_invokes_only_existing_commands(self):
        body = render("acme/acme-cla-coverage", "0.0.1", EVENTS_BRANCH)
        missing = self._invoked_commands(body) - self._known_commands()
        self.assertEqual(missing, set(),
                         f"workflow invokes commands that do not exist: {missing}")

    def test_reconcile_must_exist_before_its_workflow_is_seeded(self):
        """The shipped defect was a workflow calling a missing subcommand. The
        placeholder invokes nothing, so the existing check is quiet today — this
        is the assertion that speaks on the day M2 flips the flag."""
        if RECONCILE_IMPLEMENTED:
            self.assertIn("reconcile", self._known_commands(),
                          "RECONCILE invokes `dracla reconcile`; it must exist "
                          "before install is allowed to seed it")

    def test_placeholder_until_reconcile_ships(self):
        """Both arms assert. Guarding the only assertion behind the flag would
        make this test silently stop testing the day M2 flips it."""
        body = render("acme/acme-cla-coverage", "0.0.1", EVENTS_BRANCH)
        if RECONCILE_IMPLEMENTED:
            self.assertNotIn("not implemented", body.lower())
            self.assertIn("dracla reconcile", body)
        else:
            self.assertIn("not implemented", body.lower())

    def test_the_real_reconciler_is_least_privilege(self):
        """Asserted now so it is correct when M2 switches it on."""
        body = RECONCILE % {"version": "0.0.1", "events_branch": EVENTS_BRANCH,
                            "coverage_repo": "acme/acme-cla-coverage"}
        self.assertIn("permissions:", body)
        self.assertIn("contents: read", body)
        self.assertNotIn("contents: write", body)
        self.assertIn("concurrency:", body)

    def test_the_real_reconciler_interpolates_no_event_data(self):
        """A ${{ }} expansion of a signer field is command execution."""
        body = RECONCILE % {"version": "0.0.1", "events_branch": EVENTS_BRANCH,
                            "coverage_repo": "acme/acme-cla-coverage"}
        offenders = [l for l in body.splitlines()
                     if "${{" in l and "secrets." not in l
                     and not l.lstrip().startswith("#")]
        self.assertEqual(offenders, [])

    def test_the_real_reconciler_runs_daily(self):
        body = RECONCILE % {"version": "0.0.1", "events_branch": EVENTS_BRANCH,
                            "coverage_repo": "acme/acme-cla-coverage"}
        crons = [l for l in body.splitlines() if "cron:" in l]
        self.assertEqual(len(crons), 1)
        # Fixed minute AND fixed hour. Checking only day/month/weekday passed
        # for "17 * * * *" (hourly) and "* * * * *" (every minute) — and these
        # minutes bill to the adopter's organization.
        self.assertRegex(crons[0].split('"')[1], r"^\d+ \d+ \* \* \*$")


class TestNextSteps(unittest.TestCase):

    def test_links_point_at_github_consent(self):
        links = dict((label, url) for label, url in install_links("acme"))
        self.assertIn("github.com/apps/dracla-records/installations/new",
                      links["records"])
        self.assertIn("state=acme", links["enforcement"])

    def test_no_installer_app(self):
        """D11: provisioning is the CLI, never a third App."""
        for _, url in install_links("acme"):
            self.assertNotIn("dracla-installer", url)


class TestLayering(unittest.TestCase):

    def test_core_does_not_import_hydra(self):
        for path in (ROOT / "core" / "dracla").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in ("import hydra", "from hydra", "omegaconf"):
                self.assertNotIn(token, text, f"{path.name} must not need Hydra")

    def test_cli_does_not_mutate_sys_path(self):
        for path in (ROOT / "cli" / "dracla_cli").glob("*.py"):
            self.assertNotIn("sys.path", path.read_text(encoding="utf-8"),
                             f"{path.name} must not manipulate sys.path")


class TestCommandFunction(unittest.TestCase):
    """D3/F4: cmd_install is the function that wires everything together, and
    nothing tested it. That is why the TTY crash shipped — every part was
    covered and the seam joining them was not."""

    def _args(self, overrides, show_config=False):
        return argparse.Namespace(overrides=overrides, show_config=show_config)

    def test_refuses_without_a_tty_instead_of_crashing(self):
        """C1: input() raised EOFError, uncaught, and the shell saw success.

        Also asserts it fails before contacting GitHub — an invocation that
        cannot be confirmed should not cost a round trip first.
        """
        with mock.patch.object(main_mod.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(main_mod, "_token",
                               side_effect=AssertionError("must fail first")):
            with self.assertRaises(CliError) as ctx:
                main_mod.cmd_install(self._args(["github.org=acme"]))
        self.assertIn("force=true", str(ctx.exception.hint))

    def test_force_skips_the_prompt(self):
        admin = FakeAdmin()
        with mock.patch.object(main_mod.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(main_mod, "_token", return_value="t"), \
             mock.patch.object(main_mod, "GitHubAdmin", return_value=admin):
            rc = main_mod.cmd_install(
                self._args(["github.org=acme", "force=true"]))
        self.assertEqual(rc, 0)
        self.assertTrue(admin.writes)

    def test_declining_creates_nothing(self):
        admin = FakeAdmin()
        with mock.patch.object(main_mod.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(main_mod, "input", create=True, return_value="n"), \
             mock.patch.object(main_mod, "_token", return_value="t"), \
             mock.patch.object(main_mod, "GitHubAdmin", return_value=admin):
            with self.assertRaises(Aborted):
                main_mod.cmd_install(self._args(["github.org=acme"]))
        self.assertEqual(admin.writes, [])

    def test_the_org_gate_cannot_be_reached_around(self):
        """F4: the gate is enforced by run(), so the command path cannot skip it."""
        admin = FakeAdmin(base_permission="read")
        with mock.patch.object(main_mod, "_token", return_value="t"), \
             mock.patch.object(main_mod, "GitHubAdmin", return_value=admin):
            with self.assertRaises(CliError):
                main_mod.cmd_install(
                    self._args(["github.org=acme", "force=true"]))
        self.assertEqual(admin.writes, [], "no repository may be created")

    def test_show_config_contacts_nothing(self):
        with mock.patch.object(main_mod, "_token",
                               side_effect=AssertionError("must not need a token")):
            rc = main_mod.cmd_install(
                self._args(["github.org=acme"], show_config=True))
        self.assertEqual(rc, 0)


class TestFailureReporting(unittest.TestCase):
    """B3: a failed step used to discard everything already done."""

    def test_partial_failure_reports_what_exists(self):
        admin = FakeAdmin()
        original = admin.create_repo
        calls = {"n": 0}

        def fail_on_second(owner, name, description):
            calls["n"] += 1
            if calls["n"] == 2:
                raise CliError("coverage repo could not be created")
            return original(owner, name, description)

        admin.create_repo = fail_on_second
        with self.assertRaises(InstallFailed) as ctx:
            do_run(admin)
        outcome = ctx.exception.outcome
        self.assertIsNotNone(outcome)
        self.assertEqual(len(outcome.created), 1,
                         "the operator must be told the first repo exists")


class TestGateOrdering(unittest.TestCase):
    """The gate must block before the operator is asked to approve anything.

    Reported from real use: the prompt appeared, the operator answered yes, and
    only then did the organization gate refuse. Confirming something that was
    always going to be refused wastes the interaction and reads as a bug.
    """

    def test_blocked_org_never_reaches_the_prompt(self):
        asked = {"n": 0}

        def confirm(warnings=()):
            asked["n"] += 1

        admin = FakeAdmin(base_permission="read")
        with self.assertRaises(CliError):
            run(admin, CFG, version="0.0.1", confirm=confirm,
                records_host=admin.host_for(CFG.records_repo),
                coverage_host=admin.host_for(CFG.coverage_repo))
        self.assertEqual(asked["n"], 0, "must not prompt before the gate passes")
        self.assertEqual(admin.writes, [])

    def test_confirmation_precedes_any_creation(self):
        admin = FakeAdmin()
        order = []

        def confirm(warnings=()):
            order.append(("confirm", tuple(admin.writes)))

        run(admin, CFG, version="0.0.1", confirm=confirm,
            records_host=admin.host_for(CFG.records_repo),
            coverage_host=admin.host_for(CFG.coverage_repo))
        self.assertEqual(order[0][1], (),
                         "nothing may be created before confirmation")

    def test_the_hint_offers_a_dedicated_org(self):
        """The fix is a dedicated organization, and the message must say so."""
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        hint = ctx.exception.hint or ""
        self.assertIn("dedicated", hint)
        self.assertIn("default_repository_permission=none", hint)

    def test_gate_blocks_when_github_omits_the_permission_field(self):
        """GitHub returns the full org record only to an owner with scope; for
        anyone else it answers 200 with default_repository_permission simply
        ABSENT. Reading that as None made it indistinguishable from a personal
        account, and the gate failed open on exactly the case it exists for."""
        from dracla_cli.admin import GitHubAdmin
        admin = GitHubAdmin.__new__(GitHubAdmin)
        admin._owner_kind = {"acme": "Organization"}
        admin._viewer = "omry"
        # /orgs/acme answers 200 but WITHOUT default_repository_permission;
        # membership is active, so the create check passes and the permission
        # gate is what this test actually exercises.
        admin._get = lambda path: ({"state": "active"} if "memberships" in path
                                   else {"login": "acme"})
        self.assertEqual(admin.base_permission("acme"),
                         GitHubAdmin.UNKNOWN_PERMISSION)

        admin.get_repo = lambda full: None
        with self.assertRaises(CliError) as ctx:
            preflight(admin, CFG)
        self.assertIn("could not read", str(ctx.exception).lower())

    def test_user_account_still_returns_none_not_unknown(self):
        """The exemption must survive the fix: a real personal account has no
        organization default, and that is different from failing to read one."""
        from dracla_cli.admin import GitHubAdmin
        admin = GitHubAdmin.__new__(GitHubAdmin)
        admin._owner_kind = {"omry": "User"}
        admin._viewer = "omry"
        self.assertIsNone(admin.base_permission("omry"))

    def test_reinstall_does_not_erase_live_coverage_state(self):
        """source.json holds the projection replay head and inflight.json the
        in-flight operation markers. Install is documented as re-runnable, so
        rewriting them would reset the head and drop a signature in flight."""
        admin = FakeAdmin()
        do_run(admin)
        cov = admin.host_for(CFG.coverage_repo)
        cov.put(COVERAGE_REF, "source.json",
                '{"canonical_sha": "live"}', base_blob_sha=
                cov.read(COVERAGE_REF, "source.json")[1])
        cov.put(COVERAGE_REF, "inflight.json",
                '{"ops": {"sign-1": {}}}', base_blob_sha=
                cov.read(COVERAGE_REF, "inflight.json")[1])
        do_run(admin)
        self.assertEqual(cov.read(COVERAGE_REF, "source.json")[0],
                         '{"canonical_sha": "live"}')
        self.assertEqual(cov.read(COVERAGE_REF, "inflight.json")[0],
                         '{"ops": {"sign-1": {}}}')

    def test_a_repo_turned_public_after_preflight_is_refused(self):
        """Preflight validates visibility, then the operator answers a prompt.
        In that window another owner can create or flip the repository public;
        run() must not seed it anyway."""
        admin = FakeAdmin()

        def turn_public_while_the_prompt_is_open(warnings=()):
            # The real window: preflight has already validated visibility and
            # the operator is answering the prompt. Seeding it now would put
            # signer names and email addresses in a public repository.
            admin.repos[CFG.records_repo] = Repo(
                CFG.records_repo, False, "events", False)

        with self.assertRaises(CliError) as ctx:
            run(admin, CFG, version="0.0.1",
                records_host=admin.host_for(CFG.records_repo),
                coverage_host=admin.host_for(CFG.coverage_repo),
                confirm=turn_public_while_the_prompt_is_open)
        self.assertIn("PUBLIC", str(ctx.exception))

    def test_an_unrelated_existing_repository_is_not_reused(self):
        """Private is not "only the right people". A repository that already
        existed for something else can carry direct team and outside-collaborator
        grants, and seeding it would put signer data where those grantees read."""
        admin = FakeAdmin()
        # private, but it HAS branches and none is one install would have made.
        # Expressed as a branch count, not `size`: GitHub reports size 0 for
        # plenty of repositories that have content, so believing it skipped this
        # check for exactly the repositories most likely to be someone else's.
        admin.repos[CFG.records_repo] = Repo(CFG.records_repo, True, "main", None)
        admin.branch_counts[CFG.records_repo] = 1
        with self.assertRaises(CliError) as ctx:
            do_run(admin)
        self.assertIn("not a DraCLA repository", str(ctx.exception))

    def test_a_repository_that_cannot_be_read_is_not_called_a_collision(self):
        """403 from SAML enforcement, or a rate limit, on a genuine records
        repository. Telling the operator to rename it would have them abandon
        the repository holding the canonical CLA records."""
        admin = FakeAdmin()
        admin.repos[CFG.records_repo] = Repo(CFG.records_repo, True, "events", None)
        admin.branch_counts[CFG.records_repo] = None      # unreadable
        host = admin.host_for(CFG.records_repo)
        host.head = lambda ref: (_ for _ in ()).throw(RuntimeError("403 SAML"))
        with self.assertRaises(CliError) as ctx:
            do_run(admin, host=host)
        msg = f"{ctx.exception} {ctx.exception.hint}"
        self.assertIn("could not read", msg)
        self.assertNotIn("rename", msg.lower())

    def test_our_own_half_created_repository_is_still_reused(self):
        """The recovery path must survive the check above: install creates the
        repository and can stop before writing, leaving it empty. That is the
        partial run re-running is meant to finish, not a collision."""
        admin = FakeAdmin()
        admin.repos[CFG.records_repo] = Repo(CFG.records_repo, True, None, None)
        admin.branch_counts[CFG.records_repo] = 0        # genuinely no branches
        out, _ = do_run(admin)
        self.assertIn(EVENTS_BRANCH, str(out.steps))

    def test_slug_default_strips_the_dedicated_org_suffix(self):
        """github.org names the dedicated organization, conventionally
        <project>-cla. Defaulting the slug to it verbatim produced
        acme-cla/acme-cla-cla-records — a doubled word the org name already
        carries, and not what §6.10.3's own example shows."""
        self.assertEqual(resolve(["github.org=acme-cla"]).records_repo,
                         "acme-cla/acme-cla-records")
        self.assertEqual(resolve(["github.org=hydra-ecosystem-cla"]).records_repo,
                         "hydra-ecosystem-cla/hydra-ecosystem-cla-records")

    def test_slug_default_matches_the_suffix_case_insensitively(self):
        """GitHub logins are case-insensitive, so `ACME-CLA` and `acme-cla` are
        the same organization. A case-sensitive strip gave them different
        repository names."""
        self.assertEqual(resolve(["github.org=ACME-CLA"]).records_repo,
                         "ACME-CLA/ACME-cla-records")
        self.assertEqual(resolve(["github.org=Acme-Cla"]).records_repo,
                         "Acme-Cla/Acme-cla-records")

    def test_slug_default_leaves_an_org_named_only_cla_alone(self):
        """Stripping would leave an empty slug, so the suffix rule does not
        apply when there is nothing in front of it."""
        self.assertEqual(resolve(["github.org=cla"]).records_repo,
                         "cla/cla-cla-records")

    def test_slug_default_leaves_an_org_without_the_suffix_alone(self):
        self.assertEqual(resolve(["github.org=acme"]).records_repo,
                         "acme/acme-cla-records")

    def test_an_explicit_slug_is_taken_as_given(self):
        """The strip is a property of the DEFAULT. An explicit slug replaces the
        interpolation outright and must not be second-guessed."""
        self.assertEqual(
            resolve(["github.org=acme-cla", "recipient.slug=projx"]).records_repo,
            "acme-cla/projx-cla-records")
        self.assertEqual(
            resolve(["github.org=acme-cla", "recipient.slug=acme-cla"]).records_repo,
            "acme-cla/acme-cla-cla-records")

    def test_a_callback_that_returns_false_refuses(self):
        """Signalling consent only by not-raising works for the console prompt
        and silently provisions for any caller that returns a boolean."""
        admin = FakeAdmin()
        with self.assertRaises(Aborted):
            run(admin, CFG, version="0.0.1", confirm=lambda w: False,
                records_host=admin.host_for(CFG.records_repo),
                coverage_host=admin.host_for(CFG.coverage_repo))
        self.assertEqual(admin.writes, [])

    def test_provisioning_without_a_way_to_confirm_is_refused(self):
        """`confirm=None` used to mean "proceed", so any caller that simply did
        not pass one provisioned unguarded — the consent lived in the console
        path rather than at the boundary that does the writing."""
        with self.assertRaises(CliError) as ctx:
            run(FakeAdmin(), CFG, version="0.0.1")
        self.assertIn("confirm", str(ctx.exception).lower())

    def test_force_is_still_a_way_to_say_yes_without_a_prompt(self):
        admin = FakeAdmin()
        out = run(admin, resolve(["github.org=acme", "force=true"]),
                  version="0.0.1",
                  records_host=admin.host_for(CFG.records_repo),
                  coverage_host=admin.host_for(CFG.coverage_repo))
        self.assertIn(CFG.records_repo, out.created)

    def test_errors_do_not_quote_requirement_ids(self):
        """Requirement IDs are internal vocabulary; a user has nowhere to go
        with 'REQ-SEC-2'. Explain the risk in plain terms instead."""
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        text = f"{ctx.exception} {ctx.exception.hint}"
        self.assertNotIn("REQ-", text)

    def test_errors_do_not_cite_design_sections(self):
        """Same reasoning as requirement IDs: an operator at a terminal cannot
        resolve '§6.10.3' either. Say the thing, not where it is written."""
        with self.assertRaises(CliError) as ctx:
            resolve(["github.org=acme", "extra.bad=1"])
        text = f"{ctx.exception} {ctx.exception.hint}"
        self.assertNotIn("§", text)

    def test_seeded_content_does_not_quote_requirement_ids(self):
        """The same rule, for everything install WRITES rather than prints.

        These land in the adopter's own repositories, where a reader has even
        less way to look an identifier up than at a terminal. A guard that
        covered only error text let `REQ-PORTAL-5` into the coverage README.
        """
        from dracla_cli.install import (COVERAGE_README, DEDICATED_ORG_GUIDANCE,
                                        GENESIS_README)
        seeded = {
            "COVERAGE_README": COVERAGE_README,
            "GENESIS_README": GENESIS_README,
            "DEDICATED_ORG_GUIDANCE": DEDICATED_ORG_GUIDANCE,
            "workflow": render("acme/acme-cla-coverage", "0.0.1", EVENTS_BRANCH),
            # Both templates, not just the one render() happens to return
            # today: a guard that inspects render() output goes blind to
            # RECONCILE for as long as RECONCILE_IMPLEMENTED is false.
            "RECONCILE": RECONCILE % {"version": "0.0.1",
                                      "events_branch": EVENTS_BRANCH,
                                      "coverage_repo": "acme/acme-cla-coverage"},
        }
        for name, text in seeded.items():
            with self.subTest(seeded=name):
                self.assertNotIn("REQ-", text)

    def test_the_hint_suggests_the_user_own_command(self):
        """Not a generic incantation — their invocation, with org corrected."""
        cfg = resolve(["github.org=acme", "recipient.slug=projx"])
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), cfg)
        self.assertIn("dracla install github.org=acme-cla recipient.slug=projx",
                      ctx.exception.hint or "")

    def test_personal_accounts_are_exempt_deliberately(self):
        """A private repo on a user account starts with exactly one reader;
        there is no default granting access to people who never asked."""
        admin = FakeAdmin(owner_type="User")
        self.assertIsNone(admin.base_permission("someone"))
        self.assertEqual(preflight(admin, OWN_CFG), [],
                         "your own user account must not be gated")


class TestSuggestedCommand(unittest.TestCase):
    """The suggestion is the operator's own command, minimally changed."""

    def test_a_replaced_key_keeps_its_position(self):
        cfg = resolve(["github.org=acme", "recipient.slug=x", "force=true"])
        self.assertEqual(
            cfg.command("github.org=other"),
            "dracla install github.org=other recipient.slug=x force=true")

    def test_a_new_key_is_appended(self):
        cfg = resolve(["github.org=acme", "recipient.slug=x"])
        self.assertEqual(
            cfg.command("accept_org_read=true"),
            "dracla install github.org=acme recipient.slug=x "
            "accept_org_read=true")


class TestMissingOrganization(unittest.TestCase):
    """GitHub has no API for creating an organization — POST /orgs does not
    exist on github.com and /admin/organizations is Enterprise Server only — so
    install cannot do it and must instead make the manual step painless."""

    class _Missing(FakeAdmin):
        def owner_kind(self, owner):
            from dracla_cli.admin import GitHubAdmin as Real
            return Real.owner_kind(self, owner)

    def test_a_missing_org_explains_how_to_create_one(self):
        from dracla_cli.admin import GitHubAdmin
        from dracla.githost import NotFound

        admin = GitHubAdmin.__new__(GitHubAdmin)
        admin._owner_kind = {}
        admin._get = lambda path: (_ for _ in ()).throw(NotFound(path))

        with self.assertRaises(CliError) as ctx:
            admin.owner_kind("acme-cla")
        hint = ctx.exception.hint or ""
        self.assertIn("https://github.com/organizations/plan", hint)
        self.assertIn("default_repository_permission=none", hint,
                      "a new org defaults to read; say so before they hit it")
        self.assertIn("re-run", hint)


class TestOwnerIsHonoured(unittest.TestCase):
    """POST /user/repos creates under the authenticated user and ignores the
    owner. Reported from real use: `github.org=XY` for someone else's account
    created the repository in the operator's own account instead."""

    def _admin(self, *, viewer="omry", owner_type="User"):
        from dracla_cli.admin import GitHubAdmin
        admin = GitHubAdmin.__new__(GitHubAdmin)
        admin._owner_kind = {}
        admin._viewer = viewer
        admin.owner_kind = lambda owner: owner_type
        admin._post = lambda *a, **k: self.fail("must not POST")
        return admin

    def test_repositories_are_requested_private_and_empty(self):
        """The whole privacy position rests on this request body, and nothing
        asserted it. A source-text check would pass on a comment; this asserts
        what is actually sent, and to which endpoint."""
        from dracla_cli.admin import GitHubAdmin, Repo
        admin = GitHubAdmin.__new__(GitHubAdmin)
        admin._owner_kind = {}
        admin._viewer = "omry"
        admin.owner_kind = lambda owner: "Organization"
        sent = {}

        def fake_post(path, body):
            sent["path"], sent["body"] = path, body
            return {}

        admin._post = fake_post
        admin.get_repo = lambda full: Repo(full, True, None, True)
        admin.create_repo("acme-cla", "acme-cla-records", "d")

        self.assertEqual(sent["path"], "/orgs/acme-cla/repos",
                         "must not use /user/repos, which ignores the owner")
        self.assertIs(sent["body"]["private"], True)
        self.assertIs(sent["body"]["auto_init"], False)

    def test_a_repo_created_public_by_org_policy_is_refused(self):
        """Organization policy can override the requested visibility. The read
        back exists for that; nothing tested it."""
        from dracla_cli.admin import GitHubAdmin, Repo
        admin = GitHubAdmin.__new__(GitHubAdmin)
        admin._owner_kind = {}
        admin._viewer = "omry"
        admin.owner_kind = lambda owner: "Organization"
        admin._post = lambda path, body: {}
        admin.get_repo = lambda full: Repo(full, False, None, True)
        with self.assertRaises(CliError) as ctx:
            admin.create_repo("acme-cla", "acme-cla-records", "d")
        self.assertIn("PUBLIC", str(ctx.exception))

    def test_refuses_a_personal_account_that_is_not_yours(self):
        admin = self._admin()
        with self.assertRaises(CliError) as ctx:
            admin.create_repo("someone-else", "dummy-cla-records", "d")
        self.assertIn("belonging to someone else", ctx.exception.hint or "")

    def test_preflight_refuses_before_any_prompt(self):
        admin = FakeAdmin(owner_type="User")
        admin.viewer = lambda: "omry"
        admin.can_create_in = lambda owner: (False, "not yours")
        with self.assertRaises(CliError):
            preflight(admin, CFG)


class TestOrgGuidance(unittest.TestCase):
    """The moment the organization is chosen is when membership gets decided,
    so that is where the guidance belongs."""

    def test_the_gate_explains_how_to_create_the_org(self):
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        hint = ctx.exception.hint or ""
        self.assertIn("https://github.com/organizations/plan", hint)
        self.assertIn("default_repository_permission=none", hint)

    def test_the_gate_says_who_should_own_it_and_how_to_widen_access(self):
        """Ownership, not membership: with base=none a member gets nothing, so
        naming membership as the control was simply wrong. The hint must also
        say what to do when more people need access than should own the org."""
        with self.assertRaises(CliError) as ctx:
            preflight(FakeAdmin(base_permission="read"), CFG)
        hint = ctx.exception.hint or ""
        self.assertIn("OWNER", hint)
        self.assertIn("counsel", hint)
        self.assertIn("team", hint.lower())


if __name__ == "__main__":
    unittest.main()
