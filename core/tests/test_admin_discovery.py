"""M2/2 concrete HTTP, identity, conservative planning and no-write evidence."""
from __future__ import annotations

from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit, parse_qs

from dracla.administration import (AccountRef, AdminScope, Permissions, RepositoryRef,
                                   discover)
from dracla.github_admin import (API_ORIGIN, API_VERSION, GitHubAdministration,
                                 HttpResponse, _NoRedirect, send, credentials_from_environment)
from dracla.provisioning import InstallInput, administration_scope, plan_install
from dracla.cli.app import main
from dracla.cli.release import ReleaseError
from core.tests.test_cli_planning import ReleaseFixture


def response(value, status=200, headers=None):
    return HttpResponse(status, headers or {}, json.dumps(value).encode())


class GitHubFixture:
    def __init__(self, kind="User"):
        self.account = {"login": "acme", "id": 7, "type": kind}
        self.actor = self.account.copy() if kind == "User" else {"login": "actor", "id": 8, "type": "User"}
        self.scopes = "repo, read:user, admin:org"
        self.member = {"organization": self.account, "user": self.actor, "state": "active", "role": "admin"}
        self.repositories = {}
        self.calls = []
        self.overrides = {}
        self.sleeps = []
        self.scope = administration_scope(InstallInput("acme", "acme", True))

    def repository(self, role="records", **changes):
        name = f"acme-cla-{role}"
        return {"owner": self.account.copy(), "name": name, "full_name": f"acme/{name}",
                "id": 20 + ("records", "coverage", "control").index(role), "private": True,
                "permissions": {"admin": True, "push": True, "pull": True}, **changes}

    def sender(self, method, url, headers, timeout):
        if method != "GET" or not url.startswith(API_ORIGIN + "/"):
            raise AssertionError("Unexpected write or origin")
        if headers["X-GitHub-Api-Version"] != API_VERSION or headers["Authorization"] != "Bearer PRIVATE-TOKEN":
            raise AssertionError("Missing explicit API or authorization")
        self.calls.append((method, url, timeout))
        parsed = urlsplit(url)
        if parsed.path in self.overrides:
            override = self.overrides[parsed.path]
            if isinstance(override, list):
                override = override.pop(0)
            if isinstance(override, Exception):
                raise override
            return override
        if parsed.path == "/users/acme":
            return response(self.account)
        if parsed.path == "/user":
            return response({**self.actor, "public_repos": sum(not r["private"] for r in self.repositories.values()),
                             "owned_private_repos": sum(r["private"] for r in self.repositories.values())}, headers={"X-OAuth-Scopes": self.scopes})
        if parsed.path == "/orgs/acme":
            return response({**self.account, "public_repos": sum(not r["private"] for r in self.repositories.values()),
                             "owned_private_repos": sum(r["private"] for r in self.repositories.values())})
        if parsed.path == "/orgs/acme/memberships/actor":
            return response(self.member)
        if parsed.path in ("/user/repos", "/orgs/acme/repos", "/users/acme/repos"):
            page = int(parse_qs(parsed.query)["page"][0])
            values = list(self.repositories.values())
            return response(values[(page-1)*100:page*100])
        if parsed.path.startswith("/repos/acme/"):
            name = parsed.path.rsplit("/", 1)[1]
            return response(self.repositories[name]) if name in self.repositories else response({}, 404)
        raise AssertionError("Unexpected endpoint")

    def adapter(self, scope=None, **kwargs):
        return GitHubAdministration(scope or self.scope, sender=self.sender,
            credential_provider=lambda: "PRIVATE-TOKEN", sleep=self.sleeps.append,
            clock=lambda: 1000, **kwargs)

    def discovery(self, **kwargs):
        return discover(self.adapter(), self.scope, **kwargs)

    def paginated_inventory(self, mode, restricted):
        rows = [self.repository(name=f"unrelated-{i:03d}", full_name=f"acme/unrelated-{i:03d}", id=100 + i)
                for i in range(100)]
        self.repositories = {row["name"]: row for row in rows}
        endpoint = "/user/repos" if self.account["type"] == "User" else "/orgs/acme/repos"
        headers = {"X-GitHub-SSO": "required"} if restricted else {}
        if mode == "link":
            query = ("visibility=all&affiliation=owner&sort=full_name&direction=asc&per_page=100&page=2"
                     if self.account["type"] == "User" else
                     "type=all&sort=full_name&direction=asc&per_page=100&page=2")
            headers["Link"] = f'<{API_ORIGIN}{endpoint}?{query}>; rel="next"'
        elif mode != "full-page":
            raise AssertionError("Unknown pagination mode")
        self.overrides[endpoint] = [response(rows, headers=headers), response([])]


class DiscoveryTests(unittest.TestCase):
    def test_personal_and_org_real_endpoints_and_missing_proof(self):
        for kind, listing in (("User", "/user/repos?"), ("Organization", "/orgs/acme/repos?")):
            with self.subTest(kind=kind):
                fixture = GitHubFixture(kind)
                result = fixture.discovery()
                self.assertEqual(result.account.account, AccountRef("acme", 7, kind))
                self.assertTrue(result.account.inventory_visible)
                self.assertTrue(result.inventory_complete)
                self.assertEqual([r.state for r in result.repositories], ["missing"] * 3)
                self.assertTrue(any(listing in url for _, url, _ in fixture.calls))
                plan = plan_install(InstallInput("acme", "acme", True), ReleaseFixture().load(), result)
                self.assertTrue(plan.complete)
                self.assertEqual(plan.owner_id, 7)
                self.assertEqual([s.state for s in plan.steps], ["satisfied"] + ["blocked"] * 9)
                self.assertEqual(plan, plan_install(InstallInput("acme", "acme", True), ReleaseFixture().load(), result))

    def test_hidden_404_insufficient_scope_other_user_and_membership_stay_unknown(self):
        fixtures = []
        for scope in ("", "public_repo", "repo:status"):
            fixture = GitHubFixture(); fixture.scopes = scope; fixtures.append(fixture)
        fixture = GitHubFixture(); fixture.actor = {"login": "other", "id": 9, "type": "User"}; fixtures.append(fixture)
        for changes in ({"role": "member"}, {"state": "pending"}, {"organization": {"login": "acme", "id": 9}},
                        {"user": {"login": "other", "id": 99, "type": "User"}}):
            fixture = GitHubFixture("Organization"); fixture.member = {**fixture.member, **changes}; fixtures.append(fixture)
        fixture = GitHubFixture("Organization"); fixture.overrides["/orgs/acme/memberships/actor"] = response({}, 403); fixtures.append(fixture)
        fixture = GitHubFixture(); fixture.overrides["/user"] = response(fixture.actor, headers={"X-OAuth-Scopes": "repo", "X-GitHub-SSO": "required"}); fixtures.append(fixture)
        for fixture in fixtures:
            with self.subTest(actor=fixture.actor, kind=fixture.account["type"], scopes=fixture.scopes):
                result = fixture.discovery()
                self.assertFalse(result.account.inventory_visible)
                self.assertEqual([r.state for r in result.repositories], ["unknown"] * 3)
                self.assertFalse(plan_install(InstallInput("acme", "acme", True), ReleaseFixture().load(), result).complete)

    def test_existing_repositories_never_gain_reuse_and_permissions_privacy_are_explicit(self):
        fixture = GitHubFixture()
        fixture.repositories["acme-cla-records"] = fixture.repository(private=False, permissions={"pull": True})
        result = fixture.discovery()
        self.assertEqual(result.repositories[0].metadata.id, 20)
        self.assertEqual(result.repositories[0].metadata.permissions, Permissions(None, None, True))
        plan = plan_install(InstallInput("acme", "acme", True, True), ReleaseFixture().load(), result)
        self.assertFalse(plan.complete)
        self.assertIn("records: existing repository is not private.", plan.blockers)
        self.assertIn("records: repository administration permission is unproved.", plan.blockers)
        self.assertIn("records: existing repository blocked; provenance verifier unavailable.", plan.blockers)
        self.assertEqual(plan.repositories[0].id, 20)

    def test_invalid_accounts_and_authentication_fail_without_echoing_remote_body(self):
        for data in ({"login": "renamed", "id": 7, "type": "User"}, {"login": "acme", "id": True, "type": "User"},
                     {"login": "acme", "id": 7, "type": "Bot"}, {"login": "PRIVATE-TOKEN", "id": 7, "type": "User"}, []):
            fixture = GitHubFixture(); fixture.overrides["/users/acme"] = response(data)
            result = fixture.discovery()
            self.assertIsNone(result.account.account)
            self.assertNotIn("PRIVATE-TOKEN", repr(result))
        fixture = GitHubFixture(); fixture.overrides["/user"] = response({"message": "PRIVATE-TOKEN"}, 401)
        self.assertFalse(fixture.discovery().account.inventory_visible)

    def test_identity_malformed_permissions_rename_owner_and_id_binding(self):
        for changes in ({"name": "renamed"}, {"id": True}, {"private": 1}, {"permissions": {"admin": "true"}},
                        {"owner": {"login": "acme", "id": 99, "type": "User"}}, {"full_name": "other/acme-cla-records"}):
            fixture = GitHubFixture(); adapter = fixture.adapter(); adapter.resolve_account("acme")
            fixture.overrides["/repos/acme/acme-cla-records"] = response(fixture.repository(**changes))
            self.assertEqual(adapter.get_repository("acme", "acme-cla-records").state, "unknown")
        fixture = GitHubFixture(); fixture.repositories["acme-cla-records"] = fixture.repository()
        adapter = fixture.adapter(); adapter.resolve_account("acme")
        ref = RepositoryRef("records", "acme", "acme-cla-records", 20)
        self.assertTrue(adapter.read_visibility(ref).metadata.private)
        self.assertEqual(adapter.read_visibility(replace(ref, id=999)).state, "unknown")
        before = len(fixture.calls)
        for owner, name in (("acme", "outside"), ("elsewhere", "acme-cla-records"), ("acme", "../acme-cla-records")):
            with self.assertRaises(ValueError): adapter.get_repository(owner, name)
        with self.assertRaises(ValueError): adapter.get_repository("acme", "acme-cla-records", expected=replace(ref, role="control"))
        with self.assertRaises(ValueError): adapter.resolve_account("other")
        self.assertEqual(len(fixture.calls), before)

    def test_inventory_exact_read_races_and_duplicate_observations_block(self):
        fixture = GitHubFixture(); fixture.repositories["acme-cla-records"] = fixture.repository()
        fixture.overrides["/repos/acme/acme-cla-records"] = response(fixture.repository(id=999))
        self.assertEqual(fixture.discovery().repositories[0].state, "unknown")
        fixture.overrides["/repos/acme/acme-cla-records"] = response({}, 404)
        self.assertEqual(fixture.discovery().repositories[0].state, "unknown")
        fixture = GitHubFixture(); result = fixture.discovery()
        result = replace(result, repositories=result.repositories + (result.repositories[0],))
        self.assertFalse(plan_install(InstallInput("acme", "acme", True), ReleaseFixture().load(), result).complete)

    def test_counts_and_sso_restrictions_cannot_prove_absence(self):
        for counts in ({}, {"public_repos": 0, "owned_private_repos": 1},
                       {"public_repos": True, "owned_private_repos": 0}):
            fixture = GitHubFixture()
            fixture.overrides["/user"] = response({**fixture.actor, **counts}, headers={"X-OAuth-Scopes": "repo"})
            result = fixture.discovery()
            self.assertFalse(result.account.inventory_visible)
            self.assertEqual([r.state for r in result.repositories], ["unknown"] * 3)
        fixture = GitHubFixture()
        fixture.overrides["/repos/acme/acme-cla-records"] = response({}, 404, {"X-GitHub-SSO": "required"})
        self.assertEqual(fixture.discovery().repositories[0].state, "unknown")
        fixture = GitHubFixture("Organization")
        fixture.overrides["/orgs/acme"] = response({**fixture.account, "public_repos": 0, "owned_private_repos": 0}, headers={"X-GitHub-SSO": "partial-results"})
        self.assertFalse(fixture.discovery().account.inventory_visible)

    def test_duplicate_names_and_ids_within_a_page_block_real_adapter_and_cli(self):
        for kind in ("User", "Organization"):
            for duplicate in ("identical", "id", "name"):
                fixture = GitHubFixture(kind)
                first = fixture.repository(name="unrelated-one", full_name="acme/unrelated-one", id=100)
                second = first.copy()
                if duplicate == "id":
                    second.update(name="unrelated-two", full_name="acme/unrelated-two")
                elif duplicate == "name":
                    second["id"] = 101
                fixture.repositories = {r["name"]: r for r in (first, second)}
                endpoint = "/user/repos" if kind == "User" else "/orgs/acme/repos"
                fixture.overrides[endpoint] = response([first, second])
                with self.subTest(kind=kind, duplicate=duplicate):
                    result = fixture.discovery()
                    self.assertFalse(result.inventory_complete)
                    self.assertFalse(result.account.inventory_visible)
                    self.assertEqual([r.state for r in result.repositories], ["unknown"] * 3)
                    plan = plan_install(InstallInput("acme", "acme", True), ReleaseFixture().load(), result)
                    self.assertFalse(plan.complete)
                    output = io.StringIO()
                    self.assertEqual(main(["install", "github.owner=acme", "dry_run=true"],
                        release_loader=ReleaseFixture().load, admin_factory=fixture.adapter, output=output), 2)
                    self.assertIn("Repository inventory is incomplete", output.getvalue())

    def test_sso_restriction_blocks_explicit_and_implicit_pagination_and_force(self):
        for kind in ("User", "Organization"):
            for mode in ("link", "full-page"):
                with self.subTest(kind=kind, mode=mode):
                    restricted = GitHubFixture(kind)
                    restricted.paginated_inventory(mode, restricted=True)
                    result = restricted.discovery()
                    self.assertFalse(result.inventory_complete)
                    self.assertFalse(result.account.inventory_visible)
                    self.assertEqual([repo.state for repo in result.repositories], ["unknown"] * 3)

                    cli_fixture = GitHubFixture(kind)
                    cli_fixture.paginated_inventory(mode, restricted=True)
                    output = io.StringIO()
                    self.assertEqual(main(["install", "github.owner=acme", "dry_run=true", "force=true"],
                        release_loader=ReleaseFixture().load, admin_factory=cli_fixture.adapter, output=output), 2)
                    self.assertIn("Plan: acme/acme — blocked", output.getvalue())
                    self.assertIn("Repository inventory is incomplete", output.getvalue())

                    unrestricted = GitHubFixture(kind)
                    unrestricted.paginated_inventory(mode, restricted=False)
                    unrestricted_result = unrestricted.discovery()
                    self.assertTrue(unrestricted_result.inventory_complete)
                    self.assertTrue(unrestricted_result.account.inventory_visible)
                    self.assertEqual([repo.state for repo in unrestricted_result.repositories], ["missing"] * 3)

                    unrestricted_cli = GitHubFixture(kind)
                    unrestricted_cli.paginated_inventory(mode, restricted=False)
                    output = io.StringIO()
                    self.assertEqual(main(["install", "github.owner=acme", "dry_run=true", "force=true"],
                        release_loader=ReleaseFixture().load, admin_factory=unrestricted_cli.adapter, output=output), 0)
                    self.assertIn("Plan: acme/acme — ready", output.getvalue())

    def test_pagination_budgets_repeated_pages_denial_and_safe_links(self):
        for budget in (0, True, 101):
            with self.assertRaises(ValueError): GitHubFixture().discovery(page_budget=budget)
        fixture = GitHubFixture()
        rows = [fixture.repository(name=f"repo-{i}", full_name=f"acme/repo-{i}", id=100+i) for i in range(100)]
        fixture.overrides["/user/repos"] = response(rows)
        for budget in (1, 3):
            result = fixture.discovery(page_budget=budget)
            self.assertFalse(result.inventory_complete)
            self.assertEqual(result.repositories[0].state, "unknown")
        fixture.overrides["/user/repos"] = response({}, 403)
        self.assertFalse(fixture.discovery().inventory_complete)
        for next_url in ("https://evil.example/repos?page=2", "http://api.github.com/user/repos?page=2",
                         "https://api.github.com/user/repos?page=1", "https://api.github.com/user/repos?page=2&extra=x"):
            fixture.overrides["/user/repos"] = response([], headers={"Link": f'<{next_url}>; rel="next"'})
            self.assertFalse(fixture.discovery().inventory_complete)
        link = API_ORIGIN + "/user/repos?visibility=all&affiliation=owner&sort=full_name&direction=asc&per_page=100&page=2"
        fixture.overrides["/user/repos"] = [response(rows, headers={"Link": f'<{link}>; rel="next"'}), response([])]
        self.assertTrue(fixture.discovery().inventory_complete)

    def test_bounded_retries_rate_limits_response_size_and_redaction(self):
        for failure in (response({}, 503), TimeoutError("PRIVATE-TOKEN")):
            fixture = GitHubFixture(); fixture.overrides["/users/acme"] = failure
            self.assertIsNone(fixture.discovery().account.account)
            self.assertEqual(len(fixture.calls), 4)
            self.assertEqual(fixture.sleeps, [1.0, 2.0, 4.0])
        fixture = GitHubFixture()
        fixture.overrides["/users/acme"] = response({"message": "PRIVATE-TOKEN"}, 429,
            {"Retry-After": "60", "X-RateLimit-Remaining": "0"})
        result = fixture.discovery()
        self.assertEqual(len(fixture.calls), 1)
        self.assertEqual(result.account.rate_limit.retry_at, 1060)
        self.assertEqual(result.account.rate_limit.remaining, 0)
        self.assertNotIn("PRIVATE-TOKEN", repr(result))
        for raw in (b"x" * (1024*1024+1), b'\xff', b'{"id":1,"id":2}', b'null'):
            fixture = GitHubFixture(); fixture.overrides["/users/acme"] = HttpResponse(200, {}, raw)
            self.assertIsNone(fixture.discovery().account.account)
        fixture = GitHubFixture(); adapter = fixture.adapter()
        self.assertNotIn("PRIVATE-TOKEN", repr(adapter))
        for timeout in (True, float("nan"), 0, 61):
            with self.assertRaises(ValueError): fixture.adapter(timeout=timeout)

    def test_credentials_are_acquired_once_per_discovery_and_never_rendered(self):
        fixture = GitHubFixture(); provider = Mock(return_value="PRIVATE-TOKEN")
        adapter = GitHubAdministration(fixture.scope, sender=fixture.sender, credential_provider=provider)
        discover(adapter, fixture.scope)
        provider.assert_called_once_with()
        for value in (None, "", "token\nheader", "é"):
            adapter = GitHubAdministration(fixture.scope, sender=lambda *args: self.fail("HTTP with invalid credential"), credential_provider=lambda: value)
            self.assertIsNone(discover(adapter, fixture.scope).account.account)
        with patch.dict(os.environ, {"GH_TOKEN": "first", "GITHUB_TOKEN": "second"}, clear=True):
            self.assertEqual(credentials_from_environment(), "first")
        with patch.dict(os.environ, {"GITHUB_TOKEN": "second"}, clear=True):
            self.assertEqual(credentials_from_environment(), "second")

    def test_default_sender_bounds_reads_and_refuses_redirects(self):
        stream = Mock(); stream.code = 200; stream.headers.items.return_value = []; stream.read.return_value = b"{}"
        stream.__enter__ = Mock(return_value=stream); stream.__exit__ = Mock(return_value=False)
        opener = Mock(); opener.open.return_value = stream
        with patch("urllib.request.build_opener", return_value=opener) as build:
            self.assertEqual(send("GET", API_ORIGIN + "/user", {}, 3).body, b"{}")
        stream.read.assert_called_once_with(1024*1024+1)
        self.assertIsInstance(build.call_args.args[0], _NoRedirect)
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example"))


class CliDiscoveryTests(unittest.TestCase):
    def test_real_adapter_through_cli_success_collisions_and_force(self):
        for kind in ("User", "Organization"):
            for dry in (True, False):
                fixture = GitHubFixture(kind); output = io.StringIO()
                args = ["install", "github.owner=acme", f"dry_run={str(dry).lower()}", "force=true"]
                result = main(args, release_loader=ReleaseFixture().load, admin_factory=fixture.adapter, output=output)
                self.assertEqual(result, 0 if dry else 2)
                self.assertIn("Owner ID: 7", output.getvalue())
                self.assertIn("This deploy key is an integrity credential", output.getvalue())
                self.assertIn("hosted operator", output.getvalue())
                self.assertIn("M6; blocked", output.getvalue())
                self.assertNotIn("PRIVATE-TOKEN", output.getvalue())
                self.assertTrue(all(method == "GET" for method, _, _ in fixture.calls))
        fixture = GitHubFixture(); fixture.repositories["acme-cla-control"] = fixture.repository("control")
        output = io.StringIO()
        self.assertEqual(main(["install", "github.owner=acme", "dry_run=true", "force=true"],
            release_loader=ReleaseFixture().load, admin_factory=fixture.adapter, output=output), 2)
        self.assertIn("provenance verifier unavailable", output.getvalue())

    def test_input_and_release_fail_before_credentials_or_adapter(self):
        provider, factory = Mock(side_effect=AssertionError("credential read")), Mock(side_effect=AssertionError("adapter creation"))
        output = io.StringIO()
        for args, loader in ((["install", "github.owner=${oc.env:GH_TOKEN}"], ReleaseFixture().load),
                             (["install", "github.owner=acme"], lambda: (_ for _ in ()).throw(ReleaseError("Unavailable release")))):
            self.assertEqual(main(args, release_loader=loader, credential_provider=provider, admin_factory=factory, output=output), 2)
        provider.assert_not_called(); factory.assert_not_called()

    def test_dry_run_success_and_failure_make_no_application_writes_or_processes(self):
        # Hydra may read package configuration; deny every file creation/write.
        from dracla.cli.config import compose_install
        compose_install(["github.owner=acme"])
        old = Path.cwd(); original_open, original_os_open = io.open, os.open
        def readonly(file, mode="r", *args, **kwargs):
            if any(c in mode for c in "wax+"): raise AssertionError("file write")
            return original_open(file, mode, *args, **kwargs)
        def readonly_os(file, flags, *args, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND): raise AssertionError("file write")
            return original_os_open(file, flags, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            try:
                for denied in (False, True):
                    fixture = GitHubFixture()
                    if denied: fixture.overrides["/user/repos"] = response({}, 403)
                    with patch("io.open", side_effect=readonly), patch("os.open", side_effect=readonly_os), \
                         patch("os.mkdir", side_effect=AssertionError("mkdir")), \
                         patch("os.chdir", side_effect=AssertionError("chdir")), \
                         patch("subprocess.Popen", side_effect=AssertionError("process")), \
                         patch("socket.create_connection", side_effect=AssertionError("unexpected live network")):
                        result = main(["install", "github.owner=acme", "dry_run=true"],
                            release_loader=ReleaseFixture().load, admin_factory=fixture.adapter, output=io.StringIO())
                        self.assertEqual(result, 2 if denied else 0)
                    self.assertEqual(list(Path(directory).rglob("*")), [])
            finally:
                os.chdir(old)
