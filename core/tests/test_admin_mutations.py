"""M2/3 actual protocol, HTTP mapping and single-write recovery fixtures."""
from __future__ import annotations

import base64
from dataclasses import replace
import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, unquote, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey, SealedBox

from dracla.administration import (AccountRef, Administration, BranchRef, RepositoryRef,
                                   public_ssh_key)
from dracla.github_admin import API_ORIGIN, API_VERSION, HttpResponse, send
from core.tests.test_admin_discovery import GitHubFixture, response

HEAD = "a" * 40
OTHER_HEAD = "b" * 40
PUBLIC_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes(
    serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
    serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")


class MutationFixture(GitHubFixture):
    def __init__(self, kind="User", *, absent=False):
        super().__init__(kind)
        self.branches = {}
        self.keys = {}
        self.secret_keys = [PrivateKey(bytes([n]) * 32) for n in (1, 2)]
        self.key_version = 0
        self.workflow = {"id": 991, "path": ".github/workflows/reconcile.yml", "state": "active"}
        self.writes = []
        self.secret_payloads = []
        self.dispatches = []
        self.lose = set()
        self.lose_before = set()
        self.write_status = None
        self.acknowledgement = None
        self.after_write = lambda: None
        self.after_observation = lambda path: None
        if not absent:
            for role in ("records", "coverage", "control"):
                repo = self.repository(role, size=1, default_branch="main")
                self.repositories[repo["name"]] = repo
                self.branches[repo["name"]] = {"main": HEAD}
                self.keys[repo["name"]] = []

    def ref(self, role):
        name = f"acme-cla-{role}"
        return RepositoryRef(role, "acme", name, self.repositories[name]["id"])

    def bound(self) -> Administration:
        adapter = self.adapter()
        adapter.resolve_account("acme")
        return adapter

    def sender(self, method, url, headers, timeout, body=None):
        parsed = urlsplit(url)
        assert parsed.scheme == "https" and parsed.netloc == "api.github.com"
        assert headers["X-GitHub-Api-Version"] == API_VERSION
        assert headers["Authorization"] == "Bearer PRIVATE-TOKEN"
        path = parsed.path
        if method == "GET":
            if path in self.overrides:
                return super().sender(method, url, headers, timeout)
            if path.endswith("/branches"):
                self.calls.append((method, url, timeout))
                name = path.split("/")[3]
                page = int(parse_qs(parsed.query)["page"][0])
                rows = [{"name": n, "commit": {"sha": sha}} for n, sha in self.branches[name].items()]
                self.after_observation(path)
                return response(rows[(page - 1) * 100:page * 100])
            if path.endswith("/keys"):
                self.calls.append((method, url, timeout))
                name = path.split("/")[3]
                page = int(parse_qs(parsed.query)["page"][0])
                self.after_observation(path)
                return response(self.keys[name][(page - 1) * 100:page * 100])
            if path.endswith("/actions/secrets/public-key"):
                self.calls.append((method, url, timeout))
                self.after_observation(path)
                return response({"key_id": f"fixture-{self.key_version}", "key": base64.b64encode(
                    bytes(self.secret_keys[self.key_version].public_key)).decode("ascii")})
            if "/actions/workflows/" in path:
                self.calls.append((method, url, timeout))
                self.after_observation(path)
                return response(self.workflow)
            return super().sender(method, url, headers, timeout)

        self.calls.append((method, url, timeout))
        assert headers["Content-Type"] == "application/json" and isinstance(body, bytes)
        payload = json.loads(body)
        self.writes.append((method, path, payload))
        if self.write_status is not None:
            return response({"message": "PRIVATE-TOKEN SECRET-VALUE"}, self.write_status)
        if method == "POST" and path in ("/user/repos", "/orgs/acme/repos"):
            operation = "create"
        elif method == "PATCH" and path.startswith("/repos/acme/"):
            operation = "private"
        elif method == "POST" and path.endswith("/rename"):
            operation = "rename"
        elif method == "POST" and path.endswith("/keys"):
            operation = "key"
        elif method == "PUT" and "/actions/secrets/" in path:
            operation = "secret"
        elif method == "POST" and path.endswith("/dispatches"):
            operation = "dispatch"
        else:
            raise AssertionError("Unexpected mutation")
        if operation in self.lose_before:
            raise TimeoutError("PRIVATE-TOKEN SECRET-VALUE")
        if operation == "create":
            assert set(payload) == {"name", "private", "auto_init"}
            assert payload["private"] is True and payload["auto_init"] is False
            name = payload["name"]
            if name in self.repositories:
                return response({}, 422)
            repo = self.repository(size=0, default_branch="main", name=name,
                                   full_name=f"acme/{name}", id=101)
            self.repositories[name] = repo
            self.branches[name], self.keys[name] = {}, []
            result = response(repo, 201)
        elif operation == "private":
            assert payload == {"private": True}
            self.repositories[path.split("/")[3]]["private"] = True
            result = response(self.repositories[path.split("/")[3]])
        elif operation == "rename":
            name = path.split("/")[3]
            old = unquote(path.partition("/branches/")[2].removesuffix("/rename"))
            assert payload == {"new_name": "events"}
            self.branches[name]["events"] = self.branches[name].pop(old)
            self.repositories[name]["default_branch"] = "events"
            result = response({"name": "events", "commit": {"sha": self.branches[name]["events"]}}, 201)
        elif operation == "key":
            assert set(payload) == {"title", "key", "read_only"}
            item = {**payload, "id": 33}
            self.keys[path.split("/")[3]].append(item)
            result = response(item, 201)
        elif operation == "secret":
            assert set(payload) == {"encrypted_value", "key_id"}
            self.secret_payloads.append(payload)
            result = HttpResponse(204, {}, b"")
        else:
            assert path == "/repos/acme/acme-cla-control/actions/workflows/991/dispatches"
            assert set(payload) == {"ref", "inputs"}
            self.dispatches.append(payload)
            result = HttpResponse(204, {}, b"")
        self.after_write()
        if operation in self.lose:
            raise TimeoutError("PRIVATE-TOKEN SECRET-VALUE")
        return self.acknowledgement or result


class AdministrationMutationTests(unittest.TestCase):
    def test_empty_private_creation_personal_and_organization(self):
        for kind, endpoint in (("User", "/user/repos"), ("Organization", "/orgs/acme/repos")):
            for role in ("records", "coverage", "control"):
                with self.subTest(kind=kind, role=role):
                    fixture = MutationFixture(kind, absent=True)
                    admin = fixture.bound()
                    result = admin.create_private_repository(AccountRef("acme", 7, kind), f"acme-cla-{role}")
                    self.assertEqual(result.status, "applied-and-readback-verified")
                    self.assertEqual(result.repository, RepositoryRef(role, "acme", f"acme-cla-{role}", 101))
                    self.assertEqual(fixture.writes, [("POST", endpoint,
                        {"name": f"acme-cla-{role}", "private": True, "auto_init": False})])
                    self.assertEqual(fixture.branches[result.repository.name], {})

    def test_creation_collisions_concealment_changed_account_and_nonempty_readback(self):
        fixture = MutationFixture()
        self.assertEqual(fixture.bound().create_private_repository(AccountRef("acme", 7, "User"), "acme-cla-records").status, "conflict")
        self.assertEqual(fixture.writes, [])
        for changed in (AccountRef("acme", 8, "User"), AccountRef("acme", 7, "Organization")):
            fixture = MutationFixture(absent=True)
            self.assertEqual(fixture.bound().create_private_repository(changed, "acme-cla-records").status, "conflict")
            self.assertEqual(fixture.writes, [])
        fixture = MutationFixture(absent=True)
        fixture.scopes = "read:user"
        self.assertEqual(fixture.bound().create_private_repository(AccountRef("acme", 7, "User"), "acme-cla-records").status, "conflict")
        self.assertEqual(fixture.writes, [])
        fixture = MutationFixture(absent=True)
        fixture.after_write = lambda: fixture.branches["acme-cla-records"].update(main=HEAD)
        self.assertEqual(fixture.bound().create_private_repository(AccountRef("acme", 7, "User"), "acme-cla-records").status, "conflict")
        self.assertEqual(len(fixture.writes), 1)

    def test_creation_never_adopts_name_after_lost_response_or_retries_conflict(self):
        fixture = MutationFixture(absent=True)
        fixture.lose.add("create")
        admin = fixture.bound()
        result = admin.create_private_repository(AccountRef("acme", 7, "User"), "acme-cla-records")
        self.assertEqual(result.status, "uncertain")
        self.assertIsNone(result.repository)
        self.assertEqual(len(fixture.writes), 1)
        self.assertEqual(admin.create_private_repository(AccountRef("acme", 7, "User"), "acme-cla-records").status, "conflict")
        self.assertEqual(len(fixture.writes), 1)
        fixture = MutationFixture(absent=True)
        fixture.write_status = 422
        self.assertEqual(fixture.bound().create_private_repository(AccountRef("acme", 7, "User"), "acme-cla-records").status, "conflict")
        self.assertEqual(len(fixture.writes), 1)

    def test_private_visibility_is_one_way_and_reconciles_exact_identity(self):
        for lost in (False, True):
            fixture = MutationFixture()
            repo = fixture.ref("records")
            fixture.repositories[repo.name]["private"] = False
            if lost:
                fixture.lose.add("private")
            result = fixture.bound().set_private(repo)
            self.assertEqual(result.status, "applied-and-readback-verified")
            self.assertEqual(fixture.writes, [("PATCH", "/repos/acme/acme-cla-records", {"private": True})])
        fixture = MutationFixture()
        self.assertEqual(fixture.bound().set_private(fixture.ref("records")).status, "observed")
        self.assertEqual(fixture.writes, [])
        fixture = MutationFixture()
        repo = fixture.ref("records")
        fixture.repositories[repo.name]["private"] = False
        fixture.after_write = lambda: fixture.repositories[repo.name].update(id=999)
        self.assertEqual(fixture.bound().set_private(repo).status, "conflict")
        self.assertEqual(len(fixture.writes), 1)

    def test_records_default_branch_rename_preserves_head_and_reconciles_response_loss(self):
        for lost in (False, True):
            fixture = MutationFixture()
            repo, admin = fixture.ref("records"), fixture.bound()
            observed = admin.read_branch(repo, "main").branch
            self.assertEqual(observed, BranchRef(repo, "main", HEAD, "main"))
            if lost:
                fixture.lose.add("rename")
            result = admin.rename_branch(repo, observed, "events")
            self.assertEqual(result.status, "applied-and-readback-verified")
            self.assertEqual(result.branch, BranchRef(repo, "events", HEAD, "events"))
            self.assertEqual(admin.rename_branch(repo, observed, "events").status, "observed")
            self.assertEqual(len(fixture.writes), 1)
            self.assertEqual(fixture.writes[0][1], "/repos/acme/acme-cla-records/branches/main/rename")

    def test_branch_conflicts_and_async_acknowledgement_never_claim_success(self):
        for change in ("target", "head", "default"):
            fixture = MutationFixture()
            repo, admin = fixture.ref("records"), fixture.bound()
            observed = admin.read_branch(repo, "main").branch
            if change == "target":
                fixture.branches[repo.name]["events"] = HEAD
            elif change == "head":
                fixture.branches[repo.name]["main"] = OTHER_HEAD
            else:
                fixture.repositories[repo.name]["default_branch"] = "other"
            self.assertEqual(admin.rename_branch(repo, observed, "events").status, "conflict")
            self.assertEqual(fixture.writes, [])
        fixture = MutationFixture()
        repo, admin = fixture.ref("records"), fixture.bound()
        observed = admin.read_branch(repo, "main").branch
        fixture.lose_before.add("rename")
        self.assertEqual(admin.rename_branch(repo, observed, "events").status, "uncertain")
        self.assertEqual(len(fixture.writes), 1)
        fixture = MutationFixture()
        repo, admin = fixture.ref("records"), fixture.bound()
        observed = admin.read_branch(repo, "main").branch
        fixture.after_write = lambda: fixture.branches[repo.name].update(events=OTHER_HEAD)
        self.assertEqual(admin.rename_branch(repo, observed, "events").status, "conflict")

    def test_rename_requires_old_absence_and_expected_head_in_one_inventory(self):
        fixture = MutationFixture()
        repo, admin = fixture.ref("records"), fixture.bound()
        observed = admin.read_branch(repo, "main").branch
        row = lambda name, head: {"name": name, "commit": {"sha": head}}
        # Separate asynchronous observations must not be combined into success:
        # both names first exist at A, then only the target exists at B.
        fixture.overrides["/repos/acme/acme-cla-records/branches"] = [
            response([row("main", HEAD)]),
            response([row("main", HEAD), row("events", HEAD)]),
            response([row("events", OTHER_HEAD)]),
        ]
        self.assertEqual(admin.rename_branch(repo, observed, "events").status, "uncertain")
        self.assertEqual(len(fixture.writes), 1)

    def test_deploy_key_conflict_dominates_matching_material_in_either_order(self):
        matching = {"id": 1, "title": "previous title", "key": PUBLIC_KEY, "read_only": False}
        conflicting = {"id": 2, "title": "transport", "key": OTHER_KEY, "read_only": False}
        for rows in ([matching, conflicting], [conflicting, matching]):
            with self.subTest(ids=[k["id"] for k in rows]):
                fixture = MutationFixture()
                fixture.keys["acme-cla-records"] = rows
                result = fixture.bound().add_deploy_key(fixture.ref("records"), "transport", PUBLIC_KEY, read_only=False)
                self.assertEqual(result.status, "conflict")
                self.assertEqual(fixture.writes, [])
        fixture = MutationFixture()
        fixture.after_write = lambda: fixture.keys["acme-cla-records"].append(conflicting)
        result = fixture.bound().add_deploy_key(fixture.ref("records"), "transport", PUBLIC_KEY, read_only=False)
        self.assertEqual(result.status, "conflict")
        self.assertEqual(len(fixture.writes), 1)

    def test_already_renamed_branch_rejects_repository_or_default_drift(self):
        for field, value in (("id", 999), ("default_branch", "other")):
            with self.subTest(field=field):
                fixture = MutationFixture()
                repo, admin = fixture.ref("records"), fixture.bound()
                fixture.branches[repo.name] = {"events": HEAD}
                fixture.repositories[repo.name]["default_branch"] = "events"
                def drift(path):
                    if path.endswith("/branches"):
                        fixture.repositories[repo.name][field] = value
                fixture.after_observation = drift
                result = admin.rename_branch(repo, BranchRef(repo, "main", HEAD, "main"), "events")
                self.assertEqual(result.status, "conflict")
                self.assertEqual(fixture.writes, [])

    def test_deploy_key_requires_explicit_permissions_and_exact_material_not_title(self):
        for role in ("records", "coverage"):
            for read_only in (False, True):
                for lost in (False, True):
                    with self.subTest(role=role, read_only=read_only, lost=lost):
                        fixture = MutationFixture()
                        repo, admin = fixture.ref(role), fixture.bound()
                        if lost:
                            fixture.lose.add("key")
                        result = admin.add_deploy_key(repo, "transport", PUBLIC_KEY + " fixture comment", read_only=read_only)
                        self.assertEqual(result.status, "applied-and-readback-verified")
                        self.assertEqual(result.deploy_keys[0].id, 33)
                        self.assertEqual(result.deploy_keys[0].key, PUBLIC_KEY)
                        self.assertEqual(result.deploy_keys[0].read_only, read_only)
                        self.assertEqual(admin.add_deploy_key(repo, "other title", PUBLIC_KEY, read_only=read_only).status, "observed")
                        self.assertEqual(len(fixture.writes), 1)
        for key, permission in ((OTHER_KEY, False), (PUBLIC_KEY, True)):
            fixture = MutationFixture()
            fixture.keys["acme-cla-records"] = [{"id": 1, "title": "transport", "key": key, "read_only": permission}]
            self.assertEqual(fixture.bound().add_deploy_key(fixture.ref("records"), "transport", PUBLIC_KEY, read_only=False).status, "conflict")
            self.assertEqual(fixture.writes, [])

    def test_deploy_key_response_id_and_readback_permission_must_match(self):
        for field, value in (("id", 34), ("read_only", True), ("key", OTHER_KEY)):
            fixture = MutationFixture()
            fixture.after_write = lambda: fixture.keys["acme-cla-records"][0].update({field: value})
            # Keep the successful acknowledgement's ID/material bound to the original intent.
            fixture.acknowledgement = response({"id": 33, "title": "transport", "key": PUBLIC_KEY, "read_only": False}, 201)
            self.assertEqual(fixture.bound().add_deploy_key(fixture.ref("records"), "transport", PUBLIC_KEY, read_only=False).status, "conflict")
            self.assertEqual(len(fixture.writes), 1)
        fixture = MutationFixture()
        fixture.lose_before.add("key")
        self.assertEqual(fixture.bound().add_deploy_key(fixture.ref("records"), "transport", PUBLIC_KEY, read_only=False).status, "uncertain")
        self.assertEqual(len(fixture.writes), 1)

    def test_secret_actual_ciphertext_decrypts_with_fixture_key_and_has_no_plaintext_readback(self):
        for status in (201, 204):
            fixture = MutationFixture()
            fixture.acknowledgement = HttpResponse(status, {}, b"")
            result = fixture.bound().put_actions_secret(fixture.ref("control"), "installation_key", b"SECRET-VALUE")
            self.assertEqual(result.status, "accepted")
            method, path, payload = fixture.writes[0]
            self.assertEqual((method, path), ("PUT", "/repos/acme/acme-cla-control/actions/secrets/INSTALLATION_KEY"))
            self.assertEqual(set(payload), {"encrypted_value", "key_id"})
            self.assertEqual(payload["key_id"], "fixture-0")
            self.assertEqual(SealedBox(fixture.secret_keys[0]).decrypt(base64.b64decode(payload["encrypted_value"])), b"SECRET-VALUE")
            self.assertNotIn("SECRET-VALUE", repr(result))
            self.assertNotIn("SECRET-VALUE", json.dumps(payload))
            self.assertNotIn("PRIVATE-TOKEN", repr(result))
            self.assertTrue(all("/actions/secrets/" not in url or url.endswith("/public-key") or method == "PUT"
                                for method, url, _ in fixture.calls))

    def test_secret_loss_is_uncertain_and_an_explicit_repeat_reads_the_current_key(self):
        fixture = MutationFixture()
        admin = fixture.bound()
        fixture.lose.add("secret")
        first = admin.put_actions_secret(fixture.ref("control"), "VALUE", b"SECRET-VALUE")
        self.assertEqual(first.status, "uncertain")
        self.assertEqual(len(fixture.writes), 1)
        fixture.key_version = 1
        fixture.lose.clear()
        second = admin.put_actions_secret(fixture.ref("control"), "VALUE", b"SECRET-VALUE")
        self.assertEqual(second.status, "accepted")
        self.assertEqual(len(fixture.writes), 2)
        self.assertEqual(fixture.secret_payloads[1]["key_id"], "fixture-1")
        self.assertEqual(SealedBox(fixture.secret_keys[1]).decrypt(base64.b64decode(fixture.secret_payloads[1]["encrypted_value"])), b"SECRET-VALUE")
        self.assertNotIn("SECRET-VALUE", repr(first))

    def test_invalid_actions_public_key_never_sends_a_secret(self):
        path = "/repos/acme/acme-cla-control/actions/secrets/public-key"
        for body in ({"key_id": "x", "key": "not-base64"}, {"key_id": "x", "key": "AAAA"},
                     {"key_id": "bad/id", "key": base64.b64encode(bytes(32)).decode()}):
            fixture = MutationFixture()
            fixture.overrides[path] = response(body)
            self.assertEqual(fixture.bound().put_actions_secret(fixture.ref("control"), "VALUE", b"SECRET-VALUE").status, "uncertain")
            self.assertEqual(fixture.writes, [])

    def test_dispatch_is_exact_and_accepted_or_uncertain_never_a_completed_run(self):
        for workflow in ("reconcile.yml", 991):
            for lost in (False, True):
                fixture = MutationFixture()
                if lost:
                    fixture.lose.add("dispatch")
                result = fixture.bound().dispatch_workflow(fixture.ref("control"), workflow, "main", {"operation_id": "op1", "retry": False})
                self.assertEqual(result.status, "uncertain" if lost else "accepted")
                self.assertEqual(len(fixture.writes), 1)
                self.assertEqual(fixture.dispatches, [{"ref": "main", "inputs": {"operation_id": "op1", "retry": False}}])
                self.assertIsNone(result.branch)
                self.assertNotIn("PRIVATE-TOKEN", repr(result))
        for field, value in (("id", 992), ("path", ".github/workflows/other.yml"), ("state", "disabled_manually")):
            fixture = MutationFixture()
            fixture.workflow[field] = value
            workflow = 991 if field == "id" else "reconcile.yml"
            self.assertEqual(fixture.bound().dispatch_workflow(fixture.ref("control"), workflow, "main", {}).status, "conflict")
            self.assertEqual(fixture.writes, [])

    def test_every_repository_mutation_rejects_numeric_identity_drift_before_write(self):
        fixture = MutationFixture()
        admin = fixture.bound()
        for role, invoke in (
            ("records", lambda repo: admin.set_private(repo)),
            ("records", lambda repo: admin.rename_branch(repo, BranchRef(repo, "main", HEAD, "main"), "events")),
            ("records", lambda repo: admin.add_deploy_key(repo, "transport", PUBLIC_KEY, read_only=False)),
            ("control", lambda repo: admin.put_actions_secret(repo, "VALUE", b"SECRET-VALUE")),
            ("control", lambda repo: admin.dispatch_workflow(repo, 991, "main", {})),
        ):
            self.assertEqual(invoke(replace(fixture.ref(role), id=999)).status, "conflict")
        self.assertEqual(fixture.writes, [])

    def test_current_owner_name_permissions_and_privacy_are_required_before_mutation(self):
        operations = (
            ("records", lambda a, r: a.set_private(r)),
            ("records", lambda a, r: a.rename_branch(r, BranchRef(r, "main", HEAD, "main"), "events")),
            ("coverage", lambda a, r: a.add_deploy_key(r, "transport", PUBLIC_KEY, read_only=True)),
            ("control", lambda a, r: a.put_actions_secret(r, "VALUE", b"SECRET-VALUE")),
            ("control", lambda a, r: a.dispatch_workflow(r, 991, "main", {})),
        )
        for index, (role, invoke) in enumerate(operations):
            for change in ("owner", "name", "permission", "privacy"):
                if change == "privacy" and index == 0:
                    continue  # set_private explicitly permits the public-to-private transition.
                fixture = MutationFixture()
                repo, admin = fixture.ref(role), fixture.bound()
                value = fixture.repositories[repo.name]
                if change == "owner":
                    value["owner"] = {"login": "other", "id": 8, "type": "User"}
                elif change == "name":
                    value.update(name="other", full_name="acme/other")
                elif change == "permission":
                    value["permissions"]["admin"] = False
                else:
                    value["private"] = False
                with self.subTest(operation=index, change=change):
                    self.assertEqual(invoke(admin, repo).status, "conflict")
                    self.assertEqual(fixture.writes, [])

    def test_repository_id_change_during_operation_readback_prevents_a_write(self):
        for operation in ("rename", "key", "secret", "dispatch"):
            fixture = MutationFixture()
            role = "records" if operation in ("rename", "key") else "control"
            repo, admin = fixture.ref(role), fixture.bound()
            fixture.after_observation = lambda path: fixture.repositories[repo.name].update(id=999)
            if operation == "rename":
                result = admin.rename_branch(repo, BranchRef(repo, "main", HEAD, "main"), "events")
            elif operation == "key":
                result = admin.add_deploy_key(repo, "transport", PUBLIC_KEY, read_only=False)
            elif operation == "secret":
                result = admin.put_actions_secret(repo, "VALUE", b"SECRET-VALUE")
            else:
                result = admin.dispatch_workflow(repo, 991, "main", {})
            self.assertEqual(result.status, "conflict")
            self.assertEqual(fixture.writes, [])

    def test_role_and_input_rejection_precedes_all_HTTP(self):
        fixture = MutationFixture()
        admin = fixture.bound()
        records, control = fixture.ref("records"), fixture.ref("control")
        fixture.calls.clear()
        for invoke in (
            lambda: admin.create_private_repository(AccountRef("other", 7, "User"), "acme-cla-records"),
            lambda: admin.set_private(replace(records, owner="other")),
            lambda: admin.add_deploy_key(control, "key", PUBLIC_KEY, read_only=False),
            lambda: admin.add_deploy_key(records, "key", "PRIVATE-TOKEN", read_only=False),
            lambda: admin.add_deploy_key(records, "key", PUBLIC_KEY, read_only=1),
            lambda: admin.list_deploy_keys(records, page_budget=0),
            lambda: admin.list_deploy_keys(records, page_budget=True),
            lambda: admin.list_deploy_keys(records, page_budget=101),
            lambda: admin.rename_branch(control, BranchRef(control, "main", HEAD, "main"), "events"),
            lambda: admin.rename_branch(records, BranchRef(records, "main", HEAD, "main"), "other"),
            lambda: admin.read_branch(records, "main/../other"),
            lambda: admin.put_actions_secret(records, "VALUE", b"x"),
            lambda: admin.put_actions_secret(control, "GITHUB_TOKEN", b"x"),
            lambda: admin.put_actions_secret(control, "VALUE", b"x" * (48 * 1024 + 1)),
            lambda: admin.dispatch_workflow(records, 991, "main", {}),
            lambda: admin.dispatch_workflow(control, "../other.yml", "main", {}),
            lambda: admin.dispatch_workflow(control, True, "main", {}),
            lambda: admin.dispatch_workflow(control, 991, "main", {"x": object()}),
        ):
            with self.assertRaises(ValueError) as raised:
                invoke()
            self.assertNotIn("PRIVATE-TOKEN", str(raised.exception))
        self.assertEqual(fixture.calls, [])
        self.assertEqual(fixture.writes, [])

    def test_secret_and_dispatch_acknowledgement_requires_same_repository_readback(self):
        for operation in ("secret", "dispatch"):
            fixture = MutationFixture()
            repo, admin = fixture.ref("control"), fixture.bound()
            fixture.after_write = lambda: fixture.repositories[repo.name].update(id=999)
            result = (admin.put_actions_secret(repo, "VALUE", b"SECRET-VALUE") if operation == "secret"
                      else admin.dispatch_workflow(repo, 991, "main", {}))
            self.assertEqual(result.status, "conflict")
            self.assertEqual(len(fixture.writes), 1)

    def test_failed_post_write_readback_is_uncertain_and_never_retries(self):
        for operation in ("create", "private", "rename", "key", "secret", "dispatch"):
            fixture = MutationFixture(absent=operation == "create")
            admin = fixture.bound()
            role = "control" if operation in ("secret", "dispatch") else "records"
            name = f"acme-cla-{role}"
            fixture.after_write = lambda: fixture.overrides.update({f"/repos/acme/{name}": response({}, 403)})
            if operation == "create":
                result = admin.create_private_repository(AccountRef("acme", 7, "User"), name)
            elif operation == "private":
                fixture.repositories[name]["private"] = False
                result = admin.set_private(fixture.ref(role))
            elif operation == "rename":
                repo = fixture.ref(role)
                result = admin.rename_branch(repo, BranchRef(repo, "main", HEAD, "main"), "events")
            elif operation == "key":
                result = admin.add_deploy_key(fixture.ref(role), "transport", PUBLIC_KEY, read_only=False)
            elif operation == "secret":
                result = admin.put_actions_secret(fixture.ref(role), "VALUE", b"SECRET-VALUE")
            else:
                result = admin.dispatch_workflow(fixture.ref(role), 991, "main", {})
            with self.subTest(operation=operation):
                self.assertEqual(result.status, "uncertain")
                self.assertEqual(len(fixture.writes), 1)
                self.assertNotIn("SECRET-VALUE", repr(result))

    def test_denials_redirects_server_errors_and_response_loss_have_no_write_retry(self):
        for status in (301, 401, 403, 404, 429, 500, 502, 503, 504):
            for operation in ("private", "secret", "dispatch"):
                with self.subTest(status=status, operation=operation):
                    fixture = MutationFixture()
                    fixture.write_status = status
                    fixture.repositories["acme-cla-records"]["private"] = False
                    admin = fixture.bound()
                    if operation == "private":
                        result = admin.set_private(fixture.ref("records"))
                    elif operation == "secret":
                        result = admin.put_actions_secret(fixture.ref("control"), "VALUE", b"SECRET-VALUE")
                    else:
                        result = admin.dispatch_workflow(fixture.ref("control"), 991, "main", {})
                    self.assertIn(result.status, ("denied", "uncertain"))
                    self.assertEqual(len(fixture.writes), 1)
                    self.assertNotIn("PRIVATE-TOKEN", repr(result))
                    self.assertNotIn("SECRET-VALUE", repr(result))

    def test_key_inventory_bounds_duplicates_and_restricted_pagination(self):
        path = "/repos/acme/acme-cla-records/keys"
        item = {"id": 1, "title": "transport", "key": PUBLIC_KEY, "read_only": False}
        for data, headers in (([item, item], {}), ([item], {"X-GitHub-SSO": "partial-results"}),
                              ([item], {"Link": '<https://evil.example/keys?page=2>; rel="next"'})):
            fixture = MutationFixture()
            fixture.overrides[path] = response(data, headers=headers)
            self.assertEqual(fixture.bound().add_deploy_key(fixture.ref("records"), "transport", OTHER_KEY, read_only=False).status, "uncertain")
            self.assertEqual(fixture.writes, [])
        fixture = MutationFixture()
        link = API_ORIGIN + "/repositories/20/keys?per_page=100&page=2"
        fixture.overrides[path] = [response([item], headers={"Link": f'<{link}>; rel="next"'}), response([])]
        result = fixture.bound().list_deploy_keys(fixture.ref("records"))
        self.assertEqual(result.status, "observed")
        self.assertEqual(result.deploy_keys[0].key, PUBLIC_KEY)
        fixture = MutationFixture()
        fixture.overrides[path] = response([item], headers={"Link": f'<{link}>; rel="next"'})
        self.assertEqual(fixture.bound().list_deploy_keys(fixture.ref("records"), page_budget=1).status, "uncertain")

    def test_default_http_sender_transmits_only_the_explicit_body(self):
        stream = Mock()
        stream.code, stream.read.return_value = 204, b""
        stream.headers.items.return_value = []
        stream.__enter__, stream.__exit__ = Mock(return_value=stream), Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = stream
        with patch("urllib.request.build_opener", return_value=opener):
            result = send("PUT", API_ORIGIN + "/fixture", {"Content-Type": "application/json"}, 3, b'{"encrypted_value":"ciphertext"}')
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "PUT")
        self.assertEqual(request.data, b'{"encrypted_value":"ciphertext"}')
        self.assertEqual(result.status, 204)
        self.assertEqual(public_ssh_key(PUBLIC_KEY + " comment"), PUBLIC_KEY)
