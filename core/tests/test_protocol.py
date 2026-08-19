"""Protocol tests. Each case reproduces a finding from design/review-findings.md.

These are written as regression tests for defects the review found in the
*design*, before any of it was built. A test that fails here means the design
document and the code have diverged on something a reviewer already caught.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla import events as E                                    # noqa: E402
from dracla.append import (                                       # noqa: E402
    EVENTS_REF, OperationSuperseded, RetriesExhausted, append_event,
    read_chain_head,
)
from dracla.githost import (                                      # noqa: E402
    BlobConflict, FakeGitHost, NotFastForward,
)
from dracla import projection as P                                # noqa: E402

CONFIG = {
    "required_fields": ["legal_name", "email"],
    "confirmations": [{"label": "I have read the agreement"}],
}
AGREEMENT = {"id": "icla", "version": "v1", "digest": "sha256:d"}
SCOPE = {"orgs": ["acme"], "repos": []}


def make_event(uid: int, *, etype: str = E.ACCEPTANCE, nonce: str = "n",
               prior: str = E.GENESIS, revokes: str | None = None) -> E.Event:
    key = E.idempotency_key(
        project="acme", subject_user_id=uid, event_type=etype,
        agreement_id="icla", agreement_version="v1", agreement_digest="sha256:d",
        prior_event_id=prior, submission_nonce=nonce,
    )
    return E.Event(
        event_id=E.event_id(key), idempotency_key=key, type=etype,
        recorded_at="2026-08-18T00:00:00Z", dracla_version="0.0.1",
        agreement=dict(AGREEMENT), scope=dict(SCOPE),
        subjects=[E.Subject(uid, f"user{uid}")],
        fields={"legal_name": "A Person", "email": "a@example.com"},
        confirmations=[{"label": "I have read the agreement", "checked": True}],
        revokes=revokes,
    )


class TestIdentifiers(unittest.TestCase):
    """DR-015: both obvious derivations break a MUST; this one must not."""

    def test_same_submission_collapses(self):
        """REQ-SIGN-5: repeated delivery must not create conflicting records."""
        a, b = make_event(1, nonce="same"), make_event(1, nonce="same")
        self.assertEqual(a.event_id, b.event_id)

    def test_resign_after_revoke_is_a_distinct_path(self):
        """REQ-REV-5: a content-addressed key would collide here and be swallowed."""
        first = make_event(1, nonce="n1", prior=E.GENESIS)
        # After revocation the chain head has moved, so the re-sign differs even
        # with identical agreement content.
        again = make_event(1, nonce="n2", prior="some-revocation-event-id")
        self.assertNotEqual(first.event_id, again.event_id)

    def test_event_id_is_a_function_of_the_idempotency_key(self):
        """Path existence is therefore the REQ-REC-3 idempotency-key check."""
        ev = make_event(1)
        self.assertEqual(ev.event_id, E.event_id(ev.idempotency_key))

    def test_path_is_server_computed(self):
        """DR-013 / §8.1 #1: no client input reaches the path."""
        ev = make_event(1)
        self.assertTrue(ev.path.startswith("events/"))
        self.assertIn(ev.event_id, ev.path)


class TestValidation(unittest.TestCase):
    """DR-004: validation must precede any write."""

    def test_missing_required_field_rejected(self):
        ev = make_event(1)
        ev.fields.pop("email")
        with self.assertRaises(E.ValidationError):
            E.validate(ev, config=CONFIG)

    def test_extra_field_rejected(self):
        """REQ-SEC-1: collect only what the agreement and policy require."""
        ev = make_event(1)
        ev.fields["ip_address"] = "1.2.3.4"
        with self.assertRaises(E.ValidationError):
            E.validate(ev, config=CONFIG)

    def test_unchecked_confirmation_rejected(self):
        ev = make_event(1)
        ev.confirmations[0]["checked"] = False
        with self.assertRaises(E.ValidationError):
            E.validate(ev, config=CONFIG)

    def test_revocation_must_name_what_it_revokes(self):
        """REQ-REV-3."""
        ev = make_event(1, etype=E.REVOCATION)
        with self.assertRaises(E.ValidationError):
            E.validate(ev, config=CONFIG)
        ev.revokes = "some-acceptance"
        E.validate(ev, config=CONFIG)

    def test_invalid_event_never_reaches_canonical(self):
        host = FakeGitHost()
        ev = make_event(1)
        ev.fields.pop("email")
        with self.assertRaises(E.ValidationError):
            E.validate(ev, config=CONFIG)
        self.assertIsNone(host.head(EVENTS_REF), "nothing may be written")


class TestAppendProtocol(unittest.TestCase):
    """DR-006, DR-054: the retry must rebuild the tree and re-validate."""

    def test_concurrent_appends_both_survive(self):
        host = FakeGitHost()
        a, b = make_event(1, nonce="a"), make_event(2, nonce="b")
        append_event(host, a)
        r = append_event(host, b)
        head = host.head(EVENTS_REF)
        self.assertTrue(host.exists(head, a.path), "first event lost")
        self.assertTrue(host.exists(head, b.path), "second event lost")
        self.assertEqual(r.attempts, 1)

    def test_reusing_a_stale_tree_loses_the_concurrent_event(self):
        """The DR-006 defect, reproduced deliberately.

        A commit built from a stale tree and merely re-parented is a valid
        fast-forward, so the ref advances and history looks linear — while the
        concurrent event is absent from the tree that every reader consults.
        """
        host = FakeGitHost()
        a, b = make_event(1, nonce="a"), make_event(2, nonce="b")

        h0 = host.head(EVENTS_REF)
        stale_tree = {a.path: a.to_json()}          # built against empty head

        append_event(host, b)                       # B lands first
        h1 = host.head(EVENTS_REF)

        bad = host.commit_with_tree(parent=h1, tree=stale_tree, message="A")
        host.update_ref(EVENTS_REF, bad, force=False)   # accepted: it is a ff

        head = host.head(EVENTS_REF)
        self.assertTrue(host.exists(head, a.path))
        self.assertFalse(host.exists(head, b.path),
                         "this is the defect: B vanished behind a clean ff")

    def test_correct_protocol_survives_a_lost_race(self):
        """Same race, driven through append_event, must keep both."""
        host = FakeGitHost()
        a, b = make_event(1, nonce="a"), make_event(2, nonce="b")

        original = host.head
        landed = {"done": False}

        def head_then_interfere(ref):
            h = original(ref)
            if not landed["done"]:
                landed["done"] = True
                append_event(host, b)               # B lands between read and write
                return h                            # A still sees the old head
            return original(ref)

        host.head = head_then_interfere             # type: ignore[method-assign]
        result = append_event(host, a)
        host.head = original                        # type: ignore[method-assign]

        head = host.head(EVENTS_REF)
        self.assertGreater(result.attempts, 1, "the race must be observed")
        self.assertTrue(host.exists(head, a.path))
        self.assertTrue(host.exists(head, b.path), "DR-006 regression")

    def test_idempotent_replay_writes_nothing(self):
        host = FakeGitHost()
        ev = make_event(1)
        first = append_event(host, ev)
        before = len(host.history(EVENTS_REF))
        second = append_event(host, ev)
        self.assertFalse(first.idempotent)
        self.assertTrue(second.idempotent)
        self.assertEqual(len(host.history(EVENTS_REF)), before)

    def test_retry_revalidates_against_the_new_head(self):
        """DR-054: a superseded operation must not be blindly re-parented."""
        host = FakeGitHost()
        a, b = make_event(1, nonce="a"), make_event(2, nonce="b")
        original = host.head
        fired = {"n": 0}

        def head_then_interfere(ref):
            h = original(ref)
            if fired["n"] == 0:
                fired["n"] = 1
                append_event(host, b)
                return h
            return original(ref)

        def revalidate(event, new_head):
            raise OperationSuperseded("target changed under us")

        host.head = head_then_interfere            # type: ignore[method-assign]
        with self.assertRaises(OperationSuperseded):
            append_event(host, a, revalidate=revalidate)
        host.head = original                       # type: ignore[method-assign]

    def test_history_is_linear_with_single_parents(self):
        """REQ-REC-3: ancestry is the order; no merge commits ever."""
        host = FakeGitHost()
        for i in range(6):
            append_event(host, make_event(i, nonce=f"n{i}"))
        hist = host.history(EVENTS_REF)
        self.assertEqual(len(hist), 6)
        self.assertIsNone(hist[0].parent)
        for prev, cur in zip(hist, hist[1:]):
            self.assertEqual(cur.parent, prev.sha, "non-linear ancestry")

    def test_retries_exhausted_is_explicit(self):
        """DR-071: the caller must learn the outcome is indeterminate."""
        host = FakeGitHost()
        original = host.head
        reentrant = {"in": False}
        n = {"i": 0}

        def always_stale(ref):
            """Land a competing event on every read, so A never wins the race."""
            h = original(ref)
            if reentrant["in"]:
                return h                            # don't recurse into ourselves
            reentrant["in"] = True
            try:
                n["i"] += 1
                append_event(host, make_event(90 + n["i"], nonce=f"x{n['i']}"))
            finally:
                reentrant["in"] = False
            return h

        host.head = always_stale                   # type: ignore[method-assign]
        try:
            with self.assertRaises(RetriesExhausted):
                append_event(host, make_event(1, nonce="a"), max_attempts=3)
        finally:
            host.head = original                   # type: ignore[method-assign]

    def test_chain_head_tracks_a_subject(self):
        host = FakeGitHost()
        self.assertEqual(read_chain_head(host, EVENTS_REF, 1), E.GENESIS)
        ev = make_event(1, nonce="a")
        append_event(host, ev)
        self.assertEqual(read_chain_head(host, EVENTS_REF, 1), ev.event_id)


class TestShardConcurrency(unittest.TestCase):
    """DR-005: packed shards are read-modify-write and need a precondition."""

    def test_same_shard_concurrent_writers_keep_both_rows(self):
        host = FakeGitHost()
        a, b = 1, 1 + P.SHARD_COUNT              # collide by construction
        self.assertEqual(P.shard_path(a), P.shard_path(b))

        errors: list[BaseException] = []

        def write(uid: int):
            try:
                for _ in range(20):
                    P.write_row(host, uid, "icla",
                                P.Row(P.COVERED, "v1", "d", SCOPE, "t"))
            except BaseException as exc:            # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(u,)) for u in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertIsNotNone(P.read_row(host, a, "icla"), "row A lost")
        self.assertIsNotNone(P.read_row(host, b, "icla"), "row B lost")

    def test_unguarded_write_loses_a_revocation(self):
        """The DR-005 defect itself: read-modify-write with no precondition.

        Two users share a shard. A revocation for one is overwritten by a
        concurrent acceptance for the other, and the revoked contributor keeps
        passing checks. This is what the blob-sha precondition prevents.
        """
        host = FakeGitHost()
        a, b = 1, 1 + P.SHARD_COUNT
        path = P.shard_path(a)
        P.write_row(host, a, "icla", P.Row(P.COVERED, "v1", "d", SCOPE, "t"))

        # Both writers read the same shard state...
        doc_a, blob = P._read_json(host, path, dict)
        doc_b = json.loads(json.dumps(doc_a))

        # ...A revokes...
        doc_a[str(a)]["icla"]["decision"] = P.UNCOVERED
        host.put(P.COVERAGE_REF, path, json.dumps(doc_a, sort_keys=True),
                 base_blob_sha=blob)

        # ...and B writes back its stale copy without a precondition (force).
        doc_b[str(b)] = {"icla": {"decision": P.COVERED, "version": "v1",
                                  "digest": "d", "scope": SCOPE,
                                  "since": "t", "reason": ""}}
        _, current = host.read(P.COVERAGE_REF, path)
        host.put(P.COVERAGE_REF, path, json.dumps(doc_b, sort_keys=True),
                 base_blob_sha=current)

        self.assertEqual(
            P.evaluate(host, [a], "icla", "acme/widget")[0], "success",
            "defect reproduced: the revocation was silently lost")

    def test_guarded_write_refuses_the_stale_update(self):
        """The same sequence through write_row: the precondition rejects it."""
        host = FakeGitHost()
        a, b = 1, 1 + P.SHARD_COUNT
        path = P.shard_path(a)
        P.write_row(host, a, "icla", P.Row(P.COVERED, "v1", "d", SCOPE, "t"))

        _, stale_blob = host.read(P.COVERAGE_REF, path)
        P.write_row(host, a, "icla", P.Row(P.UNCOVERED, "v1", "d", SCOPE, "t"))

        with self.assertRaises(BlobConflict):
            host.put(P.COVERAGE_REF, path, json.dumps({}), base_blob_sha=stale_blob)

        # And the normal path re-reads, so B's row lands without clobbering A's.
        P.write_row(host, b, "icla", P.Row(P.COVERED, "v1", "d", SCOPE, "t"))
        self.assertEqual(P.read_row(host, a, "icla")["decision"], P.UNCOVERED)
        self.assertEqual(P.read_row(host, b, "icla")["decision"], P.COVERED)


class TestInflightMarker(unittest.TestCase):
    """DR-003, DR-002, DR-004: ordering, set semantics, and subject scoping."""

    def test_crash_before_commit_fails_closed(self):
        """The marker opens first, so a crash anywhere after it is visible."""
        host = FakeGitHost()
        P.write_row(host, 1, "icla", P.Row(P.COVERED, "v1", "d", SCOPE, "t"))
        self.assertEqual(P.evaluate(host, [1], "icla", "acme/widget")[0], "success")

        P.open_marker(host, "op1", [1])             # then the process dies
        self.assertEqual(
            P.evaluate(host, [1], "icla", "acme/widget")[0], "in_progress",
            "a crashed revocation must never leave the subject passing")

    def test_marker_is_scoped_to_subjects_not_the_project(self):
        """DR-004: one stuck operation must not wedge every check."""
        host = FakeGitHost()
        for uid in (1, 2):
            P.write_row(host, uid, "icla", P.Row(P.COVERED, "v1", "d", SCOPE, "t"))
        P.open_marker(host, "op1", [1])
        self.assertEqual(P.evaluate(host, [1], "icla", "acme/widget")[0], "in_progress")
        self.assertEqual(P.evaluate(host, [2], "icla", "acme/widget")[0], "success",
                         "unrelated subject must be unaffected")

    def test_two_concurrent_operations_are_both_represented(self):
        """DR-002: a scalar pointer pair cannot express this."""
        host = FakeGitHost()
        P.open_marker(host, "op1", [1])
        P.open_marker(host, "op2", [2])
        self.assertEqual(P.inflight_subjects(host), {1, 2})
        P.close_marker(host, "op1", owner="worker")
        self.assertEqual(P.inflight_subjects(host), {2},
                         "closing one operation must not clear the other")

    def test_only_the_opener_may_close_a_marker(self):
        """DR-014: without this the reconciler can drop a newer marker."""
        host = FakeGitHost()
        P.open_marker(host, "op1", [1], owner="worker-a")
        with self.assertRaises(P.MarkerNotOwned):
            P.close_marker(host, "op1", owner="worker-b")
        self.assertEqual(P.inflight_subjects(host), {1}, "must still be in flight")
        P.close_marker(host, "op1", owner="worker-a")
        self.assertEqual(P.inflight_subjects(host), set())

    def test_reconciler_may_close_after_confirming_outcome(self):
        """The one licensed exception, and it is explicit at the call site."""
        host = FakeGitHost()
        P.open_marker(host, "orphan", [1], owner="worker-a")
        P.close_marker(host, "orphan", owner="reconciler")
        self.assertEqual(P.inflight_subjects(host), set())

    def test_closing_an_absent_marker_is_idempotent(self):
        host = FakeGitHost()
        P.close_marker(host, "never-opened", owner="worker")

    def test_full_write_path_ends_clean(self):
        host = FakeGitHost()
        ev = make_event(1, nonce="a")
        E.validate(ev, config=CONFIG)               # 0. before any write
        P.open_marker(host, ev.idempotency_key, ev.subject_ids)   # 1.
        res = append_event(host, ev)                              # 2.
        P.write_row(host, 1, "icla", P.Row(P.COVERED, "v1", "d", SCOPE, "t"))  # 3.
        P.set_source(host, res.sha)
        P.close_marker(host, ev.idempotency_key, owner="worker")                  # 4.
        self.assertEqual(P.inflight_subjects(host), set())
        self.assertEqual(P.evaluate(host, [1], "icla", "acme/widget")[0], "success")


class TestScopeEvaluation(unittest.TestCase):
    """DR-007: found independently by three reviewers."""

    def test_repository_outside_recorded_scope_is_not_covered(self):
        host = FakeGitHost()
        P.write_row(host, 1, "icla",
                    P.Row(P.COVERED, "v1", "d", {"orgs": ["acme"], "repos": []}, "t"))
        self.assertEqual(P.evaluate(host, [1], "icla", "acme/widget")[0], "success")
        self.assertEqual(
            P.evaluate(host, [1], "icla", "acme-labs/widget")[0], "action_required",
            "scope must be evaluated, not merely recorded")

    def test_scope_widening_does_not_retroactively_cover(self):
        """Coverage is judged against the scope recorded with the acceptance."""
        host = FakeGitHost()
        P.write_row(host, 1, "icla",
                    P.Row(P.COVERED, "v1", "d", {"orgs": ["acme"], "repos": []}, "t"))
        # A project widening its scope must not silently extend consent.
        self.assertEqual(
            P.evaluate(host, [1], "icla", "newly-added-org/repo")[0],
            "action_required")

    def test_explicit_repo_in_scope(self):
        host = FakeGitHost()
        P.write_row(host, 1, "icla",
                    P.Row(P.COVERED, "v1", "d",
                          {"orgs": [], "repos": ["acme-labs/widget"]}, "t"))
        self.assertEqual(
            P.evaluate(host, [1], "icla", "acme-labs/widget")[0], "success")


if __name__ == "__main__":
    unittest.main()


class TestClientRetry(unittest.TestCase):
    """Transient-fault handling in the live client, exercised without network.

    Retrying is only safe because the protocol above is idempotent; these check
    that the client retries what it should and never retries a protocol signal.
    """

    def _host(self):
        from dracla.github import GitHubHost
        h = GitHubHost(repo="o/r", token="t")
        h.sleep = lambda _d: None          # no real waiting in tests
        return h

    def test_transient_network_error_is_retried_then_succeeds(self):
        import urllib.error
        from dracla import github as G
        h = self._host()
        calls = {"n": 0}

        class FakeResp:
            def read(self): return b'{"ok": true}'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise urllib.error.URLError("connection timed out")
            return FakeResp()

        orig = G.urllib.request.urlopen
        G.urllib.request.urlopen = urlopen
        try:
            self.assertEqual(h._req("GET", "/x"), {"ok": True})
        finally:
            G.urllib.request.urlopen = orig
        self.assertEqual(calls["n"], 3, "should have retried twice")

    def test_protocol_signals_are_never_retried(self):
        import io as _io
        import urllib.error
        from dracla import github as G
        from dracla.githost import BlobConflict, NotFastForward, NotFound

        for code, body, exc in [
            (404, "not found", NotFound),
            (409, "conflict", BlobConflict),
            (422, "Update is not a fast forward", NotFastForward),
        ]:
            h = self._host()
            calls = {"n": 0}

            def urlopen(req, timeout=None, code=code, body=body):
                calls["n"] += 1
                raise urllib.error.HTTPError(
                    "u", code, body, {}, _io.BytesIO(body.encode()))

            orig = G.urllib.request.urlopen
            G.urllib.request.urlopen = urlopen
            try:
                with self.assertRaises(exc):
                    h._req("GET", "/x")
            finally:
                G.urllib.request.urlopen = orig
            self.assertEqual(calls["n"], 1,
                             f"{code} is a protocol signal, not a fault")

    def test_gives_up_after_max_attempts(self):
        import urllib.error
        from dracla import github as G
        from dracla.github import GitHubError
        h = self._host()
        calls = {"n": 0}

        def urlopen(req, timeout=None):
            calls["n"] += 1
            raise urllib.error.URLError("down")

        orig = G.urllib.request.urlopen
        G.urllib.request.urlopen = urlopen
        try:
            with self.assertRaises(GitHubError):
                h._req("GET", "/x")
        finally:
            G.urllib.request.urlopen = orig
        self.assertEqual(calls["n"], h.max_attempts)

    def test_socket_timeout_is_set(self):
        """No timeout means a wedged socket hangs a Worker or a CI job."""
        from dracla import github as G
        h = self._host()
        seen = {}

        class FakeResp:
            def read(self): return b"{}"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def urlopen(req, timeout=None):
            seen["timeout"] = timeout
            return FakeResp()

        orig = G.urllib.request.urlopen
        G.urllib.request.urlopen = urlopen
        try:
            h._req("GET", "/x")
        finally:
            G.urllib.request.urlopen = orig
        self.assertEqual(seen["timeout"], h.timeout)


class TestPublicTransport(unittest.TestCase):
    """`request()` is API, not an accident.

    Administration outside the GitHost protocol — creating repositories, reading
    organization settings — needs this transport's auth, retry, and timeout
    policy and none of the protocol. Callers previously reached into `_req` to
    borrow it, which made a real dependency invisible to anyone changing it.
    """

    def test_request_is_public_and_delegates(self):
        from dracla.github import GitHubHost
        host = GitHubHost(repo="o/r", token="t")
        seen = {}

        def fake_req(method, path, body=None):
            seen.update(method=method, path=path, body=body)
            return {"ok": True}

        host._req = fake_req                        # type: ignore[method-assign]
        self.assertEqual(host.request("POST", "/x", {"a": 1}), {"ok": True})
        self.assertEqual(seen, {"method": "POST", "path": "/x", "body": {"a": 1}})

    def test_request_carries_the_retry_policy(self):
        """It must not become a bare urlopen that skips retries and timeouts.

        Exercised rather than read: a source-text assertion passes on the
        docstring, so it cannot fail for the reason the test exists.
        """
        import io as _io
        import urllib.error
        from dracla import github as G
        from dracla.github import GitHubHost

        host = GitHubHost(repo="o/r", token="t")
        host.sleep = lambda _d: None                # type: ignore[method-assign]
        calls = {"n": 0}
        seen = {}

        class FakeResp:
            def read(self): return b'{"ok": true}'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def urlopen(req, timeout=None):
            calls["n"] += 1
            seen["timeout"] = timeout
            if calls["n"] == 1:
                body = '{"message":"bad gateway"}'
                raise urllib.error.HTTPError(
                    "u", 502, body, {}, _io.BytesIO(body.encode()))
            return FakeResp()

        original = G.urllib.request.urlopen
        G.urllib.request.urlopen = urlopen
        try:
            self.assertEqual(host.request("GET", "/x"), {"ok": True})
        finally:
            G.urllib.request.urlopen = original
        self.assertEqual(calls["n"], 2, "a transient fault must be retried")
        self.assertEqual(seen["timeout"], host.timeout)


class TestEmptyRepository(unittest.TestCase):
    """A repository with no commits is not the same as a missing repository,
    and GitHub distinguishes them differently from how you would expect.

    Reported from real use: `dracla install` creates repositories empty on
    purpose, and the first head() against one crashed. GitHub answers 409
    "Git Repository is empty" for a ref read there, not 404.
    """

    def test_head_returns_none_when_the_repository_is_empty(self):
        import io as _io
        import urllib.error
        from dracla import github as G
        from dracla.github import GitHubHost

        host = GitHubHost(repo="o/r", token="t")
        host.sleep = lambda _d: None                # type: ignore[method-assign]
        body = '{"message":"Git Repository is empty.","status":"409"}'

        def urlopen(req, timeout=None):
            raise urllib.error.HTTPError(
                "u", 409, body, {}, _io.BytesIO(body.encode()))

        original = G.urllib.request.urlopen
        G.urllib.request.urlopen = urlopen
        try:
            self.assertIsNone(host.head("refs/heads/events"))
        finally:
            G.urllib.request.urlopen = original

    def test_head_still_returns_none_for_a_missing_ref(self):
        import io as _io
        import urllib.error
        from dracla import github as G
        from dracla.github import GitHubHost

        host = GitHubHost(repo="o/r", token="t")
        body = '{"message":"Not Found"}'

        def urlopen(req, timeout=None):
            raise urllib.error.HTTPError(
                "u", 404, body, {}, _io.BytesIO(body.encode()))

        original = G.urllib.request.urlopen
        G.urllib.request.urlopen = urlopen
        try:
            self.assertIsNone(host.head("refs/heads/events"))
        finally:
            G.urllib.request.urlopen = original
