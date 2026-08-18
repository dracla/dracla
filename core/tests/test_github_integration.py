"""Conformance tests: the same protocol behaviours, against the live GitHub API.

The fake in githost.py encodes a model of GitHub. These tests check the model is
right, which is the one thing the unit suite structurally cannot do — if the
model is wrong, every unit test passes and production still loses events.

Opt-in. Set both, then run:

    export DRACLA_ITEST_REPO=owner/name
    export GITHUB_TOKEN=$(gh auth token)
    python3 -m unittest core.tests.test_github_integration -v

Each test creates its own throwaway ref under `dracla-itest/` and deletes it in
teardown. No existing branch is touched.
"""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla import events as E                                    # noqa: E402
from dracla.append import EVENTS_REF, append_event                # noqa: E402
from dracla.github import from_env                                # noqa: E402
from dracla.githost import BlobConflict, NotFastForward, NotFound  # noqa: E402

HOST = from_env()
SKIP = HOST is None
REASON = "set DRACLA_ITEST_REPO and GITHUB_TOKEN to run integration tests"

AGREEMENT = {"id": "icla", "version": "v1", "digest": "sha256:d"}
SCOPE = {"orgs": ["acme"], "repos": []}


def make_event(uid: int, nonce: str = "n") -> E.Event:
    key = E.idempotency_key(
        project="itest", subject_user_id=uid, event_type=E.ACCEPTANCE,
        agreement_id="icla", agreement_version="v1", agreement_digest="sha256:d",
        prior_event_id=E.GENESIS, submission_nonce=nonce)
    return E.Event(
        event_id=E.event_id(key), idempotency_key=key, type=E.ACCEPTANCE,
        recorded_at="2026-08-18T00:00:00Z", dracla_version="0.0.1",
        agreement=dict(AGREEMENT), scope=dict(SCOPE),
        subjects=[E.Subject(uid, f"user{uid}")])


@unittest.skipIf(SKIP, REASON)
class LiveGitHubTest(unittest.TestCase):
    """Base: each test gets a private ref, seeded from the repo's default branch."""

    def setUp(self):
        self.host = HOST
        stamp = f"{int(time.time() * 1000)}-{os.getpid()}-{self._testMethodName[:24]}"
        self.ref = f"refs/heads/dracla-itest/{stamp}"
        self.addCleanup(self.host.delete_ref, self.ref)

    def seed(self) -> str:
        """Create the ref with one commit, and return its sha."""
        sha = self.host.commit(parent=None, changes={"seed.txt": "seed"},
                               message="itest seed")
        self.host.update_ref(self.ref, sha)
        return sha


class TestRefSemantics(LiveGitHubTest):
    """The two semantics the whole append protocol rests on."""

    def test_non_fast_forward_is_rejected(self):
        base = self.seed()
        a = self.host.commit(parent=base, changes={"a.txt": "a"}, message="A")
        b = self.host.commit(parent=base, changes={"b.txt": "b"}, message="B")
        self.host.update_ref(self.ref, a)
        with self.assertRaises(NotFastForward):
            self.host.update_ref(self.ref, b, force=False)
        self.assertEqual(self.host.head(self.ref), a, "ref must not have moved")

    def test_descendant_dropping_a_file_is_accepted(self):
        """DR-006's premise, confirmed against the live API.

        Nothing rejects this and nothing warns. History stays linear with a
        single parent, and the dropped file is simply gone from HEAD — which is
        precisely why append.py must rebuild on the reloaded head's base tree.
        """
        base = self.seed()
        a = self.host.commit(parent=base, changes={"a.txt": "a"}, message="A")
        self.host.update_ref(self.ref, a)
        self.assertTrue(self.host.exists(self.ref, "a.txt"))

        stale = self.host.commit_with_tree(
            parent=a, tree={"b.txt": "b"}, message="stale tree onto A")
        self.host.update_ref(self.ref, stale, force=False)      # accepted

        self.assertEqual(self.host.head(self.ref), stale)
        self.assertFalse(self.host.exists(self.ref, "a.txt"),
                         "the defect: a.txt vanished behind a clean fast-forward")

    def test_commit_builds_on_the_parents_tree(self):
        """The fix side: commit() takes base_tree from the parent it is given."""
        base = self.seed()
        a = self.host.commit(parent=base, changes={"a.txt": "a"}, message="A")
        self.host.update_ref(self.ref, a)
        b = self.host.commit(parent=a, changes={"b.txt": "b"}, message="B")
        self.host.update_ref(self.ref, b, force=False)
        self.assertTrue(self.host.exists(self.ref, "a.txt"))
        self.assertTrue(self.host.exists(self.ref, "b.txt"))

    def test_history_is_linear_with_single_parents(self):
        base = self.seed()
        prev = base
        for i in range(3):
            prev = self.host.commit(parent=prev, changes={f"f{i}.txt": str(i)},
                                    message=f"c{i}")
            self.host.update_ref(self.ref, prev, force=False)
        hist = self.host.history(self.ref)
        self.assertEqual(len(hist), 4)
        for prev_c, cur in zip(hist, hist[1:]):
            self.assertEqual(cur.parent, prev_c.sha)


class TestContentCas(LiveGitHubTest):
    """put() must be a genuine compare-and-swap (the section 5.3 shard rule)."""

    def test_stale_blob_sha_is_rejected(self):
        self.seed()
        self.host.put(self.ref, "shard.json", json.dumps({"v": 1}),
                      base_blob_sha=None)
        _, first = self.host.read(self.ref, "shard.json")

        self.host.put(self.ref, "shard.json", json.dumps({"v": 2}),
                      base_blob_sha=first)

        with self.assertRaises(BlobConflict):
            self.host.put(self.ref, "shard.json", json.dumps({"v": 3}),
                          base_blob_sha=first)          # stale
        doc, _ = self.host.read(self.ref, "shard.json")
        self.assertEqual(json.loads(doc)["v"], 2, "the stale write must not land")

    def test_create_over_existing_is_a_conflict(self):
        self.seed()
        self.host.put(self.ref, "shard.json", "{}", base_blob_sha=None)
        with self.assertRaises(BlobConflict):
            self.host.put(self.ref, "shard.json", "{}", base_blob_sha=None)


class TestAppendProtocol(LiveGitHubTest):
    """append_event end to end, against real refs."""

    def test_append_and_idempotent_replay(self):
        self.seed()
        ev = make_event(1, "a")
        first = append_event(self.host, ev, ref=self.ref)
        self.assertFalse(first.idempotent)
        self.assertTrue(self.host.exists(self.ref, ev.path))

        second = append_event(self.host, ev, ref=self.ref)
        self.assertTrue(second.idempotent, "replay must not append a second time")
        self.assertEqual(self.host.head(self.ref), first.sha)

    def test_two_events_both_survive(self):
        self.seed()
        a, b = make_event(1, "a"), make_event(2, "b")
        append_event(self.host, a, ref=self.ref)
        append_event(self.host, b, ref=self.ref)
        head = self.host.head(self.ref)
        self.assertTrue(self.host.exists(head, a.path))
        self.assertTrue(self.host.exists(head, b.path))

    def test_losing_the_race_retries_and_keeps_both(self):
        """Force a real 422 mid-append and confirm the retry path recovers."""
        self.seed()
        a, b = make_event(1, "a"), make_event(2, "b")
        original = self.host.head
        fired = {"n": 0}

        def head_then_interfere(ref):
            h = original(ref)
            if fired["n"] == 0:
                fired["n"] = 1
                append_event(self.host, b, ref=self.ref)   # B lands first
                return h                                   # A sees the old head
            return original(ref)

        self.host.head = head_then_interfere               # type: ignore[method-assign]
        try:
            result = append_event(self.host, a, ref=self.ref)
        finally:
            self.host.head = original                      # type: ignore[method-assign]

        self.assertGreater(result.attempts, 1, "the 422 must actually have happened")
        head = self.host.head(self.ref)
        self.assertTrue(self.host.exists(head, a.path))
        self.assertTrue(self.host.exists(head, b.path), "DR-006 regression on live API")


if __name__ == "__main__":
    unittest.main()
