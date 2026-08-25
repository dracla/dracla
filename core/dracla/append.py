"""Legacy plaintext append-only protocol experiment.

Revision 13 keeps the non-forced fast-forward/reload/rebuild property tested
here, but replaces this event identity and retry shape with authenticated
encrypted events, operation fingerprints, event-coupled side artifacts, and a
durable prepared-operation state machine. Do not use this module to write
project data.

One logical event per commit, single parent, fast-forward only, no merges.
Commit ancestry is the authoritative order; timestamps never resolve it.

Two rules here exist because the review found their absence loses events:

  DR-006  step 2 rebuilds the tree on the *reloaded* head's base tree. Reusing
          a previously built tree and re-parenting produces a commit GitHub
          accepts as a clean fast-forward while the concurrent event vanishes.

  DR-054  step 5 re-validates the operation against the reloaded head before
          retrying. A revocation that lost the race to a re-sign is no longer
          the same operation, and blindly re-parenting it appends an event
          whose meaning depends on replay rules nobody wrote down.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from .events import Event
from .githost import FakeGitHost, NotFastForward

EVENTS_REF = "refs/heads/events"


class RetriesExhausted(Exception):
    """Bounded retries used up. The commit may or may not have landed.

    §5.4: the caller reports the submission unresolved rather than failed, the
    in-flight marker stays open, and the reconciler settles it.
    """


class OperationSuperseded(Exception):
    """Re-validation against the reloaded head says this no longer applies."""


@dataclass
class AppendResult:
    sha: str
    attempts: int
    idempotent: bool     # already present at the reloaded head; nothing written


def append_event(
    host: FakeGitHost,
    event: Event,
    *,
    ref: str = EVENTS_REF,
    max_attempts: int = 5,
    revalidate: Callable[[Event, str | None], None] | None = None,
    jitter: Callable[[int], None] | None = None,
) -> AppendResult:
    """Append one event. Returns idempotently if it is already present."""
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        head = host.head(ref)

        # Historical simplification: path existence represents an idempotent
        # retry in this spike. Revision 13 must authenticate/decrypt the event
        # and compare its operation fingerprint before returning conflict or
        # idempotent success; path existence alone is insufficient.
        if head is not None and host.exists(head, event.path):
            return AppendResult(sha=head, attempts=attempts, idempotent=True)

        # DR-006: build on the base tree of the head we just read.
        sha = host.commit(
            parent=head,
            changes={event.path: event.to_json()},
            message=f"{event.type}: {event.event_id[:12]}",
        )
        try:
            host.update_ref(ref, sha, force=False)
            return AppendResult(sha=sha, attempts=attempts, idempotent=False)
        except NotFastForward:
            # Someone landed first. Reload, re-check idempotency, re-validate,
            # then rebuild on the new head.
            new_head = host.head(ref)
            if new_head is not None and host.exists(new_head, event.path):
                return AppendResult(sha=new_head, attempts=attempts, idempotent=True)
            if revalidate is not None:
                revalidate(event, new_head)   # may raise OperationSuperseded
            if jitter is not None:
                jitter(attempts)
            continue

    raise RetriesExhausted(
        f"{event.type} {event.event_id[:12]} after {attempts} attempts"
    )


def default_jitter(attempt: int) -> None:
    # Present for shape; the tests inject a deterministic no-op.
    random.random()


def read_chain_head(host: FakeGitHost, ref: str, subject_user_id: int) -> str:
    """Current head of one subject's event chain, for idempotency-key derivation.

    Returns events.GENESIS when the subject has no events yet.
    """
    from .events import GENESIS
    import json

    last = GENESIS
    for commit in host.history(ref):
        for path, content in sorted(commit.tree.items()):
            if not path.startswith("events/"):
                continue
            doc = json.loads(content)
            ids = [s["github_user_id"] for s in doc.get("subjects", [])]
            if subject_user_id in ids:
                last = doc["event_id"]
    return last
