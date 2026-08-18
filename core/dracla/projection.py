"""Coverage projection and the in-flight marker (design §5.3, §5.4).

The marker is the mechanism that lets the merge-group check honestly be called
authoritative, so its ordering is load-bearing:

  DR-003  the marker OPENS BEFORE the canonical commit and CLOSES after
          materialization. A marker written after the commit cannot signal a
          failure that happened before it existed, which failed *open* for
          revocation.

  DR-002  it is a set keyed by operation, not a scalar pointer. A pointer pair
          cannot represent two concurrent operations, so one signer's failure
          could be "repaired" by another's success.

  DR-004  entries name their subjects, so staleness is scoped per subject
          rather than per project. A project-global signal turned one bad
          submission into a denial of service on the whole landing gate.

  DR-005  shard writes take a blob-sha precondition. Shards are packed, so an
          unguarded read-modify-write silently drops a concurrent row — and a
          dropped revocation keeps a contributor passing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .githost import BlobConflict, FakeGitHost, NotFound

COVERAGE_REF = "refs/heads/coverage"
SHARD_COUNT = 256

INFLIGHT = "inflight.json"
SOURCE = "source.json"

COVERED = "covered"
UNCOVERED = "uncovered"


class ShardRetriesExhausted(Exception):
    pass


def shard_path(user_id: int) -> str:
    return f"users/{user_id % SHARD_COUNT:02x}.json"


def _read_json(host: FakeGitHost, path: str, default):
    try:
        content, blob = host.read(COVERAGE_REF, path)
        return json.loads(content), blob
    except NotFound:
        return default, None


# --- in-flight marker -----------------------------------------------------

def open_marker(host: FakeGitHost, idem_key: str, subjects: list[int],
                *, started_at: str = "t") -> None:
    """Record an operation as in flight. MUST happen before the canonical commit."""
    for _ in range(10):
        doc, blob = _read_json(host, INFLIGHT, ({"ops": {}}, None))
        if blob is None and doc == ({"ops": {}}, None):
            doc = {"ops": {}}
        doc.setdefault("ops", {})[idem_key] = {
            "subjects": subjects, "started_at": started_at,
        }
        try:
            host.put(COVERAGE_REF, INFLIGHT, json.dumps(doc, sort_keys=True),
                     base_blob_sha=blob)
            return
        except BlobConflict:
            continue
    raise ShardRetriesExhausted(INFLIGHT)


def close_marker(host: FakeGitHost, idem_key: str) -> None:
    """Clear an operation. Only the writer that opened it may do this (§5.4)."""
    for _ in range(10):
        doc, blob = _read_json(host, INFLIGHT, ({"ops": {}}, None))
        if isinstance(doc, tuple):
            doc = {"ops": {}}
        doc.setdefault("ops", {}).pop(idem_key, None)
        try:
            host.put(COVERAGE_REF, INFLIGHT, json.dumps(doc, sort_keys=True),
                     base_blob_sha=blob)
            return
        except BlobConflict:
            continue
    raise ShardRetriesExhausted(INFLIGHT)


def inflight_subjects(host: FakeGitHost) -> set[int]:
    doc, _ = _read_json(host, INFLIGHT, ({"ops": {}}, None))
    if isinstance(doc, tuple):
        return set()
    out: set[int] = set()
    for op in doc.get("ops", {}).values():
        out.update(op.get("subjects", []))
    return out


# --- coverage shards ------------------------------------------------------

@dataclass
class Row:
    decision: str
    version: str
    digest: str
    scope: dict
    since: str
    reason: str = ""


def write_row(host: FakeGitHost, user_id: int, agreement_id: str, row: Row,
              *, max_attempts: int = 10) -> None:
    """Update one (user, agreement) row under a blob-sha precondition (DR-005).

    On conflict we re-read and re-apply only our own key, so a concurrent
    writer's row in the same shard is preserved rather than clobbered.
    """
    path = shard_path(user_id)
    for _ in range(max_attempts):
        doc, blob = _read_json(host, path, ({}, None))
        if isinstance(doc, tuple):
            doc = {}
        doc.setdefault(str(user_id), {})[agreement_id] = {
            "decision": row.decision, "version": row.version,
            "digest": row.digest, "scope": row.scope,
            "since": row.since, "reason": row.reason,
        }
        try:
            host.put(COVERAGE_REF, path, json.dumps(doc, sort_keys=True),
                     base_blob_sha=blob)
            return
        except BlobConflict:
            continue
    raise ShardRetriesExhausted(path)


def read_row(host: FakeGitHost, user_id: int, agreement_id: str) -> dict | None:
    doc, _ = _read_json(host, shard_path(user_id), ({}, None))
    if isinstance(doc, tuple):
        return None
    return doc.get(str(user_id), {}).get(agreement_id)


def set_source(host: FakeGitHost, canonical_sha: str | None) -> None:
    for _ in range(10):
        _, blob = _read_json(host, SOURCE, (None, None))
        try:
            host.put(COVERAGE_REF, SOURCE,
                     json.dumps({"canonical_sha": canonical_sha}, sort_keys=True),
                     base_blob_sha=blob)
            return
        except BlobConflict:
            continue
    raise ShardRetriesExhausted(SOURCE)


# --- the check-side read --------------------------------------------------

def evaluate(host: FakeGitHost, subjects: list[int], agreement_id: str,
             repository: str) -> tuple[str, str]:
    """Return (conclusion, reason) for a set of subjects.

    Mirrors §6.3: in-flight subjects are indeterminate; coverage is compared
    against the scope recorded with the acceptance (DR-007), never against
    current project scope.
    """
    pending = inflight_subjects(host)
    for uid in subjects:
        if uid in pending:
            return "in_progress", f"subject {uid} has an operation in flight"
        row = read_row(host, uid, agreement_id)
        if row is None or row["decision"] != COVERED:
            return "action_required", f"subject {uid} is not covered"
        if not _in_scope(repository, row["scope"]):
            return "action_required", (
                f"subject {uid} accepted for a scope excluding {repository}"
            )
    return "success", "all subjects covered"


def _in_scope(repository: str, scope: dict) -> bool:
    org = repository.split("/", 1)[0]
    if repository in scope.get("repos", []):
        return True
    return org in scope.get("orgs", [])
