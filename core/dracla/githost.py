"""Git host abstraction plus a deterministic in-memory fake.

The fake models exactly one semantic precisely, because the whole protocol
turns on it: `update_ref(force=False)` succeeds only when the new commit
descends from the current ref value. DR-006 turned on the difference between
that and a compare-and-swap on the ref, so the fake must not conflate them.

Everything else here is deliberately shallow. This is a spike; the point is to
provoke concurrent interleavings that real GitHub cannot be made to produce on
demand.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Protocol


class NotFastForward(Exception):
    """Ref update rejected: the new commit does not descend from the current ref.

    Real GitHub answers 422 here.
    """


class BlobConflict(Exception):
    """Content update rejected: the supplied base blob sha is stale.

    Real GitHub answers 409. This is the shard compare-and-swap of §5.3.
    """


class NotFound(Exception):
    pass


@dataclass
class Commit:
    sha: str
    parent: str | None
    tree: dict[str, str]        # path -> content
    message: str


class GitHost(Protocol):
    def head(self, ref: str) -> str | None: ...
    def read(self, ref: str, path: str) -> tuple[str, str]: ...
    def exists(self, ref: str, path: str) -> bool: ...
    def commit(self, *, parent: str | None, changes: dict[str, str],
               message: str) -> str: ...
    def update_ref(self, ref: str, sha: str, *, force: bool = False) -> None: ...


class FakeGitHost:
    """In-memory git host with real fast-forward semantics."""

    def __init__(self) -> None:
        self._commits: dict[str, Commit] = {}
        self._refs: dict[str, str] = {}
        self._lock = threading.Lock()
        self.ref_update_attempts = 0
        self.ref_update_rejections = 0

    # --- plumbing ---------------------------------------------------------

    def _sha(self, parent: str | None, tree: dict[str, str], message: str) -> str:
        d = hashlib.sha1()
        d.update((parent or "").encode())
        for k in sorted(tree):
            d.update(k.encode()); d.update(b"\0"); d.update(tree[k].encode())
        d.update(message.encode())
        return d.hexdigest()

    def _tree_of(self, sha: str | None) -> dict[str, str]:
        if sha is None:
            return {}
        return dict(self._commits[sha].tree)

    def _descends_from(self, sha: str, ancestor: str | None) -> bool:
        if ancestor is None:
            return True
        cur: str | None = sha
        while cur is not None:
            if cur == ancestor:
                return True
            cur = self._commits[cur].parent
        return False

    # --- GitHost ----------------------------------------------------------

    def head(self, ref: str) -> str | None:
        with self._lock:
            return self._refs.get(ref)

    def base_tree(self, sha: str | None) -> dict[str, str]:
        with self._lock:
            return self._tree_of(sha)

    def read(self, ref_or_sha: str, path: str) -> tuple[str, str]:
        """Return (content, blob_sha). blob_sha is the CAS precondition token."""
        with self._lock:
            sha = self._refs.get(ref_or_sha, ref_or_sha)
            if sha not in self._commits:
                raise NotFound(ref_or_sha)
            tree = self._commits[sha].tree
            if path not in tree:
                raise NotFound(path)
            content = tree[path]
            return content, hashlib.sha1(content.encode()).hexdigest()

    def exists(self, ref_or_sha: str, path: str) -> bool:
        try:
            self.read(ref_or_sha, path)
            return True
        except NotFound:
            return False

    def commit(self, *, parent: str | None, changes: dict[str, str],
               message: str) -> str:
        """Create a commit whose tree is the parent's tree plus `changes`.

        Callers must pass the parent they intend; §5.2 requires the tree be
        rebuilt on the *reloaded* head's base tree, and a caller that reuses an
        older tree here will drop the concurrent event — which is exactly the
        DR-006 failure the tests reproduce.
        """
        with self._lock:
            tree = self._tree_of(parent)
            tree.update(changes)
            sha = self._sha(parent, tree, message)
            self._commits[sha] = Commit(sha, parent, tree, message)
            return sha

    def commit_with_tree(self, *, parent: str | None, tree: dict[str, str],
                         message: str) -> str:
        """Create a commit with an explicit tree, ignoring the parent's tree.

        Only used to reproduce the DR-006 defect deliberately.
        """
        with self._lock:
            sha = self._sha(parent, tree, message)
            self._commits[sha] = Commit(sha, parent, dict(tree), message)
            return sha

    def update_ref(self, ref: str, sha: str, *, force: bool = False) -> None:
        with self._lock:
            self.ref_update_attempts += 1
            current = self._refs.get(ref)
            if not force and not self._descends_from(sha, current):
                self.ref_update_rejections += 1
                raise NotFastForward(f"{sha[:8]} does not descend from {current}")
            self._refs[ref] = sha

    # --- flat file store (the coverage repo) ------------------------------

    def put(self, ref: str, path: str, content: str,
            *, base_blob_sha: str | None) -> None:
        """Write a file under a blob-sha precondition (§5.3 shard CAS).

        base_blob_sha None means "must not exist".
        """
        with self._lock:
            sha = self._refs.get(ref)
            tree = self._tree_of(sha)
            existing = tree.get(path)
            current_blob = (
                hashlib.sha1(existing.encode()).hexdigest()
                if existing is not None else None
            )
            if current_blob != base_blob_sha:
                raise BlobConflict(
                    f"{path}: expected {base_blob_sha}, found {current_blob}"
                )
            tree[path] = content
            new = self._sha(sha, tree, f"put {path}")
            self._commits[new] = Commit(new, sha, tree, f"put {path}")
            self._refs[ref] = new

    def history(self, ref: str) -> list[Commit]:
        """Oldest-first commit list. Ancestry is the authoritative order."""
        with self._lock:
            out: list[Commit] = []
            cur = self._refs.get(ref)
            while cur is not None:
                c = self._commits[cur]
                out.append(c)
                cur = c.parent
            return list(reversed(out))
