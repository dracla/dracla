"""GitHubHost — the GitHost protocol against the live GitHub API.

Stdlib only (urllib), matching the rest of core.

The mapping from protocol to API is where the correctness lives:

  update_ref(force=False)  -> PATCH git/refs, force=false. A *fast-forward
                              check*, not a compare-and-swap on the ref. This
                              was verified against the live API: a descendant
                              commit whose tree DROPS a file is accepted, which
                              is why append.py rebuilds on the reloaded head's
                              base tree (DR-006).

  put(base_blob_sha=...)   -> PUT contents with `sha`. That IS a
                              compare-and-swap: a stale blob sha returns 409.
                              This is the shard precondition of section 5.3.
"""

from __future__ import annotations

import base64
import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .githost import BlobConflict, Commit, NotFastForward, NotFound

API = "https://api.github.com"

# A stateless Worker or a CI job must not hang on a wedged socket, and a
# transient network fault must not surface as a failed signature. Both were
# missing until an integration run lost two tests to connection timeouts.
TIMEOUT_SECONDS = 20
TRANSIENT_STATUS = {500, 502, 503, 504}
MAX_ATTEMPTS = 4


class GitHubError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"{status}: {body[:300]}")
        self.status = status
        self.body = body


@dataclass
class GitHubHost:
    """One repository, addressed by `owner/name`."""

    repo: str
    token: str
    _ua: str = "dracla-core/0.0.1"
    timeout: float = TIMEOUT_SECONDS
    max_attempts: int = MAX_ATTEMPTS
    sleep = staticmethod(time.sleep)      # injectable so tests need not wait

    # --- transport --------------------------------------------------------

    def request(self, method: str, path: str,
                body: dict | None = None) -> dict | list:
        """Public transport: authenticated, retried, timed out.

        The records protocol is not the only caller. Repository and organization
        administration needs the same auth, retry, and timeout policy and none
        of the GitHost protocol, and it previously reached into `_req` to borrow
        them — a real dependency left undeclared. This is that dependency, named.
        """
        return self._req(method, path, body)

    def _req(self, method: str, path: str, body: dict | None = None) -> dict | list:
        """One API call, with a socket timeout and retries on transient faults.

        Retrying is safe here only because the protocol above is idempotent:
        section 5.2 probes for the event path before writing, and put() carries a
        blob-sha precondition, so a duplicated request cannot double-apply. The
        outcomes that must NOT be retried — 404, 409, 422 non-fast-forward — are
        protocol signals and are raised immediately.
        """
        url = path if path.startswith("http") else f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None

        for attempt in range(1, self.max_attempts + 1):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            req.add_header("User-Agent", self._ua)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", "replace")
                if e.code == 404:
                    raise NotFound(f"{method} {path}") from None
                if e.code == 409:
                    raise BlobConflict(raw) from None
                if e.code == 422 and "fast forward" in raw.lower():
                    raise NotFastForward(raw) from None
                if e.code in TRANSIENT_STATUS or self._is_rate_limited(e):
                    last = GitHubError(e.code, raw)
                    self._backoff(attempt, e)
                    continue
                raise GitHubError(e.code, raw) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                # Connection reset, DNS blip, socket timeout. Transient by
                # nature; two integration tests were lost to exactly this.
                last = e
                self._backoff(attempt, None)
                continue

        raise GitHubError(0, f"{method} {path} failed after "
                             f"{self.max_attempts} attempts: {last}")

    @staticmethod
    def _is_rate_limited(e: urllib.error.HTTPError) -> bool:
        if e.code not in (403, 429):
            return False
        return (e.headers.get("X-RateLimit-Remaining") == "0"
                or e.headers.get("Retry-After") is not None)

    def _backoff(self, attempt: int, e: urllib.error.HTTPError | None) -> None:
        """Honour Retry-After when GitHub sends it; otherwise exponential."""
        delay = None
        if e is not None:
            retry_after = e.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = float(retry_after)
        if delay is None:
            delay = min(2 ** (attempt - 1), 8) * (0.5 + random.random())
        self.sleep(delay)

    def _branch(self, ref: str) -> str:
        return ref.removeprefix("refs/heads/")

    # --- GitHost ----------------------------------------------------------

    def head(self, ref: str) -> str | None:
        """The ref's sha, or None if it does not exist.

        An **empty repository** answers 409 "Git Repository is empty" rather
        than 404, and `_req` maps 409 to BlobConflict. Reading a ref has no
        other meaning for a conflict, so both are "no such ref" here.

        This matters because repositories are deliberately created empty (design
        §6.10.3.1) so that the first branch created is the one that should be
        default. Before that, nothing ever asked an empty repository for a ref.
        """
        try:
            r = self._req("GET", f"/repos/{self.repo}/git/ref/heads/{self._branch(ref)}")
            return r["object"]["sha"]                     # type: ignore[index]
        except (NotFound, BlobConflict):
            return None

    def read(self, ref_or_sha: str, path: str) -> tuple[str, str]:
        """Return (content, blob_sha). blob_sha is the CAS token for put()."""
        r = self._req(
            "GET", f"/repos/{self.repo}/contents/{path}?ref={ref_or_sha}")
        if isinstance(r, list):
            raise NotFound(f"{path} is a directory")
        content = base64.b64decode(r["content"]).decode("utf-8")
        return content, r["sha"]

    def exists(self, ref_or_sha: str, path: str) -> bool:
        try:
            self.read(ref_or_sha, path)
            return True
        except NotFound:
            return False

    def base_tree(self, sha: str | None) -> dict[str, str]:
        """Not used on the write path; append.py passes base_tree via the API."""
        if sha is None:
            return {}
        r = self._req("GET",
                      f"/repos/{self.repo}/git/trees/{sha}?recursive=1")
        return {e["path"]: e["sha"] for e in r["tree"]      # type: ignore[index]
                if e["type"] == "blob"}

    def commit(self, *, parent: str | None, changes: dict[str, str],
               message: str) -> str:
        """Create a commit whose tree is the parent's tree plus `changes`.

        `base_tree` is taken from `parent`, so this always builds on the tree of
        the commit passed in. append.py's retry passes the *reloaded* head, and
        that is what makes the DR-006 defect unreachable through this path.
        """
        tree_entries = []
        for path, content in changes.items():
            blob = self._req("POST", f"/repos/{self.repo}/git/blobs",
                             {"content": content, "encoding": "utf-8"})
            tree_entries.append({"path": path, "mode": "100644",
                                 "type": "blob", "sha": blob["sha"]})  # type: ignore[index]

        tree_body: dict = {"tree": tree_entries}
        if parent is not None:
            pc = self._req("GET", f"/repos/{self.repo}/git/commits/{parent}")
            tree_body["base_tree"] = pc["tree"]["sha"]      # type: ignore[index]
        tree = self._req("POST", f"/repos/{self.repo}/git/trees", tree_body)

        commit_body: dict = {"message": message, "tree": tree["sha"]}  # type: ignore[index]
        commit_body["parents"] = [parent] if parent else []
        c = self._req("POST", f"/repos/{self.repo}/git/commits", commit_body)
        return c["sha"]                                    # type: ignore[index]

    def commit_with_tree(self, *, parent: str | None, tree: dict[str, str],
                         message: str) -> str:
        """Explicit tree, ignoring the parent's. Only for reproducing DR-006."""
        entries = []
        for path, content in tree.items():
            blob = self._req("POST", f"/repos/{self.repo}/git/blobs",
                             {"content": content, "encoding": "utf-8"})
            entries.append({"path": path, "mode": "100644",
                            "type": "blob", "sha": blob["sha"]})       # type: ignore[index]
        t = self._req("POST", f"/repos/{self.repo}/git/trees", {"tree": entries})
        c = self._req("POST", f"/repos/{self.repo}/git/commits",
                      {"message": message, "tree": t["sha"],           # type: ignore[index]
                       "parents": [parent] if parent else []})
        return c["sha"]                                    # type: ignore[index]

    def update_ref(self, ref: str, sha: str, *, force: bool = False) -> None:
        branch = self._branch(ref)
        if self.head(ref) is None:
            self._req("POST", f"/repos/{self.repo}/git/refs",
                      {"ref": f"refs/heads/{branch}", "sha": sha})
            return
        self._req("PATCH", f"/repos/{self.repo}/git/refs/heads/{branch}",
                  {"sha": sha, "force": force})

    def put(self, ref: str, path: str, content: str,
            *, base_blob_sha: str | None) -> None:
        """Write under a blob-sha precondition. Stale sha -> 409 -> BlobConflict."""
        body: dict = {
            "message": f"put {path}",
            "content": base64.b64encode(content.encode()).decode(),
            "branch": self._branch(ref),
        }
        if base_blob_sha is not None:
            body["sha"] = base_blob_sha
        try:
            self._req("PUT", f"/repos/{self.repo}/contents/{path}", body)
        except GitHubError as e:
            # Creating a file that already exists is also a conflict; GitHub
            # reports it as 422 rather than 409.
            if e.status == 422 and "sha" in e.body.lower():
                raise BlobConflict(e.body) from None
            raise

    def history(self, ref: str) -> list[Commit]:
        """Oldest-first. Only the fields the protocol needs."""
        out: list[Commit] = []
        sha = self.head(ref)
        while sha is not None:
            c = self._req("GET", f"/repos/{self.repo}/git/commits/{sha}")
            parents = c["parents"]                          # type: ignore[index]
            out.append(Commit(sha=sha, parent=parents[0]["sha"] if parents else None,
                              tree={}, message=c["message"]))  # type: ignore[index]
            sha = parents[0]["sha"] if parents else None
        return list(reversed(out))

    def delete_ref(self, ref: str) -> None:
        try:
            self._req("DELETE",
                      f"/repos/{self.repo}/git/refs/heads/{self._branch(ref)}")
        except NotFound:
            pass


def from_env() -> GitHubHost | None:
    """Build a host from DRACLA_ITEST_REPO and a token, or None if unset."""
    repo = os.environ.get("DRACLA_ITEST_REPO")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not repo or not token:
        return None
    return GitHubHost(repo=repo, token=token)
