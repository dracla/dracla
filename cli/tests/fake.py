"""Fakes for the two seams install talks through: administration and records.

D4: the records host is core's own `FakeGitHost`, not a second implementation.
An earlier version defined a looser one here, which would have drifted from the
protocol it is standing in for — and the whole point of core's fake is that its
fidelity was verified against the live API.

Only administration needs a fake of its own, because core has no such surface.
"""

from __future__ import annotations

from dracla.githost import FakeGitHost

from dracla_cli.admin import CreateRepoResult, GitHubAdmin, Repo


class FakeAdmin:
    """Stands in for dracla_cli.admin.GitHubAdmin."""

    # Mirrors the real surface: callers distinguish "could not read the
    # setting" from a real permission value, and the fake must too.
    UNKNOWN_PERMISSION = GitHubAdmin.UNKNOWN_PERMISSION

    def __init__(self, *, owner_type="Organization", base_permission="none",
                 existing=None, private_on_create=True):
        self.owner_type = owner_type
        self._base = base_permission
        self.repos: dict[str, Repo] = dict(existing or {})
        self.private_on_create = private_on_create
        self.writes: list[tuple[str, str]] = []
        self.hosts: dict[str, FakeGitHost] = {}
        # Override branch counts per repo where a test needs a shape the
        # fake host cannot express (a stranger's repo with only `main`).
        self.branch_counts: dict[str, int | None] = {}

    def owner_kind(self, owner: str) -> str:
        return self.owner_type

    def viewer(self) -> str:
        return "test-user"

    def can_create_in(self, owner: str) -> tuple[bool, str]:
        """Mirrors GitHubAdmin.can_create_in rather than always allowing.

        Hardcoding True let two tests assert that personal accounts are exempt
        from the organization gate while the real class was refusing them — the
        fake was the only thing the property held for.
        """
        if self.owner_type != "Organization":
            if owner.lower() != self.viewer().lower():
                return False, (
                    f"'{owner}' is a personal account belonging to someone else")
            return True, ""
        return True, ""

    def base_permission(self, owner: str):
        return None if self.owner_type != "Organization" else self._base

    def host_for(self, repo: str) -> FakeGitHost:
        return self.hosts.setdefault(repo, FakeGitHost())

    def get_repo(self, full_name: str):
        repo = self.repos.get(full_name)
        if repo is None or repo.default_branch is not None:
            return repo
        host = self.hosts.get(full_name)
        if host is None:
            return repo
        # GitHub makes the first branch in an empty repository the default; it
        # does not require a PATCH. Model that platform behavior so the fake
        # cannot make the implementation or dry-run claim a write that is not
        # present on the real path.
        for ref in ("refs/heads/events", "refs/heads/coverage"):
            if host.head(ref) is not None:
                branch = ref.rsplit("/", 1)[-1]
                repo = Repo(repo.full_name, repo.private, branch, repo.empty)
                self.repos[full_name] = repo
                break
        return repo

    def branch_count(self, full_name: str) -> int | None:
        """Mirrors GitHubAdmin.branch_count: refs, never `size`.

        Defaults to whatever the fake host holds, so a repository seeded into
        `repos` without content reads as empty — which is the half-created case
        install must still finish.
        """
        if full_name in self.branch_counts:
            return self.branch_counts[full_name]
        host = self.hosts.get(full_name)
        return 0 if host is None else len(getattr(host, "_refs", {}) or {})

    def create_repo(self, owner: str, name: str,
                    description: str) -> CreateRepoResult:
        full = f"{owner}/{name}"
        self.writes.append(("create_repo", full))
        repo = Repo(full_name=full, private=self.private_on_create,
                    default_branch=None, empty=True)
        self.repos[full] = repo
        return CreateRepoResult(repo, created=True)

    def set_default_branch(self, full_name: str, branch: str) -> None:
        self.writes.append(("set_default_branch", f"{full_name}:{branch}"))
        cur = self.repos[full_name]
        self.repos[full_name] = Repo(cur.full_name, cur.private, branch, cur.empty)
