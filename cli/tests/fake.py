"""Fakes for the two seams install talks through: administration and records.

D4: the records host is core's own `FakeGitHost`, not a second implementation.
An earlier version defined a looser one here, which would have drifted from the
protocol it is standing in for — and the whole point of core's fake is that its
fidelity was verified against the live API.

Only administration needs a fake of its own, because core has no such surface.
"""

from __future__ import annotations

from dracla.githost import FakeGitHost

from dracla_cli.admin import GitHubAdmin, Repo


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
        return self.repos.get(full_name)

    def create_repo(self, owner: str, name: str, description: str) -> Repo:
        full = f"{owner}/{name}"
        self.writes.append(("create_repo", full))
        repo = Repo(full_name=full, private=self.private_on_create,
                    default_branch=None, empty=True)
        self.repos[full] = repo
        return repo

    def set_default_branch(self, full_name: str, branch: str) -> None:
        self.writes.append(("set_default_branch", f"{full_name}:{branch}"))
        cur = self.repos[full_name]
        self.repos[full_name] = Repo(cur.full_name, cur.private, branch, cur.empty)
