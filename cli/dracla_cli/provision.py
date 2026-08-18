"""Create the repository pair for a project (design §9, D11).

Runs with the administrator's own credentials. DraCLA holds no provisioning
privilege at any point, so there is nothing to leave behind if this fails
partway — re-running is the recovery.

Every step is idempotent: an existing repo with the right shape is accepted
rather than treated as an error, because a half-finished install is the normal
failure and the user should be able to just run the command again.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "core"))

from dracla.github import GitHubError, GitHubHost      # noqa: E402
from dracla.githost import NotFound                    # noqa: E402

from .config import ProjectConfig                      # noqa: E402
from .errors import CliError                           # noqa: E402


@dataclass
class RepoPair:
    records: str
    coverage: str
    created: list[str]        # which ones this run actually created


class Provisioner:
    """Creates and inspects repositories with the administrator's token."""

    def __init__(self, token: str, owner: str, *, dry_run: bool = False):
        self.token = token
        self.owner = owner
        self.dry_run = dry_run
        # A host bound to no repo; used for org-level and per-repo calls.
        self._api = GitHubHost(repo="", token=token)

    # --- probes -----------------------------------------------------------

    def owner_kind(self) -> str:
        """'Organization' or 'User'. Repo creation differs between them."""
        try:
            doc = self._api._req("GET", f"/users/{self.owner}")
            return doc["type"]                          # type: ignore[index]
        except NotFound:
            raise CliError(f"no such GitHub account: {self.owner}") from None

    def base_permission(self) -> str | None:
        """The org's default member permission, or None for a user account.

        `REQ-SEC-2` exempts DraCLA from encrypting signer fields *on the basis
        that* the private records repository is a sufficient access boundary.
        That is conditional on an ACL nobody checks: many orgs default members
        to Read, which would make every member a records reader. So the install
        flow looks, and says so loudly (DR-033).
        """
        if self.owner_kind() != "Organization":
            return None
        try:
            doc = self._api._req("GET", f"/orgs/{self.owner}")
            return doc.get("default_repository_permission")   # type: ignore[union-attr]
        except (NotFound, GitHubError):
            # Needs org admin to read; absence is not fatal, but we must not
            # silently claim the boundary holds.
            return "unknown"

    def repo_exists(self, full_name: str) -> bool:
        try:
            self._api._req("GET", f"/repos/{full_name}")
            return True
        except NotFound:
            return False

    def repo_is_private(self, full_name: str) -> bool:
        doc = self._api._req("GET", f"/repos/{full_name}")
        return bool(doc["private"])                     # type: ignore[index]

    # --- actions ----------------------------------------------------------

    def create_repo(self, name: str, description: str) -> str:
        full = f"{self.owner}/{name}"
        if self.repo_exists(full):
            if not self.repo_is_private(full):
                raise CliError(
                    f"{full} already exists and is PUBLIC",
                    hint="records and coverage must both be private; rename or "
                         "delete it, or choose another slug")
            return full
        if self.dry_run:
            return full

        body = {
            "name": name,
            "description": description,
            "private": True,
            "has_issues": False,
            "has_wiki": False,
            "has_projects": False,
            "auto_init": True,
        }
        path = (f"/orgs/{self.owner}/repos"
                if self.owner_kind() == "Organization" else "/user/repos")
        try:
            self._api._req("POST", path, body)
        except GitHubError as e:
            raise CliError(
                f"could not create {full}: {e}",
                hint="you need permission to create repositories in "
                     f"{self.owner}") from None
        return full

    def provision(self, cfg: ProjectConfig) -> RepoPair:
        records = f"{cfg.slug}-cla-records"
        coverage = f"{cfg.slug}-cla-coverage"
        created: list[str] = []

        for name, desc in (
            (records, f"DraCLA canonical CLA records for {cfg.slug}. "
                      "Append-only. Contains signer data."),
            (coverage, f"DraCLA coverage projection for {cfg.slug}. "
                       "Derived, PII-free. Do not make public."),
        ):
            full = f"{self.owner}/{name}"
            existed = self.repo_exists(full)
            self.create_repo(name, desc)
            if not existed:
                created.append(full)

        return RepoPair(records=f"{self.owner}/{records}",
                        coverage=f"{self.owner}/{coverage}",
                        created=created)


def preflight(prov: Provisioner, cfg: ProjectConfig) -> list[str]:
    """Checks worth failing on before anything is created.

    Returned as warnings rather than raised, so `--dry-run` can show all of them
    at once instead of one per run.
    """
    warnings: list[str] = []

    base = prov.base_permission()
    if base not in (None, "none"):
        warnings.append(
            f"organization {prov.owner} grants members '{base}' on new "
            f"repositories.\n"
            f"    Every member would be able to read signer names and emails.\n"
            f"    REQ-SEC-2 treats the private repository as the access "
            f"boundary, so this weakens it.\n"
            f"    Restrict both repositories explicitly after install, or set "
            f"the org default to 'none'.")

    for repo in (cfg.records_repo(prov.owner), cfg.coverage_repo(prov.owner)):
        if prov.repo_exists(repo):
            warnings.append(f"{repo} already exists; install will reuse it")

    return warnings
