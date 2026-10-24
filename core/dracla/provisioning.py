"""Plain install inputs and deterministic planning. This module performs no I/O."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from .administration import AdminScope, Discovery

_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_OWNER = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?", re.ASCII)


@dataclass(frozen=True)
class InstallInput:
    owner: str
    slug: str
    dry_run: bool = False
    force: bool = False

    def __post_init__(self) -> None:
        if type(self.owner) is not str or not _OWNER.fullmatch(self.owner):
            raise ValueError("github.owner must be an ASCII GitHub account login")
        if type(self.slug) is not str or not self.slug.isascii():
            raise ValueError("project.slug must be ASCII")
        slug = self.slug.casefold()
        if not _SLUG.fullmatch(slug):
            raise ValueError("project.slug does not satisfy the project naming rule")
        if type(self.dry_run) is not bool or type(self.force) is not bool:
            raise ValueError("dry_run and force must be booleans")
        object.__setattr__(self, "owner", self.owner.casefold())
        object.__setattr__(self, "slug", slug)


@dataclass(frozen=True)
class PlannedRepository:
    role: str
    owner: str
    name: str
    id: int | None = None


@dataclass(frozen=True)
class PlannedStep:
    description: str
    engine: str
    state: str
    reason: str


class ReleaseDeclarations(Protocol):
    package_version: str
    source_commit_oid: str
    policy_sha256: str
    dependency_constraints_sha256: str
    provenance_identity: str


@dataclass(frozen=True)
class PlannedRelease:
    package_version: str
    source_commit_oid: str
    policy_sha256: str
    dependency_constraints_sha256: str
    provenance_identity: str


@dataclass(frozen=True)
class InstallPlan:
    owner: str
    slug: str
    repositories: tuple[PlannedRepository, ...]
    steps: tuple[PlannedStep, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    release: PlannedRelease
    owner_id: int | None = None

    @property
    def complete(self) -> bool:
        return not self.blockers


def administration_scope(config: InstallInput) -> AdminScope:
    return AdminScope(config.owner, tuple((role, f"{config.slug}-cla-{role}")
                                          for role in ("records", "coverage", "control")))


def plan_install(config: InstallInput, release: ReleaseDeclarations, discovery: Discovery) -> InstallPlan:
    """Recompute a public plan from current typed observations; no I/O or reuse."""
    scope = administration_scope(config)
    account = discovery.account.account
    blockers = []
    if account is None or account.login != config.owner:
        blockers.append("Account identity unavailable or mismatched.")
    if not discovery.account.inventory_visible:
        blockers.append("Complete private repository visibility and administration permission are unproved.")
    if not discovery.inventory_complete:
        blockers.append("Repository inventory is incomplete.")
    observations = {(o.owner, o.name): o for o in discovery.repositories}
    if len(observations) != len(discovery.repositories) or set(observations) != {(scope.owner, n) for _, n in scope.repositories}:
        blockers.append("Exact three-repository observation set unavailable.")
    repositories = []
    for role, name in scope.repositories:
        observation = observations.get((scope.owner, name))
        metadata = observation.metadata if observation else None
        repositories.append(PlannedRepository(role, scope.owner, name, metadata.id if metadata else None))
        if observation is None or observation.state == "unknown":
            blockers.append(f"{role}: repository state unknown.")
        elif metadata is not None:
            if metadata.owner != account or metadata.name != name:
                blockers.append(f"{role}: repository identity mismatch.")
            if not metadata.private:
                blockers.append(f"{role}: existing repository is not private.")
            if metadata.permissions.admin is not True:
                blockers.append(f"{role}: repository administration permission is unproved.")
            blockers.append(f"{role}: existing repository blocked; provenance verifier unavailable.")
    if not config.dry_run:
        blockers.append("Installation requires the M3, M5 and M6 engines.")
    descriptions = (
        "Preflight owner, release, dependencies and repository permissions; report unavailable execution engines.",
        "Confirm exact identities unless dry_run or force suppresses confirmation.",
        "Create all three repositories empty and private; verify readback.",
        "Create the mandatory records README root commit.",
        "Rename the initial records branch to events and verify the default branch.",
        "Seed control with the pinned workflow and provenance manifest.",
        "Warn about transport-key integrity reach, then provision and challenge credentials.",
        "Disclose hosted trust, then generate and verify project and recovery keys.",
        "Initialize operation, coverage and keyring state through the M6 installer.",
        "Print the three App installation links; portal connection remains separate.",
    )
    steps = tuple(PlannedStep(description, "M2" if index == 0 else "M6" if index not in (5, 6) else "M3/M5/M6",
                              "blocked" if index == 0 and blockers else "satisfied" if index == 0 else "blocked",
                              "Current read-only metadata and local release checks." if index == 0 and not blockers
                              else "Execution engine or prerequisite unavailable.")
                  for index, description in enumerate(descriptions))
    return InstallPlan(
        config.owner,
        config.slug,
        tuple(repositories), steps, tuple(blockers),
        ("Release metadata is declared by the executing package; it is not independent proof of that package.",
         "A plan does not mean installed, connected, signable or routable.",
         "Repository names alone never prove project ownership or permission to reuse.",
         "This deploy key is an integrity credential. Anyone who obtains it can read "
         "encrypted repository data and can rewrite, delete, roll back, or replay that "
         "data, which may affect CLA check results. This deploy key cannot decrypt CLA "
         "records by itself.",
         "People and workflows able to use control Actions secrets are integrity controllers.",
         "The hosted operator controls wrapping roots and is trusted for signer confidentiality and integrity."),
        PlannedRelease(release.package_version, release.source_commit_oid, release.policy_sha256,
                       release.dependency_constraints_sha256, release.provenance_identity),
        account.id if account and account.login == config.owner else None,
    )
