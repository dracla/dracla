"""Plain install inputs and deterministic planning. This module performs no I/O."""
from __future__ import annotations

from dataclasses import dataclass, replace
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


@dataclass(frozen=True)
class VerifiedInstallation:
    """Trusted owning-verifier result, never a user-supplied provenance claim.

    Before returning this value, M6 must verify every existing repository's
    canonical manifest and root ancestry, common project ID and generation,
    candidate K and initial keys head B. These serializers and checks belong
    to M6. M2 checks the result's bindings to the current observations only.
    No production M2 path constructs this result.
    """
    owner_id: int
    slug: str
    release: PlannedRelease
    repositories: tuple[PlannedRepository, ...]


class InstallationVerifier(Protocol):
    def verify(self, config: InstallInput, release: PlannedRelease,
               discovery: Discovery) -> VerifiedInstallation | None:
        """Return complete verified provenance, or None for any unproved input."""
        ...


@dataclass(frozen=True)
class FreshObservations:
    """Fresh reads and local release checks, with an optional verifier result.

    The caller obtains verified_installation only from InstallationVerifier.
    The planner consumes values and never calls that I/O-owning port itself.
    """
    config: InstallInput
    release: ReleaseDeclarations
    discovery: Discovery
    verified_installation: VerifiedInstallation | None = None


def _release(release: ReleaseDeclarations) -> PlannedRelease:
    return PlannedRelease(release.package_version, release.source_commit_oid, release.policy_sha256,
                          release.dependency_constraints_sha256, release.provenance_identity)


def administration_scope(config: InstallInput) -> AdminScope:
    return AdminScope(config.owner, tuple((role, f"{config.slug}-cla-{role}")
                                          for role in ("records", "coverage", "control")))


def plan_install(config: InstallInput, release: ReleaseDeclarations, discovery: Discovery,
                 *, verified_installation: VerifiedInstallation | None = None) -> InstallPlan:
    """Recompute a public plan from current typed observations; no I/O."""
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
    existing = tuple(PlannedRepository(role, scope.owner, name, observation.metadata.id)
                     for role, name in scope.repositories
                     if (observation := observations.get((scope.owner, name))) is not None
                     and observation.metadata is not None)
    verified = (verified_installation is not None and account is not None
                and type(account.id) is int
                and len(existing) == len(scope.repositories)
                and all(type(repository.id) is int for repository in existing)
                and type(verified_installation.owner_id) is int
                and verified_installation.owner_id == account.id
                and verified_installation.slug == config.slug
                and verified_installation.release == _release(release)
                and all(type(repository.id) is int for repository in verified_installation.repositories)
                and verified_installation.repositories == existing)
    if verified_installation is not None and not verified:
        blockers.append("Verified provenance does not match current identities and release.")
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
            if not verified:
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
        _release(release),
        account.id if account and account.login == config.owner else None,
    )


def plan_resume(previous_plan: InstallPlan, fresh_observations: FreshObservations) -> InstallPlan:
    """Recompute fixed intent; old steps, blockers and completion flags are ignored.

    A known identity that disappears also conflicts: incomplete fresh evidence
    cannot silently turn a previously observed repository into an absent name.
    The result is a plan, never permission to execute installer operations.
    """
    fresh = fresh_observations
    fixed = InstallInput(previous_plan.owner, previous_plan.slug,
                         dry_run=fresh.config.dry_run, force=fresh.config.force)
    plan = plan_install(fixed, previous_plan.release, fresh.discovery,
                        verified_installation=fresh.verified_installation)
    conflicts = []
    if (fresh.config.owner, fresh.config.slug) != (previous_plan.owner, previous_plan.slug):
        conflicts.append("Resume conflict: owner or slug changed; create an explicit new plan.")
    if _release(fresh.release) != previous_plan.release:
        conflicts.append("Resume conflict: release or policy changed; create an explicit new plan.")
    if previous_plan.owner_id is not None and plan.owner_id != previous_plan.owner_id:
        conflicts.append("Resume conflict: owner ID changed or unavailable; create an explicit new plan.")
    old = {(r.role, r.owner, r.name): r.id for r in previous_plan.repositories}
    expected = {(r.role, r.owner, r.name) for r in plan.repositories}
    if set(old) != expected or len(old) != len(previous_plan.repositories):
        conflicts.append("Resume conflict: repository intent changed; create an explicit new plan.")
    for repo in plan.repositories:
        prior_id = old.get((repo.role, repo.owner, repo.name))
        if prior_id is not None and repo.id != prior_id:
            conflicts.append(f"Resume conflict: {repo.role} ID changed or unavailable; create an explicit new plan.")
    if conflicts:
        anchored_repositories = tuple(
            replace(repo, id=old[(repo.role, repo.owner, repo.name)])
            if old.get((repo.role, repo.owner, repo.name)) is not None else repo
            for repo in plan.repositories
        )
        plan = replace(plan,
                       repositories=anchored_repositories,
                       owner_id=previous_plan.owner_id if previous_plan.owner_id is not None else plan.owner_id,
                       release=previous_plan.release,
                       blockers=tuple(conflicts) + plan.blockers,
                       steps=tuple(replace(s, state="blocked", reason="Resume conflict requires a new plan.")
                                   for s in plan.steps))
    return plan
