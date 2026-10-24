"""Plain install inputs and deterministic planning. This module performs no I/O."""
from __future__ import annotations

from dataclasses import dataclass
import re

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


@dataclass(frozen=True)
class InstallPlan:
    owner: str
    slug: str
    repositories: tuple[PlannedRepository, ...]
    steps: tuple[str, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.blockers


def initial_plan(config: InstallInput) -> InstallPlan:
    """Describe intended names, without claiming discovered IDs or installation."""
    return InstallPlan(
        config.owner,
        config.slug,
        tuple(PlannedRepository(role, config.owner, f"{config.slug}-cla-{role}")
              for role in ("records", "coverage", "control")),
        ("Preflight owner, release, dependencies, repository permissions and required engines.",
         "Confirm exact identities unless dry_run or force suppresses confirmation.",
         "Create all three repositories empty and private; verify readback.",
         "Create the mandatory records README root commit.",
         "Rename the initial records branch to events and verify the default branch.",
         "Seed control with the pinned workflow and provenance manifest.",
         "Warn about transport-key integrity reach, then provision and challenge credentials.",
         "Disclose hosted trust, then generate and verify project and recovery keys.",
         "Initialize operation, coverage and keyring state through the M6 installer.",
         "Print the three App installation links; portal connection remains separate."),
        ("Live account and repository discovery is unavailable.",) +
        (() if config.dry_run else ("Installation requires the M3, M5 and M6 engines.",)),
        ("Release metadata is declared by the executing package; it is not independent proof of that package.",
         "A plan does not mean installed, connected, signable or routable.",
         "Repository names alone never prove project ownership or permission to reuse.",
         "This deploy key is an integrity credential. Anyone who obtains it can read "
         "encrypted repository data and can rewrite, delete, roll back, or replay that "
         "data, which may affect CLA check results. This deploy key cannot decrypt CLA "
         "records by itself.",
         "People and workflows able to use control Actions secrets are integrity controllers.",
         "The hosted operator controls wrapping roots and is trusted for signer confidentiality and integrity."),
    )
