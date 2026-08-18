"""Project configuration: the resolved artifact committed to canonical.

Design §6.9. The administrator authors YAML and Hydra composes it *on the
client*; `dracla config` writes the resolved result as plain JSON. What lands in
the repository is inert — no `defaults:`, no `${...}`, no config-group
references, and no dependency on the composition engine to know what it says.

Nothing here is imported by `core`. Composition is a client concern; core
receives a plain dict.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any

from .errors import CliError

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}$")
CONFIG_PATH = "config/project.json"
SCHEMA_VERSION = 1


@dataclass
class Recipient:
    """The legal person receiving the rights granted by the agreement.

    `REQ-CONFIG-2`: DraCLA must not assume the GitHub organization is the
    recipient. Hydra's own trademarks moved from Meta Platforms to an individual
    while the GitHub org stayed put — that is the case this field exists for.

    Immutable once chosen (§5.5): past acceptances granted rights to a specific
    entity and cannot be retroactively reassigned. Changing it is a new project.
    """

    legal_name: str
    contact: str
    address: str = ""


@dataclass
class Scope:
    """Which repositories an agreement covers (`REQ-CONFIG-3`).

    Captured with every acceptance and evaluated at check time against the
    scope recorded *then*, not the project's current scope — so widening scope
    does not retroactively extend consent (§6.3, DR-007).
    """

    orgs: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)

    def covers(self, repository: str) -> bool:
        if repository in self.repos:
            return True
        return repository.split("/", 1)[0] in self.orgs


@dataclass
class Confirmation:
    """A checkbox the signer must tick, with its exact label.

    `REQ-SIGN-3` requires the label be preserved with the acceptance, because
    the evidence is what the signer actually saw.
    """

    id: str
    label: str


@dataclass
class ProjectConfig:
    slug: str
    recipient: Recipient
    scope: Scope
    agreement_id: str = "icla"
    required_fields: list[str] = field(default_factory=lambda: ["legal_name", "email"])
    confirmations: list[Confirmation] = field(default_factory=list)
    privacy_policy_url: str = ""
    retention_statement: str = ""
    exemption_rules: list[dict[str, Any]] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    # --- validation -------------------------------------------------------

    def validate(self) -> None:
        if not SLUG_RE.match(self.slug):
            raise CliError(
                f"invalid slug {self.slug!r}",
                hint="lowercase letters, digits and hyphens; 2-39 characters")
        if not self.recipient.legal_name.strip():
            raise CliError(
                "recipient.legal_name is required",
                hint="REQ-CONFIG-2: name the legal person receiving the rights, "
                     "which may not be the GitHub organization")
        if not self.scope.orgs and not self.scope.repos:
            raise CliError(
                "scope is empty",
                hint="list the organizations or repositories the agreement covers")
        if not self.required_fields:
            raise CliError(
                "required_fields is empty",
                hint="at least one signer field is needed to identify the signer")
        if not self.privacy_policy_url:
            raise CliError(
                "privacy_policy_url is required",
                hint="REQ-SEC-3: the signing page must link to your privacy policy "
                     "before acceptance")
        if not self.retention_statement:
            raise CliError(
                "retention_statement is required",
                hint="REQ-SEC-7: signing and revocation must explain that evidence "
                     "is retained after revocation")
        seen = set()
        for c in self.confirmations:
            if c.id in seen:
                raise CliError(f"duplicate confirmation id {c.id!r}")
            seen.add(c.id)
            if not c.label.strip():
                raise CliError(f"confirmation {c.id!r} has an empty label")

    # --- serialization ----------------------------------------------------

    def to_json(self) -> str:
        """Resolved, sorted, stable — this is what gets committed."""
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> "ProjectConfig":
        version = doc.get("schema_version", 1)
        if version != SCHEMA_VERSION:
            raise CliError(
                f"config schema_version {version} is not supported",
                hint=f"this dracla understands version {SCHEMA_VERSION}")
        return cls(
            slug=doc["slug"],
            recipient=Recipient(**doc["recipient"]),
            scope=Scope(**doc["scope"]),
            agreement_id=doc.get("agreement_id", "icla"),
            required_fields=list(doc.get("required_fields", [])),
            confirmations=[Confirmation(**c) for c in doc.get("confirmations", [])],
            privacy_policy_url=doc.get("privacy_policy_url", ""),
            retention_statement=doc.get("retention_statement", ""),
            exemption_rules=list(doc.get("exemption_rules", [])),
        )

    def records_repo(self, owner: str) -> str:
        return f"{owner}/{self.slug}-cla-records"

    def coverage_repo(self, owner: str) -> str:
        return f"{owner}/{self.slug}-cla-coverage"


def compose(overrides: list[str] | None = None,
            config_dir: str | None = None) -> ProjectConfig:
    """Compose configuration with Hydra, if it is available and configured.

    Hydra is optional at this layer on purpose. A single project has one config
    and needs no composition; the value appears when one maintainer runs several
    projects that share a base and differ only in recipient, agreement, and
    scope (§6.9). So a missing Hydra is not an error — it just means no
    composition.
    """
    if not config_dir:
        raise CliError("no config directory given",
                       hint="pass --config-dir, or use `dracla init` to create one")
    try:
        from hydra import compose as hydra_compose, initialize_config_dir
        from omegaconf import OmegaConf
    except ImportError as e:  # pragma: no cover - environment dependent
        raise CliError(
            "hydra-core is required for config composition",
            hint="pip install hydra-core, or hand-write config/project.json") from e

    with initialize_config_dir(config_dir=config_dir, version_base=None):
        cfg = hydra_compose(config_name="project", overrides=overrides or [])
    # Resolve everything now: what leaves this function must not depend on
    # Hydra to be understood.
    resolved = OmegaConf.to_container(cfg, resolve=True)
    return ProjectConfig.from_dict(resolved)      # type: ignore[arg-type]
