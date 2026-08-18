"""Event envelope and identifier derivation.

Implements design/high-level-design.md §5.1. The identifier derivation is the
part worth reading carefully: DR-015 established that the obvious choices each
break a MUST, so the inputs here are chosen to satisfy both at once.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any

from . import SCHEMA_VERSION

ACCEPTANCE = "acceptance"
REVOCATION = "revocation"
AGREEMENT_PUBLISHED = "agreement_published"
AGREEMENT_ACTIVATED = "agreement_activated"
OVERRIDE = "override"
EXEMPTION = "exemption"
EXEMPTION_REVOKED = "exemption_revoked"
CONFIG_UPDATED = "config_updated"

EVENT_TYPES = {
    ACCEPTANCE, REVOCATION, AGREEMENT_PUBLISHED, AGREEMENT_ACTIVATED,
    OVERRIDE, EXEMPTION, EXEMPTION_REVOKED, CONFIG_UPDATED,
}

GENESIS = "genesis"


class ValidationError(Exception):
    """Raised before any write. §5.4 requires validation to precede the commit."""


def _h(*parts: str) -> str:
    d = hashlib.sha256()
    for p in parts:
        d.update(p.encode("utf-8"))
        d.update(b"\x00")          # unambiguous separator; no field can span
    return d.hexdigest()


def idempotency_key(
    *,
    project: str,
    subject_user_id: int,
    event_type: str,
    agreement_id: str,
    agreement_version: str,
    agreement_digest: str,
    prior_event_id: str,
    submission_nonce: str,
) -> str:
    """Stable key for one logical operation (§5.1).

    `prior_event_id` — the current head of this subject's event chain — is what
    makes re-signing after a revocation a distinct path rather than a collision
    with the original acceptance (REQ-REV-5). A purely content-addressed key
    would make those two identical.

    `submission_nonce` — server-issued with the form, single-use — is what makes
    a repeated delivery of the *same* submission collapse instead of appending a
    duplicate (REQ-SIGN-5). A timestamp or fresh random here would break that.
    """
    return _h(
        project, str(subject_user_id), event_type,
        agreement_id, agreement_version, agreement_digest,
        prior_event_id, submission_nonce,
    )


def event_id(idem_key: str) -> str:
    """event_id is a pure function of the idempotency key.

    That equivalence is what lets §5.2's path-existence probe *be* the
    idempotency-key check REQ-REC-3 asks for, with no second index.
    """
    return _h(idem_key)


def event_path(eid: str) -> str:
    """Server-computed path. Never derived from client input (DR-013, §8.1 #1)."""
    return f"events/{eid[:2]}/{eid[2:4]}/{eid}.json"


@dataclass
class Subject:
    github_user_id: int
    login_snapshot: str


@dataclass
class Event:
    event_id: str
    idempotency_key: str
    type: str
    recorded_at: str
    dracla_version: str
    agreement: dict[str, Any]
    scope: dict[str, Any]
    subjects: list[Subject] = field(default_factory=list)
    actor: Subject | None = None
    fields: dict[str, str] = field(default_factory=dict)
    confirmations: list[dict[str, Any]] = field(default_factory=list)
    revokes: str | None = None
    supersedes: str | None = None
    applies_to: dict[str, Any] | None = None
    schema_version: int = SCHEMA_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @property
    def path(self) -> str:
        return event_path(self.event_id)

    @property
    def subject_ids(self) -> list[int]:
        return [s.github_user_id for s in self.subjects]


def validate(event: Event, *, config: dict[str, Any]) -> None:
    """Full validation. Must run before any write (§5.4, DR-004).

    Canonical is append-only and cannot be pruned, so an invalid event committed
    first is permanent. Everything checkable is checked here.
    """
    if event.schema_version != SCHEMA_VERSION:
        raise ValidationError(f"unknown schema_version {event.schema_version}")
    if event.type not in EVENT_TYPES:
        raise ValidationError(f"unknown event type {event.type!r}")
    if event.event_id != event_id(event.idempotency_key):
        raise ValidationError("event_id is not the hash of idempotency_key")

    if event.type in (ACCEPTANCE, REVOCATION):
        if len(event.subjects) != 1:
            raise ValidationError(f"{event.type} must carry exactly one subject")
        for key in ("id", "version", "digest"):
            if not event.agreement.get(key):
                raise ValidationError(f"agreement.{key} is required")

    if event.type == ACCEPTANCE:
        # `config` is the resolved project configuration (config/project.yaml,
        # composed by the CLI — design 6.9). It reaches here as a plain dict;
        # nothing in core depends on Hydra.
        required = set(config.get("required_fields", []))
        got = set(event.fields)
        if missing := required - got:
            raise ValidationError(f"missing required fields: {sorted(missing)}")
        # REQ-SEC-1: collect only what the agreement and policy require.
        if extra := got - required:
            raise ValidationError(f"fields not in project config: {sorted(extra)}")

        want = [c["label"] for c in config.get("confirmations", [])]
        have = [c["label"] for c in event.confirmations]
        if want != have:
            raise ValidationError("confirmation labels do not match project config")
        if not all(c.get("checked") for c in event.confirmations):
            # An unchecked confirmation is a rejected submission, not a record.
            raise ValidationError("all confirmations must be checked")

    if event.type == REVOCATION and not event.revokes:
        raise ValidationError("revocation must identify the acceptance it revokes")

    if event.type == OVERRIDE:
        if not event.applies_to or "tree_digest" not in event.applies_to:
            raise ValidationError("override must bind to content (tree_digest)")
        if not event.actor:
            raise ValidationError("override must be attributable to an actor")
