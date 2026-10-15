"""Authenticated action forms and immutable no-op proofs (HLD §5.4).

Callers supply an authenticated live session and only active or still-eligible
HMAC keys. They fetch terminal events at the form's confirmed commit; this
module performs no session lookup, canonical read, authorization query or write.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any

from . import events as _events
from .canonical import canonical_json, parse_canonical_json
from .encoding import base64url_decode, base64url_encode
from .event_identity import derive_event_identity, event_path


class ActionFormError(ValueError):
    """A form, its authentication/context, or its terminal proof is invalid."""


@dataclass(frozen=True, slots=True)
class FormActionSpec:
    action_type: str
    write_type: str
    terminal_types: tuple[str, ...]


_ACTION_TYPES = (
    "acceptance", "revocation", "project_connected",
    "project_repository_owner_changed", "project_succeeded", "keyring_activated",
    "agreement_published", "agreement_activated", "agreement_activation_restored",
    "enforcement_scope_requested", "exemption", "exemption_snapshot",
    "exemption_rule_configured", "exemption_rule_withdrawn",
    "exemption_source_withdrawn", "records_reader_authorized",
    "records_reader_snapshot_authorized", "records_reader_withdrawn",
    "records_reader_rule_configured", "records_reader_rule_withdrawn",
    "override", "override_withdrawn", "retry_requested", "config_updated",
)
_TERMINALS = {
    "agreement_activation_restored": ("agreement_activated", "agreement_activation_restored"),
    "enforcement_scope_requested": ("enforcement_scope_activated",),
    "retry_requested": (),
}
_REGISTRY = MappingProxyType({
    name: FormActionSpec(name, name, _TERMINALS.get(name, (name,)))
    for name in _ACTION_TYPES
})
_DOMAIN = b"dracla-action-form-v1\0"
_VERIFIED_FORM = object()
_LIFETIME = timedelta(hours=7, minutes=55)
_FORM_FIELDS = (
    "v", "algorithm", "kid", "session_jti", "github_user_id", "project_id",
    "type", "operation_nonce", "confirmed_canonical_oid", "operation_sha256",
    "terminal_noop_event_id", "issued_at", "expires_at",
)


def form_action_spec(event_type: str) -> FormActionSpec:
    """Look up exactly one Table 5.4-A row; internal types are never actions."""
    if type(event_type) is not str or event_type not in _REGISTRY:
        raise ActionFormError("unsupported form action")
    return _REGISTRY[event_type]


def _time(value: Any) -> datetime:
    _events._timestamp(value, "form time")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _check_payload(value: Any) -> dict[str, Any]:
    try:
        obj = _events._exact_object(value, _FORM_FIELDS, "action form")
        if type(obj["v"]) is not int or obj["v"] != 1 or obj["algorithm"] != "HS256":
            raise ActionFormError("unsupported form version or algorithm")
        base64url_decode(obj["kid"], expected_length=16)
        base64url_decode(obj["operation_nonce"], expected_length=16)
        _events._string(obj["session_jti"], "session_jti")
        _events._positive(obj["github_user_id"], "github_user_id")
        _events._string(obj["project_id"], "project_id")
        _events._oid(obj["confirmed_canonical_oid"], "confirmed_canonical_oid")
        _events._digest(obj["operation_sha256"], "operation_sha256")
        spec = form_action_spec(obj["type"])
        terminal = obj["terminal_noop_event_id"]
        if terminal is not None:
            _events._event_id(terminal, "terminal_noop_event_id")
            if not spec.terminal_types:
                raise ActionFormError("this action has no terminal no-op")
        issued, expires = _time(obj["issued_at"]), _time(obj["expires_at"])
        if not timedelta() <= expires - issued <= _LIFETIME:
            raise ActionFormError("invalid form lifetime")
        return dict(obj)
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise ActionFormError("invalid action-form payload") from error


@dataclass(frozen=True, slots=True)
class ActionForm:
    v: int
    algorithm: str
    kid: str
    session_jti: str
    github_user_id: int
    project_id: str
    type: str
    operation_nonce: str
    confirmed_canonical_oid: str
    operation_sha256: str
    terminal_noop_event_id: str | None
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _check_payload(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True, slots=True)
class ActionFormContext:
    """The current live session and authenticated request's recomputed inputs.

    confirmed_canonical_oid is the current events head. A terminal no-op may
    outlive that head; its separate immutable read must use the form's old head.
    """

    current_time: str
    session_expires_at: str
    session_jti: str
    github_user_id: int
    project_id: str
    type: str
    operation_nonce: str
    confirmed_canonical_oid: str
    operation_sha256: str

    def __post_init__(self) -> None:
        try:
            _time(self.current_time)
            _time(self.session_expires_at)
            _events._string(self.session_jti, "session_jti")
            _events._positive(self.github_user_id, "github_user_id")
            _events._string(self.project_id, "project_id")
            form_action_spec(self.type)
            base64url_decode(self.operation_nonce, expected_length=16)
            _events._oid(self.confirmed_canonical_oid, "confirmed_canonical_oid")
            _events._digest(self.operation_sha256, "operation_sha256")
        except (ValueError, TypeError) as error:
            raise ActionFormError("invalid action-form context") from error


@dataclass(frozen=True, slots=True, init=False)
class VerifiedActionForm:
    """An immutable verification result; ordinary callers cannot construct it."""

    form: ActionForm

    def __init__(self, form: ActionForm, *, _verified: object = None) -> None:
        if _verified is not _VERIFIED_FORM:
            raise ActionFormError("use verify_action_form to obtain a verified form")
        object.__setattr__(self, "form", form)

    @property
    def is_noop(self) -> bool:
        return self.form.terminal_noop_event_id is not None

    @property
    def preparable(self) -> bool:
        """A no-op never becomes eligible for preparation on a later retry."""
        return not self.is_noop


def _form(payload: Any) -> ActionForm:
    value = payload.to_dict() if isinstance(payload, ActionForm) else payload
    return ActionForm(**_check_payload(value))


def _key(key: Any) -> bytes:
    if type(key) is not bytes or not key:
        raise ActionFormError("HMAC key must be nonempty bytes")
    return key


def encode_action_form(payload: Any, *, key: bytes) -> str:
    """Encode exactly unpadded-base64url JCS, one dot, and the HS256 tag."""
    data = canonical_json(_form(payload).to_dict())
    tag = hmac.new(_key(key), _DOMAIN + data, hashlib.sha256).digest()
    return base64url_encode(data) + "." + base64url_encode(tag)


def verify_action_form(
    token: str, *, keys: Mapping[str, bytes], context: ActionFormContext,
) -> VerifiedActionForm:
    """Verify strict bytes, an explicitly eligible key, and all request bindings."""
    if type(token) is not str or token.count(".") != 1:
        raise ActionFormError("invalid action-form encoding")
    try:
        payload_part, tag_part = token.split(".")
        data = base64url_decode(payload_part)
        tag = base64url_decode(tag_part, expected_length=32)
        form = _form(parse_canonical_json(data))
    except (ValueError, TypeError, RecursionError) as error:
        raise ActionFormError("invalid action-form encoding") from error
    if not isinstance(keys, Mapping) or form.kid not in keys:
        raise ActionFormError("unknown or ineligible form key")
    expected_tag = hmac.new(_key(keys[form.kid]), _DOMAIN + data, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ActionFormError("action-form authentication failed")
    if not isinstance(context, ActionFormContext):
        raise ActionFormError("invalid action-form context")
    bound = (
        "session_jti", "github_user_id", "project_id", "type",
        "operation_nonce", "operation_sha256",
    )
    if any(getattr(form, name) != getattr(context, name) for name in bound):
        raise ActionFormError("action-form context does not match")
    issued, expires = _time(form.issued_at), _time(form.expires_at)
    if not issued <= _time(context.current_time) < expires or expires > _time(context.session_expires_at):
        raise ActionFormError("action form is outside its absolute lifetime")
    if form.terminal_noop_event_id is None and form.confirmed_canonical_oid != context.confirmed_canonical_oid:
        raise ActionFormError("canonical head changed; render a fresh action")
    return VerifiedActionForm(form, _verified=_VERIFIED_FORM)


def validate_terminal_noop(
    form: VerifiedActionForm, event: Any, operation: Any, *,
    expected_project_id: str, expected_confirmed_oid: str,
) -> None:
    """Prove the exact desired effect from the one immutable bound event read.

    operation is the submitted closed {target, payload} object. Its digest uses
    canonical-event semantics: only acceptance/revocation hash the head; other
    event types hash null. The form independently authenticates its read head.
    Issuance must already have established the terminal event's state currency.
    """
    if not isinstance(form, VerifiedActionForm) or not form.is_noop:
        raise ActionFormError("a verified terminal no-op form is required")
    value = form.form
    if value.project_id != expected_project_id or value.confirmed_canonical_oid != expected_confirmed_oid:
        raise ActionFormError("terminal read context does not match form")
    try:
        op = _events._exact_object(operation, ("target", "payload"), "form operation")
        target, payload = _events._parse_target_payload(value.type, op["target"], op["payload"])
        target, payload = _events._thaw(target), _events._thaw(payload)
        if value.type in {"acceptance", "revocation"}:
            coverage = target["coverage_tuple"]
            if coverage["project_id"] != value.project_id or coverage["github_user_id"] != value.github_user_id:
                raise ActionFormError("contributor operation does not match form actor and project")
            if value.type == "acceptance" and coverage["recipient_id"] != target["recipient"]["recipient_id"]:
                raise ActionFormError("acceptance recipient does not match coverage tuple")
        identity = derive_event_identity(
            value.project_id, value.operation_nonce,
            {"kind": "github", "github_user_id": value.github_user_id, "login_snapshot": "authenticated-user"},
            value.type, target, payload,
            value.confirmed_canonical_oid if value.type in {"acceptance", "revocation"} else None,
        )
        if identity.operation_sha256 != value.operation_sha256:
            raise ActionFormError("submitted effect does not match authenticated operation digest")
        path = event_path(value.terminal_noop_event_id)
        validate = _events.parse_event_jcs if type(event) is bytes else _events.validate_event
        terminal = validate(event, expected_project_id=expected_project_id, expected_path=path)
        if terminal.type not in form_action_spec(value.type).terminal_types:
            raise ActionFormError("terminal event type does not match action")
        prior = terminal.to_dict()
        if value.type == "enforcement_scope_requested":
            same_effect = prior["payload"]["desired_scope"] == payload["desired_scope"]
        elif value.type == "agreement_activation_restored":
            same_target = (
                prior["target"]["agreement_id"] == target["agreement_id"]
                and (
                    terminal.event_id == target["activation_event_id"]
                    if terminal.type == "agreement_activated"
                    else prior["target"]["activation_event_id"] == target["activation_event_id"]
                )
            )
            same_effect = same_target and prior["payload"]["accepted_versions"] == payload["accepted_versions"]
        else:
            same_effect = prior["target"] == target and prior["payload"] == payload
        if not same_effect:
            raise ActionFormError("terminal event establishes a different desired effect")
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise ActionFormError("invalid terminal no-op proof") from error
