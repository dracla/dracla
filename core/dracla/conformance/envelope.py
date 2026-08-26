"""Authenticated revision-13 private-artifact envelope."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .artifacts import (
    ArtifactIdentity,
    ArtifactIdentityError,
    resolve_artifact_identity,
)
from .canonical import CanonicalJsonError, canonical_json, parse_canonical_json
from .encoding import Base64UrlError, base64url_decode, base64url_encode

ENVELOPE_VERSION = 1
ALGORITHM = "A256GCM"
DATA_KEY_BYTES = 32
KEY_ID_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
_CSV_FORMULA_TRIGGERS = frozenset("=+-@\t\r\n")

_ENVELOPE_FIELDS = {
    "envelope_version",
    "algorithm",
    "project_id",
    "artifact_kind",
    "logical_id",
    "schema_version",
    "kid",
    "nonce",
    "ciphertext",
}
_AAD_FIELDS = _ENVELOPE_FIELDS - {"nonce", "ciphertext"}


class ArtifactEnvelopeError(ValueError):
    """Base class for rejected encrypted artifact envelopes."""


class ArtifactEnvelopeFormatError(ArtifactEnvelopeError):
    """Envelope bytes or plaintext do not have the required canonical form."""


class ArtifactEnvelopeContextError(ArtifactEnvelopeError):
    """Envelope metadata does not match its caller-derived context."""


class UnknownArtifactKeyError(ArtifactEnvelopeError):
    """No retained data key matches the envelope key ID."""


class ArtifactAuthenticationError(ArtifactEnvelopeError):
    """AES-GCM authentication failed."""


def _resolved_identity(identity: ArtifactIdentity) -> ArtifactIdentity:
    if type(identity) is not ArtifactIdentity:
        raise ArtifactEnvelopeContextError("identity must be an ArtifactIdentity")
    try:
        resolved = resolve_artifact_identity(
            identity.repository_role, identity.branch, identity.path
        )
    except ArtifactIdentityError as error:
        raise ArtifactEnvelopeContextError(
            "artifact identity is not in the v1 namespace"
        ) from error
    if resolved != identity:
        raise ArtifactEnvelopeContextError(
            "artifact identity does not match its v1 path"
        )
    return resolved


def _project_id(value: str) -> str:
    if type(value) is not str or not value:
        raise ArtifactEnvelopeContextError("project_id must be a non-empty string")
    return value


def _exact_bytes(value: bytes, *, length: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ArtifactEnvelopeFormatError(f"{label} must be exactly {length} bytes")
    return value


def _metadata(
    *, project_id: str, identity: ArtifactIdentity, kid: str
) -> dict[str, Any]:
    return {
        "envelope_version": ENVELOPE_VERSION,
        "algorithm": ALGORITHM,
        "project_id": project_id,
        "artifact_kind": identity.artifact_kind,
        "logical_id": identity.logical_id,
        "schema_version": identity.schema_version,
        "kid": kid,
    }


def artifact_aad(
    *, project_id: str, identity: ArtifactIdentity, kid: bytes
) -> bytes:
    """Return the exact RFC 8785 additional-authenticated-data bytes."""

    identity = _resolved_identity(identity)
    kid = _exact_bytes(kid, length=KEY_ID_BYTES, label="kid")
    return canonical_json(
        _metadata(
            project_id=_project_id(project_id),
            identity=identity,
            kid=base64url_encode(kid),
        )
    )


def _validate_plaintext(plaintext: bytes, *, identity: ArtifactIdentity) -> None:
    if type(plaintext) is not bytes:
        raise TypeError("artifact plaintext must be bytes")
    if identity.artifact_kind == "export-csv":
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ArtifactEnvelopeFormatError(
                "CSV artifact plaintext must be exact UTF-8 bytes"
            ) from error
        if plaintext.startswith(b"\xef\xbb\xbf"):
            raise ArtifactEnvelopeFormatError(
                "CSV artifact plaintext must not have a byte-order mark"
            )
        _validate_formula_neutralized_csv(text)
        return
    try:
        parse_canonical_json(plaintext)
    except CanonicalJsonError as error:
        raise ArtifactEnvelopeFormatError(
            "JSON artifact plaintext must be exact RFC 8785 bytes"
        ) from error


def _validate_formula_neutralized_csv(text: str) -> None:
    """Validate strict CSV structure and each cell's first character."""

    mode = "field-start"
    first_quoted_character = False
    index = 0
    while index < len(text):
        character = text[index]
        if mode == "field-start":
            if character == '"':
                mode = "quoted"
                first_quoted_character = True
                index += 1
            elif character == ",":
                index += 1
            elif character in "\r\n":
                index += (
                    2
                    if character == "\r" and text[index : index + 2] == "\r\n"
                    else 1
                )
            else:
                if character in _CSV_FORMULA_TRIGGERS:
                    raise ArtifactEnvelopeFormatError(
                        "CSV artifact cells must be formula-neutralized "
                        "before encryption"
                    )
                mode = "unquoted"
                index += 1
        elif mode == "unquoted":
            if character == ",":
                mode = "field-start"
                index += 1
            elif character in "\r\n":
                mode = "field-start"
                index += (
                    2
                    if character == "\r" and text[index : index + 2] == "\r\n"
                    else 1
                )
            elif character == '"':
                raise ArtifactEnvelopeFormatError(
                    "CSV artifact plaintext must be valid CSV"
                )
            else:
                index += 1
        elif mode == "quoted":
            if character == '"':
                if text[index : index + 2] == '""':
                    first_quoted_character = False
                    index += 2
                else:
                    mode = "after-quote"
                    index += 1
            else:
                if first_quoted_character and character in _CSV_FORMULA_TRIGGERS:
                    raise ArtifactEnvelopeFormatError(
                        "CSV artifact cells must be formula-neutralized "
                        "before encryption"
                    )
                first_quoted_character = False
                index += 1
        elif character == ",":
            mode = "field-start"
            index += 1
        elif character in "\r\n":
            mode = "field-start"
            index += (
                2
                if character == "\r" and text[index : index + 2] == "\r\n"
                else 1
            )
        else:
            raise ArtifactEnvelopeFormatError(
                "CSV artifact plaintext must be valid CSV"
            )
    if mode == "quoted":
        raise ArtifactEnvelopeFormatError(
            "CSV artifact plaintext must be valid CSV"
        )


def encrypt_artifact(
    plaintext: bytes,
    *,
    project_id: str,
    identity: ArtifactIdentity,
    kid: bytes,
    key: bytes,
) -> bytes:
    """Encrypt one path-bound artifact using a fresh production nonce."""

    identity = _resolved_identity(identity)
    project_id = _project_id(project_id)
    kid = _exact_bytes(kid, length=KEY_ID_BYTES, label="kid")
    key = _exact_bytes(key, length=DATA_KEY_BYTES, label="key")
    _validate_plaintext(plaintext, identity=identity)
    nonce = _exact_bytes(
        secrets.token_bytes(NONCE_BYTES), length=NONCE_BYTES, label="nonce"
    )
    kid_text = base64url_encode(kid)
    metadata = _metadata(project_id=project_id, identity=identity, kid=kid_text)
    aad = canonical_json(metadata)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return canonical_json(
        {
            **metadata,
            "nonce": base64url_encode(nonce),
            "ciphertext": base64url_encode(ciphertext),
        }
    )


def encrypt_json_artifact(
    value: Any,
    *,
    project_id: str,
    identity: ArtifactIdentity,
    kid: bytes,
    key: bytes,
) -> bytes:
    """Canonicalize and encrypt one JSON artifact."""

    if _resolved_identity(identity).artifact_kind == "export-csv":
        raise ArtifactEnvelopeContextError("export-csv requires exact byte plaintext")
    return encrypt_artifact(
        canonical_json(value),
        project_id=project_id,
        identity=identity,
        kid=kid,
        key=key,
    )


def _parse_envelope(data: bytes) -> dict[str, Any]:
    try:
        value = parse_canonical_json(data)
    except (CanonicalJsonError, TypeError) as error:
        raise ArtifactEnvelopeFormatError(
            "envelope must be exact canonical JSON bytes"
        ) from error
    if type(value) is not dict or set(value) != _ENVELOPE_FIELDS:
        raise ArtifactEnvelopeFormatError("envelope has missing or extra fields")
    return value


def _require_metadata(
    envelope: dict[str, Any],
    *,
    expected_project_id: str,
    expected_identity: ArtifactIdentity,
) -> None:
    scalar_types = {
        "envelope_version": int,
        "algorithm": str,
        "project_id": str,
        "artifact_kind": str,
        "logical_id": str,
        "schema_version": int,
        "kid": str,
        "nonce": str,
        "ciphertext": str,
    }
    if any(type(envelope[name]) is not kind for name, kind in scalar_types.items()):
        raise ArtifactEnvelopeFormatError("envelope fields have invalid JSON types")
    if envelope["envelope_version"] != ENVELOPE_VERSION:
        raise ArtifactEnvelopeFormatError("unsupported envelope_version")
    if envelope["algorithm"] != ALGORITHM:
        raise ArtifactEnvelopeFormatError("unsupported envelope algorithm")
    if envelope["schema_version"] != expected_identity.schema_version:
        raise ArtifactEnvelopeContextError(
            "envelope schema_version does not match path"
        )
    expected = _metadata(
        project_id=expected_project_id,
        identity=expected_identity,
        kid=envelope["kid"],
    )
    if any(envelope[name] != expected[name] for name in _AAD_FIELDS):
        raise ArtifactEnvelopeContextError(
            "envelope metadata does not match expected context"
        )


def _key_for(keys: Mapping[str, bytes], kid: str) -> bytes:
    if not isinstance(keys, Mapping):
        raise TypeError("keys must be a mapping from encoded key IDs to raw keys")
    if kid not in keys:
        raise UnknownArtifactKeyError(f"unknown artifact key ID {kid}")
    try:
        key = keys[kid]
    except KeyError as error:
        raise UnknownArtifactKeyError(f"unknown artifact key ID {kid}") from error
    return _exact_bytes(key, length=DATA_KEY_BYTES, label="key")


def decrypt_artifact(
    data: bytes,
    *,
    expected_project_id: str,
    expected_identity: ArtifactIdentity,
    keys: Mapping[str, bytes],
) -> bytes:
    """Authenticate and decrypt one artifact in caller-derived context."""

    expected_identity = _resolved_identity(expected_identity)
    expected_project_id = _project_id(expected_project_id)
    envelope = _parse_envelope(data)
    _require_metadata(
        envelope,
        expected_project_id=expected_project_id,
        expected_identity=expected_identity,
    )
    try:
        base64url_decode(
            envelope["kid"], expected_length=KEY_ID_BYTES, label="kid"
        )
        nonce = base64url_decode(
            envelope["nonce"], expected_length=NONCE_BYTES, label="nonce"
        )
        ciphertext = base64url_decode(envelope["ciphertext"], label="ciphertext")
    except Base64UrlError as error:
        raise ArtifactEnvelopeFormatError(str(error)) from error
    if len(ciphertext) < TAG_BYTES:
        raise ArtifactEnvelopeFormatError("ciphertext must include a 16-byte tag")
    key = _key_for(keys, envelope["kid"])
    aad = canonical_json({name: envelope[name] for name in _AAD_FIELDS})
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise ArtifactAuthenticationError("artifact authentication failed") from error
    _validate_plaintext(plaintext, identity=expected_identity)
    return plaintext


def decrypt_json_artifact(
    data: bytes,
    *,
    expected_project_id: str,
    expected_identity: ArtifactIdentity,
    keys: Mapping[str, bytes],
) -> Any:
    """Authenticate, decrypt, and parse one canonical JSON artifact."""

    if _resolved_identity(expected_identity).artifact_kind == "export-csv":
        raise ArtifactEnvelopeContextError("export-csv is not a JSON artifact")
    plaintext = decrypt_artifact(
        data,
        expected_project_id=expected_project_id,
        expected_identity=expected_identity,
        keys=keys,
    )
    return parse_canonical_json(plaintext)
