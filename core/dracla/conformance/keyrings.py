"""Authenticated wrapped-key copies and canonical revision-13 keyrings."""

from __future__ import annotations

import secrets
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import CanonicalJsonError, canonical_json, parse_canonical_json
from .encoding import Base64UrlError, base64url_decode, base64url_encode
from .envelope import (
    ALGORITHM,
    DATA_KEY_BYTES,
    KEY_ID_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
)

WRAP_VERSION = 1
KEYRING_VERSION = 1
WRAPPED_KEY_ALGORITHM = ALGORITHM

CAPABILITIES = frozenset({"records", "coverage"})
WRAPPER_IDS = frozenset(
    {
        "portal-records",
        "portal-coverage",
        "enforcer-coverage",
        "control",
        "recovery",
    }
)
WRAPPER_CAPABILITIES = MappingProxyType(
    {
        "portal-records": frozenset({"records"}),
        "portal-coverage": frozenset({"coverage"}),
        "enforcer-coverage": frozenset({"coverage"}),
        "control": frozenset({"records", "coverage"}),
        "recovery": frozenset({"records", "coverage"}),
    }
)

_WRAPPED_KEY_FIELDS = {
    "wrap_version",
    "algorithm",
    "project_id",
    "capability",
    "data_kid",
    "wrapper_id",
    "wrapper_generation",
    "nonce",
    "wrapped_key",
}
_WRAPPED_KEY_AAD_FIELDS = _WRAPPED_KEY_FIELDS - {"nonce", "wrapped_key"}
_KEYRING_FIELDS = {"keyring_version", "keys"}


class KeyringError(ValueError):
    """Base class for rejected wrapped-key copies and keyrings."""


class KeyringFormatError(KeyringError):
    """Keyring bytes or wrapped-key fields do not have the required form."""


class KeyringContextError(KeyringError):
    """A wrapped key does not match its caller-derived context."""


class UnknownWrappingKeyError(KeyringError):
    """No wrapping key matches a copy's exact wrapper and generation."""


class KeyringAuthenticationError(KeyringError):
    """AES-GCM authentication failed for a wrapped key copy."""


# These aliases make the error boundary explicit to callers that name the
# individual wrapped-key operation rather than the keyring container.
WrappedKeyError = KeyringError
WrappedKeyFormatError = KeyringFormatError
WrappedKeyContextError = KeyringContextError
WrappedKeyAuthenticationError = KeyringAuthenticationError


def _project_id(
    value: str, *, error: type[KeyringError] = KeyringContextError
) -> str:
    if type(value) is not str or not value:
        raise error("project_id must be a non-empty string")
    return value


def _generation(value: str) -> str:
    if type(value) is not str or not value:
        raise KeyringContextError("wrapper_generation must be a non-empty string")
    return value


def _exact_bytes(value: bytes, *, length: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise KeyringFormatError(f"{label} must be exactly {length} bytes")
    return value


def _capability(value: str) -> str:
    if type(value) is not str or value not in CAPABILITIES:
        raise KeyringContextError("capability is not supported")
    return value


def _wrapper_id(value: str) -> str:
    if type(value) is not str or value not in WRAPPER_IDS:
        raise KeyringContextError("wrapper_id is not supported")
    return value


def _check_pair(capability: str, wrapper_id: str) -> None:
    if capability not in WRAPPER_CAPABILITIES[wrapper_id]:
        raise KeyringContextError("capability and wrapper_id are not compatible")


def _copy_object(copy: "WrappedKeyCopy") -> dict[str, Any]:
    """Return the JSON data model after the caller has type-checked a copy."""

    return {
        "wrap_version": copy.wrap_version,
        "algorithm": copy.algorithm,
        "project_id": copy.project_id,
        "capability": copy.capability,
        "data_kid": copy.data_kid,
        "wrapper_id": copy.wrapper_id,
        "wrapper_generation": copy.wrapper_generation,
        "nonce": copy.nonce,
        "wrapped_key": copy.wrapped_key,
    }


def _validate_copy(copy: "WrappedKeyCopy") -> "WrappedKeyCopy":
    """Validate every immutable field before using it as crypto input."""

    if type(copy) is not WrappedKeyCopy:
        raise KeyringFormatError("value must be a WrappedKeyCopy")
    if type(copy.wrap_version) is not int or copy.wrap_version != WRAP_VERSION:
        raise KeyringFormatError("unsupported wrap_version")
    if type(copy.algorithm) is not str or copy.algorithm != WRAPPED_KEY_ALGORITHM:
        raise KeyringFormatError("unsupported wrapped-key algorithm")
    _project_id(copy.project_id)
    capability = _capability(copy.capability)
    wrapper_id = _wrapper_id(copy.wrapper_id)
    _check_pair(capability, wrapper_id)
    _generation(copy.wrapper_generation)
    for field, length in (
        ("data_kid", KEY_ID_BYTES),
        ("nonce", NONCE_BYTES),
        ("wrapped_key", DATA_KEY_BYTES + TAG_BYTES),
    ):
        value = getattr(copy, field)
        if type(value) is not str:
            raise KeyringFormatError(f"{field} must be a base64url string")
        try:
            base64url_decode(value, expected_length=length, label=field)
        except Base64UrlError as error:
            raise KeyringFormatError(
                f"{field} is not a valid wrapped-key encoding"
            ) from error
    return copy


def _copy_canonical_bytes(copy: "WrappedKeyCopy") -> bytes:
    return canonical_json(_copy_object(_validate_copy(copy)))


@dataclass(frozen=True, slots=True)
class WrappedKeyCopy:
    """One canonical, authenticated copy of a project data key.

    Binary fields are stored in their canonical unpadded base64url form so the
    model mirrors the on-disk object without retaining raw key material.
    """

    project_id: str
    capability: str
    data_kid: str
    wrapper_id: str
    wrapper_generation: str
    nonce: str
    wrapped_key: str
    wrap_version: int = WRAP_VERSION
    algorithm: str = WRAPPED_KEY_ALGORITHM

    def __post_init__(self) -> None:
        _validate_copy(self)

    @property
    def canonical_bytes(self) -> bytes:
        """Return this object's exact RFC 8785 UTF-8 bytes."""

        return _copy_canonical_bytes(self)


@dataclass(frozen=True, slots=True)
class Keyring:
    """An immutable sequence of wrapped-key copies."""

    keys: tuple[WrappedKeyCopy, ...]

    def __post_init__(self) -> None:
        if isinstance(self.keys, (str, bytes, bytearray)) or not isinstance(
            self.keys, Iterable
        ):
            raise KeyringFormatError(
                "keys must be an iterable of WrappedKeyCopy values"
            )
        values = tuple(self.keys)
        for copy in values:
            _validate_copy(copy)
        object.__setattr__(self, "keys", values)

    @property
    def canonical_bytes(self) -> bytes:
        """Return this keyring's exact RFC 8785 UTF-8 bytes."""

        return _encode_keyring_values(self.keys)


def _wrap_aad_object(copy: WrappedKeyCopy) -> dict[str, Any]:
    _validate_copy(copy)
    return {
        name: value
        for name, value in _copy_object(copy).items()
        if name in _WRAPPED_KEY_AAD_FIELDS
    }


def wrapped_key_aad(copy: WrappedKeyCopy) -> bytes:
    """Return the exact canonical AAD for one wrapped-key copy."""

    return canonical_json(_wrap_aad_object(copy))


def wrap_key_copy(
    data_key: bytes,
    *,
    project_id: str,
    capability: str,
    data_kid: bytes,
    wrapper_id: str,
    wrapper_generation: str,
    wrapping_key: bytes,
) -> WrappedKeyCopy:
    """Encrypt one 32-byte data key under one 32-byte wrapping key."""

    data_key = _exact_bytes(data_key, length=DATA_KEY_BYTES, label="data_key")
    wrapping_key = _exact_bytes(
        wrapping_key, length=DATA_KEY_BYTES, label="wrapping_key"
    )
    data_kid = _exact_bytes(data_kid, length=KEY_ID_BYTES, label="data_kid")
    project_id = _project_id(project_id)
    capability = _capability(capability)
    wrapper_id = _wrapper_id(wrapper_id)
    _check_pair(capability, wrapper_id)
    wrapper_generation = _generation(wrapper_generation)
    nonce = _exact_bytes(
        secrets.token_bytes(NONCE_BYTES), length=NONCE_BYTES, label="nonce"
    )
    copy = WrappedKeyCopy(
        project_id=project_id,
        capability=capability,
        data_kid=base64url_encode(data_kid),
        wrapper_id=wrapper_id,
        wrapper_generation=wrapper_generation,
        nonce=base64url_encode(nonce),
        # The AAD omits wrapped_key, but the immutable model still requires a
        # complete canonical field set while the ciphertext is being made.
        wrapped_key=base64url_encode(bytes(DATA_KEY_BYTES + TAG_BYTES)),
    )
    wrapped = AESGCM(wrapping_key).encrypt(
        nonce,
        data_key,
        canonical_json(_wrap_aad_object(copy)),
    )
    return WrappedKeyCopy(
        project_id=copy.project_id,
        capability=copy.capability,
        data_kid=copy.data_kid,
        wrapper_id=copy.wrapper_id,
        wrapper_generation=copy.wrapper_generation,
        nonce=copy.nonce,
        wrapped_key=base64url_encode(wrapped),
    )


def _wrapping_key_for(
    wrapping_keys: Mapping[tuple[str, str], bytes], key_id: tuple[str, str]
) -> bytes:
    if not isinstance(wrapping_keys, Mapping):
        raise TypeError(
            "wrapping_keys must map (wrapper_id, wrapper_generation) to raw keys"
        )
    # Membership is deliberately checked before indexing.  In particular, a
    # defaultdict must not manufacture a key for an unknown wrapper generation.
    if key_id not in wrapping_keys:
        raise UnknownWrappingKeyError("unknown wrapping key")
    try:
        key = wrapping_keys[key_id]
    except KeyError as error:
        raise UnknownWrappingKeyError("unknown wrapping key") from error
    return _exact_bytes(key, length=DATA_KEY_BYTES, label="wrapping_key")


def unwrap_key_copy(
    copy: WrappedKeyCopy,
    *,
    expected_project_id: str,
    expected_capability: str,
    wrapping_keys: Mapping[tuple[str, str], bytes],
) -> bytes:
    """Authenticate and decrypt one copy in caller-derived context."""

    copy = _validate_copy(copy)
    expected_project_id = _project_id(expected_project_id)
    expected_capability = _capability(expected_capability)
    if copy.project_id != expected_project_id:
        raise KeyringContextError("wrapped key project does not match expected context")
    if copy.capability != expected_capability:
        raise KeyringContextError(
            "wrapped key capability does not match expected context"
        )
    key = _wrapping_key_for(
        wrapping_keys, (copy.wrapper_id, copy.wrapper_generation)
    )
    # _validate_copy above proves both encodings canonical and the wrapped
    # ciphertext length exact before these values become cryptographic input.
    nonce = base64url_decode(copy.nonce, expected_length=NONCE_BYTES, label="nonce")
    wrapped = base64url_decode(
        copy.wrapped_key,
        expected_length=DATA_KEY_BYTES + TAG_BYTES,
        label="wrapped_key",
    )
    try:
        data_key = AESGCM(key).decrypt(
            nonce, wrapped, wrapped_key_aad(copy)
        )
    except InvalidTag as error:
        raise KeyringAuthenticationError("wrapped-key authentication failed") from error
    # AES-GCM preserves the plaintext length; the validated 48-byte wrapped
    # field therefore yields exactly the required 32-byte data key.
    return data_key


def _explicit_values(
    values: Collection[str], *, vocabulary: frozenset[str], label: str
) -> frozenset[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(
        values, Collection
    ):
        raise TypeError(f"{label} must be an explicit collection")
    try:
        normalized = frozenset(values)
    except (TypeError, ValueError) as error:
        raise KeyringContextError(
            f"{label} contains an unsupported value"
        ) from error
    if any(type(value) is not str or value not in vocabulary for value in normalized):
        raise KeyringContextError(f"{label} contains an unsupported value")
    return normalized


def _validate_generation_map(
    known_generations: Mapping[str, Collection[str]],
) -> None:
    if not isinstance(known_generations, Mapping):
        raise TypeError(
            "known_generations must map wrapper IDs to explicit collections"
        )
    for wrapper_id, generations in known_generations.items():
        if type(wrapper_id) is not str or wrapper_id not in WRAPPER_IDS:
            raise KeyringContextError(
                "known_generations contains an unsupported wrapper"
            )
        if isinstance(generations, (str, bytes, bytearray)) or not isinstance(
            generations, Collection
        ):
            raise TypeError("known_generations values must be explicit collections")
        if any(
            type(generation) is not str or not generation
            for generation in generations
        ):
            raise KeyringContextError(
                "known_generations contains an invalid generation"
            )


def _parse_keyring(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes:
        raise TypeError("keyring input must be bytes")
    try:
        value = parse_canonical_json(data)
    except (CanonicalJsonError, TypeError) as error:
        raise KeyringFormatError(
            "keyring must be exact canonical JSON bytes"
        ) from error
    if type(value) is not dict or set(value) != _KEYRING_FIELDS:
        raise KeyringFormatError("keyring has missing or extra fields")
    if type(value["keyring_version"]) is not int:
        raise KeyringFormatError("keyring_version has an invalid type")
    if value["keyring_version"] != KEYRING_VERSION:
        raise KeyringFormatError("unsupported keyring_version")
    if type(value["keys"]) is not list:
        raise KeyringFormatError("keyring keys must be an array")
    return value


def _copy_from_object(value: Any) -> WrappedKeyCopy:
    if type(value) is not dict or set(value) != _WRAPPED_KEY_FIELDS:
        raise KeyringFormatError("wrapped-key object has missing or extra fields")
    scalar_types = {
        "wrap_version": int,
        "algorithm": str,
        "project_id": str,
        "capability": str,
        "data_kid": str,
        "wrapper_id": str,
        "wrapper_generation": str,
        "nonce": str,
        "wrapped_key": str,
    }
    if any(type(value[name]) is not kind for name, kind in scalar_types.items()):
        raise KeyringFormatError("wrapped-key fields have invalid JSON types")
    return WrappedKeyCopy(**value)


def decode_keyring(
    data: bytes,
    *,
    expected_project_id: str,
    allowed_capabilities: Collection[str],
    allowed_wrappers: Collection[str],
    known_generations: Mapping[str, Collection[str]],
) -> Keyring:
    """Parse and validate a canonical keyring in caller-derived context."""

    expected_project_id = _project_id(expected_project_id)
    allowed_capabilities = _explicit_values(
        allowed_capabilities, vocabulary=CAPABILITIES, label="allowed_capabilities"
    )
    allowed_wrappers = _explicit_values(
        allowed_wrappers, vocabulary=WRAPPER_IDS, label="allowed_wrappers"
    )
    _validate_generation_map(known_generations)
    value = _parse_keyring(data)
    copies: list[WrappedKeyCopy] = []
    identities: set[tuple[str, str, str]] = set()
    encoded_entries: list[bytes] = []
    for entry in value["keys"]:
        copy = _copy_from_object(entry)
        if copy.project_id != expected_project_id:
            raise KeyringContextError(
                "wrapped key project does not match expected context"
            )
        if copy.capability not in allowed_capabilities:
            raise KeyringContextError("wrapped key capability is not allowed")
        if copy.wrapper_id not in allowed_wrappers:
            raise KeyringContextError("wrapped key wrapper is not allowed")
        # Test membership before indexing so a missing wrapper cannot trigger a
        # defaultdict fallback or other implicit key creation.
        if copy.wrapper_id not in known_generations:
            raise KeyringContextError("wrapped key wrapper has no known generations")
        try:
            generations = known_generations[copy.wrapper_id]
        except KeyError as error:
            raise KeyringContextError(
                "wrapped key wrapper has no known generations"
            ) from error
        if copy.wrapper_generation not in generations:
            raise KeyringContextError("wrapped key generation is not known")
        identity = (copy.capability, copy.data_kid, copy.wrapper_id)
        if identity in identities:
            raise KeyringFormatError(
                "keyring contains a duplicate wrapped-key identity"
            )
        identities.add(identity)
        copies.append(copy)
        encoded_entries.append(copy.canonical_bytes)
    if encoded_entries != sorted(encoded_entries):
        raise KeyringFormatError("keyring keys are not in canonical order")
    return Keyring(tuple(copies))


def _encode_keyring_values(copies: Iterable[WrappedKeyCopy]) -> bytes:
    values = tuple(copies)
    identities: set[tuple[str, str, str]] = set()
    encoded: list[tuple[bytes, dict[str, Any]]] = []
    for copy in values:
        copy = _validate_copy(copy)
        identity = (copy.capability, copy.data_kid, copy.wrapper_id)
        if identity in identities:
            raise KeyringFormatError(
                "keyring contains a duplicate wrapped-key identity"
            )
        identities.add(identity)
        encoded.append((copy.canonical_bytes, _copy_object(copy)))
    encoded.sort(key=lambda item: item[0])
    return canonical_json(
        {"keyring_version": KEYRING_VERSION, "keys": [item[1] for item in encoded]}
    )


def encode_keyring(copies: Iterable[WrappedKeyCopy] | Keyring) -> bytes:
    """Return canonical bytes for copies sorted by individual object bytes."""

    if isinstance(copies, Keyring):
        values = copies.keys
    elif isinstance(copies, (str, bytes, bytearray)) or not isinstance(
        copies, Iterable
    ):
        raise TypeError("copies must be an iterable of WrappedKeyCopy values")
    else:
        values = copies
    return _encode_keyring_values(values)
