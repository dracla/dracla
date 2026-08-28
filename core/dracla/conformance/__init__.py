"""Revision-13 conformance primitives.

This package is deliberately separate from the legacy plaintext protocol
spike.  Its public values are byte-level contracts shared by every DraCLA
runtime.
"""

from .artifacts import (  # noqa: F401
    ArtifactIdentity,
    ArtifactIdentityError,
    override_key,
    resolve_artifact_identity,
    segment,
)
from .canonical import (  # noqa: F401
    CanonicalJsonError,
    NonCanonicalJsonError,
    canonical_json,
    parse_canonical_json,
)
from .encoding import (  # noqa: F401
    Base64UrlError,
    base64url_decode,
    base64url_encode,
)
from .envelope import (  # noqa: F401
    ArtifactAuthenticationError,
    ArtifactEnvelopeContextError,
    ArtifactEnvelopeError,
    ArtifactEnvelopeFormatError,
    UnknownArtifactKeyError,
    artifact_aad,
    decrypt_artifact,
    decrypt_json_artifact,
    encrypt_artifact,
    encrypt_json_artifact,
)
from .keyrings import (  # noqa: F401
    CAPABILITIES,
    KEYRING_VERSION,
    WRAPPER_CAPABILITIES,
    WRAPPER_IDS,
    WRAP_VERSION,
    Keyring,
    KeyringAuthenticationError,
    KeyringContextError,
    KeyringError,
    KeyringFormatError,
    UnknownWrappingKeyError,
    WrappedKeyAuthenticationError,
    WrappedKeyContextError,
    WrappedKeyCopy,
    WrappedKeyError,
    WrappedKeyFormatError,
    decode_keyring,
    encode_keyring,
    unwrap_key_copy,
    wrap_key_copy,
    wrapped_key_aad,
)
