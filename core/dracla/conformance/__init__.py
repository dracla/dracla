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

