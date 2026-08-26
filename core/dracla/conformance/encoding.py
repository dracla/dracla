"""Strict shared encodings used by revision-13 byte contracts."""

from __future__ import annotations

import base64
import binascii


class Base64UrlError(ValueError):
    """A value is not canonical unpadded RFC 4648 base64url."""


def base64url_encode(value: bytes) -> str:
    """Encode exact bytes with the URL-safe alphabet and no padding."""

    if type(value) is not bytes:
        raise TypeError("base64url input must be bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(
    value: str,
    *,
    expected_length: int | None = None,
    label: str = "value",
) -> bytes:
    """Decode only the unique unpadded base64url representation."""

    if type(value) is not str:
        raise Base64UrlError(f"{label} must be a base64url string")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise Base64UrlError(
            f"{label} is not canonical unpadded base64url"
        ) from error
    if base64url_encode(decoded) != value:
        raise Base64UrlError(f"{label} is not canonical unpadded base64url")
    if expected_length is not None and len(decoded) != expected_length:
        raise Base64UrlError(f"{label} must encode exactly {expected_length} bytes")
    return decoded
