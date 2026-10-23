"""Check bundled release declarations and dependencies before credentials.

These local consistency checks do not authenticate the executing package.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import metadata, resources
import re
from typing import Callable

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from dracla.conformance.canonical import parse_canonical_json

_MAX_BYTES = 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", re.ASCII)
_POLICY_KEYS = {"release_policy_version", "package_version", "source_commit_oid", "provenance_identity",
                "dependency_constraints_sha256"}


class ReleaseError(ValueError):
    """Invalid or unavailable release evidence; message contains no input data."""


@dataclass(frozen=True)
class ReleaseIdentity:
    package_version: str
    source_commit_oid: str
    provenance_identity: str
    policy_sha256: str
    dependency_constraints_sha256: str


def _fail() -> None:
    raise ReleaseError("Release evidence is unavailable or invalid; no authorization was requested")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _closed_json(data: bytes, keys: set[str], version_key: str) -> dict:
    if type(data) is not bytes or not data or len(data) > _MAX_BYTES:
        _fail()
    obj = parse_canonical_json(data)
    if type(obj) is not dict or set(obj) != keys or type(obj[version_key]) is not int or obj[version_key] != 1:
        _fail()
    return obj


def _exact_version(value: object) -> str:
    if not _text(value) or str(Version(value)) != value:
        _fail()
    return value


def _constraints(data: bytes) -> dict[str, str]:
    if type(data) is not bytes or not data or len(data) > _MAX_BYTES or not data.endswith(b"\n") or b"\r" in data:
        _fail()
    pins = {}
    names = []
    for line in data.decode("utf-8").split("\n")[:-1]:
        if line.count("==") != 1:
            _fail()
        name, version = line.split("==")
        if canonicalize_name(name, validate=True) != name or name == "dracla" or name in pins:
            _fail()
        pins[name] = _exact_version(version)
        names.append(name)
    if names != sorted(names):
        _fail()
    return pins


def _runtime_closure(root, distribution: Callable, pins: dict[str, str]) -> None:
    """Follow active runtime requirements, including marker/extras propagation."""
    environment = default_environment()
    seen = {}
    pending = [("dracla", frozenset())]
    processed = {}
    distributions = {"dracla": root}
    while pending:
        name, extras = pending.pop()
        accumulated = processed.get(name, frozenset()) | extras
        if name in processed and accumulated == processed[name]:
            continue
        processed[name] = accumulated
        dist = distributions[name]
        if canonicalize_name(dist.metadata["Name"], validate=True) != name:
            _fail()
        version = _exact_version(dist.version)
        if name != "dracla":
            if pins.get(name) != version:
                _fail()
            seen[name] = version
        for value in dist.requires or ():
            req = Requirement(value)
            if req.marker is not None and not any(req.marker.evaluate({**environment, "extra": extra})
                                                  for extra in accumulated | {""}):
                continue
            if req.url is not None:
                _fail()
            dep_name = canonicalize_name(req.name, validate=True)
            dep = distributions.get(dep_name)
            if dep is None:
                dep = distribution(dep_name)
                distributions[dep_name] = dep
            if not req.specifier.contains(Version(dep.version), prereleases=True):
                _fail()
            pending.append((dep_name, frozenset(canonicalize_name(e) for e in req.extras)))
    if seen != pins:
        _fail()


def _package_resource(name: str) -> bytes:
    with resources.files("dracla").joinpath(name).open("rb") as stream:
        return stream.read(_MAX_BYTES + 1)


def load_release_policy(*, read_resource=_package_resource, distribution=metadata.distribution) -> ReleaseIdentity:
    """Read installed resources and metadata; never synthesize development proof."""
    try:
        root = distribution("dracla")
        policy_data = read_resource("release-policy.json")
        policy = _closed_json(policy_data, _POLICY_KEYS, "release_policy_version")
        version = _exact_version(policy["package_version"])
        if version != _exact_version(root.version):
            _fail()
        for key in _POLICY_KEYS - {"release_policy_version"}:
            if not _text(policy[key]):
                _fail()
        if not _OID.fullmatch(policy["source_commit_oid"]) or not _DIGEST.fullmatch(policy["dependency_constraints_sha256"]):
            _fail()
        constraints_data = read_resource("dependency-constraints.txt")
        if _sha(constraints_data) != policy["dependency_constraints_sha256"]:
            _fail()
        _runtime_closure(root, distribution, _constraints(constraints_data))
        policy_digest = _sha(policy_data)
        return ReleaseIdentity(version, policy["source_commit_oid"], policy["provenance_identity"],
                               policy_digest, policy["dependency_constraints_sha256"])
    except ReleaseError:
        raise
    except Exception:
        _fail()
