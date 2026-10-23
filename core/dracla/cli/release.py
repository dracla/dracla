"""Validate installed release declarations before any credential acquisition.

The external manifest identifies declared final artifacts. It cannot identify
which artifact a parent installer selected or authenticate a compromised package.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import metadata, resources
import ipaddress
import re
import time
from typing import Callable
from urllib import error, parse, request

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version

from dracla.conformance.canonical import parse_canonical_json

_MAX_BYTES = 1024 * 1024
_TIMEOUT = 10
_ATTEMPTS = 4
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", re.ASCII)
_POLICY_KEYS = {"release_policy_version", "package_version", "source_commit_oid", "provenance_identity",
                "dependency_constraints_sha256", "allowed_artifacts_url"}
_MANIFEST_KEYS = {"allowed_artifacts_version", "package_version", "release_policy_sha256",
                  "source_commit_oid", "provenance_identity", "dependency_constraints_sha256", "artifacts"}


class ReleaseError(ValueError):
    """Invalid or unavailable release evidence; message contains no input data."""


@dataclass(frozen=True)
class ReleaseIdentity:
    package_version: str
    source_commit_oid: str
    provenance_identity: str
    policy_sha256: str
    dependency_constraints_sha256: str
    manifest_sha256: str


def _fail() -> None:
    raise ReleaseError("Release evidence is unavailable or invalid; no authorization was requested")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _url_origin(url: str) -> tuple[str, int]:
    if not _text(url) or any(c.isspace() for c in url) or "\\" in url:
        _fail()
    u = parse.urlsplit(url)
    if (u.scheme != "https" or not u.hostname or u.username is not None or u.password is not None
            or u.query or u.fragment or "?" in url or "#" in url or not u.path or u.path == "/"):
        _fail()
    host = u.hostname.casefold()
    if host == "localhost" or host.endswith((".localhost", ".local")) or "." not in host:
        _fail()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host, re.ASCII):
            _fail()
    else:
        if not address.is_global:
            _fail()
    return host, u.port or 443


class _SameOriginRedirect(request.HTTPRedirectHandler):
    def __init__(self, origin: tuple[str, int]):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _url_origin(newurl) != self.origin:
            _fail()
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_manifest(url: str, *, opener_factory=request.build_opener, sleep=time.sleep) -> bytes:
    """Public HTTPS only, same-origin redirects, finite reads and four attempts."""
    try:
        origin = _url_origin(url)
        # No ambient proxy credentials, cookie processor, persistent cache or auth.
        opener = opener_factory(request.ProxyHandler({}), _SameOriginRedirect(origin))
        for attempt in range(_ATTEMPTS):
            try:
                req = request.Request(url, headers={"Accept": "application/json"}, method="GET")
                with opener.open(req, timeout=_TIMEOUT) as response:
                    if response.status != 200 or _url_origin(response.geturl()) != origin:
                        _fail()
                    data = response.read(_MAX_BYTES + 1)
                    if type(data) is not bytes or not data or len(data) > _MAX_BYTES:
                        _fail()
                    return data
            except error.HTTPError as exc:
                exc.close()
                if exc.code not in {429, 500, 502, 503, 504} or attempt == _ATTEMPTS - 1:
                    _fail()
            except (error.URLError, TimeoutError, OSError):
                if attempt == _ATTEMPTS - 1:
                    _fail()
            sleep(0.1 * (2 ** attempt))
    except ReleaseError:
        raise
    except Exception:
        _fail()


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
    return resources.files("dracla").joinpath(name).read_bytes()


def load_release_policy(*, read_resource=_package_resource, distribution=metadata.distribution,
                        fetch=fetch_manifest) -> ReleaseIdentity:
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
        _url_origin(policy["allowed_artifacts_url"])
        # Bind the locator to the exact version as a complete decoded URL segment.
        if not {version, "v" + version}.intersection(parse.unquote(parse.urlsplit(policy["allowed_artifacts_url"]).path).split("/")):
            _fail()
        constraints_data = read_resource("dependency-constraints.txt")
        if _sha(constraints_data) != policy["dependency_constraints_sha256"]:
            _fail()
        _runtime_closure(root, distribution, _constraints(constraints_data))
        manifest_data = fetch(policy["allowed_artifacts_url"])
        manifest = _closed_json(manifest_data, _MANIFEST_KEYS, "allowed_artifacts_version")
        policy_digest = _sha(policy_data)
        for key in ("package_version", "source_commit_oid", "provenance_identity", "dependency_constraints_sha256"):
            if manifest[key] != policy[key]:
                _fail()
        if manifest["release_policy_sha256"] != policy_digest:
            _fail()
        artifacts = manifest["artifacts"]
        if type(artifacts) is not list or not artifacts:
            _fail()
        filenames = []
        for artifact in artifacts:
            if type(artifact) is not dict or set(artifact) != {"filename", "sha256"}:
                _fail()
            filename = artifact["filename"]
            if (not _text(filename) or not filename.isascii() or "/" in filename or "\\" in filename
                    or not re.fullmatch(r"[A-Za-z0-9_.+-]+", filename, re.ASCII)
                    or type(artifact["sha256"]) is not str or not _DIGEST.fullmatch(artifact["sha256"])):
                _fail()
            if filename.endswith(".whl"):
                name, artifact_version, _, _ = parse_wheel_filename(filename)
            else:
                name, artifact_version = parse_sdist_filename(filename)
            if canonicalize_name(name) != "dracla" or artifact_version != Version(version):
                _fail()
            filenames.append(filename)
        if filenames != sorted(set(filenames)):
            _fail()
        return ReleaseIdentity(version, policy["source_commit_oid"], policy["provenance_identity"],
                               policy_digest, policy["dependency_constraints_sha256"], _sha(manifest_data))
    except ReleaseError:
        raise
    except Exception:
        _fail()
