"""Explicit operator and protected-installation credentials for records I/O."""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dracla.administration import RepositoryRef, numeric_id
from dracla.conformance import base64url_encode
from dracla.github_admin import API_ORIGIN, API_VERSION, HttpResponse, send


class RecordsError(ValueError):
    """A fixed, non-private failure category; never contains provider payloads."""

    def __init__(self, category: str = "records-unavailable"):
        allowed = {"records-unavailable", "identity-mismatch", "scope-mismatch", "invalid-history",
                   "invalid-bootstrap", "invalid-key", "projection-mismatch", "reader-denied",
                   "resource-limit", "snapshot-changed", "invalid-configuration"}
        self.category = category if category in allowed else "records-unavailable"
        super().__init__(self.category)


class AuthorizationFailure(RecordsError):
    """A rejected token; callers must recheck identity before retrying a read."""


def unique_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise RecordsError() from None


def opaque_token(value: object) -> str:
    if type(value) is not str or not value or not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise RecordsError()
    return value


def request_json(sender: Callable, method: str, path: str, token: str,
                 body: dict | None = None, *, timeout: float = 10.0, paginated: bool = False):
    """Return JSON, plus response headers when the caller checks pagination."""
    if not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n#"):
        raise RecordsError("invalid-configuration")
    try:
        response = sender(method, API_ORIGIN + path,
                          {"Authorization": "Bearer " + opaque_token(token),
                           "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                           "User-Agent": "DraCLA-records"}, timeout,
                          None if body is None else json.dumps(body, separators=(",", ":")).encode())
        if not isinstance(response, HttpResponse) or len(response.body) > 1024 * 1024:
            raise RecordsError("resource-limit")
        if response.status in (401, 403):
            raise AuthorizationFailure()
        if response.status != (201 if method == "POST" else 200):
            raise RecordsError()
        if not paginated and any(str(k).lower() == "link" and str(v).strip()
                                 for k, v in response.headers.items()):
            raise RecordsError("scope-mismatch")
        value = unique_json(response.body)
        return (value, dict(response.headers)) if paginated else value
    except RecordsError:
        raise
    except Exception:
        raise RecordsError() from None


def inventory_page_links(headers: Mapping, page: int) -> dict[str, int]:
    """Check GitHub's page relations without following a supplied URL."""
    values = [value for key, value in headers.items() if str(key).lower() == "link"]
    if not values:
        return {}
    if len(values) != 1 or type(values[0]) is not str:
        raise RecordsError("scope-mismatch")
    relations = {}
    for link in values[0].split(",") if values[0].strip() else ():
        match = re.fullmatch(r'\s*<([^<>\s]+)>\s*;\s*rel="(next|prev|first|last)"\s*', link)
        if match is None or match[2] in relations:
            raise RecordsError("scope-mismatch")
        try:
            url = urlsplit(match[1])
            query = parse_qs(url.query, strict_parsing=True)
            number = query["page"][0]
            if (url.scheme != "https" or url.netloc != "api.github.com"
                    or url.path != "/installation/repositories" or url.fragment
                    or set(query) != {"page", "per_page"} or query["per_page"] != ["100"]
                    or query["page"] != [number] or not re.fullmatch(r"[1-9][0-9]*", number)):
                raise ValueError()
            target = int(number)
            relation = match[2]
            if (relation == "next" and target != page + 1
                    or relation == "prev" and target != page - 1
                    or relation == "first" and target != 1
                    or relation == "last" and target < page):
                raise ValueError()
        except (ValueError, KeyError, IndexError):
            raise RecordsError("scope-mismatch") from None
        relations[relation] = target
    has_next = "next" in relations
    if "last" in relations and (relations["last"] > page) != has_next:
        raise RecordsError("scope-mismatch")
    return relations


@dataclass(frozen=True)
class ProjectBinding:
    project_id: str
    owner_id: int
    repositories: tuple[RepositoryRef, ...]

    def __post_init__(self):
        numeric_id(self.owner_id)
        if type(self.project_id) is not str or not self.project_id:
            raise RecordsError("invalid-configuration")
        if (type(self.repositories) is not tuple or len(self.repositories) != 3
                or any(type(r) is not RepositoryRef for r in self.repositories)
                or tuple(r.role for r in self.repositories) != ("records", "coverage", "control")
                or len({r.id for r in self.repositories}) != 3
                or len({(r.owner, r.name) for r in self.repositories}) != 3
                or len({r.owner for r in self.repositories}) != 1):
            raise RecordsError("invalid-configuration")

    def repo(self, role: str) -> RepositoryRef:
        for repo in self.repositories:
            if repo.role == role:
                return repo
        raise RecordsError("scope-mismatch")

    def ids(self) -> dict[str, int]:
        return {r.role: r.id for r in self.repositories}

    @property
    def data_ids(self) -> tuple[int, int]:
        return self.repo("records").id, self.repo("coverage").id


class OperatorCredentials:
    """Operator mode is selected explicitly, never as an App failure fallback."""

    mode = "operator"

    def __init__(self, credential_provider: Callable[[], str | None], *, sender: Callable = send):
        self._provider, self.sender = credential_provider, sender
        self._credential = None
        self.user_id: int | None = None
        self.login: str | None = None

    def __repr__(self):
        return "OperatorCredentials()"

    def authorize(self, binding: ProjectBinding):
        self._credential = None
        try:
            credential = opaque_token(self._provider())
        except Exception:
            raise RecordsError() from None
        user = request_json(self.sender, "GET", "/user", credential)
        try:
            identity = numeric_id(user["id"])
            from dracla.administration import login
            name = login(user["login"])
        except (ValueError, TypeError, KeyError):
            raise RecordsError("identity-mismatch") from None
        if self.user_id is not None and identity != self.user_id:
            raise RecordsError("identity-mismatch")
        self._credential, self.user_id, self.login = credential, identity, name

    def token(self) -> str:
        return opaque_token(self._credential)


@dataclass(frozen=True)
class InstallationBinding:
    """Protected control configuration; never reconstructed from business data."""

    app_id: int
    client_id: str
    installation_id: int
    owner_id: int
    assignments: tuple[tuple[str, tuple[int, int]], ...]
    excluded_repository_ids: tuple[int, ...]

    def __post_init__(self):
        for value in (self.app_id, self.installation_id, self.owner_id):
            numeric_id(value)
        opaque_token(self.client_id)
        if (type(self.assignments) is not tuple or not self.assignments
                or any(type(a) is not tuple or len(a) != 2 for a in self.assignments)
                or type(self.excluded_repository_ids) is not tuple
                or len(set(self.excluded_repository_ids)) != len(self.excluded_repository_ids)):
            raise RecordsError("invalid-configuration")
        if len({a[0] for a in self.assignments}) != len(self.assignments):
            raise RecordsError("invalid-configuration")
        ids = []
        for project, pair in self.assignments:
            if type(project) is not str or not project or type(pair) is not tuple or len(pair) != 2:
                raise RecordsError("invalid-configuration")
            for value in pair:
                numeric_id(value)
            ids.extend(pair)
        for value in self.excluded_repository_ids:
            numeric_id(value)
        if len(set(ids)) != len(ids) or not self.excluded_repository_ids or set(ids).intersection(self.excluded_repository_ids):
            raise RecordsError("scope-mismatch")


class InstallationCredentials:
    """Verify the full installation; mint separate arrangement-scoped tokens."""

    mode = "control"
    _permissions = {"contents": "write", "metadata": "read"}

    def __init__(self, protected: InstallationBinding, private_key_provider: Callable[[], bytes], *,
                 sender: Callable = send, clock: Callable[[], float] = time.time, margin: int = 60,
                 contents: str = 'read'):
        if (type(protected) is not InstallationBinding or type(margin) is not int or not 0 < margin <= 300
                or contents not in ('read', 'write')):
            raise RecordsError("invalid-configuration")
        self.protected, self._provider, self.sender, self._clock = protected, private_key_provider, sender, clock
        self._requested = {'contents': contents, 'metadata': 'read'}
        self._margin, self._credential, self._expiry, self._binding = margin, None, 0.0, None

    def __repr__(self):
        return f"InstallationCredentials(app_id={self.protected.app_id}, installation_id={self.protected.installation_id})"

    def _jwt(self):
        try:
            now = int(self._clock())
            key = serialization.load_pem_private_key(self._provider(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
                raise RecordsError()
            header = base64url_encode(b'{"alg":"RS256","typ":"JWT"}')
            payload = base64url_encode(json.dumps({"iat": now - 60, "exp": now + 540,
                                                  "iss": self.protected.client_id}, separators=(",", ":")).encode())
            signed = (header + "." + payload).encode()
            return signed.decode() + "." + base64url_encode(key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))
        except Exception:
            raise RecordsError() from None

    def _mint(self, jwt: str, repositories: tuple[int, ...] | None, permissions: dict):
        body = {"permissions": permissions}
        if repositories is not None:
            body["repository_ids"] = list(repositories)
        value = request_json(self.sender, "POST", f"/app/installations/{self.protected.installation_id}/access_tokens", jwt, body)
        try:
            token = opaque_token(value["token"])
            expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
            now = self._clock()
            if expiry.tzinfo is None or expiry.utcoffset() != timezone.utc.utcoffset(expiry):
                raise RecordsError()
            expiry = expiry.timestamp()
            if (not math.isfinite(now) or not now + self._margin < expiry <= now + 3600 + self._margin
                    or value["permissions"] != permissions or value["repository_selection"] != "selected"):
                raise RecordsError("scope-mismatch")
            return token, expiry
        except (KeyError, TypeError, ValueError, AttributeError):
            raise RecordsError("scope-mismatch") from None

    def authorize(self, binding: ProjectBinding):
        self._credential, self._expiry, self._binding = None, 0.0, None
        p = self.protected
        if (binding.owner_id != p.owner_id or (binding.project_id, binding.data_ids) not in p.assignments
                or binding.repo("control").id not in p.excluded_repository_ids):
            raise RecordsError("scope-mismatch")
        jwt = self._jwt()
        app = request_json(self.sender, "GET", "/app", jwt)
        installs = request_json(self.sender, "GET", "/app/installations?per_page=100&page=1", jwt)
        installation = request_json(self.sender, "GET", f"/app/installations/{p.installation_id}", jwt)
        try:
            if (numeric_id(app["id"]) != p.app_id or app["client_id"] != p.client_id or numeric_id(app["owner"]["id"]) != p.owner_id
                    or app["permissions"] != self._permissions or app["events"] != []
                    or type(installs) is not list or len(installs) != 1 or numeric_id(installs[0]["id"]) != p.installation_id
                    or numeric_id(installation["id"]) != p.installation_id or numeric_id(installation["app_id"]) != p.app_id
                    or numeric_id(installation["account"]["id"]) != p.owner_id or numeric_id(installation["target_id"]) != p.owner_id
                    or installation["repository_selection"] != "selected" or installation["suspended_at"] is not None
                    or installation["permissions"] != self._permissions or installation["events"] != []):
                raise RecordsError("scope-mismatch")
            inventory_token, _ = self._mint(jwt, None, {"contents": "read", "metadata": "read"})
            expected = {repo_id for _, pair in p.assignments for repo_id in pair}
            found, total, last_page = set(), None, None
            for page in range(1, 1001):
                result, headers = request_json(self.sender, "GET", f"/installation/repositories?per_page=100&page={page}", inventory_token,
                                               paginated=True)
                count, repos = result["total_count"], result["repositories"]
                if type(count) is not int or count < 0 or type(repos) is not list or len(repos) > 100 or (total is not None and total != count):
                    raise RecordsError("scope-mismatch")
                total = count
                for repo in repos:
                    repo_id = numeric_id(repo["id"])
                    if repo_id in found or repo_id not in expected or repo["private"] is not True or numeric_id(repo["owner"]["id"]) != p.owner_id:
                        raise RecordsError("scope-mismatch")
                    found.add(repo_id)
                links = inventory_page_links(headers, page)
                if "last" in links:
                    if last_page is not None and links["last"] != last_page:
                        raise RecordsError("scope-mismatch")
                    last_page = links["last"]
                if (("next" in links) != (len(found) < total)
                        or last_page is not None and (page < last_page) != (len(found) < total)):
                    raise RecordsError("scope-mismatch")
                if len(found) == total:
                    break
                if not repos or len(found) > total:
                    raise RecordsError("scope-mismatch")
            else:
                raise RecordsError("resource-limit")
            if found != expected:
                raise RecordsError("scope-mismatch")
            self._credential, self._expiry = self._mint(jwt, binding.data_ids, self._requested)
            self._binding = binding
        except RecordsError:
            self._credential, self._expiry, self._binding = None, 0.0, None
            raise
        except (ValueError, KeyError, TypeError):
            self._credential, self._expiry, self._binding = None, 0.0, None
            raise RecordsError("scope-mismatch") from None

    def token(self) -> str:
        if self._binding is None:
            raise RecordsError("scope-mismatch")
        try:
            now = self._clock()
            if not math.isfinite(now):
                raise ValueError()
        except Exception:
            self._credential, self._expiry, self._binding = None, 0.0, None
            raise RecordsError() from None
        if now + self._margin >= self._expiry:
            self.authorize(self._binding)
        return opaque_token(self._credential)
