"""Bounded GitHub administration reads. No records transport or installer engine."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
import time
from typing import Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from .administration import (AccountObservation, AccountRef, AdminScope, Permissions,
                             RateLimit, RepositoryMetadata, RepositoryObservation,
                             RepositoryPage, RepositoryRef, login)

API_ORIGIN = "https://api.github.com"
API_VERSION = "2022-11-28"
_MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(method: str, url: str, headers: Mapping[str, str], timeout: float) -> HttpResponse:
    """Do not follow redirects or persist response/credential data."""
    request = urllib.request.Request(url, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return HttpResponse(response.code, dict(response.headers.items()), response.read(_MAX_BYTES + 1))


def credentials_from_environment() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


class GitHubAdministration:
    def __init__(self, scope: AdminScope, *, credential_provider: Callable[[], str | None] = credentials_from_environment,
                 sender: Callable = send, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep, timeout: float = 10.0):
        if not isinstance(scope, AdminScope) or not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("Invalid administration configuration")
        self.scope = scope
        self._provider, self._sender, self._clock, self._sleep = credential_provider, sender, clock, sleep
        self._timeout = timeout
        self._account: AccountRef | None = None
        self._actor: AccountRef | None = None
        self._inventory_visible = False
        self._credential: str | None = None

    def __repr__(self) -> str:
        return f"GitHubAdministration(scope={self.scope!r})"

    @staticmethod
    def _rate(headers: Mapping[str, str], now: float, status: int) -> RateLimit:
        def integer(name):
            value = headers.get(name, "")
            return int(value) if type(value) is str and value.isascii() and value.isdigit() and len(value) <= 12 else None
        delay = integer("retry-after")
        reset = integer("x-ratelimit-reset")
        remaining = integer("x-ratelimit-remaining")
        retry_at = int(now) + delay if delay is not None else None
        if retry_at is None and (remaining == 0 or status == 429):
            retry_at = reset
        return RateLimit(remaining, retry_at)

    def _get(self, path: str) -> tuple[object | None, Mapping[str, str], str, RateLimit]:
        # Every path is built by a named operation from validated components.
        try:
            credential = self._credential if self._credential is not None else self._provider()
            if type(credential) is not str or not credential or not credential.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in credential):
                return None, {}, "GitHub credentials unavailable.", RateLimit()
            self._credential = credential
            headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                       "Authorization": "Bearer " + credential, "User-Agent": "DraCLA-administration"}
        except Exception:
            return None, {}, "GitHub credentials unavailable.", RateLimit()
        rate = RateLimit()
        for attempt in range(4):
            try:
                response = self._sender("GET", API_ORIGIN + path, headers, self._timeout)
                if not isinstance(response, HttpResponse) or type(response.status) is not int or not isinstance(response.body, bytes) or len(response.body) > _MAX_BYTES:
                    return None, {}, "Invalid or oversized GitHub response.", rate
                received = {k.lower(): v for k, v in response.headers.items() if type(k) is str and type(v) is str}
                rate = self._rate(received, self._clock(), response.status)
                if response.status == 200:
                    def unique(pairs):
                        result = {}
                        for key, value in pairs:
                            if key in result:
                                raise ValueError("Duplicate response field")
                            result[key] = value
                        return result
                    return json.loads(response.body.decode("utf-8"), object_pairs_hook=unique), received, "", rate
                if response.status == 404:
                    return None, {}, ("GitHub permission denied or rate limited." if "x-github-sso" in received
                                      else "Repository is missing or inaccessible."), rate
                if response.status in (401, 403):
                    return None, {}, "GitHub permission denied or rate limited.", rate
                if response.status == 429 or response.status in (500, 502, 503, 504):
                    if rate.retry_at is not None and rate.retry_at > self._clock() + 4:
                        return None, {}, "GitHub rate limit requires a later retry.", rate
                    if attempt < 3:
                        self._sleep(min(4.0, max(2.0 ** attempt, (rate.retry_at or 0) - self._clock())))
                        continue
                return None, {}, "GitHub read failed or redirect refused.", rate
            except (ValueError, UnicodeError, TypeError, AttributeError):
                return None, {}, "Invalid GitHub response.", rate
            except Exception:
                if attempt < 3:
                    self._sleep(2.0 ** attempt)
                    continue
        return None, {}, "GitHub read attempts exhausted.", rate

    @staticmethod
    def _account_ref(data: object) -> AccountRef:
        if not isinstance(data, dict):
            raise ValueError("Invalid account response")
        return AccountRef(data.get("login"), data.get("id"), data.get("type"))

    def resolve_account(self, owner: str) -> AccountObservation:
        owner = login(owner)
        if owner != self.scope.owner:
            raise ValueError("Account is outside the administration scope")
        self._account, self._actor, self._inventory_visible = None, None, False
        self._credential = None
        data, _, reason, rate = self._get("/users/" + owner)
        try:
            account = self._account_ref(data)
            if account.login != owner:
                raise ValueError("Account renamed")
        except ValueError:
            return AccountObservation(None, reason=reason or "Invalid account identity.", rate_limit=rate)
        self._account = account
        data, headers, reason, rate = self._get("/user")
        try:
            actor = self._account_ref(data)
            if actor.kind != "User":
                raise ValueError("Invalid authenticated actor")
        except ValueError:
            return AccountObservation(account, reason=reason or "Authenticated actor unavailable.", rate_limit=rate)
        self._account, self._actor = account, actor
        counts = data
        # A fine-grained token's visible subset is not proof of absence.
        full_repo = "repo" in {s.strip() for s in headers.get("x-oauth-scopes", "").split(",")}
        visible = full_repo and account == actor
        if account.kind == "Organization":
            data, member_headers, reason, rate = self._get(f"/orgs/{owner}/memberships/{actor.login}")
            try:
                organization = self._account_ref({**data["organization"], "type": "Organization"})
                member = self._account_ref(data["user"])
                visible = (full_repo and organization == account and member == actor
                           and data["state"] == "active" and data["role"] == "admin"
                           and "x-github-sso" not in member_headers)
            except (TypeError, KeyError, ValueError):
                visible = False
            counts, org_headers, _, rate = self._get(f"/orgs/{owner}")
            try:
                if self._account_ref({**counts, "type": "Organization"}) != account or "x-github-sso" in org_headers:
                    visible = False
            except (ValueError, TypeError):
                visible = False
        visible = visible and "x-github-sso" not in headers
        public_count = counts.get("public_repos") if isinstance(counts, dict) else None
        private_count = counts.get("owned_private_repos") if isinstance(counts, dict) else None
        counts_valid = all(type(v) is int and v >= 0 for v in (public_count, private_count))
        visible = visible and counts_valid
        self._inventory_visible = visible
        return AccountObservation(account, visible, "" if visible else "Complete private repository visibility and administration permission are unproved.", rate,
                                  public_count + private_count if counts_valid else None, private_count if counts_valid else None)

    def _metadata(self, data: object, account: AccountRef) -> RepositoryMetadata:
        if not isinstance(data, dict):
            raise ValueError("Invalid repository response")
        owner = self._account_ref(data.get("owner"))
        if owner != account:
            raise ValueError("Repository moved to another owner")
        permissions = data.get("permissions", {})
        if not isinstance(permissions, dict):
            raise ValueError("Invalid permission response")
        result = RepositoryMetadata(owner, data.get("name"), data.get("id"), data.get("private"),
                                    Permissions(*(permissions.get(p) for p in ("admin", "push", "pull"))))
        if data.get("full_name", "").casefold() != f"{owner.login}/{result.name}":
            raise ValueError("Repository full name changed")
        return result

    def get_repository(self, owner: str, name: str, *, expected: RepositoryRef | None = None) -> RepositoryObservation:
        role = self.scope.require(owner, name)
        owner, name = owner.casefold(), name.casefold()
        if expected is not None:
            self.scope.require(expected.owner, expected.name, expected.role)
            if (expected.role, expected.owner, expected.name) != (role, owner, name):
                raise ValueError("Repository reference does not match request")
        if self._account is None:
            return RepositoryObservation(owner, name, "unknown", reason="Account identity unavailable.")
        data, _, reason, rate = self._get(f"/repos/{owner}/{name}")
        if data is None:
            return RepositoryObservation(owner, name, "unknown", reason=reason, rate_limit=rate)
        try:
            metadata = self._metadata(data, self._account)
            if metadata.name != name or (expected is not None and metadata.id != expected.id):
                raise ValueError("Repository renamed or numeric identity changed")
            return RepositoryObservation(owner, name, "observed", metadata, rate_limit=rate)
        except (ValueError, TypeError, AttributeError):
            return RepositoryObservation(owner, name, "unknown", reason="Repository identity or metadata mismatch.", rate_limit=rate)

    def read_visibility(self, repository: RepositoryRef) -> RepositoryObservation:
        return self.get_repository(repository.owner, repository.name, expected=repository)

    def list_repositories(self, account: AccountRef, cursor: int = 1) -> RepositoryPage:
        if account != self._account or account.login != self.scope.owner:
            raise ValueError("Account identity does not match current discovery")
        if type(cursor) is not int or not 1 <= cursor <= 100:
            raise ValueError("Invalid repository page")
        if account.kind == "Organization":
            path = f"/orgs/{account.login}/repos?type=all&sort=full_name&direction=asc&per_page=100&page={cursor}"
        elif account == self._actor:
            path = f"/user/repos?visibility=all&affiliation=owner&sort=full_name&direction=asc&per_page=100&page={cursor}"
        else:
            path = f"/users/{account.login}/repos?type=owner&sort=full_name&direction=asc&per_page=100&page={cursor}"
        data, headers, reason, rate = self._get(path)
        if not isinstance(data, list) or len(data) > 100:
            return RepositoryPage((), None, False, reason or "Invalid repository inventory.", rate)
        try:
            repositories = tuple(self._metadata(item, account) for item in data)
            if "x-github-sso" in headers:
                return RepositoryPage(repositories, None, False, "Repository visibility is restricted.", rate)
            # Parse the next link only as evidence; never request an arbitrary URL.
            next_links = [part.strip() for part in headers.get("link", "").split(",") if 'rel="next"' in part]
            if len(next_links) > 1:
                raise ValueError("Duplicate next link")
            if next_links:
                target = next_links[0].split(">", 1)[0].removeprefix("<")
                parsed = urllib.parse.urlsplit(target)
                query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
                expected_query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
                expected_query["page"] = [str(cursor + 1)]
                allowed_paths = {path.split("?", 1)[0]}
                if account.kind == "Organization":
                    allowed_paths.add(f"/organizations/{account.id}/repos")
                elif account != self._actor:
                    allowed_paths.add(f"/user/{account.id}/repos")
                if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.fragment
                        or parsed.path not in allowed_paths or query != expected_query):
                    raise ValueError("Unsafe next page")
                return RepositoryPage(repositories, cursor + 1, False, rate_limit=rate)
            # A full page without a next link is conservatively probed once more.
            if len(data) == 100:
                return RepositoryPage(repositories, cursor + 1, False, rate_limit=rate)
            return RepositoryPage(repositories, None, True, rate_limit=rate)
        except (ValueError, TypeError, AttributeError):
            return RepositoryPage((), None, False, "Invalid or inconsistent repository inventory.", rate)
