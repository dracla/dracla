"""Bounded, identity-bound GitHub administration. No installer engine."""
from __future__ import annotations

from dataclasses import dataclass, field
import base64
import json
import math
import os
import re
import time
from typing import Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from .administration import (AccountObservation, AccountRef, AdminScope, Permissions,
                             RateLimit, RepositoryMetadata, RepositoryObservation,
                             RepositoryPage, RepositoryRef, login, repository_name,
                             ActionsPublicKey, AdministrationResult, BranchRef, DeployKey,
                             ROLES, branch_name, discover, public_ssh_key)

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


def send(method: str, url: str, headers: Mapping[str, str], timeout: float, body: bytes | None = None) -> HttpResponse:
    """Do not follow redirects or persist response/credential data."""
    request = urllib.request.Request(url, headers=dict(headers), method=method, data=body)
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

    def _headers(self) -> dict[str, str] | None:
        try:
            credential = self._credential if self._credential is not None else self._provider()
            if type(credential) is not str or not credential or not credential.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in credential):
                return None
            self._credential = credential
            return {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                       "Authorization": "Bearer " + credential, "User-Agent": "DraCLA-administration"}
        except Exception:
            return None

    @staticmethod
    def _json(response: HttpResponse) -> object:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate response field")
                result[key] = value
            return result
        return json.loads(response.body.decode("utf-8"), object_pairs_hook=unique)

    def _get(self, path: str) -> tuple[object | None, Mapping[str, str], str, RateLimit]:
        # Every path is built by a named operation from validated components.
        headers = self._headers()
        if headers is None:
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
                    return self._json(response), received, "", rate
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

    def _scope_ref(self, repository: RepositoryRef, roles=ROLES) -> None:
        if not isinstance(repository, RepositoryRef):
            raise ValueError("Validated repository identity required")
        self.scope.require(repository.owner, repository.name, repository.role)
        if repository.role not in roles:
            raise ValueError("Operation is not permitted for this repository role")

    def _repository(self, repository: RepositoryRef, *, private: bool = True):
        self._scope_ref(repository)
        if self._account is None:
            return None, AdministrationResult("denied", repository, "Resolve account identity before administration.")
        data, headers, reason, rate = self._get(f"/repos/{repository.owner}/{repository.name}")
        if data is None:
            return None, AdministrationResult("denied" if "permission denied" in reason else "uncertain",
                                              repository, "Repository identity or permission unavailable.", rate_limit=rate)
        try:
            metadata = self._metadata(data, self._account)
            if (metadata.name != repository.name or metadata.id != repository.id
                    or metadata.permissions.admin is not True or "x-github-sso" in headers
                    or (private and not metadata.private)):
                raise ValueError("Repository precondition failed")
            return data, None
        except (ValueError, TypeError, AttributeError):
            return None, AdministrationResult("conflict", repository, "Repository identity, privacy or administration permission changed.")

    def _write(self, method: str, path: str, payload: dict) -> tuple[HttpResponse | None, RateLimit]:
        """Exactly one attempt. A lost response is not permission to repeat a write."""
        headers = self._headers()
        if headers is None:
            return HttpResponse(401, {}, b""), RateLimit()
        try:
            body = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
            if len(body) > _MAX_BYTES:
                return HttpResponse(400, {}, b""), RateLimit()
            headers = {**headers, "Content-Type": "application/json"}
            response = self._sender(method, API_ORIGIN + path, headers, self._timeout, body)
            if (not isinstance(response, HttpResponse) or type(response.status) is not int
                    or not isinstance(response.body, bytes) or len(response.body) > _MAX_BYTES):
                return None, RateLimit()
            received = {k.lower(): v for k, v in response.headers.items() if type(k) is str and type(v) is str}
            return response, self._rate(received, self._clock(), response.status)
        except Exception:
            return None, RateLimit()

    @staticmethod
    def _write_failure(response, repository, rate):
        if response is not None and response.status in (400, 409, 422):
            return AdministrationResult("conflict", repository, "GitHub rejected the requested state; no write retry.", rate_limit=rate)
        if response is not None and (response.status in (401, 403, 404, 429) or 300 <= response.status < 400):
            return AdministrationResult("denied", repository, "GitHub write denied or redirected; no write retry.", rate_limit=rate)
        return None

    @staticmethod
    def _unverified_write(failure):
        # A rejected read after a write cannot establish that the write was rejected.
        return AdministrationResult("conflict" if failure.status == "conflict" else "uncertain",
                                    failure.repository, "Write attempted; exact postcondition unavailable; no write retry.",
                                    rate_limit=failure.rate_limit)

    def _paged(self, repository: RepositoryRef, suffix: str, parse, page_budget: int = 10):
        if type(page_budget) is not int or not 1 <= page_budget <= 100:
            raise ValueError("Invalid pagination budget")
        rows, seen = [], set()
        prefix = f"/repos/{repository.owner}/{repository.name}/{suffix}"
        for page in range(1, page_budget + 1):
            path = f"{prefix}?per_page=100&page={page}"
            data, headers, reason, rate = self._get(path)
            try:
                if not isinstance(data, list) or len(data) > 100 or "x-github-sso" in headers:
                    raise ValueError("Incomplete inventory")
                for value in data:
                    parsed = parse(value)
                    identity = parsed.name if isinstance(parsed, BranchRef) else parsed.id
                    if identity in seen:
                        raise ValueError("Repeated inventory entry")
                    seen.add(identity)
                    rows.append(parsed)
                links = [part.strip() for part in headers.get("link", "").split(",") if 'rel="next"' in part]
                if len(links) > 1:
                    raise ValueError("Duplicate next link")
                if links:
                    link = urllib.parse.urlsplit(links[0].split(">", 1)[0].removeprefix("<"))
                    if (link.scheme != "https" or link.netloc != "api.github.com" or link.fragment
                            or link.path not in (prefix, f"/repositories/{repository.id}/{suffix}")
                            or urllib.parse.parse_qs(link.query, strict_parsing=True) != {"per_page": ["100"], "page": [str(page + 1)]}):
                        raise ValueError("Unsafe next page")
                elif len(data) < 100:
                    return tuple(rows), None
            except (ValueError, TypeError, AttributeError, KeyError):
                return (), AdministrationResult("uncertain", repository, "Incomplete or invalid administration inventory.", rate_limit=rate)
        return (), AdministrationResult("uncertain", repository, "Administration pagination budget exhausted.")

    def create_private_repository(self, account: AccountRef, name: str) -> AdministrationResult:
        name = repository_name(name)
        if not isinstance(account, AccountRef):
            raise ValueError("Validated account identity required")
        role = self.scope.require(account.login, name)
        current = discover(self, self.scope)
        if current.account.account != account:
            return AdministrationResult("conflict", reason="Account identity changed.")
        observation = next((r for r in current.repositories if r.name == name), None)
        if observation is None or observation.state != "missing":
            return AdministrationResult("conflict", reason="Exact scoped name is not proved absent; never adopt an existing name.")
        if account.kind == "User" and account != self._actor:
            return AdministrationResult("denied", reason="Personal creation requires the authenticated account.")
        path = "/user/repos" if account.kind == "User" else f"/orgs/{account.login}/repos"
        response, rate = self._write("POST", path, {"name": name, "private": True, "auto_init": False})
        failure = self._write_failure(response, None, rate)
        if failure:
            return failure
        if response is None or response.status != 201:
            self.get_repository(account.login, name)
            return AdministrationResult("uncertain", reason="Creation acknowledgement unavailable; name-only readback cannot establish ownership.", rate_limit=rate)
        try:
            data = self._json(response)
            metadata = self._metadata(data, account)
            if metadata.name != name or not metadata.private or metadata.permissions.admin is not True or type(data.get("size")) is not int or data["size"] != 0:
                raise ValueError("Creation response mismatch")
            repository = RepositoryRef(role, account.login, name, metadata.id)
            readback, failure = self._repository(repository)
            if failure:
                return self._unverified_write(failure)
            branches, failure = self._branches(repository, readback)
            if failure:
                return failure
            final, failure = self._repository(repository)
            if failure:
                return self._unverified_write(failure)
            if branches or type(final.get("size")) is not int or final["size"] != 0:
                return AdministrationResult("conflict", repository, "Created repository is not empty.")
            return AdministrationResult("applied-and-readback-verified", repository, "Exact empty private repository creation verified.", rate_limit=rate)
        except (ValueError, TypeError, AttributeError, KeyError, UnicodeError):
            return AdministrationResult("uncertain", reason="Creation response did not establish exact empty private repository identity.", rate_limit=rate)

    def set_private(self, repository: RepositoryRef) -> AdministrationResult:
        data, failure = self._repository(repository, private=False)
        if failure:
            return failure
        if data["private"]:
            return AdministrationResult("observed", repository, "Exact repository is already private.")
        response, rate = self._write("PATCH", f"/repos/{repository.owner}/{repository.name}", {"private": True})
        failure = self._write_failure(response, repository, rate)
        if failure:
            return failure
        data, failure = self._repository(repository, private=False)
        if failure:
            return self._unverified_write(failure)
        if data["private"]:
            return AdministrationResult("applied-and-readback-verified", repository, "Exact repository private visibility verified.", rate_limit=rate)
        return AdministrationResult("uncertain", repository, "Private visibility was not established; no write retry.", rate_limit=rate)

    def _branches(self, repository, data):
        try:
            default = branch_name(data["default_branch"])
        except (ValueError, TypeError, KeyError):
            return (), AdministrationResult("uncertain", repository, "Default branch identity unavailable.")
        return self._paged(repository, "branches", lambda row: BranchRef(repository, row["name"], row["commit"]["sha"], default))

    def _branch_inventory(self, repository: RepositoryRef):
        data, failure = self._repository(repository)
        if failure:
            return (), failure
        branches, failure = self._branches(repository, data)
        if failure:
            return (), failure
        final, failure = self._repository(repository)
        if failure:
            return (), failure
        if final.get("default_branch") != data["default_branch"]:
            return (), AdministrationResult("conflict", repository, "Default branch changed during observation.")
        return branches, None

    def read_branch(self, repository: RepositoryRef, name: str) -> AdministrationResult:
        name = branch_name(name)
        branches, failure = self._branch_inventory(repository)
        if failure:
            return failure
        branch = next((b for b in branches if b.name == name), None)
        return AdministrationResult("observed" if branch else "missing", repository, branch=branch)

    def rename_branch(self, repository: RepositoryRef, observed: BranchRef, new_name: str) -> AdministrationResult:
        self._scope_ref(repository, ("records",))
        new_name = branch_name(new_name)
        if not isinstance(observed, BranchRef) or observed.repository != repository or new_name != "events":
            raise ValueError("Exact observed records branch and events target required")
        branches, failure = self._branch_inventory(repository)
        if failure:
            return failure
        source = next((b for b in branches if b.name == observed.name), None)
        target = next((b for b in branches if b.name == new_name), None)
        if target and target.head == observed.head and target.default_branch == new_name and (source is None or observed.name == new_name):
            return AdministrationResult("observed", repository, "Exact renamed default branch already observed.", branch=target)
        if target or source != observed or observed.name != observed.default_branch:
            return AdministrationResult("conflict", repository, "Initial default/head changed or target branch already exists.")
        current, failure = self._repository(repository)
        if failure:
            return failure
        if current.get("default_branch") != observed.default_branch:
            return AdministrationResult("conflict", repository, "Default branch changed before rename.")
        response, rate = self._write("POST", f"/repos/{repository.owner}/{repository.name}/branches/{urllib.parse.quote(observed.name, safe='')}/rename", {"new_name": new_name})
        failure = self._write_failure(response, repository, rate)
        if failure:
            return failure
        branches, failure = self._branch_inventory(repository)
        if failure:
            return self._unverified_write(failure)
        target = next((b for b in branches if b.name == new_name), None)
        source = next((b for b in branches if b.name == observed.name), None)
        if target and target.head == observed.head and target.default_branch == new_name and source is None:
            return AdministrationResult("applied-and-readback-verified", repository, "Same-head records default branch rename verified.", branch=target, rate_limit=rate)
        if target and target.head != observed.head:
            return AdministrationResult("conflict", repository, "Branch readback conflicts with the intended rename.", rate_limit=rate)
        return AdministrationResult("uncertain", repository, "Branch rename not yet proved; no write retry.", rate_limit=rate)

    def list_deploy_keys(self, repository: RepositoryRef, *, page_budget: int = 10) -> AdministrationResult:
        self._scope_ref(repository, ("records", "coverage"))
        if type(page_budget) is not int or not 1 <= page_budget <= 100:
            raise ValueError("Invalid pagination budget")
        _, failure = self._repository(repository)
        if failure:
            return failure
        keys, failure = self._paged(repository, "keys", lambda row: DeployKey(row["id"], row["title"], row["key"], row["read_only"]), page_budget)
        if failure:
            return failure
        _, failure = self._repository(repository)
        if failure:
            return failure
        if len({k.key for k in keys}) != len(keys):
            return AdministrationResult("conflict", repository, "Duplicate deploy key material.")
        return AdministrationResult("observed", repository, deploy_keys=keys)

    def add_deploy_key(self, repository: RepositoryRef, title: str, key: str, *, read_only: bool) -> AdministrationResult:
        self._scope_ref(repository, ("records", "coverage"))
        key = public_ssh_key(key)
        if type(title) is not str or not title or len(title) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in title) or type(read_only) is not bool:
            raise ValueError("Explicit deploy key title and permission required")
        before = self.list_deploy_keys(repository)
        if before.status != "observed":
            return before
        if any((k.key == key and k.read_only != read_only) or (k.title == title and k.key != key)
               for k in before.deploy_keys):
            return AdministrationResult("conflict", repository, "Deploy key material or permission conflicts.")
        existing = next((k for k in before.deploy_keys if k.key == key and k.read_only == read_only), None)
        if existing:
            return AdministrationResult("observed", repository, "Exact key and permission already observed.", deploy_keys=(existing,))
        response, rate = self._write("POST", f"/repos/{repository.owner}/{repository.name}/keys", {"title": title, "key": key, "read_only": read_only})
        failure = self._write_failure(response, repository, rate)
        if failure:
            return failure
        expected_id = None
        if response is not None and response.status == 201:
            try:
                value = self._json(response)
                created = DeployKey(value["id"], value["title"], value["key"], value["read_only"])
                if created.key != key or created.read_only != read_only:
                    return AdministrationResult("conflict", repository, "Deploy key response conflicts with intent.")
                expected_id = created.id
            except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
                return AdministrationResult("uncertain", repository, "Invalid deploy key acknowledgement.", rate_limit=rate)
        after = self.list_deploy_keys(repository)
        if after.status != "observed":
            return self._unverified_write(after)
        if any((k.key == key and k.read_only != read_only) or (k.title == title and k.key != key)
               for k in after.deploy_keys):
            return AdministrationResult("conflict", repository, "Deploy key readback conflicts with intended identity or permission.")
        matches = [k for k in after.deploy_keys if k.key == key and k.read_only == read_only]
        if len(matches) == 1 and (expected_id is None or matches[0].id == expected_id):
            return AdministrationResult("applied-and-readback-verified", repository, "Exact deploy key and permission verified.", deploy_keys=tuple(matches), rate_limit=rate)
        if any(k.key == key or k.title == title for k in after.deploy_keys):
            return AdministrationResult("conflict", repository, "Deploy key readback conflicts with intended identity or permission.")
        return AdministrationResult("uncertain", repository, "Deploy key creation not established; no write retry.", rate_limit=rate)

    def get_actions_public_key(self, repository: RepositoryRef) -> AdministrationResult:
        self._scope_ref(repository, ("control",))
        _, failure = self._repository(repository)
        if failure:
            return failure
        data, _, reason, rate = self._get(f"/repos/{repository.owner}/{repository.name}/actions/secrets/public-key")
        try:
            encoded = data["key"]
            key = base64.b64decode(encoded, validate=True)
            if base64.b64encode(key).decode("ascii") != encoded:
                raise ValueError("Non-canonical key")
            public = ActionsPublicKey(repository, data["key_id"], key)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            return AdministrationResult("uncertain", repository, "Actions encryption key unavailable or invalid.", rate_limit=rate)
        _, failure = self._repository(repository)
        return failure or AdministrationResult("observed", repository, public_key=public, rate_limit=rate)

    def put_actions_secret(self, repository: RepositoryRef, name: str, value: bytes) -> AdministrationResult:
        self._scope_ref(repository, ("control",))
        if (type(name) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", name)
                or name.upper().startswith("GITHUB_") or type(value) is not bytes or len(value) > 48 * 1024):
            raise ValueError("Invalid Actions secret input")
        public = self.get_actions_public_key(repository)
        if public.status != "observed":
            return public
        try:
            from nacl.public import PublicKey, SealedBox
            encrypted = base64.b64encode(SealedBox(PublicKey(public.public_key.key)).encrypt(value)).decode("ascii")
        except Exception:
            return AdministrationResult("denied", repository, "Actions secret encryption unavailable.")
        response, rate = self._write("PUT", f"/repos/{repository.owner}/{repository.name}/actions/secrets/{name.upper()}", {"encrypted_value": encrypted, "key_id": public.public_key.key_id})
        failure = self._write_failure(response, repository, rate)
        if failure:
            return failure
        if response is not None and response.status in (201, 204):
            _, failure = self._repository(repository)
            if failure:
                return self._unverified_write(failure)
            return AdministrationResult("accepted", repository, "Secret update accepted; stored plaintext cannot be read back or verified.", rate_limit=rate)
        return AdministrationResult("uncertain", repository, "Secret acknowledgement unavailable; caller-authorized repeat must use a fresh public key.", rate_limit=rate)

    def dispatch_workflow(self, repository: RepositoryRef, workflow: int | str, ref: str, inputs: Mapping[str, str | bool | int]) -> AdministrationResult:
        self._scope_ref(repository, ("control",))
        ref = branch_name(ref)
        if not ((type(workflow) is int and workflow > 0) or (type(workflow) is str and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,199}\.ya?ml", workflow))):
            raise ValueError("Explicit workflow ID or filename required")
        if not isinstance(inputs, Mapping) or len(inputs) > 25:
            raise ValueError("Invalid workflow inputs")
        supplied = dict(inputs)
        if any(type(k) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,99}", k)
               or type(v) not in (str, bool, int) or (type(v) is str and len(v) > 4096)
               or (type(v) is int and abs(v) > 2 ** 53 - 1) for k, v in supplied.items()):
            raise ValueError("Invalid workflow inputs")
        _, failure = self._repository(repository)
        if failure:
            return failure
        data, _, reason, rate = self._get(f"/repos/{repository.owner}/{repository.name}/actions/workflows/{workflow}")
        try:
            identity = data["id"]
            if (type(identity) is not int or identity <= 0 or data["state"] != "active"
                    or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,199}\.ya?ml", data["path"])
                    or (type(workflow) is int and identity != workflow)
                    or (type(workflow) is str and data["path"] != ".github/workflows/" + workflow)):
                raise ValueError("Workflow identity mismatch")
        except (ValueError, TypeError, KeyError, AttributeError):
            return AdministrationResult("conflict", repository, "Workflow identity unavailable, inactive or changed.", rate_limit=rate)
        _, failure = self._repository(repository)
        if failure:
            return failure
        response, rate = self._write("POST", f"/repos/{repository.owner}/{repository.name}/actions/workflows/{identity}/dispatches", {"ref": ref, "inputs": supplied})
        failure = self._write_failure(response, repository, rate)
        if failure:
            return failure
        if response is not None and response.status == 204:
            _, failure = self._repository(repository)
            if failure:
                return self._unverified_write(failure)
            return AdministrationResult("accepted", repository, "Workflow dispatch accepted; no particular run or completion observed.", rate_limit=rate)
        return AdministrationResult("uncertain", repository, "Workflow dispatch acknowledgement unavailable; never repeat automatically.", rate_limit=rate)
