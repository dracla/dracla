"""Identity-bound administration observations. No transport or client imports."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import re
from typing import Mapping, Protocol

_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}", re.ASCII)
ROLES = ("records", "coverage", "control")


def login(value: str) -> str:
    if type(value) is not str or not _LOGIN.fullmatch(value):
        raise ValueError("Invalid account login")
    return value.casefold()


def repository_name(value: str) -> str:
    if type(value) is not str or not _NAME.fullmatch(value) or value in (".", ".."):
        raise ValueError("Invalid repository name")
    return value.casefold()


def numeric_id(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("Invalid numeric identity")
    return value


@dataclass(frozen=True)
class AccountRef:
    login: str
    id: int
    kind: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "login", login(self.login))
        numeric_id(self.id)
        if self.kind not in ("User", "Organization"):
            raise ValueError("Unsupported account type")


@dataclass(frozen=True)
class AdminScope:
    owner: str
    repositories: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "owner", login(self.owner))
        if tuple(role for role, _ in self.repositories) != ROLES:
            raise ValueError("Scope requires the three exact repository roles")
        names = tuple(repository_name(name) for _, name in self.repositories)
        if len(set(names)) != 3:
            raise ValueError("Scope repository names must be distinct")
        object.__setattr__(self, "repositories", tuple(zip(ROLES, names)))

    def require(self, owner: str, name: str, role: str | None = None) -> str:
        owner, name = login(owner), repository_name(name)
        matches = [r for r, n in self.repositories if n == name and (role is None or role == r)]
        if owner != self.owner or len(matches) != 1:
            raise ValueError("Repository is outside the administration scope")
        return matches[0]


@dataclass(frozen=True)
class RepositoryRef:
    role: str
    owner: str
    name: str
    id: int

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError("Unsupported repository role")
        object.__setattr__(self, "owner", login(self.owner))
        object.__setattr__(self, "name", repository_name(self.name))
        numeric_id(self.id)


@dataclass(frozen=True)
class Permissions:
    admin: bool | None = None
    push: bool | None = None
    pull: bool | None = None

    def __post_init__(self) -> None:
        if any(v is not None and type(v) is not bool for v in (self.admin, self.push, self.pull)):
            raise ValueError("Invalid repository permissions")


@dataclass(frozen=True)
class RepositoryMetadata:
    owner: AccountRef
    name: str
    id: int
    private: bool
    permissions: Permissions

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", repository_name(self.name))
        numeric_id(self.id)
        if type(self.private) is not bool or not isinstance(self.permissions, Permissions):
            raise ValueError("Invalid repository metadata")


@dataclass(frozen=True)
class RateLimit:
    remaining: int | None = None
    retry_at: int | None = None


@dataclass(frozen=True)
class AccountObservation:
    account: AccountRef | None
    inventory_visible: bool = False
    reason: str = "Account or permission evidence unavailable."
    rate_limit: RateLimit = RateLimit()
    repository_count: int | None = None
    private_repository_count: int | None = None


@dataclass(frozen=True)
class RepositoryObservation:
    owner: str
    name: str
    state: str
    metadata: RepositoryMetadata | None = None
    reason: str = ""
    rate_limit: RateLimit = RateLimit()

    def __post_init__(self) -> None:
        object.__setattr__(self, "owner", login(self.owner))
        object.__setattr__(self, "name", repository_name(self.name))
        if self.state not in ("observed", "missing", "unknown"):
            raise ValueError("Invalid repository observation")
        if (self.state == "observed") != (self.metadata is not None):
            raise ValueError("Repository observation lacks its exact metadata")


@dataclass(frozen=True)
class RepositoryPage:
    repositories: tuple[RepositoryMetadata, ...]
    next_page: int | None
    complete: bool
    reason: str = ""
    rate_limit: RateLimit = RateLimit()


def branch_name(value: str) -> str:
    """Validate a Git branch/tag name before putting it in an encoded path."""
    if (type(value) is not str or not value or len(value) > 1024
            or value == "@" or value.startswith(("-", "/")) or value.endswith(("/", "."))
            or ".." in value or "@{" in value
            or any(ord(c) < 33 or ord(c) == 127 or c in "~^:?*[\\" for c in value)
            or any(not part or part.startswith(".") or part.endswith(".lock") for part in value.split("/"))):
        raise ValueError("Invalid branch or tag name")
    try:
        if len(value.encode("utf-8")) > 1024:
            raise ValueError("Invalid branch or tag name")
    except UnicodeError:
        raise ValueError("Invalid branch or tag name") from None
    return value


def public_ssh_key(value: str) -> str:
    """Compare key material, not a user-controlled comment or title."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import UnsupportedAlgorithm
    if type(value) is not str or not value.isascii() or len(value) > 16384 or "\n" in value or "\r" in value:
        raise ValueError("Invalid SSH public key")
    try:
        key = serialization.load_ssh_public_key(value.encode("ascii"))
        return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")
    except (ValueError, TypeError, UnicodeError, UnsupportedAlgorithm):
        raise ValueError("Invalid SSH public key") from None


@dataclass(frozen=True)
class BranchRef:
    repository: RepositoryRef
    name: str
    head: str
    default_branch: str

    def __post_init__(self) -> None:
        if not isinstance(self.repository, RepositoryRef) or type(self.head) is not str or not re.fullmatch(r"[0-9a-f]{40}", self.head):
            raise ValueError("Invalid branch identity")
        branch_name(self.name)
        branch_name(self.default_branch)


@dataclass(frozen=True)
class DeployKey:
    id: int
    title: str
    key: str
    read_only: bool

    def __post_init__(self) -> None:
        numeric_id(self.id)
        if type(self.title) is not str or len(self.title) > 1024 or type(self.read_only) is not bool:
            raise ValueError("Invalid deploy key metadata")
        object.__setattr__(self, "key", public_ssh_key(self.key))


@dataclass(frozen=True)
class ActionsPublicKey:
    repository: RepositoryRef
    key_id: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.repository, RepositoryRef) or type(self.key_id) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.key_id)
                or type(self.key) is not bytes or len(self.key) != 32):
            raise ValueError("Invalid Actions public key")


@dataclass(frozen=True)
class AdministrationResult:
    status: str
    repository: RepositoryRef | None = None
    reason: str = ""
    branch: BranchRef | None = None
    deploy_keys: tuple[DeployKey, ...] = ()
    public_key: ActionsPublicKey | None = None
    rate_limit: RateLimit = RateLimit()

    def __post_init__(self) -> None:
        if self.status not in {"observed", "applied-and-readback-verified", "accepted", "uncertain", "conflict", "missing", "denied"}:
            raise ValueError("Invalid administration result")


class Administration(Protocol):
    def resolve_account(self, owner: str) -> AccountObservation: ...
    def get_repository(self, owner: str, name: str, *, expected: RepositoryRef | None = None) -> RepositoryObservation: ...
    def list_repositories(self, account: AccountRef, cursor: int = 1) -> RepositoryPage: ...
    def read_visibility(self, repository: RepositoryRef) -> RepositoryObservation: ...
    def create_private_repository(self, account: AccountRef, name: str) -> AdministrationResult: ...
    def set_private(self, repository: RepositoryRef) -> AdministrationResult: ...
    def read_branch(self, repository: RepositoryRef, name: str) -> AdministrationResult: ...
    def rename_branch(self, repository: RepositoryRef, observed: BranchRef, new_name: str) -> AdministrationResult: ...
    def list_deploy_keys(self, repository: RepositoryRef, *, page_budget: int = 10) -> AdministrationResult: ...
    def add_deploy_key(self, repository: RepositoryRef, title: str, key: str, *, read_only: bool) -> AdministrationResult: ...
    def get_actions_public_key(self, repository: RepositoryRef) -> AdministrationResult: ...
    def put_actions_secret(self, repository: RepositoryRef, name: str, value: bytes) -> AdministrationResult: ...
    def dispatch_workflow(self, repository: RepositoryRef, workflow: int | str, ref: str, inputs: Mapping[str, str | bool | int]) -> AdministrationResult: ...


@dataclass(frozen=True)
class Discovery:
    account: AccountObservation
    repositories: tuple[RepositoryObservation, ...]
    inventory_complete: bool


def discover(admin: Administration, scope: AdminScope, *, page_budget: int = 10) -> Discovery:
    """Read fresh exact names; only a complete visible inventory can prove absence."""
    if type(page_budget) is not int or not 1 <= page_budget <= 100:
        raise ValueError("Invalid pagination budget")
    account = admin.resolve_account(scope.owner)
    if account.account is None or account.account.login != scope.owner:
        return Discovery(account, (), False)
    inventory: dict[str, RepositoryMetadata] = {}
    identities: set[int] = set()
    cursor, complete = 1, False
    for _ in range(page_budget):
        page = admin.list_repositories(account.account, cursor)
        if (len({repo.name for repo in page.repositories}) != len(page.repositories)
                or len({repo.id for repo in page.repositories}) != len(page.repositories)
                or any(repo.owner != account.account or repo.name in inventory or repo.id in identities
                       for repo in page.repositories)):
            break
        for repo in page.repositories:
            inventory[repo.name] = repo
            identities.add(repo.id)
        if page.complete:
            complete = page.next_page is None
            break
        if page.next_page != cursor + 1:
            break
        cursor = page.next_page
    observations = []
    visible = (complete and account.inventory_visible
               and len(inventory) == account.repository_count
               and sum(repo.private for repo in inventory.values()) == account.private_repository_count)
    for _, name in scope.repositories:
        observed = admin.get_repository(scope.owner, name)
        listed = inventory.get(name)
        if observed.state == "observed" and (observed.metadata.owner != account.account
                or (listed is not None and observed.metadata != listed)):
            observed = RepositoryObservation(scope.owner, name, "unknown", reason="Repository identity or metadata changed during discovery.")
        elif listed is not None and observed.state != "observed":
            observed = RepositoryObservation(scope.owner, name, "unknown", reason="Repository inventory and exact read disagree.")
        elif (observed.state == "unknown" and observed.reason == "Repository is missing or inaccessible."
              and visible and listed is None):
            observed = RepositoryObservation(scope.owner, name, "missing", reason="Absent from complete identity-bound visible inventory.")
        observations.append(observed)
    if not visible:
        account = replace(account, inventory_visible=False)
    return Discovery(account, tuple(observations), complete)
