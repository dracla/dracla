"""GitHub repository and organization administration (§6.10.5).

Deliberately separate from `dracla.githost.GitHost`. That protocol models the
append-only records layer — head, read, commit, update_ref — and says nothing
about creating repositories, reading organization settings, or promoting a
default branch. A previous implementation reached through `GitHubHost` into its
private transport at six call sites because this surface did not exist.

It is also the seam the tests substitute, which is why it is a class rather than
a set of functions.
"""

from __future__ import annotations

from dataclasses import dataclass

from dracla.github import GitHubError, GitHubHost
from dracla.githost import NotFound

from .errors import CliError


@dataclass
class Repo:
    full_name: str
    private: bool
    default_branch: str | None
    empty: bool


class GitHubAdmin:
    """Administration calls, made with the operator's own credentials."""

    def __init__(self, token: str):
        self._token = token
        # One client for administration; host_for() reuses the same policy for
        # records access, so retry and timeout behaviour is not duplicated per
        # path (A2).
        self._transport = GitHubHost(repo="", token=token)
        self._owner_kind: dict[str, str] = {}

    def host_for(self, repo: str) -> GitHubHost:
        """A records host for `repo`, built from the same credentials."""
        return GitHubHost(repo=repo, token=self._token)

    # --- transport --------------------------------------------------------

    def _get(self, path: str) -> dict:
        return self._transport.request("GET", path)          # type: ignore[return-value]

    def _post(self, path: str, body: dict) -> dict:
        return self._transport.request("POST", path, body)   # type: ignore[return-value]

    def _patch(self, path: str, body: dict) -> dict:
        return self._transport.request("PATCH", path, body)  # type: ignore[return-value]

    # --- owner ------------------------------------------------------------

    def owner_kind(self, owner: str) -> str:
        """'Organization' or 'User'. Cached: repo creation asks again.

        A missing account is almost always the dedicated organization not
        existing yet (§6.10.4), so the error says how to create one rather than
        reporting a bare 404. GitHub has no API for creating an organization —
        `POST /orgs` does not exist on github.com and `/admin/organizations` is
        Enterprise Server only — so this step is unavoidably manual.
        """
        if owner not in self._owner_kind:
            try:
                self._owner_kind[owner] = self._get(f"/users/{owner}")["type"]
            except NotFound:
                from .install import DEDICATED_ORG_GUIDANCE, _create_org_steps
                raise CliError(
                    f"no GitHub account named '{owner}'",
                    hint=(f"DraCLA keeps CLA records in an organization of "
                          f"their own, holding\n"
                          f"nothing else. GitHub has no API for creating one, "
                          f"so this is manual:\n"
                          f"\n"
                          f"{_create_org_steps(owner)}"
                          f"\n"
                          f"    3. re-run this command\n"
                          f"\n"
                          f"{DEDICATED_ORG_GUIDANCE}\n")) from None
        return self._owner_kind[owner]

    UNKNOWN_PERMISSION = "<could not read organization settings>"

    def viewer(self) -> str:
        """The authenticated user's login."""
        if not hasattr(self, "_viewer"):
            self._viewer = self._get("/user")["login"]
        return self._viewer

    def can_create_in(self, owner: str) -> tuple[bool, str]:
        """May the authenticated user create repositories under `owner`?

        Checked before the operator is asked to confirm anything. Without it,
        install prompts "About to create XY/..." for an account the operator has
        no access to, and only fails at creation — after they have said yes.
        """
        if self.owner_kind(owner) == "User":
            if owner.lower() != self.viewer().lower():
                return False, (
                    f"'{owner}' is a personal account belonging to someone else")
            return True, ""
        try:
            membership = self._get(f"/user/memberships/orgs/{owner}")
        except (NotFound, GitHubError):
            return False, f"you are not a member of '{owner}'"
        if membership.get("state") != "active":
            return False, f"your membership of '{owner}' is not active"
        return True, ""

    def base_permission(self, owner: str) -> str | None:
        """The org's default member permission, or None for a user account.

        `REQ-SEC-2` exempts DraCLA from encrypting signer fields on the basis
        that the private records repository is a sufficient access boundary.
        When an organization grants members read by default, that basis is
        false — so install looks rather than assuming.
        """
        if self.owner_kind(owner) != "Organization":
            return None
        try:
            org = self._get(f"/orgs/{owner}")
            if "default_repository_permission" not in org:
                # GitHub returns the full organization record only to an owner
                # with sufficient scope; for anyone else it answers 200 with the
                # field simply absent. Returning None there would be read as
                # "personal account, exempt" and the gate would fail OPEN on the
                # exact case it exists for. Not knowing is not permission.
                return self.UNKNOWN_PERMISSION
            return org["default_repository_permission"]
        except (NotFound, GitHubError):
            # F2: reading this needs organization admin. Failing closed is
            # right — we must not report that the boundary holds when we could
            # not check — but the operator must be told we could not read it,
            # not that the setting is literally "unknown".
            return self.UNKNOWN_PERMISSION

    # --- repositories -----------------------------------------------------

    def get_repo(self, full_name: str) -> Repo | None:
        try:
            doc = self._get(f"/repos/{full_name}")
        except NotFound:
            return None
        return Repo(full_name=full_name,
                    private=bool(doc["private"]),
                    default_branch=doc.get("default_branch"),
                    empty=bool(doc.get("size", 0) == 0))

    def create_repo(self, owner: str, name: str, description: str) -> Repo:
        """Create a PRIVATE, EMPTY repository.

        Empty on purpose (§6.10.3.1): `auto_init` would create `main`, which
        would then have to be demoted and deleted — extra operations, an
        interval in which the default branch is wrong, and a stray branch if the
        run stops in between. The `events` branch becomes the first ref that
        ever exists instead.
        """
        body = {
            "name": name,
            "description": description,
            "private": True,
            "auto_init": False,
            "has_issues": False,
            "has_wiki": False,
            "has_projects": False,
        }
        # POST /user/repos creates under the AUTHENTICATED user and ignores
        # `owner` entirely, so using it for someone else's account silently
        # creates the repository in the wrong place. Refuse rather than
        # redirect: this function creates repositories that will hold signer
        # data, and creating one somewhere the operator did not name is worse
        # than failing.
        if self.owner_kind(owner) == "Organization":
            path = f"/orgs/{owner}/repos"
        else:
            if owner.lower() != self.viewer().lower():
                raise CliError(
                    f"cannot create repositories under '{owner}'",
                    hint=f"'{owner}' is a personal account belonging to someone "
                         f"else. github.org must name an organization you\n"
                         f"administer, dedicated to CLA records.")
            path = "/user/repos"
        try:
            self._post(path, body)
        except GitHubError as e:
            # B5: the repository can appear between our existence check and
            # this call. GitHub reports that as 422 name-already-exists, and
            # diagnosing it as a permissions problem sends the operator the
            # wrong way.
            if e.status == 422 and "already exists" in e.body:
                existing = self.get_repo(f"{owner}/{name}")
                if existing is not None:
                    # Same rule as a freshly created one: the race winner may
                    # have made it public, and returning it here would skip the
                    # read-back check below.
                    if not existing.private:
                        raise CliError(
                            f"{owner}/{name} already exists and is PUBLIC",
                            hint="it is intended to hold signer names and email "
                                 "addresses; make it private or choose another "
                                 "recipient.slug") from None
                    return existing
            raise CliError(
                f"could not create {owner}/{name}",
                hint=f"you need permission to create repositories in {owner} "
                     f"(GitHub returned {e.status})") from None

        # Organization policy can override the requested visibility, and
        # REQ-SEC-2 rests on this repository being private, so read it back
        # rather than trusting the request.
        created = self.get_repo(f"{owner}/{name}")
        if created is None:
            raise CliError(
                f"created a repository but cannot find it at {owner}/{name}",
                hint="this should not happen; check whether a repository was "
                     "created somewhere unexpected before re-running")
        if not created.private:
            raise CliError(
                f"{owner}/{name} was created but is PUBLIC",
                hint="organization policy overrode the private setting. Make it "
                     "private now — it is intended to hold signer names and "
                     "email addresses.")
        return created

    def set_default_branch(self, full_name: str, branch: str) -> None:
        self._patch(f"/repos/{full_name}", {"default_branch": branch})
