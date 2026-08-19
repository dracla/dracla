"""`dracla install` — provision a project's repository pair (§6.10).

Idempotent and re-runnable rather than transactional; GitHub offers no way to be
transactional, so each step is individually safe to repeat and the order puts
the cheapest failures first. A partial run is the expected failure and
re-running is the recovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from dracla.github import GitHubHost
from dracla.githost import NotFound

from .admin import GitHubAdmin
from .config import InstallConfig
from .errors import CliError
from .workflow import WORKFLOW_PATH, render

EVENTS_BRANCH = "events"
EVENTS_REF = f"refs/heads/{EVENTS_BRANCH}"

# The coverage projection's branch. Its layout is §5.3; install seeds the two
# files the enforcer reads on every check so the documented shape exists from
# the start rather than being conjured by the first signature.
COVERAGE_BRANCH = "coverage"
COVERAGE_REF = f"refs/heads/{COVERAGE_BRANCH}"

DEDICATED_ORG_GUIDANCE = """\
Keep its OWNER list small. With the base permission at none, ownership
is what carries access — that setting governs members, while owners hold
admin on every repository and it cannot be lowered. Owners should be the
people who would actually use that evidence if the agreement were ever
tested: whoever the agreement grants rights to, their counsel, and
whoever administers agreement versions — not the project's maintainers
generally.

If more people need to read the records than should own the
organization, give a team read on the records repository instead. Adding
owners hands them control of the whole organization; raising the base
permission re-opens what this check exists to close."""


def _create_org_steps(org: str) -> str:
    """The steps to stand up a dedicated organization.

    GitHub has no API for creating one, so this is unavoidably manual, and a
    new organization lets every member read new repositories — which is the
    thing being guarded against. Say both up front rather than letting the
    operator discover the second after doing the first.
    """
    return (f"    1. create '{org}' at https://github.com/organizations/plan\n"
            f"       (the Free plan is enough)\n"
            f"\n"
            f"    2. gh api -X PATCH /orgs/{org} \\\n"
            f"         -f default_repository_permission=none\n")


EMPTY_SOURCE = '{\n  "canonical_sha": null,\n  "built_at": null,\n  "dracla_version": null\n}\n'
EMPTY_INFLIGHT = '{\n  "ops": {}\n}\n'

COVERAGE_README = """\
# Coverage projection

Derived from the canonical records; PII-free by construction, and **not**
public — this is a complete `user_id -> covered?` directory. Publishing it would
let anyone enumerate who has and has not signed, which DraCLA does not permit:
coverage is answerable one contributor at a time, never as a list.

Written by DraCLA. Do not edit by hand: it is regenerated from canonical events
and any manual change will be overwritten.
"""

GENESIS_README = """\
# Canonical CLA records

Append-only. One logical event per commit; commit ancestry is the authoritative
order. Never rewrite this branch.

This branch is the repository default because the reconciler must run both on
push and on a schedule, and GitHub reads `push:` workflows from the branch
pushed but `schedule:` workflows only from the default branch.

Configuration, agreements, and events are written here by DraCLA. Do not edit
them by hand.
"""


class Result(str, Enum):
    """What happened to one step. A4: an enum rather than display text, so a
    test or a future --json can assert on outcomes without parsing English."""
    CREATED = "created"
    EXISTS = "exists"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    SEEDED = "seeded"
    SET = "set"
    WOULD_CREATE = "would create"
    WOULD_UPDATE = "would update"
    WOULD_SET = "would set"


@dataclass
class Step:
    what: str
    result: Result
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.result.value}{f' {self.detail}' if self.detail else ''}"


@dataclass
class Outcome:
    records: str
    coverage: str
    created: list[str] = field(default_factory=list)
    would_create: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def note(self, what: str, result: Result, detail: str = "") -> None:
        self.steps.append(Step(what, result, detail))


def _looks_like_ours(admin, full: str) -> bool:
    """Does this repository carry a branch install would have created?

    Cheap provenance, not authentication: it distinguishes a re-run over our own
    repository from a collision with an unrelated one. It cannot prove the
    repository is safe, which is why an empty repository is accepted separately
    rather than folded in here.
    """
    host = admin.host_for(full)
    for ref in (EVENTS_REF, COVERAGE_REF):
        try:
            if host.head(ref) is not None:
                return True
        except Exception:
            # A transport fault here must not read as provenance.
            return False
    return False


def preflight(admin: GitHubAdmin, cfg: InstallConfig) -> list[str]:
    """Checks before anything is created. Raises on the one that matters.

    §6.10.4: both repositories go into an organization dedicated to this, so the
    base permission there governs only the people who administer the CLA. That
    is a requirement rather than a preference because the alternative cannot be
    made safe — GitHub base permissions are a floor, repository settings can
    raise a member's access and never lower it, so an organization defaulting to
    `read` exposes signer names and email addresses with no repository-level
    remedy at all.

    There is therefore no override. In an organization created for this purpose
    there is no legitimate reason to decline, and an override would only let
    someone install into the wrong organization by accident.

    Personal accounts are exempt deliberately: no default grants access to people
    who never asked for it, so a private repository there starts with one reader.
    """
    warnings: list[str] = []

    # Before anything else, and before the operator is asked to confirm: can
    # they even create repositories here? Otherwise install prompts about
    # repositories in an account they have no access to and fails afterwards.
    allowed, why = admin.can_create_in(cfg.org)
    if not allowed:
        raise CliError(
            f"cannot create repositories in '{cfg.org}': {why}",
            hint=(f"github.org must name an organization you administer, "
                  f"dedicated to\n"
                  f"CLA records. If it does not exist yet, create it at\n"
                  f"https://github.com/organizations/plan and re-run.\n"))

    base = admin.base_permission(cfg.org)

    if base is not None and base != "none":
        unreadable = base == admin.UNKNOWN_PERMISSION
        raise CliError(
            "could not read the organization's default repository permission"
            if unreadable else
            f"every member of '{cfg.org}' would be able to read {cfg.records_repo}",
            hint=(f"That repository holds contributors' legal names and email\n"
                  f"addresses. Nothing but its privacy protects them, and this\n"
                  f"cannot be fixed on the repository: a base permission is a\n"
                  f"floor, so repository settings can raise a member's access but\n"
                  f"never lower it.\n"
                  f"\n"
                  f"'{cfg.org}' should be an organization dedicated to CLA\n"
                  f"records, holding nothing else. If it is, set:\n"
                  f"\n"
                  f"    gh api -X PATCH /orgs/{cfg.org} \\\n"
                  f"      -f default_repository_permission=none\n"
                  f"\n"
                  f"If '{cfg.org}' is where your project's code lives, install\n"
                  f"somewhere dedicated instead. You will probably need to\n"
                  f"create it:\n"
                  f"\n"
                  f"{_create_org_steps(cfg.org + '-cla')}"
                  f"\n"
                  f"    3. {cfg.command(f'github.org={cfg.org}-cla')}\n"
                  f"\n"
                  f"{DEDICATED_ORG_GUIDANCE}\n"))

    for full in (cfg.records_repo, cfg.coverage_repo):
        repo = admin.get_repo(full)
        if repo is None:
            continue
        if not repo.private:
            raise CliError(
                f"{full} already exists and is PUBLIC",
                hint="records and coverage must both be private; rename or "
                     "delete it, or choose another recipient.slug")
        warnings.append(f"{full} already exists; install will reuse it")

    return warnings


class InstallFailed(CliError):
    """A step failed. Carries what already happened (B3).

    Install is idempotent, so re-running is the recovery — but the operator can
    only act on that if they are told which repositories now exist.
    """

    def __init__(self, message: str, *, hint: str | None = None,
                 outcome: Outcome | None = None):
        super().__init__(message, hint=hint)
        self.outcome = outcome


def run(admin: GitHubAdmin, cfg: InstallConfig, *, version: str,
        records_host=None, coverage_host=None, confirm=None) -> Outcome:
    """Provision the pair. Enforces the organization gate itself (F1).

    The gate used to be a separate `preflight()` the caller had to remember.
    §6.10.4 says it must block, and a control that depends on every caller
    invoking it first is a convention, not a control — so it lives here.

    `confirm` is invoked *after* the gate and before anything is created, which
    is the order §6.10.3.1 specifies. Taking it as a callback rather than
    leaving it to the caller is what keeps both properties at once: the gate
    cannot be skipped, and the operator is never asked to approve something that
    was going to be refused anyway.
    """
    out = Outcome(records=cfg.records_repo, coverage=cfg.coverage_repo)
    out.warnings = preflight(admin, cfg)

    # The same argument as the gate above, applied to consent. `confirm=None`
    # used to mean "proceed", so provisioning was unguarded for any caller that
    # simply did not pass it — the safety lived in the console path rather than
    # here. A dry run writes nothing and `force` is the operator saying so out
    # loud; anything else must supply a way to ask.
    if confirm is not None:
        confirm(out.warnings)
    elif not (cfg.dry_run or cfg.force):
        raise CliError(
            "refusing to provision without a way to confirm",
            hint="pass force=true to proceed without a prompt")

    dry_run = cfg.dry_run

    for full, name, desc in (
        (cfg.records_repo, cfg.records_name,
         f"DraCLA canonical CLA records for {cfg.slug}. Append-only. "
         "Contains signer data."),
        (cfg.coverage_repo, cfg.coverage_name,
         f"DraCLA coverage projection for {cfg.slug}. Derived and PII-free, "
         "but not public."),
    ):
        existing = admin.get_repo(full)
        if existing is not None:
            # Re-validate visibility HERE, not only in preflight. Between the
            # preflight check and this line the operator answered a prompt, and
            # in that window another owner can create this repository public or
            # flip an existing one. Seeding it anyway would put signer names and
            # email addresses in a public repository.
            if not existing.private:
                raise InstallFailed(
                    f"{full} exists and is PUBLIC",
                    hint="it must be private before install can use it; "
                         "nothing further was written",
                    outcome=out)
            # Private is not the same as "only the right people". A repository
            # that already existed for something else can carry direct team and
            # outside-collaborator grants that the organization default says
            # nothing about, and seeding it would put signer names and email
            # addresses where those grantees can read them.
            #
            # Empty means install created it and stopped before writing — the
            # partial run this is designed to recover from. Non-empty with no
            # trace of DraCLA is a name collision with somebody else's
            # repository, and reuse is refused rather than guessed at.
            if not existing.empty and not _looks_like_ours(admin, full):
                raise InstallFailed(
                    f"{full} already exists and is not a DraCLA repository",
                    hint=f"it has content but no '{EVENTS_BRANCH}' or "
                         f"'{COVERAGE_BRANCH}' branch, so this is a name "
                         f"collision rather than a re-run. Its existing "
                         f"collaborators would be able to read signer data.\n"
                         f"Rename it, or choose another recipient.slug.",
                    outcome=out)
            out.note(full, Result.EXISTS)
            continue
        if dry_run:
            out.would_create.append(full)
            out.note(full, Result.WOULD_CREATE)
            continue
        try:
            admin.create_repo(cfg.org, name, desc)
        except CliError as e:
            # B3: tell the operator what already exists before they re-run.
            raise InstallFailed(str(e), hint=e.hint, outcome=out) from None
        out.created.append(full)
        out.note(full, Result.CREATED)

    if dry_run:
        out.note("events branch", Result.WOULD_CREATE)
        out.note("default branch", Result.WOULD_SET, f"to {EVENTS_BRANCH}")
        out.note("workflow", Result.WOULD_CREATE)
        return out

    host = records_host or admin.host_for(cfg.records_repo)
    body = render(cfg.coverage_repo, version, EVENTS_BRANCH)

    # The branch begins with TWO bootstrap commits, not one: the README, then
    # the workflow. That is forced, not chosen — the Contents API writes one
    # path per commit, and it is the only API available here (see below).
    # §6.10.3.1 records the consequence. Both commits carry no event, so the
    # one-logical-event-per-commit rule is untouched either way.
    if host.head(EVENTS_REF) is None:
        # The Git Data API is unavailable on an empty repository — creating a
        # blob there answers 409 "Git Repository is empty" — so the first commit
        # must go through the Contents API, which can create a branch in an
        # empty repository. GitHub then makes it the default branch because it
        # is the only one, which is exactly what §6.10.1 needs and why the
        # repositories are created without auto_init.
        host.put(EVENTS_REF, "README.md", GENESIS_README, base_blob_sha=None)
        out.note("events branch", Result.CREATED)
    else:
        out.note("events branch", Result.EXISTS)

    repo = admin.get_repo(cfg.records_repo)
    if repo is not None and repo.default_branch != EVENTS_BRANCH:
        admin.set_default_branch(cfg.records_repo, EVENTS_BRANCH)
        out.note("default branch", Result.SET, f"to {EVENTS_BRANCH}")
    else:
        out.note("default branch", Result.UNCHANGED, EVENTS_BRANCH)

    try:
        existing, blob = host.read(EVENTS_REF, WORKFLOW_PATH)
        if existing == body:
            out.note("workflow", Result.UNCHANGED)
        else:
            host.put(EVENTS_REF, WORKFLOW_PATH, body, base_blob_sha=blob)
            out.note("workflow", Result.UPDATED)
    except NotFound:
        host.put(EVENTS_REF, WORKFLOW_PATH, body, base_blob_sha=None)
        out.note("workflow", Result.SEEDED)

    # B2: §5.3 defines the coverage layout; something has to create it. The
    # enforcer's reads fail closed on a missing projection, which is safe, but
    # relying on that leaves a documented layout nobody produces.
    cov = coverage_host or admin.host_for(cfg.coverage_repo)
    if cov.head(COVERAGE_REF) is None:
        # Same constraint as the events branch: Contents API to bootstrap.
        cov.put(COVERAGE_REF, "README.md", COVERAGE_README, base_blob_sha=None)
        out.note("coverage projection", Result.CREATED)
    else:
        out.note("coverage projection", Result.EXISTS)

    # SEED ONLY. These files are live state once the project is connected:
    # source.json carries the projection's replay head and inflight.json the
    # in-flight operation markers §5.3 uses for orphan recovery. Install is
    # documented as re-runnable — an upgrade path — so writing them
    # unconditionally would reset the replay head and drop an in-flight
    # signature on any re-run against a working project. Absent means
    # uninitialized; present means someone else owns it.
    for path, content in (("source.json", EMPTY_SOURCE),
                          ("inflight.json", EMPTY_INFLIGHT)):
        try:
            cov.read(COVERAGE_REF, path)
            out.note(f"coverage {path}", Result.EXISTS)
        except NotFound:
            cov.put(COVERAGE_REF, path, content, base_blob_sha=None)
            out.note(f"coverage {path}", Result.SEEDED)

    return out
