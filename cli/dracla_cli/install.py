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
from .errors import Aborted, CliError
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
# Empty on purpose, and seeded on purpose: the enforcer reads this on every
# check and an unreadable log fails closed (design §5.3) — if install did not
# create it, every check on a fresh project would fail until the first
# agreement activation happened to.
EMPTY_INTENTS = '[]\n'

# One tuple, used by the real seed loop and the dry-run preview alike, so the
# preview cannot drift from what install actually seeds.
SEEDS = (("source.json", EMPTY_SOURCE),
         ("inflight.json", EMPTY_INFLIGHT),
         ("intents.json", EMPTY_INTENTS))

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
    WOULD_BECOME = "would become"


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


OURS, COLLISION, UNREADABLE = "ours", "collision", "unreadable"

# Exact contents of the one-file root commit install creates per repository. A
# branch merely NAMED `events`, or a current README copied there later, is not
# provenance. Reuse requires the branch root itself to be precisely the commit
# install creates first.
_GENESIS_CONTENT = {
    EVENTS_REF: GENESIS_README,
    COVERAGE_REF: COVERAGE_README,
}


def _provenance(admin, full: str, expected_ref: str) -> str:
    """Is this repository one install made, one it can finish, or someone else's?

    Cheap provenance, not authentication: it separates a re-run over our own
    repository from a name collision with an unrelated one. Three rules, each
    from a defect:

    - Judged against `expected_ref` for THIS repository — `events` for
      records, `coverage` for coverage. An earlier version accepted either
      branch name for either repository, so a records candidate carrying only
      an unrelated `coverage` branch read as ours.
    - The branch root must contain exactly the canonical DraCLA genesis README
      and no other path. Install creates the branch BY writing that one file;
      inspecting the current README instead would accept an unrelated history
      that copied the public marker later.
    - Emptiness is asked of the branch list, never of `size` — GitHub reports
      `size: 0` for repositories that have content.

    A transport fault returns UNREADABLE rather than COLLISION. The two need
    different advice: 403 from SAML enforcement or a rate limit on a genuine,
    fully-provisioned records repository would otherwise tell the operator to
    rename or abandon the repository holding the canonical CLA records.
    """
    host = admin.host_for(full)
    try:
        if host.head(expected_ref) is not None:
            history = host.history(expected_ref)
            if not history:
                return COLLISION
            root = history[0]
            root_tree = host.base_tree(root.sha)
            readme, _ = host.read(root.sha, "README.md")
            if (set(root_tree) == {"README.md"}
                    and readme == _GENESIS_CONTENT[expected_ref]):
                return OURS
            return COLLISION
    except NotFound:
        # The branch exists but its README does not: not a shape install can
        # produce, since the branch is created by writing the README.
        return COLLISION
    except Exception:
        return UNREADABLE
    count = admin.branch_count(full)
    if count is None:
        return UNREADABLE
    return OURS if count == 0 else COLLISION


def _require_safe_base_permission(admin: GitHubAdmin,
                                  cfg: InstallConfig) -> None:
    """Fail closed unless the dedicated org's member default is `none`."""
    base = admin.base_permission(cfg.org)
    if base is None or base == "none":
        return
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

    _require_safe_base_permission(admin, cfg)

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


def _with_outcome(error: Exception, out: Outcome) -> InstallFailed:
    """Translate any post-confirmation failure without losing completed steps."""
    if isinstance(error, InstallFailed):
        return error
    hint = error.hint if isinstance(error, CliError) else None
    if hint is None:
        hint = ("completed steps are listed above. Correct the failure and "
                "re-run; install rechecks existing state before every write")
    return InstallFailed(str(error), hint=hint, outcome=out)


def _provision(admin, cfg, out, host, cov, body, *, write: bool,
               fresh_records: bool = False,
               fresh_coverage: bool = False) -> None:
    """One walk over every provisioning step, shared by the real run and the
    --dry-run preview (`write=False`). One body means the preview cannot drift
    from what install actually does — the same argument `SEEDS` makes for the
    seed list. The fresh flags are preview-only: a repository the real run
    just created can be probed, but one that does not exist yet cannot, so the
    preview declares every step under it WOULD_CREATE instead of probing.

    The events branch begins with TWO bootstrap commits, not one: the README,
    then the workflow. That is forced, not chosen — the Contents API writes
    one path per commit, and it is the only API available here (see below).
    §6.10.3.1 records the consequence. Both commits carry no event, so the
    one-logical-event-per-commit rule is untouched either way.
    """
    if fresh_records:
        out.note("events branch", Result.WOULD_CREATE)
        out.note("default branch", Result.WOULD_BECOME,
                 f"{EVENTS_BRANCH} automatically with the first branch")
        out.note("workflow", Result.WOULD_CREATE)
    else:
        if host.head(EVENTS_REF) is None:
            if write:
                # The Git Data API is unavailable on an empty repository —
                # creating a blob there answers 409 "Git Repository is empty" —
                # so the first commit must go through the Contents API, which
                # can create a branch in an empty repository. GitHub then makes
                # it the default branch because it is the only one, which is
                # exactly what §6.10.1 needs and why the repositories are
                # created without auto_init.
                host.put(EVENTS_REF, "README.md", GENESIS_README,
                         base_blob_sha=None)
                out.note("events branch", Result.CREATED)
            else:
                out.note("events branch", Result.WOULD_CREATE)
        else:
            out.note("events branch", Result.EXISTS)

        repo = admin.get_repo(cfg.records_repo)
        if repo is not None and repo.default_branch != EVENTS_BRANCH:
            if write:
                admin.set_default_branch(cfg.records_repo, EVENTS_BRANCH)
                out.note("default branch", Result.SET, f"to {EVENTS_BRANCH}")
            else:
                out.note("default branch", Result.WOULD_SET,
                         f"to {EVENTS_BRANCH}")
        else:
            out.note("default branch", Result.UNCHANGED, EVENTS_BRANCH)

        try:
            existing, blob = host.read(EVENTS_REF, WORKFLOW_PATH)
            if existing == body:
                out.note("workflow", Result.UNCHANGED)
            elif write:
                host.put(EVENTS_REF, WORKFLOW_PATH, body, base_blob_sha=blob)
                out.note("workflow", Result.UPDATED)
            else:
                out.note("workflow", Result.WOULD_UPDATE)
        except NotFound:
            if write:
                host.put(EVENTS_REF, WORKFLOW_PATH, body, base_blob_sha=None)
                out.note("workflow", Result.SEEDED)
            else:
                out.note("workflow", Result.WOULD_CREATE)

    # B2: §5.3 defines the coverage layout; something has to create it. The
    # enforcer's reads fail closed on a missing projection, which is safe, but
    # relying on that leaves a documented layout nobody produces.
    if fresh_coverage:
        out.note("coverage projection", Result.WOULD_CREATE)
        for path, _ in SEEDS:
            out.note(f"coverage {path}", Result.WOULD_CREATE)
        return
    if cov.head(COVERAGE_REF) is None:
        if write:
            # Same constraint as the events branch: Contents API to bootstrap.
            cov.put(COVERAGE_REF, "README.md", COVERAGE_README,
                    base_blob_sha=None)
            out.note("coverage projection", Result.CREATED)
        else:
            out.note("coverage projection", Result.WOULD_CREATE)
    else:
        out.note("coverage projection", Result.EXISTS)

    # SEED ONLY. These files are live state once the project is connected:
    # source.json carries the projection's replay head and inflight.json the
    # in-flight operation markers §5.3 uses for orphan recovery. Install is
    # documented as re-runnable — an upgrade path — so writing them
    # unconditionally would reset the replay head and drop an in-flight
    # signature on any re-run against a working project. Absent means
    # uninitialized; present means someone else owns it.
    for path, content in SEEDS:
        try:
            cov.read(COVERAGE_REF, path)
            out.note(f"coverage {path}", Result.EXISTS)
        except NotFound:
            if write:
                cov.put(COVERAGE_REF, path, content, base_blob_sha=None)
                out.note(f"coverage {path}", Result.SEEDED)
            else:
                out.note(f"coverage {path}", Result.WOULD_CREATE)


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

    dry_run = cfg.dry_run

    # The same argument as the gate above, applied to consent. A dry run writes
    # nothing and `force` is the operator saying yes explicitly; every other
    # path requires literal affirmative confirmation. Returning None, 0, an
    # empty string, or any other non-True value is not consent.
    if not (dry_run or cfg.force):
        if confirm is None:
            raise CliError(
                "refusing to provision without a way to confirm",
                hint="pass force=true to proceed without a prompt")
        if confirm(out.warnings) is not True:
            raise Aborted("cancelled; nothing was created")

    # Confirmation can remain open arbitrarily long. Re-read the organization
    # boundary after it and immediately before the first write; another owner
    # may have raised the member default from none to read in that window.
    if not dry_run:
        _require_safe_base_permission(admin, cfg)

    for full, name, desc, expected_ref in (
        (cfg.records_repo, cfg.records_name,
         f"DraCLA canonical CLA records for {cfg.slug}. Append-only. "
         "Contains signer data.", EVENTS_REF),
        (cfg.coverage_repo, cfg.coverage_name,
         f"DraCLA coverage projection for {cfg.slug}. Derived and PII-free, "
         "but not public.", COVERAGE_REF),
    ):
        existing = admin.get_repo(full)
        if existing is None:
            if dry_run:
                out.would_create.append(full)
                out.note(full, Result.WOULD_CREATE)
                continue
            try:
                creation = admin.create_repo(cfg.org, name, desc)
            except Exception as e:
                raise _with_outcome(e, out) from None
            if creation.created:
                out.created.append(full)
                out.note(full, Result.CREATED)
                continue
            # A repository won the race between GET and POST. It is existing
            # state, not something this run created, so it must traverse the
            # same visibility and provenance checks as an initial GET hit.
            existing = creation.repo

        # Re-validate visibility HERE, not only in preflight. Between the
        # preflight check and this line the operator answered a prompt, and in
        # that window another owner can create this repository public or flip
        # an existing one. Seeding it anyway would put signer names and email
        # addresses in a public repository.
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
        # Empty reuse is intentionally unchanged here pending the owner-reserved
        # provenance/nonce decision. Non-empty repositories must have the exact
        # DraCLA root commit rather than a marker copied into current content.
        verdict = _provenance(admin, full, expected_ref)
        if verdict == UNREADABLE:
            raise InstallFailed(
                f"could not read {full} to check what it is",
                hint="GitHub refused or failed the branch read. That is not "
                     "the same as a name collision, so no advice about "
                     "renaming it is offered here.\n"
                     "Check the token is authorized for this organization "
                     "(SAML SSO needs it explicitly) and re-run.",
                outcome=out)
        if verdict == COLLISION:
            raise InstallFailed(
                f"{full} already exists and is not a DraCLA repository",
                hint=f"its '{expected_ref.rsplit('/', 1)[-1]}' branch is "
                     f"missing or not rooted at the exact DraCLA genesis, so "
                     f"this is a name collision rather than a re-run. "
                     f"Its existing collaborators would be able to read "
                     f"signer data.\n"
                     f"Rename it, empty it, or choose another "
                     f"recipient.slug.",
                outcome=out)
        out.note(full, Result.EXISTS)

    try:
        host = records_host or admin.host_for(cfg.records_repo)
        cov = coverage_host or admin.host_for(cfg.coverage_repo)
        body = render(cfg.coverage_repo, version, EVENTS_BRANCH)

        if dry_run:
            # The preview walks the same steps as the real run, with write=False.
            # A separate hand-written preview once omitted the coverage section
            # and told a re-run it "would create" a branch that already exists;
            # dry-run's whole purpose is to be trustworthy, so it shares the walk
            # instead of imitating it.
            _provision(admin, cfg, out, host, cov, body, write=False,
                       fresh_records=cfg.records_repo in out.would_create,
                       fresh_coverage=cfg.coverage_repo in out.would_create)
            return out

        _provision(admin, cfg, out, host, cov, body, write=True)
        return out
    except Exception as e:
        # Every write boundary below repository creation — branch bootstrap,
        # default promotion, workflow and projection seeds — preserves the same
        # Outcome contract. Protocol conflicts are not CliError subclasses, so
        # catching only the console error hierarchy silently discarded it.
        raise _with_outcome(e, out) from None
