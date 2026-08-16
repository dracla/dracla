# DraCLA Requirements

Status: Locked
Date: 17 August 2026

## 1. Purpose

DraCLA is a project-neutral, GitHub-native system for managing Contributor
License Agreements (CLAs). It provides authenticated signing, durable records,
pull request enforcement, revocation, entity coverage, exports, and a searchable
dashboard without requiring each open source project to operate a conventional
signature database.

DraCLA is software for administering agreements supplied by a project. It does
not draft agreements, determine whether an agreement is legally sufficient, or
provide legal advice.

The project name is **DraCLA**. Repository names, package names, Python imports,
and command names use lowercase `dracla`.

## 2. Requirement language

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe requirement
strength. Requirements marked "Open" record decisions that have not yet been
made and MUST NOT be silently resolved during implementation.

## 3. Product principles

1. GitHub is the identity provider and durable system of record.
2. Agreement text and every acceptance are tied to an immutable version and
   content digest.
3. Evidence is append-only. Revocation or correction does not erase history.
4. Sensitive signer data is private by default.
5. Public status surfaces disclose only what contributors need.
6. Projects retain control of their agreements, records, access, and keys.
7. The core workflow MUST work for organizations using GitHub Free.
8. DraCLA MUST remain generic and MUST NOT contain Hydra-specific policy or
   agreement text.

## 4. Actors

- **Contributor:** A GitHub user who signs or revokes an Individual CLA.
- **Entity signatory:** A person authorized to execute an Entity CLA.
- **Authorized Contributor:** A GitHub user covered by a recorded Entity CLA.
- **Project administrator:** A maintainer authorized to configure DraCLA and
  administer project records and policy.
- **Records reader:** A maintainer permitted to view the project's private CLA
  records and dashboard.
- **DraCLA GitHub App:** The application that authenticates users, processes
  GitHub events, and reports pull request status.

## 5. Project configuration

### REQ-CONFIG-1: Independent project ownership

Each adopting project MUST own its configuration and records. DraCLA MUST NOT
require signature records from unrelated projects to share a repository or
encryption key.

### REQ-CONFIG-2: Agreement recipient

Project configuration MUST identify the legal person or entity receiving the
rights granted by each agreement. DraCLA MUST NOT assume that a GitHub
organization is itself the legal recipient.

### REQ-CONFIG-3: Repository scope

A project MUST be able to define which GitHub organizations and repositories an
agreement covers. The effective scope MUST be captured with every acceptance.

### REQ-CONFIG-4: Agreement types

The initial release MUST support an Individual CLA signed electronically by a
contributor. Entity CLA support is a post-initial-release requirement and, when
introduced, MUST be configurable without changing DraCLA source code.

## 6. Agreement management

### REQ-AGR-1: Immutable versions

Every published agreement version MUST have:

- a project-defined agreement identifier;
- an explicit version identifier;
- the exact agreement content or an immutable content reference;
- a cryptographic digest of the content;
- its effective publication time; and
- its project and repository scope.

Published versions MUST NOT be modified in place.

### REQ-AGR-2: Version transitions

When a project activates a new agreement version, DraCLA MUST preserve all
earlier versions and their acceptances. Project policy MUST determine whether
an earlier acceptance remains current or the contributor must re-sign.

### REQ-AGR-3: Presentation before acceptance

The signing page MUST show the complete agreement, its recipient, version,
scope, and required signer fields before enabling acceptance.

### REQ-AGR-4: Project-supplied policy

DraCLA MUST treat agreement language and project contribution policy as
project-supplied inputs. It MUST NOT infer legal meaning from agreement text.

## 7. Individual signing

### REQ-SIGN-1: GitHub authentication

A contributor MUST authenticate with GitHub before signing. DraCLA MUST record
the stable GitHub numeric user ID as the primary account identifier and the
current login as a historical snapshot.

### REQ-SIGN-2: Explicit assent

Acceptance MUST require an affirmative action on a form that clearly identifies
the agreement and project. Merely opening a page, opening a pull request, or
authenticating with GitHub MUST NOT constitute acceptance.

### REQ-SIGN-3: Signer fields

Projects MUST be able to require a full legal name, email address, and explicit
confirmations appropriate to their agreement. Required fields and the exact
confirmation labels MUST be preserved with the acceptance record.

### REQ-SIGN-4: Acceptance evidence

An acceptance record MUST include at least:

- GitHub numeric user ID and login snapshot;
- agreement identifier, version, and digest;
- project and repository scope;
- acceptance timestamp;
- submitted signer fields and confirmations;
- the DraCLA software version or event schema version; and
- a unique event identifier.

### REQ-SIGN-5: Idempotency

Repeated delivery of the same acceptance request MUST NOT create conflicting
records. Legitimate re-signing MUST create a new event linked to the earlier
acceptance.

## 8. Revocation and re-signing

### REQ-REV-1: Contributor-controlled revocation

An authenticated contributor MUST be able to revoke their current acceptance
from the same project-facing portal used to inspect or sign the CLA.

### REQ-REV-2: Clear effect

Before confirmation, the portal MUST explain that revocation changes DraCLA
coverage for contributions considered after revocation but does not delete the
record or withdraw rights already granted under an irrevocable license.

### REQ-REV-3: Append-only event

Revocation MUST append a timestamped event tied to the acceptance being
revoked. It MUST NOT delete or rewrite the acceptance.

### REQ-REV-4: Enforcement after revocation

After revocation, DraCLA MUST report the contributor as not currently covered
for new merge decisions until the contributor signs an acceptable agreement
version again. Existing accepted contributions and historical evidence remain
unchanged.

### REQ-REV-5: Re-signing

A revoked contributor MUST be able to re-sign. The new acceptance MUST be a new
event and MUST NOT reactivate or mutate the old event.

## 9. Entity CLAs

Entity CLA support is explicitly deferred from the initial release. The
requirements in this section apply when that support is introduced.

### REQ-ENTITY-1: Manual administration

Entity CLAs MUST use an explicit manual administration path. DraCLA is not
required to negotiate agreements or automate corporate signature collection.

### REQ-ENTITY-2: Entity evidence

An Entity CLA record MUST identify the entity, authorized signatory, agreement
version and digest, effective date, project scope, and retained evidence of
execution.

### REQ-ENTITY-3: Authorized Contributors

Project administrators MUST be able to add and remove GitHub users from an
entity's Authorized Contributor list. Each change MUST be append-only,
timestamped, attributable to an administrator, and tied to the relevant Entity
CLA.

### REQ-ENTITY-4: Coverage decisions

Pull request checks MUST be able to recognize current Entity CLA coverage
without requiring the contributor to sign an Individual CLA automatically.

### REQ-ENTITY-5: Contributor visibility

After GitHub authentication, a contributor MUST be able to see whether DraCLA
considers them covered by an Entity CLA. Sensitive entity evidence MUST remain
private.

## 10. Pull request enforcement

### REQ-CHECK-1: GitHub check

DraCLA MUST publish an unambiguous GitHub check result for configured pull
requests. Public checks, badges, and comments MUST disclose only one of:

- CLA satisfied;
- action required; or
- temporarily unavailable.

After authentication, the contributor portal MUST show the exact reason for an
action-required result, such as no acceptance, revocation, an insufficient
agreement version, or an unresolved contributor identity.

For GitHub Check Runs, current coverage MUST use the `success` conclusion.
States that require contributor or maintainer action MUST use a non-passing
conclusion such as `failure` or `action_required`; they MUST NOT use `neutral`
or `skipped`. While evaluation is actively pending, the GitHub App MUST use a
state available to GitHub Apps, such as `queued` or `in_progress`, rather than a
state reserved to GitHub Actions.

### REQ-CHECK-2: Coverage subjects

DraCLA MUST evaluate the pull request opener and every GitHub-resolved author
and co-author of every commit in the pull request. Subjects MUST be deduplicated
by stable GitHub numeric user ID, and every subject MUST have current coverage.
If GitHub cannot resolve an author or co-author to a user ID, the result MUST be
action required.

Non-human accounts MUST follow the same rule unless project configuration
explicitly exempts them. Exemptions and maintainer overrides MUST be
attributable, append-only events. An override MUST identify the pull request
head commit and the unresolved or uncovered subjects to which it applies.

### REQ-CHECK-3: Merge enforcement

For strong enforcement, projects MUST be able to require a GitHub merge queue
and make DraCLA a required check for merge groups. On a `merge_group`
`checks_requested` event, DraCLA MUST evaluate the merge candidate's current
pull requests and commits against the latest canonical CLA records and report
on the merge-group commit. This merge-group result is the authoritative CLA
decision for landing.

The ordinary pull request check is early feedback. Without a required merge
queue, DraCLA MAY report pull request status but MUST NOT claim that it performs
a final pre-landing check. Documentation MUST also explain that repository
administrators may retain a GitHub-supported bypass capability.

### REQ-CHECK-4: Evaluation triggers

Pull request creation and synchronization MUST evaluate that pull request.
Signing from a pull request flow MUST re-evaluate the originating pull request.
The authoritative merge-group check MUST always evaluate current pull request
content against the canonical CLA state observed when that check runs.

Signing, revocation, and agreement changes MUST NOT require a global scan of
open pull requests. DraCLA MAY add broader re-evaluation or derived indexes as
an optimization, but core correctness MUST NOT depend on them.

### REQ-CHECK-5: Unavailable service

If DraCLA cannot establish current coverage, it MUST NOT report a successful
check. While automatic recovery is in progress, it SHOULD leave a clear
`queued` or `in_progress` result. When evaluation cannot continue without
intervention, it SHOULD complete with `failure` or `action_required`. In either
case, the result MUST explain how evaluation will be retried or how an
authorized user can request a retry without exposing private signer data.

## 11. Records

### REQ-REC-1: Private repository

Each project MUST be able to use a private GitHub repository as its authoritative
CLA record store. Core operation MUST NOT require a paid GitHub plan.

### REQ-REC-2: Repository boundary

The GitHub App MUST receive only the repository permissions needed to append and
read records and report checks. Cross-repository access MUST be explicit.

### REQ-REC-3: Append-only history

Signatures, revocations, agreement publications, entity authorizations, and
administrative corrections MUST be represented as append-only events. A
correction MUST reference the event it corrects and preserve the original.

The canonical records branch MUST contain one logical event per commit. Each
event commit MUST have the current branch head as its single parent, and
DraCLA MUST update the branch only by fast-forward. Commit ancestry is the
authoritative event order; author, committer, and event timestamps MUST NOT
resolve ordering conflicts.

When a concurrent writer advances the branch first, DraCLA MUST reload the new
head, check the operation's stable idempotency key, and retry without losing or
duplicating either event. DraCLA MUST NOT create merge commits in the canonical
event history.

### REQ-REC-4: Integrity

Records MUST be cryptographically tied to their agreement content through the
agreement digest and Git commit object ID. In the initial release, repository
administrators are trusted: DraCLA MUST never force-update or delete canonical
history, and backups MUST preserve commit history and recorded branch-head
identities. DraCLA MUST document that it cannot detect rewriting by an
administrator who controls both the repository and every backup.

Independent event signatures, external checkpoints, and integrity-key
management MAY be added as optional future hardening.

### REQ-REC-5: Portable formats

The canonical event format MUST be documented, versioned, and readable without
DraCLA. Projects MUST be able to export current and historical records as JSON
and CSV.

### REQ-REC-6: Rebuildability

Derived indexes, dashboards, and reports MUST be reproducible from canonical
events. Generated artifacts MUST NOT become an independent source of truth.

### REQ-REC-7: Backup

DraCLA MUST document a backup and recovery procedure for the records repository
and any keys required to interpret protected record content.

## 12. Privacy and security

### REQ-SEC-1: Data minimization

DraCLA MUST collect only fields required by the selected agreement and project
policy. It MUST NOT collect an IP address merely because a signing workflow can
observe it.

### REQ-SEC-2: Private signer information

Legal names, email addresses, form responses, entity evidence, and raw audit
events MUST NOT appear in public dashboards, badges, comments, checks, logs, or
workflow artifacts.

### REQ-SEC-3: Project privacy policy

The signing page MUST link to the adopting project's privacy policy before
acceptance.

### REQ-SEC-4: Authentication security

The web flow MUST protect signing, revocation, and administrative actions
against forged requests, replay, and cross-site request forgery. GitHub tokens
and application secrets MUST NOT be stored in records repositories or exposed
to browser code unnecessarily.

### REQ-SEC-5: Webhook security

GitHub webhook authenticity MUST be verified. Replayed or duplicated webhook
deliveries MUST be safe.

### REQ-SEC-6: Authorization

Administrative access MUST be derived from current GitHub authorization. The
private dashboard SHOULD authorize a viewer by verifying that the viewer can
read the project's records repository, rather than maintaining a second user
allowlist.

### REQ-SEC-7: Retention transparency

The signing and revocation flows MUST explain that agreement evidence is
retained after revocation. Retention and correction procedures MUST be
documented per project.

### REQ-SEC-8: Untrusted content and exports

DraCLA MUST treat agreement content, project configuration, signer fields,
confirmation labels, and record-derived dashboard values as untrusted input.
Content rendered into HTML, checks, badges, or generated artifacts MUST be
contextually escaped. If project-supplied markup is supported, it MUST be
sanitized with an explicit allowlist and rendered under a restrictive Content
Security Policy.

CSV exports MUST prevent cells derived from untrusted input from being
interpreted as spreadsheet formulas while preserving the unmodified canonical
value in the JSON export.

## 13. Contributor portal and badges

### REQ-PORTAL-1: Project page

Each project MUST have a stable contributor-facing page. After GitHub login it
MUST show the viewer's exact Individual CLA status and offer the applicable
Sign, Re-sign, or Revoke action.

### REQ-PORTAL-2: CONTRIBUTING badge

DraCLA MUST provide a project badge suitable for `CONTRIBUTING.md`. Because a
GitHub-rendered image cannot safely identify its viewer, this shared badge MUST
show a generic state such as "CLA: sign or check status" and link to the
project page.

### REQ-PORTAL-3: Pull request badge

A pull request badge or comment MUST use the same generic public states as the
GitHub check and MUST NOT display or encode the exact coverage or failure
reason. It SHOULD link to the authenticated project page for details.

### REQ-PORTAL-4: Accessible wording

Status text and actions MUST be understandable without relying on badge color.
Contributor-facing language SHOULD be factual, concise, and should avoid
implying that signing transfers copyright when the configured agreement grants
only a license.

## 14. Maintainer dashboard

### REQ-DASH-1: Dynamic private dashboard

DraCLA MUST provide a private, dynamic dashboard comparable to Backlog Atlas in
interaction style. Filtering and sorting SHOULD happen immediately in the
browser after loading a generated index.

### REQ-DASH-2: Filters

The dashboard MUST support filtering by:

- GitHub user;
- project and repository scope;
- agreement identifier and version;
- current, revoked, superseded, or indeterminate status;
- Individual CLA coverage and, when supported, Entity CLA coverage; and
- acceptance or revocation date.

### REQ-DASH-3: Access boundary

Dashboard access MUST require GitHub authentication and current permission to
read the project's records repository. A publicly hosted application shell MAY
be used, but private data MUST NOT be embedded in public static assets.

### REQ-DASH-4: Derived index

The dashboard SHOULD consume a generated, private index optimized for filtering
rather than loading every evidence record. The index MUST be reproducible and
MUST contain no more sensitive data than the dashboard requires.

### REQ-DASH-5: Live updates

Record changes MUST trigger regeneration of the dashboard index. The dashboard
MAY refresh or poll for the latest generated index; real-time streaming is not
required.

## 15. Deployment and portability

### REQ-OPS-1: Self-hosting

DraCLA MUST be deployable by an open source project without dependence on a
DraCLA-operated multi-tenant service.

### REQ-OPS-2: No records database

The initial architecture MUST use the project's GitHub records repository as
durable storage. A stateless web or authentication component MAY be used, but a
separate persistent application database MUST NOT be required for core signing,
revocation, checks, or dashboard reconstruction.

### REQ-OPS-3: GitHub Free baseline

The documented baseline MUST work for a GitHub organization on the Free plan.
Features that require paid GitHub plans MAY be documented as optional
hardening, but MUST NOT be prerequisites for correct core behavior.

The GitHub Free baseline MUST use public contributing repositories when branch
protection or required checks are part of enforcement; the authoritative
records repository MAY remain private. Documentation MUST state that enforcing
required checks on a private contributing repository depends on a GitHub plan
that supports branch protection for private repositories.

Strong final enforcement in the baseline MUST use a required merge queue and a
required DraCLA merge-group check. Core operation MUST NOT require a durable
job queue, reverse pull request index, or global pull request rescan.

### REQ-OPS-4: Generic installation

Installation MUST be driven by project configuration and documented so that a
project unrelated to Hydra can deploy DraCLA without editing source code.

### REQ-OPS-5: Observability

Operational logs MUST identify failed events and correlation identifiers while
excluding signer PII and credentials.

## 16. Initial release scope

The first usable release MUST demonstrate all of the following:

1. Register one project and publish a versioned Individual CLA.
2. Authenticate a GitHub user and record explicit acceptance.
3. Evaluate the opener and every GitHub-resolved commit author and co-author.
4. Report a passing early check when every subject is covered and a non-passing
   check when a subject is uncovered or unresolved.
5. Re-evaluate the originating pull request after signing from its flow.
6. Enforce a fresh required check on a GitHub merge-group candidate.
7. Allow the contributor to inspect status, revoke, and re-sign.
8. Rebuild JSON and CSV exports from canonical events.
9. Present a private dashboard with live filtering.
10. Provide a generic project badge and contributor portal link.
11. Install for a second sample project using configuration only.

### REQ-VERIFY-1: Release traceability

Release acceptance MUST include a traceability matrix mapping every in-scope
`MUST` requirement to an automated test or an explicitly recorded manual
verification. An unmet or unverified `MUST` requirement MUST prevent release
unless the requirements document explicitly defers it.

### REQ-VERIFY-2: Required acceptance scenarios

The initial release verification MUST include at least:

- every documented coverage outcome and its GitHub check state and conclusion;
- pull requests with multiple commit authors, co-authors, unresolved identities,
  explicit bot exemptions, and an attributable head-specific override;
- a required merge-group check that observes a revocation or agreement change
  made after the ordinary pull request check;
- service-unavailable behavior and both automatic and user-requested retry;
- malicious agreement, configuration, signer, and dashboard values rendered in
  every supported output format;
- spreadsheet-formula payloads in CSV exports while JSON retains the canonical
  value;
- loss of a viewer's or administrator's GitHub authorization;
- backup restoration followed by a complete rebuild of current status, JSON and
  CSV exports, and the dashboard index; and
- a clean installation in the documented GitHub Free baseline using a public
  contributing repository and a private records repository.

## 17. Initial non-goals

The initial release does not need to provide:

- legal advice or agreement drafting;
- Entity CLA records, Authorized Contributor administration, or entity-derived
  pull request coverage;
- negotiation of alternative Entity CLA terms;
- automated determination of contribution ownership or employer permission;
- identity proofing beyond authenticated GitHub identity and project-required
  signer fields;
- GitLab, Gerrit, or non-GitHub forge integration;
- a public directory of signer PII;
- a mobile application;
- billing, subscriptions, or hosted-service account management; or
- a generalized electronic-signature platform for documents unrelated to
  software contributions.

## 18. Open decisions

The following decisions require explicit resolution before implementation that
depends on them:

1. **Agreement transition policy:** the supported rules for deciding when an
   older acceptance remains current.
2. **Sensitive-record protection:** whether signer fields are encrypted inside
   the private records repository, and the corresponding key-management and
   recovery design.
3. **Administrative corrections:** the exact approval rules for correcting
   mistaken records without rewriting history.
4. **Web runtime:** the minimum stateless hosting model needed for GitHub OAuth,
   contributor actions, and the private dashboard.
5. **Public status exposure:** whether projects may publish individual status
   endpoints beyond pull request-specific checks and badges.
6. **Historical import:** whether the initial release must import records from
   hosted CLA Assistant or other CLA systems.

## 19. Acceptance of this requirements document

This document defines product requirements, not an implementation architecture.
A design proposal MUST map its major components to these requirement IDs and
MUST identify any requirement it defers or cannot satisfy.

This requirements baseline is locked. A substantive change MUST be proposed as
an explicit requirements change, identify the affected requirement IDs and
rationale, and receive project approval before it is incorporated. The document
MUST be marked Draft while such a change is under review and Locked again only
after the revised baseline is approved. Editorial corrections that do not alter
meaning MAY be made through normal review.
