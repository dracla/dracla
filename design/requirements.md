# DraCLA Requirements

Status: Locked
Date: 23 August 2026
Revision: 12 — requires application-layer encryption for private records and
derived coverage, separates repository visibility from plaintext-reader
authorization, and requires adopter-controlled key recovery; see section 20.

## 1. Purpose

DraCLA is a project-neutral, GitHub-native system for managing Contributor
License Agreements (CLAs). It provides authenticated signing, durable records,
pull request enforcement, revocation, entity coverage (post-initial release,
section 9), exports, and a searchable
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
4. Signer data is private by default.
5. Public status surfaces disclose only what contributors need.
6. Projects retain control of their agreements, records, and access, and can
   self-host DraCLA when they require independent control of operational keys.
7. The core workflow MUST work for organizations using GitHub Free.
8. DraCLA MUST remain generic and MUST NOT contain Hydra-specific policy or
   agreement text.

## 4. Actors

- **Contributor:** A GitHub user who signs or revokes an Individual CLA.
- **Entity signatory:** A person authorized to execute an Entity CLA.
- **Authorized Contributor:** A GitHub user covered by a recorded Entity CLA.
- **Project administrator:** A maintainer authorized for a specific DraCLA
  administrative action under `REQ-SEC-6`. This is not a single global role.
- **Records reader:** An authenticated person explicitly authorized through
  DraCLA to view the project's private CLA records and dashboard. GitHub
  repository read access alone does not confer this role.
- **Key controller:** A person or service that can obtain a project decryption
  key or cause trusted code to use it, including through control of secrets,
  protected key-bearing workflows, a decryption service, or recovery material.
- **Shared DraCLA operator:** The person or organization operating DraCLA's
  shared hosted deployment and its GitHub Apps. A project using that deployment
  trusts this operator with the maximum access described by `REQ-OPS-6`.
- **DraCLA GitHub App(s):** The application or applications that authenticate
  users, process GitHub events, and report pull request status.

## 5. Project configuration

### REQ-CONFIG-1: Independent project ownership

Each adopting project MUST own its configuration and records. DraCLA MUST NOT
require signature records from unrelated projects to share a repository.
Every project MUST use records and coverage data-encryption keys that are not
used by any unrelated project. A shared hosted deployment MAY use one wrapping
root across projects for the records capability and a separate wrapping root
across projects for the coverage capability. Every wrapped project key MUST be
authenticated to its project identity and capability so it cannot be
substituted across projects or between records and enforcement. A self-hosted
deployment MUST use wrapping roots controlled by that adopter.

### REQ-CONFIG-2: Agreement recipient

Each agreement version MUST identify the legal person or entity receiving the
rights granted by that agreement. DraCLA MUST NOT assume that a GitHub
organization is itself the legal recipient. The recipient identity MUST be
immutable for that agreement version and MUST be bound into its acceptance
evidence.

A change of legal recipient MUST create a distinct project identity, or an
explicitly identified successor project with a new agreement version. It MUST
NOT rewrite the recipient associated with an earlier version or acceptance.

### REQ-CONFIG-3: Enforcement scope

A project MUST be able to define the GitHub organizations and repositories in
which DraCLA enforces an agreement. This configuration is the **enforcement
scope**; it determines where DraCLA runs checks, not the legal scope of the
rights granted by an acceptance.

The agreement text defines its own legal scope. DraCLA MUST present that text
but MUST NOT interpret it or derive legal coverage from repository
configuration. Widening or narrowing enforcement scope MUST NOT alter an
existing grant, invalidate an acceptance, or require re-signing by itself.

For overlap enforcement, a **coordination domain** is one DraCLA deployment and
the authoritative project registry it operates. A GitHub repository MUST NOT be
in the enforcement scope of more than one DraCLA project within the same
coordination domain. A repository binding or organization-wide selector change
that would create such an overlap MUST fail without changing either project.
Moving a repository between projects in one domain MUST be an explicit removal
from the old project followed by a binding to the new project; it MUST NOT
create a period of simultaneous membership.

Repository creation, rename, transfer, ownership change, restoration, or
another GitHub-side lifecycle change can alter which scope entries match
without changing DraCLA configuration. If such a change makes one repository
match more than one project in a coordination domain, DraCLA MUST select
neither project and MUST fail closed for that repository until the conflict is
resolved. The public result MUST state that the repository is covered by more
than one CLA project and that an administrator must resolve the conflict, but
MUST NOT identify the matching projects or expose their private configuration.
Other repositories in those projects MUST continue operating normally.

DraCLA MUST provide authenticated administrative tools for this conflict. A
viewer MUST have current `admin` permission on the affected repository. The
tools MUST disclose only the affected repository, every matching project
identifier, the scope entries that caused the conflict, and the authority
required for each resolution action. This permission MUST NOT grant access to
signer records or unrelated project configuration.

The tools MUST let an administrator perform each resolution action for which
they have current authority, such as removing or narrowing a binding or
selector or completing an explicit non-overlapping move. Inspection authority
MUST NOT authorize a scope mutation by itself. When the actor lacks authority
for a required action, the tools MUST identify that authority and MUST NOT
perform the action. DraCLA MUST NOT choose a project by precedence or move the
repository automatically. Resolution authority MUST follow `REQ-SEC-6`.
Detection and recovery MUST NOT depend on delivery of any single GitHub event;
periodic reconciliation MUST detect missed lifecycle changes. The conflict and
its resolution MUST NOT alter CLA evidence, invalidate an acceptance, or
require contributors to re-sign.

The enforcement path MUST NOT authorize a repository from an eventually
consistent route after the coordination domain has recorded that route as
pending, unavailable, or replaced. Route publication MUST therefore use a
repository-scoped, strongly consistent fail-closed gate. Every enforcement
request MUST compare the gate's current state and generation with the routed
projection. A missing or unavailable gate, a pending state, or any state or
generation mismatch MUST fail closed only the affected repository. Cache
invalidation, time-based expiry, and later reconciliation MAY reduce or repair
staleness but MUST NOT be the safety proof.

An authenticated GitHub enforcement event whose repository identity or
installation facts differ from the routed projection MUST reject that route
and put the repository through the same fail-closed reconciliation path. Event
data MAY invalidate a route but MUST NOT select a replacement project without
the authoritative registry derivation.

The shared hosted deployment is one coordination domain. Each independently
operated self-hosted deployment is a separate domain. DraCLA cannot discover or
prevent two independent domains from targeting the same repository without
making them depend on shared global state. Such a configuration is unsupported
administrator misconfiguration and MUST be documented; DraCLA MUST NOT claim
global uniqueness across independent domains.

### REQ-CONFIG-4: Agreement types

The initial release MUST support an Individual CLA signed electronically by a
contributor and MUST permit exactly one agreement identifier per project.
Agreement versions under that identifier follow `REQ-AGR-2`; they are not
separate agreements. Entity CLA support is a post-initial-release requirement
and, when introduced, MUST be configurable without changing DraCLA source code.
Before a later release permits more than one agreement identifier for a
project, its requirements MUST define whether and how those agreements combine
to provide coverage.

### REQ-CONFIG-5: Scope authorization

A repository or organization MUST NOT enter a project's enforcement scope
without the consent of a person authorized to administer that repository's
owner. Consent MUST be verified when enforcement scope is first bound and again
whenever it is widened, and MUST be recorded attributably. Installing a DraCLA
App MUST NOT by itself constitute consent to any specific project's agreement.

## 6. Agreement management

### REQ-AGR-1: Immutable versions

Every published agreement version MUST have:

- a project-defined agreement identifier;
- an explicit version identifier;
- the immutable legal recipient identity;
- the exact agreement content or an immutable content reference;
- a cryptographic digest of the content;
- its publication time.

Published versions MUST NOT be modified in place.

### REQ-AGR-2: Version transitions

Publishing a version and activating it are distinct acts. A project MAY publish
multiple immutable versions. Publishing MUST NOT affect coverage, and an
inactive version MUST NOT be offered for signing. Activation is immediate,
selects exactly one active and signable version for an agreement, and replaces
the version that was active before it. A project with no active version has no
signable agreement.

When a project activates a new agreement version, DraCLA MUST preserve all
earlier versions and their acceptances.

Every activation event MUST carry a `supersedes_coverage` boolean:

- If `true`, an acceptance of an earlier version MUST NOT provide current
  coverage for a merge decision made after the activation takes effect, and the
  contributor MUST accept the active version before new contributions can land.
- If `false`, every acceptance that provided current coverage immediately
  before activation MUST continue to do so. This MUST NOT revive an acceptance
  that was already revoked, superseded, or otherwise not current.

DraCLA MUST NOT infer which applies from the agreement text; the project
declares it on the activation, consistent with `REQ-AGR-4`. The declaration MUST
be carried on the append-only activation event, not in mutable configuration,
because it determines who is covered.

Future-effective or scheduled activations MUST NOT be supported. Contributors
MUST NOT be shown or allowed to sign a version before it is active.

### REQ-AGR-3: Presentation before acceptance

The signing page MUST show the complete agreement, its recipient, version, and
required signer fields before enabling acceptance. Any legal scope shown to the
signer MUST come from the agreement itself, not from DraCLA enforcement scope.

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
- immutable legal recipient identity;
- agreement identifier, version, and digest;
- acceptance timestamp;
- submitted signer fields and confirmations;
- the DraCLA software version or event schema version;
- the canonical idempotency key; and
- a unique event identifier.

### REQ-SIGN-5: Idempotency

Every mutating contributor or administrative submission, including acceptance,
revocation, and re-signing, MUST carry a canonical idempotency key. The key MUST
remain stable across retries of one submission and MUST be fresh for a new
explicit action, even when its submitted values are identical to an earlier
action. Reuse of one key with different authenticated actor, operation type,
target, or payload MUST fail as a conflict and MUST NOT append an event. The
corresponding event record MUST preserve the key and define an unambiguous
mapping between that key and the event identity or path.

Repeated delivery of the same acceptance submission MUST return the result of
the original operation and MUST NOT create conflicting records. Correcting
signer-submitted fields MUST require the signer to complete
the signing flow again with fresh explicit assent. The resulting acceptance
MUST be a new event linked to the earlier acceptance and MUST supersede it for
current-state reporting without modifying it. An administrator MUST NOT edit or
replace signer-submitted acceptance data.

## 8. Revocation and re-signing

### REQ-REV-1: Contributor-controlled revocation

An authenticated contributor MUST be able to revoke current coverage for a
specific agreement from the same project-facing portal used to inspect or sign
that agreement. The revoked **coverage tuple** is:

- the contributor's stable GitHub numeric user ID;
- the DraCLA project identity;
- the agreement identifier; and
- the immutable legal recipient identity.

Agreement version and repository enforcement scope are not part of this tuple.
Revocation applies to every earlier acceptance of every version for the selected
tuple. It affects coverage in every repository where that project and agreement
are enforced, including repositories added to the enforcement scope later. A
change to enforcement scope MUST NOT narrow, widen, remove, or otherwise alter
the revocation event itself. The initial release MUST NOT provide an implicit
operation that revokes other projects, agreements, recipients, or users.
An abuse control MUST NOT trap a contributor in covered status by refusing a
valid revocation solely because of earlier successful acceptance or revocation
events.

### REQ-REV-2: Clear effect

Before confirmation, the portal MUST explain that revocation changes DraCLA
coverage for contributions considered after revocation but does not delete the
record or withdraw rights already granted under an irrevocable license.

After a successful revocation, the portal MUST clearly confirm success, identify
the project, agreement, and legal recipient, and explain that every earlier
acceptance for that coverage tuple remains in history but no longer provides
coverage for future merge decisions in any repository where the tuple is
enforced.

### REQ-REV-3: Append-only event

Revocation MUST append a timestamped event that identifies the complete coverage
tuple, the canonical idempotency key, and the immutable canonical-state identity
against which the contributor confirmed the action. By its position in
canonical event order, the revocation event MUST cut off coverage from every
earlier acceptance for that tuple without deleting, rewriting, or reclassifying
any earlier event.

If an acceptance for the same tuple lands after confirmation but before the
revocation can be appended, semantic revalidation under `REQ-REC-3` MUST reject
the stale revocation and require fresh confirmation. Retrying a revocation that
already landed with the same idempotency key MUST return the original event as
an idempotent result.

### REQ-REV-4: Enforcement after revocation

After revocation, DraCLA MUST report the contributor as not currently covered
for the selected tuple in every repository where it is enforced. Activating
another version or changing repository enforcement scope MUST NOT revive an
earlier acceptance. Coverage resumes only from a later acceptance for that same
tuple. Existing accepted contributions, other coverage tuples, and historical
evidence remain unchanged.

### REQ-REV-5: Re-signing

A revoked contributor MUST be able to re-sign. The successful revocation screen
MUST offer an immediate and easy action, such as **Restore coverage**, that opens
the signing flow with the same project, agreement, and recipient already
selected. The flow MUST still show the complete active agreement and require
fresh explicit assent under `REQ-AGR-3` and `REQ-SIGN-2`.

The resulting acceptance MUST be a new event after the revocation. It restores
coverage only from that point onward and MUST NOT delete, reactivate, or mutate
any earlier acceptance or revocation event. DraCLA MUST NOT impose a cap on
successful acceptance or revocation events that prevents this fresh acceptance.
Idempotent retries and semantic no-ops MUST still append nothing. Any future
abuse control MUST preserve both immediate revocation and immediate fresh
re-signing.

## 9. Entity CLAs

Entity CLA support is explicitly deferred from the initial release. The
requirements in this section apply when that support is introduced.

### REQ-ENTITY-1: Manual administration

Entity CLAs MUST use an explicit manual administration path. DraCLA is not
required to negotiate agreements or automate corporate signature collection.

### REQ-ENTITY-2: Entity evidence

An Entity CLA record MUST identify the entity, authorized signatory, immutable
recipient identity, agreement version and digest, effective date, and retained
evidence of execution.

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

After authentication, the contributor portal MUST show a contributor the exact
reason for their own action-required status, such as no acceptance, revocation,
an insufficient agreement version, or an unresolved contributor identity.
Information about other pull request subjects MUST follow `REQ-PORTAL-6`.

For GitHub Check Runs, current coverage MUST use the `success` conclusion.
States that require contributor or maintainer action MUST use a non-passing
conclusion such as `failure` or `action_required`; they MUST NOT use `neutral`
or `skipped`. While evaluation is actively pending, the GitHub App MUST use a
state available to GitHub Apps, such as `queued` or `in_progress`, rather than a
state reserved to GitHub Actions.

The multiple-project conflict defined by `REQ-CONFIG-3` is the sole exception
to the generic-only wording above. Its public result MUST use `action required`
and MUST also state that the repository is covered by more than one CLA project
and that an administrator must resolve the conflict. It MUST NOT identify a
matching project, disclose a matching scope entry, or expose private
configuration.

### REQ-CHECK-2: Coverage subjects

DraCLA MUST evaluate the pull request opener and every GitHub-resolved author
of every commit in the pull request. Subjects MUST be deduplicated by stable
GitHub numeric user ID, and every subject MUST have current coverage. If GitHub
cannot resolve a commit author to a user ID, the result MUST be action required.

For commit authors, "GitHub-resolved" means only the account attribution
reported by GitHub for that commit. DraCLA MUST NOT present that attribution as
proof that the account holder authored or approved the commit, and the initial
release MUST NOT require signed commits. Documentation MUST explain that commit
author metadata can be fabricated and can expose the aggregate CLA result for a
chosen GitHub identity. Public output MUST remain aggregate, and exact
per-subject disclosure MUST follow `REQ-PORTAL-6`.

`Co-authored-by` trailers are self-declared, unauthenticated commit-message
text. They MUST NOT determine a public check result, because any party able to
write a commit could otherwise both block an unrelated pull request and read any
GitHub user's coverage status from the public result. DraCLA MUST still surface
trailer-declared co-authors, with their coverage status, to authorized viewers
of that pull request under `REQ-PORTAL-6`, so that a project can require them to
sign or record an explicit decision. A project MAY configure trailer-declared
co-authors to block its own checks where its threat model permits.

Non-human accounts MUST follow the same rules unless project configuration
explicitly exempts them.

A project MUST also be able to exempt a named human account where the
contributor's rights are already granted by another instrument, such as an
employment agreement or a prior assignment. Such an exemption MUST record the
asserted basis and a reference to the governing instrument, MUST be attributable
to the administrator who asserted it, and MUST be reported distinctly from an
acceptance so that it is never mistaken for a signature. DraCLA MUST NOT assess
whether the asserted basis is legally sufficient.

Projects MUST support explicit exemptions for individually selected accounts
and selecting a GitHub team as a convenience. A **snapshot** selection MUST
show the team's current members, permit the administrator to select all or any
subset, and create explicit per-account exemptions; later membership changes
MUST NOT alter those exemptions. Snapshot MUST be the default when a team is
selected.

Projects MUST also support an explicitly selected **continuous** team exemption
rule. The rule is a standing delegation: while active, GitHub team membership
administrators can cause members to become exempt or cease being exempt by
changing that team's membership. The configuring administrator MUST be warned
of that consequence before confirmation. The rule MUST carry the asserted
basis and governing-instrument reference for the exemptions it creates.
Creating, changing, or withdrawing the rule MUST be an attributable canonical
administrative event authorized under `REQ-SEC-6`.

Every match or withdrawal produced by a continuous rule MUST be materialized as
an append-only per-account event that references the canonical rule event and
thereby its asserted basis and administrator, and records the stable team
identity and GitHub membership evidence observed. Because materialization
executes the already-authorized standing rule rather than claiming a new human
action, it MUST identify the automation principal and MUST NOT represent the
administrator as performing the later materialization. Coverage decisions MUST
NOT depend on unrecorded live membership state.

One account MAY have multiple active exemption sources, including individual,
snapshot, and continuous-team sources. Effective exemption is the union of
those sources. Withdrawing one source MUST withdraw only that source. The
confirmation MUST state either that the account is no longer exempt or that it
remains exempt, and in the latter case MUST identify every remaining active
source to the authorized administrator.

Exemptions and maintainer overrides MUST be attributable, append-only events,
and MUST be revocable by a later event without erasing the original. An override
MUST identify the pull request and the content it was granted against, and the
unresolved or uncovered subjects to which it applies.

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

### REQ-REC-1: Encrypted project custody and reader authorization

Each project MUST be able to use a project-controlled private GitHub repository
as its authoritative CLA record store. Core operation MUST NOT require a paid
GitHub plan or a dedicated GitHub organization.

The authoritative records repository and every repository containing private
derived or coverage artifacts MUST remain private. Application-layer
encryption is mandatory additional protection and does not make a public
records repository conforming.

Private record content stored in GitHub MUST be protected by the
application-layer encryption required by `REQ-SEC-2`. Repository read access
without decryption capability MUST reveal ciphertext rather than private record
content and MUST NOT by itself authorize portal or dashboard access. An
ordinary repository reader or read-only GitHub App that has no decryption
capability is not a records reader. A private repository in the project's
existing organization, or under a personal account, is therefore a conforming
custody shape when the remaining authorization and key-control requirements are
met. A dedicated organization MAY be used as defense in depth.

Reader authorization MUST support individually selected accounts, team
snapshots, and continuous team authorization. A snapshot MUST authorize only
the selected current members and MUST be the default when a team is selected.
A continuous team authorization is an explicitly selected standing delegation
to that team's membership administrators; the authorizing administrator MUST
be warned that future membership changes authorize new readers and cease
authorizing departed members without another DraCLA action. Multiple active
authorization sources combine by union. Withdrawing one source MUST identify
any remaining source that still authorizes the reader. Every reader
authorization, withdrawal, or standing delegation MUST be an attributable
canonical administrative event authorized under `REQ-SEC-6`.

Every plaintext read MUST require GitHub authentication and a current
authorization derived from those canonical reader sources, except for a
contributor reading only their own exact status as permitted by
`REQ-PORTAL-6`. Authorization MUST be checked before private content is
returned, and a reader MUST receive only the permitted plaintext result, not a
raw project decryption key. Loss of authorization MUST deny later reads without
requiring repository access to be changed.

Every key controller is part of the project's trusted computing and
administrative boundary even when that principal is not an ordinary records
reader. DraCLA MUST document which people and services are key controllers,
why they are necessary, and what plaintext they could obtain or cause trusted
code to reveal. At minimum this includes principals controlling project
decryption keys, protected key-bearing workflows or secrets, deployed
decryption services, and recovery material. DraCLA MUST NOT claim that
encryption protects records from a key controller. Repository readers and
read-only Apps without one of those capabilities MUST NOT be treated as key
controllers merely because they can fetch ciphertext.

### REQ-REC-2: Repository boundary

Each GitHub App and credential MUST receive only the repository permissions its
function requires. The records and enforcement capability boundary is
mandatory: a credential exposed to pull request or webhook enforcement traffic
MUST NOT decrypt signer evidence or other private canonical records, and a
credential that can append private records MUST NOT report enforcement
decisions. Private canonical records and the private enforcement projection
MUST use independently rotatable decryption authority so the enforcement path
can evaluate coverage without receiving the records decryption key. Separate
GitHub Apps or equivalently isolated credentials MAY implement the remaining
boundary. Cross-repository access MUST be explicit, and permission checks
across the boundary MUST exchange only the minimum authorization result rather
than either credential or decryption key.

### REQ-REC-3: Append-only history

Signatures, revocations, agreement publications and activations, exemptions,
overrides, and entity authorizations MUST be represented as append-only events.
Signer corrections MUST follow `REQ-SIGN-5` and preserve the original
acceptance.

The canonical records branch MUST contain one logical event per commit. This
governs event commits: a commit that carries an event MUST carry exactly one.
The branch MUST begin with one root bootstrap commit that contains a README with
record-format, recovery, and operator instructions and carries no event. The
first event commit and every later event commit MUST have the current branch
head as its single parent. Consumers MUST identify events by their recorded
paths and MUST NOT assume every commit carries an event. DraCLA MUST update the
branch only by fast-forward. Commit ancestry is the authoritative event order;
author, committer, and event timestamps MUST NOT resolve ordering conflicts.

When a concurrent writer advances the branch first, DraCLA MUST reload the new
head and check the operation's canonical idempotency key. If the same operation
already landed, it MUST return that event as an idempotent no-op. Otherwise it
MUST revalidate the original actor, target, and semantic effect against the new
head before building a new event. It MAY append only if the original operation
is still valid; it MUST return a conflict or require a fresh action when the
target or meaning changed. It MUST NOT silently retarget an operation or merely
re-parent a stale event. DraCLA MUST NOT create merge commits in the canonical
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

The canonical event and encryption-envelope formats MUST be documented,
versioned, and readable without the DraCLA service when the project has its
repositories and recovery material. Recovery MUST NOT depend on an
undocumented proprietary service. Projects MUST be able to export current and
historical records as JSON and CSV. Plaintext exports MAY be delivered to an
authorized reader, but MUST NOT be persisted in repository content, logs,
workflow artifacts, or another durable location that lacks the private-record
access boundary.

### REQ-REC-6: Rebuildability

Derived indexes, dashboards, and reports MUST be reproducible from canonical
events. Generated artifacts MUST NOT become an independent source of truth.

### REQ-REC-7: Backup

DraCLA MUST document a backup and recovery procedure for the records repository
and every key required to interpret protected record content. The adopter MUST
receive recovery material sufficient to decrypt its canonical history and
private derived state without the shared DraCLA operator, rewrap or reinstall
project keys for a replacement deployment, and retain access to data encrypted
under older keys after rotation. Recovery material MUST itself be protected as
a key-controller capability. Release verification MUST exercise restoration
from repository backups plus this recovery material.

Before the first private record or derived artifact is written, DraCLA MUST
create the adopter-controlled recovery material, verify that it can recover a
recovery challenge protected by each actual initial project data-encryption
key — the records key and the coverage key — and deliver the recovery material
to the adopter. The installer MUST prominently recommend storing the recovery
material in a password manager or other safe storage. DraCLA MUST NOT begin
private writes if recovery readiness cannot be verified for either actual key.

Before any artifact is written under a rotated key, DraCLA MUST similarly
verify that the actual new key can be recovered through both the new live path
and the adopter-controlled recovery material. The previous decryption authority
MUST remain available until that transition succeeds; a failed transition MUST
leave the previous key active and MUST NOT strand older history.

### REQ-REC-8: Canonical configuration events

Every administrative change that can affect coverage or acceptance evidence
MUST append a canonical event before it becomes effective. This includes
project connection or successor binding, enforcement-scope bindings and
changes, agreement publication and activation, required signer fields and
confirmations, exemptions and exemption rules, overrides, and entity
authorization changes when entity support exists.

Each administrative event MUST identify the stable GitHub numeric actor ID and
login snapshot and the authorization decision checked at action time.
Authorization evidence MUST identify the resource, exact operation, required
permission or other GitHub authority, and the result or evidence observed. The
event MUST also contain the complete effective value or an immutable reference
to it. Secrets MUST NOT be copied into events. Current coverage and evidence
state MUST be reproducible from these events without relying on mutable
configuration history.

## 12. Privacy and security

### REQ-SEC-1: Data minimization

DraCLA MUST collect only fields required by the selected agreement and project
policy. It MUST NOT collect an IP address merely because a signing workflow can
observe it.

### REQ-SEC-2: Private signer records

Legal names, email addresses, form responses, entity evidence, and raw audit
events are private project records and MUST NOT appear in public dashboards,
badges, comments, checks, logs, or workflow artifacts. Canonical private
records and every private derived artifact stored in GitHub, including indexes,
exports, coverage mappings, exemptions, and private operational projections,
MUST use authenticated application-layer encryption. Private values MUST NOT
appear in repository paths, filenames, commit messages, or other unencrypted
repository metadata. The documented encryption envelope MUST bind ciphertext
to its project, artifact kind, logical identity, schema version, and key ID so
that ciphertext cannot be silently substituted across projects or purposes.

Private canonical records and private enforcement projections MUST be
cryptographically separated as required by `REQ-REC-2`. Key rotation MUST
support reading append-only history and derived state written under retained
older keys. Loss, corruption, or unavailability of required key material MUST
fail closed and MUST NOT produce a successful coverage result.

A hosted serverless endpoint, protected workflow, or authorized reader client
MAY process plaintext transiently for an authorized operation, but MUST NOT
retain it outside the project's encrypted repositories or an explicitly
requested authorized export. DraCLA MUST document any unavoidable unencrypted
metadata leakage, such as repository-level timing or aggregate object counts,
and MUST NOT claim that encryption protects data while it is being processed
by trusted code or from a key controller defined by `REQ-REC-1`.

### REQ-SEC-3: Project privacy policy

The signing page MUST link to the adopting project's privacy policy before
acceptance.

### REQ-SEC-4: Authentication security

The web flow MUST protect signing, revocation, and administrative actions
against forged requests, replay, and cross-site request forgery. GitHub tokens
and unwrapped application or decryption secrets MUST NOT be stored in repository
content or exposed to browser code. A wrapped project key MAY be stored with
ciphertext only when its wrapping key is held outside that repository and the
wrapped value does not give repository readers decryption capability.

### REQ-SEC-5: Webhook security

GitHub webhook authenticity MUST be verified. Replayed or duplicated webhook
deliveries MUST be safe.

### REQ-SEC-6: Authorization

Administrative access MUST be derived from current GitHub authorization and
rechecked at action time. Each administrative event MUST record the actor's
stable GitHub numeric ID and login snapshot, the GitHub resource checked, and
the exact operation, required permission or other GitHub authority, and
authorization result or evidence observed.

The initial release MUST enforce this minimum authorization matrix:

| Action | Resource and minimum current authority |
| --- | --- |
| Connect a project or explicit successor | `admin` on the records repository, and GitHub must authorize the actor to configure every App installation being bound under its current account policies |
| Publish or activate an agreement; change signer fields, project policy, exemptions, or exemption rules | `admin` on the records repository |
| Authorize or withdraw a records reader, reader snapshot, or continuous reader rule | `admin` on the records repository |
| Bind, widen, narrow, or remove enforcement scope for a repository | `admin` on that contributing repository |
| Bind, widen, narrow, or remove an organization-wide selector | organization owner for that organization |
| Inspect a multiple-project scope conflict | `admin` on the affected contributing repository; disclosure remains limited by `REQ-CONFIG-3` |
| Grant or revoke a pull-request-specific override | `maintain` on the contributing repository |
| Request an administrative retry | `write` on the contributing repository |
| Read private records or another subject's exact status or reason | GitHub authentication and current records-reader authorization under `REQ-REC-1`; repository read access alone is neither required nor sufficient |
| Install or rotate a repository-scoped credential | `admin` on every affected repository |
| Configure an App installation or rotate an App-owned credential | GitHub must authorize the actor to perform that exact operation under its current account and App policies |

An implementation MAY require stronger permission but MUST NOT accept weaker
permission. Authentication to one project or repository MUST NOT authorize an
action on another. The private dashboard SHOULD authorize a viewer from the
same canonical records-reader sources as every other plaintext read rather than
maintain a second user allowlist.

An authenticated subject viewing their own exact status or reason under
`REQ-PORTAL-6` is not performing an administrative action and does not need
records-repository access.

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

### REQ-SEC-9: Credential lifecycle

Every long-lived credential DraCLA provisions or requires — including project
decryption keys, wrapping keys, recovery material, deploy keys, App private
keys, and webhook secrets — MUST have a documented rotation procedure and a
documented response to administrator or maintainer departure. Documentation
MUST state what each credential can reach, decrypt, forge, or cause trusted code
to reveal; where each usable or wrapped copy is held; which principals control
it; and how old encrypted history remains recoverable after rotation. DraCLA
Apps that append events MUST NOT be able to modify a workflow that receives
unwrapped project keys or any executable or control input that such a workflow
uses.

### REQ-SEC-10: Software supply chain

Every distributed DraCLA release and deployed service version MUST have an
immutable identity and verifiable provenance linking it to reviewed source and
declared build inputs. Production workflows, actions, containers, packages, and
other executable dependencies MUST be pinned by immutable digest or commit
identity rather than a mutable branch or tag.

A workflow or job receiving an unwrapped project key MUST execute only pinned
DraCLA release code and pinned executable dependencies. It MUST NOT execute,
import, source, or treat as control configuration repository content writable
by an event-appending App. Schema-validated canonical business data from such
content MAY affect CLA results only through fixed, pinned DraCLA code. It MUST
NOT select executable code, dependencies, commands, modules, or any other
code-loading or execution behavior.

An adopting project MUST control when it upgrades adopter-deployed code that
can read its records or report its checks. Upgrade instructions for that code
MUST verify provenance and MUST provide a documented rollback to a previously
verified release.

For the shared hosted deployment, the shared DraCLA operator controls upgrades
and rollback. The deployment MUST expose its deployed immutable release
identity for audit and incident response, and an adopting project MUST be able
to stop trusting that deployment by revoking its App access and migrating to a
self-hosted deployment as required by `REQ-OPS-6`.

## 13. Contributor portal and badges

### REQ-PORTAL-1: Project page

Each project MUST have a stable contributor-facing page. After GitHub login it
MUST show the viewer's exact Individual CLA status separately for each
agreement and offer the applicable Sign, Re-sign, or agreement-specific Revoke
action. Signing MUST use a conventional agreement
review and acceptance flow. Contributors MUST NOT be required to interact with
GitHub issues, pull requests, workflow controls, or repository files to manage
their CLA.

### REQ-PORTAL-2: CONTRIBUTING badge

DraCLA MUST provide a project badge suitable for `CONTRIBUTING.md`. Because a
GitHub-rendered image cannot safely identify its viewer, this shared badge MUST
show a generic state such as "CLA: sign or check status" and link to the
project page.

### REQ-PORTAL-3: Pull request badge

A pull request badge or comment MUST use the same generic public states as the
GitHub check and MUST NOT display or encode the exact coverage or failure
reason. The bounded multiple-project conflict message permitted by
`REQ-CHECK-1` is the sole exception; it MUST NOT identify a matching project,
disclose a matching scope entry, or expose signer status or private
configuration. The badge or comment SHOULD link to the authenticated project
page for details.

### REQ-PORTAL-4: Accessible wording

Status text and actions MUST be understandable without relying on badge color.
Contributor-facing language SHOULD be factual, concise, and should avoid
implying that signing transfers copyright when the configured agreement grants
only a license.

### REQ-PORTAL-5: No public signer lookup

DraCLA MUST NOT provide an unauthenticated endpoint or directory for querying a
specific GitHub user's CLA status. Public status MUST remain contextual to a
configured pull request and use the generic states defined by `REQ-CHECK-1`.
Within the `action required` state, the bounded repository-conflict message
required by `REQ-CONFIG-3` is permitted. That message describes ambiguous
repository configuration; it MUST NOT disclose a signer's status, a matching
project identifier or scope entry, or other private configuration.
Derived artifacts that map users to coverage MUST NOT be publicly readable or
enumerable, in aggregate or in bulk, whether or not they contain names or
addresses. This restriction MUST NOT prevent an authenticated contributor from
viewing their own exact status or an authorized records reader from using the
private dashboard.

The aggregate public check for a pull request necessarily reveals whether all
GitHub-reported subjects are covered. DraCLA accepts this contextual oracle as
a residual limitation of public enforcement; it MUST document that commit
author metadata can be fabricated and MUST NOT describe the result as proof of
authorship or identity. This exception does not permit a user lookup endpoint,
bulk artifact, or exact public reason.

### REQ-PORTAL-6: Pull request disclosure tiers

Pull-request status details MUST follow these tiers:

- An unauthenticated or otherwise unauthorized viewer may see only the generic
  aggregate state in `REQ-CHECK-1`, including its bounded multiple-project
  conflict message when that exception applies.
- An authenticated subject may see their own exact status and reason.
- A viewer with current `write` permission on the contributing repository
  may see aggregate reason categories and counts, but not subject identities or
  another subject's exact status.
- A records reader authorized under `REQ-REC-1` may see GitHub identities and
  exact per-subject reasons for that pull request.

No pull-request view may expose legal names, email addresses, signer form
fields, or raw acceptance evidence. For a private contributing repository, the
records-facing portal MUST obtain only a yes-or-no current permission result
from the isolated enforcement capability; it MUST NOT receive the enforcement
credential or broaden the records credential to the contributing repository.

## 14. Maintainer dashboard

### REQ-DASH-1: Dynamic private dashboard

DraCLA MUST provide a private, dynamic dashboard. Filtering and sorting SHOULD
happen immediately in the browser after loading a generated index.

### REQ-DASH-2: Filters

The dashboard MUST support filtering by:

- GitHub user;
- project and repository enforcement scope;
- agreement identifier and version;
- current, revoked, superseded, or indeterminate status;
- Individual CLA coverage and, when supported, Entity CLA coverage; and
- acceptance or revocation date.

### REQ-DASH-3: Access boundary

Dashboard access MUST require GitHub authentication and current records-reader
authorization under `REQ-REC-1`. GitHub permission to read the records
repository alone MUST NOT grant dashboard access. A publicly hosted application
shell MAY be used, but private data MUST NOT be embedded in public static
assets. Decryption MUST occur only after authorization and MUST return no raw
project key to the browser.

### REQ-DASH-4: Derived index

The dashboard SHOULD consume a generated, private index optimized for filtering
rather than loading every evidence record. The index MUST be reproducible and
MUST contain no more private data than the dashboard requires.

### REQ-DASH-5: Live updates

Record changes MUST trigger regeneration of the dashboard index. The dashboard
MAY refresh or poll for the latest generated index; real-time streaming is not
required.

## 15. Deployment and portability

### REQ-OPS-1: Self-hosting

DraCLA SHOULD provide a shared DraCLA-operated deployment as the default
adoption path. It MUST also be deployable by an open source project without
dependence on that shared service.

### REQ-OPS-2: No records database

The initial architecture MUST use the project's GitHub records repository as
durable storage for agreements and CLA evidence. A static frontend and
serverless endpoints MUST provide GitHub authentication, signing, re-signing,
revocation, and status. The serverless component MAY use short-lived signed or
encrypted session state and provider-managed secret storage.

Pull request checks MAY additionally use provider-managed, strongly consistent
operational routing state solely as the repository-scoped gate required by
`REQ-CONFIG-3`. That state MUST contain no agreement text, signer identity,
acceptance, revocation, exemption, or other CLA evidence; MUST be reconstructible
from the authoritative GitHub repositories and current GitHub repository facts;
and MUST fail closed if it is missing, unavailable, exhausted, or inconsistent.
A separate persistent application database MUST NOT be required for signing,
re-signing, revocation, dashboard reconstruction, or any check data beyond this
bounded routing gate.

Background validation, index generation, exports, and pull request enforcement
SHOULD run in GitHub Actions. The serverless component MUST remain replaceable
and MUST NOT make its hosting provider a durable system of record.

### REQ-OPS-3: GitHub Free baseline

The documented baseline MUST work for a GitHub organization on the Free plan.
Features that require paid GitHub plans MAY be documented as optional
hardening, but MUST NOT be prerequisites for correct core behavior.

The GitHub Free baseline MUST use public contributing repositories when branch
protection or required checks are part of enforcement; the authoritative
records repository MUST remain private. Documentation MUST state that enforcing
required checks on a private contributing repository depends on a GitHub plan
that supports branch protection for private repositories.

Strong final enforcement in the baseline MUST use a required merge queue and a
required DraCLA merge-group check. Core operation MUST NOT require a durable
job queue, reverse pull request index, or global pull request rescan.

The documented initial deployment MUST identify a serverless option that, at
release time, fits within the provider's published free tier for a stated
capacity envelope. Documentation MUST state the request and compute assumptions,
the applicable provider limits, and the behavior when those limits are reached.

### REQ-OPS-4: Generic installation

Installation MUST be driven by project configuration and documented so that a
project unrelated to Hydra can deploy DraCLA without editing source code.

### REQ-OPS-5: Observability

Operational logs MUST identify failed events and correlation identifiers while
excluding signer PII and credentials.

### REQ-OPS-6: Shared hosted deployment

One shared serverless deployment MUST be able to serve multiple projects
without requiring a separately deployed worker or function per project. It MAY
use repository-scoped routing coordination objects only as permitted by
`REQ-OPS-2`; all other serverless request handling remains stateless. Each
project's agreements and canonical records MUST remain in repositories
controlled by that project. Project routing, GitHub App installations,
authorization, and record access MUST be isolated so that one project cannot
access or modify another project's private records.

A project using the shared deployment MUST trust the shared DraCLA operator.
The operator controls the deployed code and service-side key-wrapping
credentials and therefore has the technical ability to cause its services to
decrypt signer records and to report or forge check results. Tenant isolation
limits accidental and cross-project access but MUST NOT be presented as
protection from the operator. The hosted documentation MUST disclose this trust
boundary and the deployed release identity. A project that does not accept this
operator trust MUST use a self-hosted deployment with project-controlled
operational credentials.

Before a project authorizes the shared deployment, installation MUST clearly
state that the shared operator can technically access the PII of every hosted
project and link to an FAQ that explains which hosted components and operator
credentials create that access, which enforcement components remain unable to
decrypt signer PII, and how to choose or migrate to self-hosting.

Self-hosting MUST be a viable, documented, and supported deployment mode using
the same released DraCLA code. Release verification MUST exercise clean
self-hosted installation, operation with adopter-controlled wrapping roots,
upgrade and rollback, and migration from the shared deployment.

Projects MUST be able to revoke the shared GitHub App and migrate to a
self-hosted deployment without converting their canonical records. The
adopter-controlled recovery material required by `REQ-REC-7` MUST be sufficient
to reinstall or rewrap the project keys for that migration without assistance
from the former operator.

## 16. Initial release scope

The first usable release MUST demonstrate all of the following:

1. Register one project with exactly one agreement identifier and publish a
   versioned Individual CLA.
2. Authenticate a GitHub user and record explicit acceptance.
3. Evaluate the opener and every GitHub-resolved commit author; surface
   trailer-declared co-authors, with coverage status, to authorized viewers
   (`REQ-CHECK-2`, `REQ-PORTAL-6`).
4. Report a passing early check when every subject is covered and a non-passing
   check when a subject is uncovered or unresolved.
5. Re-evaluate the originating pull request after signing from its flow.
6. Enforce a fresh required check on a GitHub merge-group candidate.
7. Allow the contributor to inspect status, revoke with a clear confirmation,
   and restore coverage through an immediate re-signing path.
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
- individual exemptions, a team snapshot selecting all and a subset of current
  members, a continuous team rule adding and withdrawing future members,
  multiple simultaneous exemption sources, and withdrawal confirmation that
  reports every source still keeping the account exempt;
- a required merge-group check that observes a revocation or agreement change
  made after the ordinary pull request check;
- service-unavailable behavior and both automatic and user-requested retry;
- malicious agreement, configuration, signer, and dashboard values rendered in
  every supported output format;
- spreadsheet-formula payloads in CSV exports while JSON retains the canonical
  value;
- loss of a viewer's or administrator's GitHub authorization;
- enforcement of every row in the administrative authorization matrix,
  including stable actor ID, login snapshot, exact operation, authority, and
  observed authorization evidence;
- refusal to bind a repository or organization-wide selector that would place
  a repository in two DraCLA projects within one coordination domain; an
  explicit move between projects that never creates simultaneous membership;
  a repository transfer into an organization-wide selector that creates an
  overlap without a DraCLA configuration change; fail-closed enforcement only
  for that repository; the bounded public `action required` message from
  `REQ-CONFIG-3` without a matching project identifier, matching scope entry,
  signer status, or private configuration; authenticated inspection and
  authorized resolution of the matching projects and scope entries; inspection
  by an administrator of the affected repository without signer-record or
  unrelated-configuration disclosure; refusal of inspection to a
  lower-permission viewer; separate authorization of every resolution mutation;
  rejection of a stale cached route when the repository-scoped gate is pending
  or names another generation; fail-closed behavior when that gate is
  unavailable or its free-tier limit is exhausted; rejection and reconciliation
  when authenticated GitHub event facts differ from the routed repository
  facts; reconstruction of lost gate state from authoritative sources without
  changing CLA evidence; recovery after a missed lifecycle event through
  reconciliation; continued operation of unaffected repositories; and
  documentation that independent domains cannot enforce global uniqueness;
- refusal to configure a second agreement identifier for an initial-release
  project;
- records-repository installation in an existing organization and under a
  personal account without requiring a dedicated organization; ciphertext-only
  access by an ordinary repository reader and a read-only App; denial of
  private portal and dashboard data to either one; and documented treatment of
  repository administrators, protected-workflow and secret controllers,
  hosted services, and recovery custodians as key controllers;
- individual, selected-member snapshot, and continuous-team records-reader
  authorization; access by an authorized reader who has no repository access;
  denial after authorization is withdrawn; union of simultaneous reader
  sources; and withdrawal confirmation that reports every remaining source;
- authenticated encryption of canonical private records, private derived
  indexes and exports, coverage mappings, exemptions, and operational
  projections; rejection of ciphertext moved across projects or artifact
  purposes; absence of private values from unencrypted repository metadata;
  cryptographic separation that lets enforcement decrypt coverage but not
  signer evidence; and fail-closed behavior for missing, corrupt, or
  unavailable key material;
- project-key rotation with continued reading of append-only history and
  derived state written under old keys; verified recovery of both actual
  initial project data keys before the first private write and of the actual
  new key before rotation; retention of the old key until rotation succeeds;
  protection of the key-bearing workflow and all its executable or control
  inputs from the event-appending Apps; execution of only pinned code by
  key-bearing jobs; schema-validated canonical business data affecting results
  only through that fixed code and never selecting executable behavior; and
  verification that no repository content, log, workflow artifact, public
  asset, or unauthorized browser response contains plaintext private data;
- an empty-repository installation whose mandatory first commit contains the
  operator README and whose first event has the then-current branch head as its
  single parent;
- concurrent append loss followed by semantic revalidation, covering the
  idempotent no-op, valid retry, and conflict outcomes;
- immediate agreement activation, refusal to sign inactive versions, and a
  non-superseding activation that does not revive an already invalid acceptance;
- forward-looking revocation across every earlier version for one coverage
  tuple, including current and later enforcement-scope repositories; a clear
  success explanation; and restoration only through a later acceptance reached
  directly from the revocation confirmation screen;
- repeated successful acceptance and revocation beyond any former bounded
  window, while idempotent retries and semantic no-ops append nothing and both
  revocation and immediate fresh re-signing remain available;
- a lost revocation response followed by an idempotent retry, conflicting reuse
  of its key with changed data, and an acceptance landing after revocation
  confirmation causing the stale revocation to require fresh confirmation;
- pull-request disclosure at every `REQ-PORTAL-6` tier, including a private
  contributing repository and separation of the records and enforcement
  credentials;
- verification of release provenance and immutable execution pins; for an
  adopter-deployed component, an adopter-controlled upgrade and rollback to a
  previously verified release; and for the shared hosted deployment, an
  operator rollback and exposed deployed release identity;
- a shared hosted deployment serving at least two projects, including denied
  attempts to read or write records through the wrong project route or GitHub
  App installation; separate records and enforcement wrapping roots; explicit
  installation and FAQ disclosure that the operator can access all
  hosted-project PII; and an enforcement component unable to decrypt that PII;
- migration from the shared hosted deployment to a self-hosted deployment using
  the existing canonical records without conversion, plus clean installation,
  operation, upgrade, and rollback with adopter-controlled wrapping roots;
- backup restoration using only repository backups, adopter-controlled recovery
  material, and the documented formats, followed by reinstallation or
  rewrapping for a replacement deployment and a complete rebuild of current
  status, JSON and CSV exports, and the dashboard index; and
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
- importing historical records from CLA Assistant or other CLA systems;
- a mobile application;
- billing, subscriptions, or hosted-service account management; or
- a generalized electronic-signature platform for documents unrelated to
  software contributions.

## 18. Open decisions

No open decisions remain for the initial release.

## 19. Acceptance of this requirements document

This document defines product requirements, not an implementation architecture.
A design proposal MUST map its major components to these requirement IDs and
MUST identify any requirement it defers or cannot satisfy.

A locked requirements baseline may change only through an explicit substantive
requirements proposal that identifies the affected requirement IDs and
rationale and receives project approval before incorporation. The document
MUST be marked Draft while such a change is under review and Locked again only
after the revised baseline is approved. Editorial corrections that do not alter
meaning MAY be made through normal review.

## 20. Revision history

### Revision 12 — 23 August 2026

The HLD review showed that the Revision 11 plaintext access boundary could not
reliably enumerate every GitHub App able to read a private repository and could
only fail closed after an unintended reader might already have copied data.
The project owner selected encryption as the privacy boundary instead. This
revision supersedes the records-access policy adopted in Revision 11 and the
plaintext records-ACL decision recorded in Revision 4:

- **Encrypted project custody (`REQ-REC-1`, `REQ-SEC-2`).** Canonical private
  records and every private derived or coverage artifact stored in GitHub now
  require authenticated application-layer encryption. Repository read access
  without a decryption capability exposes ciphertext and does not grant portal
  or dashboard access. Existing-organization and personal-account private
  repositories are supported; a dedicated CLA organization is optional defense
  in depth rather than a prerequisite.
- **Reader authorization (`REQ-REC-1`, `REQ-SEC-6`, `REQ-DASH-3`).** Individual,
  snapshot, and continuous-team sources now authorize plaintext reads through
  DraCLA, independently of repository access. Authorization is checked before
  every read, multiple sources combine by union, and readers receive permitted
  plaintext results rather than project keys.
- **Key boundary and trust (`REQ-REC-1`, `REQ-REC-2`, `REQ-SEC-9`,
  `REQ-OPS-6`).** Records and coverage use independently rotatable decryption
  authority, and the enforcement path cannot decrypt signer evidence. People
  or services that control keys, key-bearing workflows or secrets, decryption
  services, or recovery material are explicitly trusted key controllers. The
  shared operator remains fully trusted for hosted decryption. Each project has
  distinct records and coverage data keys; hosted wrapping roots are separated
  by capability and every wrapped key is bound to its project and capability.
- **Portability and recovery (`REQ-REC-5`, `REQ-REC-7`).** The encryption
  envelope is documented and service-independent. Adopter-controlled recovery
  material must preserve old history across rotation and allow migration to a
  replacement or self-hosted deployment without the former operator. Recovery
  of both actual initial project data keys is verified before the first private
  write, and recovery of the actual new key is verified before rotation, while
  the old key remains available until rotation succeeds.
- **Private custody and hosted disclosure (`REQ-REC-1`, `REQ-OPS-3`,
  `REQ-OPS-6`).** Repositories containing private records or derived data must
  remain private even though their contents are encrypted. Installation and
  the FAQ disclose the shared operator's technical ability to access all
  hosted-project PII, and self-hosting is a supported, release-verified path
  for adopters that reject that trust.
- **Key-bearing execution (`REQ-SEC-9`, `REQ-SEC-10`).** Jobs receiving
  unwrapped keys execute only immutable pinned DraCLA code and dependencies;
  schema-validated canonical business data may affect CLA results through that
  fixed code, but content writable by an event-appending App can never select
  code, dependencies, commands, modules, or other executable behavior.
- **Verification (`REQ-VERIFY-2`).** Acceptance now covers ciphertext-only
  repository readers and Apps, reader authorization without repository access,
  encrypted private derivatives, cross-purpose substitution rejection, key
  separation and failure, rotation, protected workflows, plaintext leakage,
  and independent recovery.

*Rationale.* A private repository ACL is useful defense in depth, but it is not
a reliable confidentiality boundary when another App can read repository
contents and DraCLA cannot completely enumerate that access. Encryption makes
the decryption capability the explicit boundary and lets adopters keep the
repositories in their normal organization while preserving service-independent
custody. It does not protect against a key controller or compromised trusted
code, and the requirements now say so directly.

### Revision 11 — 22 August 2026

The current-head HLD review exposed three places where bounded automation
silently overrode an approved human policy:

- **Exemption sources (`REQ-CHECK-2`, `REQ-REC-8`, `REQ-SEC-6`).** DraCLA now
  distinguishes individual exemptions, team snapshots, and explicitly
  delegated continuous team rules. Continuous rules delegate exemption power
  to team membership administrators and must say so. Every effective change is
  materialized as evidence, multiple sources combine by union, and withdrawing
  one source reports any source that still keeps the account exempt.
- **Records-reader changes (`REQ-REC-1`, `REQ-SEC-6`).** Reader authorization
  is individual, snapshot, or a clearly disclosed continuous-team
  delegation. A credentialed periodic verifier must enumerate effective access
  and fail the project closed on unauthorized or indeterminate access. The safe
  authorize-before-grant sequence and the irreversible exposure risk of doing
  it backward are now mandatory documentation.
- **Revocation and re-signing (`REQ-REV-1`, `REQ-REV-5`).** A successful-event
  cap may not trap a contributor in either covered or uncovered status.
  Idempotent retries and no-ops remain write-free, but the initial release does
  not cap successful acceptance and revocation events.

*Rationale.* Snapshot and standing-delegation workflows are both legitimate,
but they confer different authority and must not be conflated. Records access
must have an implementable verifier and an explicit safe operating sequence.
Finally, an append-budget optimization cannot contradict contributor-controlled
revocation or the promised immediate path back to coverage.

### Revision 10 — 22 August 2026

The PR-scoped HLD review found that an eventually consistent pending marker can
arrive after a stale route has already authorized a merge. The project owner
kept the strict one-project invariant and selected a small strongly consistent
routing gate instead of renewable signed leases or mandatory adopter-owned
Cloudflare deployments:

- **Strict routing barrier.** `REQ-CONFIG-3` now requires every check to compare
  its routed generation with repository-scoped strongly consistent state.
  Pending, missing, unavailable, or mismatched state fails closed only the
  affected repository. Authenticated GitHub facts may invalidate a stale route
  but cannot select a replacement project.
- **Bounded operational state.** `REQ-OPS-2` permits only the rebuildable
  routing gate on the check path. It cannot contain CLA evidence and does not
  replace adopter-owned GitHub repositories as the durable system of record.
- **Shared deployment.** `REQ-OPS-6` permits repository-scoped coordination
  objects within one shared deployment; adopters are not required to provide
  Cloudflare credentials or receive a separate deployed function.
- **Verification.** `REQ-VERIFY-2` adds stale-route, gate-loss, quota-exhaustion,
  GitHub-fact mismatch, reconstruction, and unaffected-repository cases.

*Rationale.* Durable Objects are available on Cloudflare's free tier and give
the routing decision a strongly consistent generation check without periodic
per-repository writes. GitHub remains authoritative for configuration and CLA
evidence; the provider-held state is a minimal fail-closed projection that can
be rebuilt.

### Revision 9 — 22 August 2026

The exact-head PR review found that Revision 8 required a bounded public
message for a multiple-project scope conflict while the general check and
portal rules still prohibited every public reason:

- **Bounded conflict disclosure (`R2-1`, `R8-1`).** `REQ-CHECK-1`,
  `REQ-PORTAL-3`, `REQ-PORTAL-5`, and `REQ-PORTAL-6` now identify the
  `REQ-CONFIG-3` message as the sole exception to generic-only public wording.
  The check remains in the generic `action required` state and may reveal only
  that the repository is covered by more than one CLA project and needs
  administrator resolution. Matching project identifiers, scope entries,
  signer status, and private configuration remain non-public. `REQ-VERIFY-2`
  requires acceptance coverage of both the bounded message and that disclosure
  limit.

*Rationale.* The accepted conflict flow cannot direct an administrator to the
right recovery path if another requirement forbids its message. Naming the
exception at every public-disclosure rule removes that contradiction without
widening what the public can learn.

### Revision 8 — 22 August 2026

The current-head PR review found that the coordination-domain uniqueness rule
covered DraCLA configuration changes but not repository lifecycle changes made
directly in GitHub. The project owner approved fail-closed, repository-local
handling and explicit administrative recovery:

- **GitHub-side overlap (`R1-1`).** `REQ-CONFIG-3` now requires DraCLA to
  select neither project when creation, rename, transfer, ownership change,
  restoration, or another external lifecycle change makes a repository match
  multiple projects. Only the affected repository is blocked; its public
  result directs an administrator to resolve the conflict without exposing the
  matching projects.
- **Administrative recovery (`R1-1`).** An authenticated administrative path
  lets an administrator of the affected repository inspect only the matching
  project identifiers, scope entries, and required resolution authorities.
  Inspection grants neither signer-record access nor mutation authority;
  resolution actions remain separately authorized. DraCLA neither applies
  precedence nor moves a repository automatically, and reconciliation catches
  missed GitHub events.

*Rationale.* A GitHub repository transfer can change selector membership
without invoking a DraCLA scope mutation, so validation only at configuration
write time cannot preserve the one-project invariant. Blocking the ambiguous
repository prevents DraCLA from choosing the wrong agreement or recipient,
while leaving other repositories, CLA evidence, and contributor coverage
unchanged.

### Revision 7 — 21 August 2026

The PR-scoped deep-design-review loop found two gaps in the interaction between
non-superseding agreement versions, revocation, and append retries. The project
owner defined the forward-looking behavior and approved both repairs:

- **Revocation identity and effect (`R1-1`).** `REQ-REV-1` through
  `REQ-REV-5` now define a stable user/project/agreement/recipient coverage
  tuple. One revocation cuts off coverage from every earlier acceptance of
  every version for that tuple without changing history or depending on the
  current repository enforcement scope. The success screen explains the effect
  and offers an immediate path to restore coverage through fresh assent.
- **Revocation idempotency (`R1-2`).** `REQ-SIGN-5` now applies the canonical
  idempotency contract to every contributor mutation. `REQ-REV-3` records the
  key, returns the original result after a lost response, and requires fresh
  confirmation when a concurrent acceptance changes the meaning of a pending
  revocation.

*Rationale.* Revocation is a new event governing coverage from its canonical
position onward. It neither edits old signatures nor silently reaches a later
signature the contributor did not see, and an easy "Restore coverage" action
remains a genuine new acceptance rather than erasing the revocation.

### Revision 6 — 21 August 2026

Round 4 verified three Revision 5 fixes and reopened two. The project owner
clarified the remaining architectural boundary, and both findings were repaired:

- **Administrative authorization evidence (`R1-9`).** `REQ-REC-8` and
  `REQ-SEC-6` now record an authorization decision, exact operation, required
  permission or other GitHub authority, and observed evidence. Named permission
  levels remain where GitHub supplies them; App operations no longer need an
  invented uniform permission.
- **Coordination-domain uniqueness (`R3-1`).** `REQ-CONFIG-3` enforces one
  project per repository within a hosted or self-hosted registry, while stating
  plainly that independent deployments cannot provide global uniqueness without
  shared state. Double-targeting by independent deployments is unsupported
  administrator misconfiguration rather than a guarantee DraCLA cannot enforce.

*Rationale.* The requirements now demand evidence the named GitHub actor can
actually produce and preserve independent self-hosting without hiding a global
coordination dependency.

### Revision 5 — 21 August 2026

Five findings were reopened or added by the 21 August 2026 review loop,
decided individually by the project owner, and incorporated together:

- **Administrative authority (`R1-9`).** `REQ-SEC-6` now covers narrowing or
  removing enforcement scope and revoking overrides, separates a subject's own
  status from records-reader access, removes deferred entity administration
  from the initial matrix, and defers App authority to GitHub's operation-level
  authorization rather than inventing a uniform installation permission.
- **Supply chain (`R1-14`).** `REQ-SEC-10` preserves adopter-controlled upgrade
  and rollback for adopter-deployed code while stating that the trusted shared
  operator controls hosted upgrades and rollback.
- **Shared operator trust (`R3-3`).** The shared operator is now an explicit
  principal, and `REQ-OPS-6` discloses its maximum technical access and directs
  projects that reject that trust to self-host.
- **One agreement (`R3-2`).** `REQ-CONFIG-4` permits exactly one agreement
  identifier per initial-release project and defers combination semantics until
  a future release supports multiple identifiers.
- **No project overlap (`R3-1`).** `REQ-CONFIG-3` prohibits one repository from
  belonging to two DraCLA projects and defines an explicit non-overlapping move.

*Rationale.* These changes finish the initial authorization matrix and make the
single-agreement, single-project enforcement model explicit. They also align
supply-chain control with the accepted shared-service trust model instead of
promising adopter control over operator-deployed code.

### Revision 4 — 21 August 2026

Fourteen changes were proposed by the 20 August 2026 deep-design review,
decided individually by the project owner, and incorporated together:

- **Recipient identity (`R1-1`).** `REQ-CONFIG-2`, `REQ-AGR-1`, and
  `REQ-SIGN-4` bind the immutable legal recipient into the agreement version
  and acceptance evidence; a recipient change creates a distinct or explicit
  successor project.
- **Legal scope versus enforcement scope (`R1-4`).** `REQ-CONFIG-3` now defines
  only where DraCLA enforces. The agreement defines legal scope, DraCLA does
  not interpret it, and enforcement-scope changes do not alter grants or
  invalidate signatures.
- **Immediate activation (`R1-5`).** `REQ-AGR-2` removes scheduled activation
  and early signing, permits multiple published versions but only one active
  signable version, and defines chained `supersedes_coverage` behavior without
  revival of an already non-current acceptance. This supersedes Revision 2's
  staged-activation clause.
- **Commit attribution limitation (`R1-8`).** `REQ-CHECK-2` and
  `REQ-PORTAL-5` identify GitHub's commit-author association as attribution,
  not proof, and explicitly document the residual aggregate coverage oracle.
- **Credential isolation (`R1-13`).** `REQ-REC-2` makes the private-records and
  enforcement credential boundary mandatory.
- **Pull-request disclosure (`R1-3`).** `REQ-PORTAL-6` defines public,
  subject, contributing-maintainer, and records-reader tiers and the private
  contributing-repository permission-check boundary.
- **Records ACL (`R1-11`).** `REQ-REC-1` requires every effective reader to be
  authorized and defines the supported dedicated-organization,
  personal-repository, and other-organization custody shapes.
- **Administrative authority (`R1-9`).** `REQ-SEC-6` defines the minimum
  action/resource/permission matrix and stable actor attribution.
- **Idempotency identity (`R1-10`).** `REQ-SIGN-4` and `REQ-SIGN-5` require a
  canonical event field, stable replay identity, fresh identity for a new act,
  and conflict on same-key/different-operation reuse.
- **Append-race meaning (`R1-6`).** `REQ-REC-3` requires reload and semantic
  revalidation, with explicit no-op, append, or conflict outcomes and no silent
  retargeting.
- **Canonical configuration (`R1-12`).** New `REQ-REC-8` requires an
  attributable event for every coverage- or evidence-affecting change.
- **Supply chain (`R1-14`).** New `REQ-SEC-10` requires immutable execution
  identity, verifiable provenance, adopter-controlled upgrades, and rollback.
- **Mandatory root commit (`R1-2`).** `REQ-REC-3` requires the canonical
  branch's root commit to contain the operator README before the first event.
- **Agreement-specific revocation (`R1-7`).** `REQ-REV-1` through
  `REQ-REV-4` and `REQ-PORTAL-1` make status and revocation agreement-specific;
  the initial release has no implicit project-wide revoke-all operation.

*Rationale.* These changes make the requirements implementable without leaving
identity, authorization, ordering, disclosure, or trust rules for builders to
invent. They narrow DraCLA to enforcement policy where agreement text owns
legal meaning, and they remove staged behavior that had no contributor-facing
path before activation.

### Revision 3 — 20 August 2026

Five changes: two new requirements and three amendments, proposed from the
review trail of this document and the accepted high-level design, and approved.
Recorded here as section 19 requires.

**`REQ-CONFIG-5` — scope authorization (new).** A repository or organization
enters a project's enforcement scope only with the verified, attributable consent of
someone who administers its owner; App installation alone is not consent.

*Rationale.* The design's §7 closes a look-alike attack in which an unclaimed
repository could be bound into a stranger's project and its contributors
steered to sign the wrong agreement at a genuine portal. That control existed
only in the design; a requirement now demands it of any implementation.
*Affected:* new. Interacts with `REQ-CONFIG-3` (enforcement scope remains
definable) and
`REQ-OPS-6` (isolation).

**`REQ-SEC-9` — credential lifecycle (new).** Long-lived credentials require
documented rotation and departure procedures, and documentation of what each
can reach.

*Rationale.* The coverage deploy key never expires, is reachable by anyone
with write access to the records repository, and confers the ability to forge
enforcement decisions. No requirement answered to that exposure.
*Affected:* new. Interacts with `REQ-SEC-4` (storage) and `REQ-REC-7` (keys in
backup).

**`REQ-PORTAL-5` — enumerability.** Derived artifacts mapping users to
coverage must not be publicly readable or enumerable, with or without names.

*Rationale.* The endpoint ban alone left bulk disclosure of derived coverage
data unaddressed; per-subject coverage is already public through check runs,
and what privacy protects is the aggregate.
*Affected:* `REQ-PORTAL-5`. Interacts with `REQ-SEC-2` and `REQ-DASH-4`.

**`REQ-REC-3` — event commits.** The one-logical-event-per-commit rule is
pinned to its intended reading: it governs commits that carry events;
pre-event bootstrap commits are permitted; consumers identify events by
recorded path, never by commit position.

*Rationale.* The sentence admitted a stricter reading under which the
branch-bootstrap sequence the design requires would be non-conformant, and the
design carried a declared interpretation as a bridge. The requirement now says
what it meant.
*Affected:* `REQ-REC-3`.

*Superseded by Revision 4.* A bootstrap root commit containing the operator
README is now mandatory rather than merely permitted.

**`REQ-REC-2` — per-application permissions.** Rephrased for one or more
GitHub Apps, each holding only what its function requires; splitting records
access from check reporting is explicitly permitted.

*Rationale.* The accepted design splits two Apps precisely so no credential
spans records and enforcement; the previous singular phrasing predated that
and read as prescribing one App holding both.
*Affected:* `REQ-REC-2`, section 4 actor list. Interacts with D3 in the design.

*Superseded by Revision 4.* The records/enforcement capability split is now a
mandatory credential boundary rather than an optional App topology.

### Revision 2 — 18 August 2026

Two substantive changes, proposed from the high-level design and approved.
Both are recorded here as required by section 19.

**`REQ-AGR-2` — version transitions.** Separates publishing from activating,
and lets an activation declare whether it invalidates prior acceptances.

*Rationale.* The previous text made every version change invalidate every
contributor at once, with no way to correct a typo without a project-wide
re-signing event. `REQ-AGR-4` forbids DraCLA inferring legal meaning from
agreement text, so it must not assume every version bump is substantive either;
the project declares it. Separating publish from activate handles the purely
editorial case with no declaration at all. The staged-activation clause exists so
the blast radius of a substantive change is visible in advance rather than
turning every open pull request red without warning.

*Affected:* `REQ-AGR-2`. Interacts with `REQ-AGR-1` (the declaration rides the
immutable activation event) and `REQ-AGR-4`.

*Superseded by Revision 4.* Activations are immediate, inactive versions are
not signable, and future-effective staged activation is no longer supported.

**`REQ-CHECK-2` — coverage subjects.** `Co-authored-by` trailers no longer
determine a public check result; they are surfaced to authorized viewers
instead. Exemptions are extended from non-human accounts to named human accounts
with a recorded basis, and rule-based exemptions must materialize as events.

*Rationale.* A trailer is unauthenticated commit-message text that any commit
author can write. Treating it as a blocking public subject created two defects:
anyone could read any GitHub user's coverage status off the public check by
naming them in a trailer, and anyone could jam unrelated pull requests by naming
a contributor who later revoked. It also failed closed in the common legitimate
case, because most trailer addresses cannot be resolved to an account. Demoting
trailers removes both attacks and the false-failure case while preserving the
purpose of the rule: genuine co-authors are still surfaced and can still be
required to sign.

This narrows who must be covered, and the residual gap is stated plainly: a
co-author declared only by a trailer may contribute without signing unless a
maintainer acts. The project retains the option to make trailers blocking.

The human-exemption clause records the common case of contributors whose rights
are already assigned by employment. DraCLA records the assertion and its author;
it does not evaluate it, consistent with `REQ-AGR-4` and the purpose statement in
section 1.

*Affected:* `REQ-CHECK-2`. Interacts with `REQ-PORTAL-5` (the trailer oracle was
a functional equivalent of the forbidden lookup), `REQ-CHECK-1` (reasons remain
non-public), and `REQ-DASH-2` (exemption is a distinct reportable status).

*Not resolved by this change.* Commit author email is also attacker-controlled,
so a public check still leaks coverage to a party willing to author a commit
under a target's address. That residual is documented in the design rather than
claimed as closed.
