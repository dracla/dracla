# M4 — Enforcement and routing requirements

Status: scoped draft from the locked product baseline. Requirements review,
architecture approval, detailed planning and implementation are separate gates.

## 1. Outcome and authority

M4 makes GitHub pull-request feedback and authoritative merge-group decisions
use the correct project's current coverage. It supplies the shared routing
coordinator, signed route publication, repository gates and recovery integration
needed to keep those decisions fail closed during concurrent changes.

This is a milestone specification, not a change to product scope. The governing
inputs are the locked [product requirements](../requirements.md),
[product HLD](../high-level-design.md) and
[M3 recovery contracts](../lld/m3-control-reconciler.md). Parent requirements
and their prose remain binding. The [roadmap](../../docs/roadmap.md) and
[ownership map](../low-level-design.md#4-complete-hld-ownership-map) locate work;
they do not override those authorities. This package covers the complete M4
milestone, including integration and failure recovery.

M1's Python-authored schemas, shared corpus and TypeScript conformance subset
already exist. M2's administration/provisioning seams and M3's record transport,
replay, reconciliation and export engines also exist in the inspected source.
M3 delivery is approved on the current unmerged stack; it is not a published
production prerequisite. The current `api/wrangler.toml` launches a benchmark,
not the production enforcement or portal service. M4 must supply the missing
runtime foundation rather than assume a hosted service already exists.

## 2. Responsibilities and boundaries

`worker-enforce` owns authenticated GitHub enforcement events, contributing
repository observations, coverage reads, check/comment writes and check
recovery. It receives the enforcer App capability and coverage wrapping root,
never a records key or records-App credential.

M4's routing coordinator runs within `worker-portal` and owns registry
derivation, routing signatures, gate transitions and route reconciliation. This
is a shared foundation, not a third public Worker. M5 adds OAuth, Connect,
sign/revoke, private reads and administrative user flows over that foundation.
Only comparison and exact publication-reservation operations are exposed to
enforcement through a narrow service binding. M4 must not acquire portal
namespace-mutation authority merely to complete checks.

GitHub canonical events remain business and administrative truth. Coverage,
signed KV routes and repository-scoped Durable Object rows remain bounded
projections. M4 introduces no alternate CLA database, durable job queue,
reverse pull-request index, duplicate contract corpus or complete edge replay.

M5 owns authentication and confirmation for scope changes, conflict tools,
overrides, exemptions and reader administration. M4 must define and implement
the routing and observation services those flows need. M6 owns installation
orchestration and deployment setup; M7 owns the dashboard, final public assets
and release-wide verification. These boundaries do not defer M4's underlying
check, routing, disclosure or recovery obligations.

## 3. Observable requirements

### M4-R01 — Authenticated, bounded event processing

Select the per-App webhook secret by the receiving route. Verify the SHA-256
signature over the original bytes with constant-time comparison before parsing
or routing the body. Reject `sha1=` and never try another App's secret on the
same route. Handle pull-request creation/synchronization, merge-group
`checks_requested`, supported check re-requests, exact authoritative check
completion, the default-branch push fallback and relevant lifecycle triggers.
Duplicate, replayed, stale and
out-of-order deliveries must be safe. Do not claim that GitHub supplies a
trusted event timestamp or globally ordered delivery.

Reject other Apps' check runs, unsupported actions, ordinary completion
namespaces and malformed authoritative identities before a publication gate
call. Bind the App, repository, installation, head and exact check identity.
Late evaluations must not replace results for a newer pull-request head.

### M4-R02 — Complete subject and content resolution

Evaluate the pull-request opener and every GitHub-resolved commit author,
deduplicated by numeric user ID. An unresolved author or an incomplete commit
listing cannot pass. Respect GitHub's 250-commit endpoint limit and the
documented bounded-pagination/resource limits; never evaluate a partial set.
Resolve the exact associated pull request and current head's root Git tree OID
for content-bound overrides. Missing, changed or ambiguous identity is
non-passing. Do not replace GitHub tree identity with a reconstructed digest.

Collect trailer-declared co-authors for authorized views. They do not block
public checks by default. Preserve the parent's optional project policy for
blocking trailers; do not enable it silently or introduce a public lookup.
GitHub attribution is not proof of authorship or consent. Initial enforcement
does not require signed commits and must document the residual attribution,
griefing and aggregate-status oracle risks.

### M4-R03 — One validated encrypted coverage observation

Resolve the coverage branch once to immutable commit `C`. Read all required
fence, marker, project lifecycle, active-agreement, exemption, subject-shard
and wrapped-key inputs against that observation and their specified immutable
identities. Validate the existing shared schemas, authenticated envelopes,
project/purpose/key bindings, metadata and semantic relations before using
them. Fetch each required packed shard once. Unknown, missing, corrupt,
cross-project, cross-purpose, unavailable or inconsistent inputs never pass.

Apply the precomputed coverage decision and active accepted-version test;
consume effective exemption booleans and exact active PR/content/subject
overrides. Do not infer legal scope from routing, recompute full history at the
edge, expose exemption sources to enforcement, or invent multi-agreement rules.

### M4-R04 — Mutation freshness and project lifecycle

Apply the fence before exemptions and coverage. A project-wide mutation blocks
all ordinary subjects; a subject mutation blocks affected ordinary subjects.
Unrelated ordinary subjects may continue from one valid snapshot. A valid
success reservation permits ordinary evaluation only as specified by HLD §5.4;
every non-idle fence prevents a new authoritative success reservation.

Validate exact correspondence between mutation fences and any in-flight
marker, including valid pre-open/post-close absence. An idle or
success-reserved fence requires no marker. Missing or mismatched operational
state is unavailable. Succeeded projects use only the validated successor
route; unknown lifecycle never falls back to active.

### M4-R05 — Official merge-queue association and decision time

Support the locked ALLGREEN queue configuration, not HEADGREEN. Use the
official queue data for the canonical base branch to identify exactly one queue
entry matching the merge-group head and exactly one associated pull request.
Missing, truncated, duplicate, unsupported or inconsistent association is
unavailable. Freshly resolve that PR's opener, authors, current head and root
tree and evaluate coverage; never copy its earlier ordinary result.

Evaluate only that entry's PR, even when the synthetic branch includes earlier
entries. Completed authoritative decisions remain valid for their landing
attempt after later record/configuration changes. A rebuilt entry or new
`checks_requested` delivery gets a fresh decision. Without a required merge
queue, describe ordinary checks as feedback rather than final pre-landing
enforcement. Document administrators' GitHub-supported bypass ability.

When no required merge queue supplies final enforcement, re-verify pushes to
the contributing repository's default branch. If a commit landed without
satisfying the CLA requirements, open an issue containing only that commit's
SHA, the generic state and an authenticated-portal link. Never name subjects or
include record-derived details. This detects a problem after merging; it does
not prevent the merge. The enforcer App's `push` subscription and Issues-write
capability must be present in its deployment contract and acceptance tests.

### M4-R06 — Ordered authoritative success and exact recovery

Reserve the idle coverage decision fence at the evaluated commit before
reserving publication against the exact active repository route. Publish a
completed success only while both reservations remain held. Validate the
create response's App-bound check identity, head, status and conclusion. Use
the existing deterministic authoritative identity and disjoint ordinary
namespace. A mutation or route transition that wins first prevents success.

An independent authenticated completion observation, or the specified bounded
exact GitHub read during recovery, confirms the routing reservation. An
ambiguous create response retains the relevant reservations until exact
recovery establishes the terminal check. The prescribed zero-match path
creates and reads back a non-passing result; duplicate/truncated/ambiguous
observations remain reserved for reconciliation. Clear only matching
reservations in the specified order. Age, an absent marker, or a local caller
assertion never authorizes clearing them.

### M4-R07 — Generic, actionable public output

Use fixed public wording for CLA satisfied, action required and temporarily
unavailable, with the sole bounded repository-conflict exception required by
the parent. Current coverage uses `success`; action and uncertainty never use
`neutral` or `skipped` to pass. Pending evaluation uses a GitHub-App-supported
queued/in-progress state; exhausted/intervention cases complete non-passing.

Checks, the required PR comment and the bounded fallback issue provide the
authorized portal/retry path
without subject identities, subject counts, record-derived details, project
conflict identifiers, scope entries, private configuration or mentions. Escape
all untrusted output. Exact status, aggregate reasons, named subject details
and trailer information are disclosed only through the parent's graded
authenticated views, delivered with M5/M7; no new public reason API is implied.

### M4-R08 — One authoritative routing derivation

Derive routes from canonical effective scope, an immutable private registry
generation and current verified GitHub identities/installations. Honor numeric
repository/account identity, exact repository-token bindings and owner-scoped
project claims. A request resolves one project before project repository
access; event data can invalidate a route but cannot select a replacement.

Reject write-created overlap against the complete selector set. A GitHub-side
overlap selects neither project and quarantines only the affected repository.
Moves remove the old binding and activate that generation before a new bind.
Scope changes never rewrite evidence, change legal grants or require signing
again. Distinguish intentional unmanaged state from unverifiable installation
or match state. A verified unmanaged repository receives no check, including
no fabricated final passing check when an administrator offboards it.

### M4-R09 — Signed KV plus strongly consistent repository gates

Read signed routes at the stable repository-ID key. Verify the accepted
signing key and unsigned semantic digest separately, so signature-only key
rotation does not change route meaning. Compare repository identity,
installation, state, generation, registry OID and digest with the exact gate.
Pending, unavailable, absent, exhausted, erroneous or mismatched state fails
closed for that repository. A matching conflict route discloses only the
bounded conflict message. Stale KV and cached misses may delay recovery; they
never authorize a wrong-project decision.

Gates store only the bounded routing/transition/publication fields in HLD §7.
Their state must be reconstructible from authoritative sources, including
exact coverage publication-reservation evidence where required. Do not place
signer identities, agreements, coverage, exemptions or private records in a
gate. Gate transactions perform no external I/O.

### M4-R10 — Recoverable administrative route transitions

Consume exact authorized canonical requests and enforce the locked
prepare/pending/activate/publish/commit sequence. Every affected gate must
acknowledge pending before canonical activation. Recheck the exact required
live authority before activation. Deterministic activation/abandonment child
identities are mutually exclusive. A request alone, or `project_connected`
alone, never activates scope.

Before activation, restore only the matching transition after proving no
activation; partial restoration stays safely pending. After activation,
finish that exact generation forward; rollback is a new authorized change.
Every begin, reserve, confirm, commit, restore and unavailable operation is
conditional and idempotent on its full expected identity. Stale calls must not
regress generation, restore an unrelated row or pass a publication reservation.

### M4-R11 — GitHub lifecycle reconciliation and isolation

Use lifecycle/registry webhooks as verified doorbells and re-read current
sources. Scheduled reconciliation runs the same derivation and detects missed
creation, rename, transfer, ownership, deletion/restoration and installation
changes. Changed or unverifiable facts first invalidate the affected gate.
Unchanged derivations perform no unnecessary gate/KV write. Preserve numeric
identity and tombstones; never silently reassign a slug/owner or route through
a partial project repository transfer. M5 owns the separately authorized
owner-migration flow; M4 implements its exact publication transition.

The coordinator's request-bound GitHub-fact challenges and enforcer-side
observations must not export installation tokens or confer records authority.
The no-project repository-control capability resolves only the numeric
repository and one current verified enforcer installation. It may publish the
specified fixed non-passing output for matching `conflict`, `pending` or
`unavailable` gate states. Only `conflict` permits the current repository-admin
inspection probe. This capability never selects a project, reads project
repositories, mints records authority or authorizes a resolution mutation.
Unknown installations and token/repository mismatches fail closed. Conflict
inspection does not authorize resolution. Document unsupported double-targeting
by independent coordination domains; do not claim cross-domain uniqueness.

### M4-R12 — Recovery drivers and actual M3 integration

Provide the enforcer's daily missing/in-progress check sweep and exact
publication-confirmation recovery. Re-requests evaluate through the same
authorized path. Signing from a PR can request that originating PR's
reevaluation through the M5 integration. Correctness does not require a global
scan after signing, revocation or agreement changes.

Complete M3's authenticated route-unavailable repair and independent
publication-confirmation boundaries. A bulk rebuild cannot run merely because
a caller claims the route is unavailable. Retain unavailability through a
complete read-back-verified rebuild and recover only the exact reservation or
transition. Missing proof remains explicitly blocked. M3 retains ownership of
replay, persisted operation recovery and control workflow execution; M4 must
not reimplement those engines or add Checks authority to control credentials.

For a credential incident, first make every affected arrangement's route
unavailable. Shared-App or wrapping-root exposure requires fan-out to all
affected assignments; token-only exposure follows the token's actual scope.
Accept M3's authenticated containment and transport/rebuild evidence without
granting the control job Checks authority. Keep routes closed until the
required all-token containment barrier is proven, live identities and successor
bindings match, and authenticated ref/history verification and complete
read-back-verified coverage/derived rebuilding finish. Unknown issuance,
unproved expiry/invalidation or missing evidence cannot restore a route.

M4 owns the affected open-PR sweep and fresh check evaluations, followed by a
conditional restoration of only the matching incident/route identity. A stale
restore must not reopen a newer quarantine. If decryption or wrapping authority
was exposed, require the parent's actual successor-data-key verification and
mutable-state rebuild; a successor transport credential alone is insufficient.
Preserve retained canonical history and recovery keys. Existing production
containment probes and M7 release acceptance remain separate required evidence.

### M4-R13 — Capability separation and replaceable deployment

Keep records and enforcement credentials and wrapping roots separate. Validate
each current installation/repository binding; no guessed installation,
cross-project cache authorization or broader fallback token is acceptable.
Use the narrow non-public service-binding surface for cross-Worker operations.
Runtime configuration must enforce these bindings, safe observability and
immutable executable dependencies. Document credentials' reach and rotation,
retained-key compatibility, missing-key failure and signing-key rollover.

The approved enforcer permission inventory includes `push` and Issues write
for the default-branch fallback. GitHub grants accepted repository permissions
across an installation's selected repositories, including coverage repositories
if selected; the App key's reach is broader than the normal operation's token.
Normal tokens name the exact repository ID and request only the needed
permissions; coverage reads request contents read only. Runtime issue creation
is limited to the bounded fallback on contributing repositories. Do not claim a
create-only issue permission or that normal token narrowing contains an exposed
App key. Preserve the no-project capability limits of R11.

Support the locked shared-hosted and independent self-hosted topologies,
without a per-project Worker or a separate persistent application database.
M4's production bindings and deployment inputs must be usable by M6, rather
than depend on a benchmark configuration. Keep the adopted declared
serverless-enforcement deviation from `REQ-OPS-2` explicit.

### M4-R14 — Operational bounds and evidence

Bound pages, API calls, payloads, CPU work and scheduled fan-out against the
existing release profile and provider envelope. Incomplete work fails closed;
no partial scan establishes coverage, uniqueness or membership. The GitHub Free
baseline uses public contributing repos with required checks/merge queue and
private records/coverage/control/registry. Paid private-repo protection is
optional hardening, not a core prerequisite.

Emit safe failed-event identifiers/categories and correlation IDs, with no
request bodies, credentials or private values in logs or exception output.
Distinguish absent checks when the Worker cannot run from an explicit
non-passing response. Include retry, quota-exhaustion and missed-delivery
procedures. Measurement and test hooks must support M7's A2/A3/A6 release
evidence without making synthetic tests or a successful design review stand
in for live acceptance.

Account for every event-wide push delivery, including ignored refs and coverage
updates, and every additional fallback/fan-out invocation. Filtering does not
remove the incoming request cost. Expose fallback gate/CPU/subrequest
measurements to M7's model and include the runtime/test work in the LOC estimate.
The setup guide and deployment contract must identify the added App permission
and require its actual installation approval before fallback acceptance.

## 4. Acceptance coverage

Each row is a required observable outcome, not evidence that it has run.
Detailed planning must assign it to concrete slices and integrated checks.

| Requirement | Required acceptance evidence | Parent authority |
|---|---|---|
| R01 | Raw-body SHA-256 HMAC verified before parse/routing; SHA-1 and cross-App-secret injection rejected; duplicate/reordered delivery; other-App/namespace completion rejection before RPC; stale-head race; default-branch push trigger | `REQ-SEC-5`; HLD §4, §6.3, §6.4, §7.2, §8.1.2 |
| R02 | Multi-author/opener dedup; unresolved user; pagination/250 bound; trailer default/opt-in; exact root-tree override including history-only rebase and content change | `REQ-CHECK-2`; HLD §6.3–6.4 |
| R03 | Shared-vector validation plus actual immutable GitHub reads; mixed-commit prevention; retained keys; all malformed/cross-project inputs deny | `REQ-REC-2`; `REQ-SEC-2`; HLD §4, §5.3 |
| R04 | Every valid fence/marker combination, overlap/non-overlap, lifecycle/successor and malformed pair | HLD §5.4; `REQ-CHECK-4` |
| R05 | Official two-entry ALLGREEN queue, missing/ambiguous/truncated association, fresh post-revocation/version check, completed-before-change preservation and rebuilt entry; no-queue default-branch push detects a commit lacking CLA coverage and creates only the bounded generic issue | `REQ-CHECK-3`; `REQ-VERIFY-2`; HLD §6.4 |
| R06 | Check-vs-mutation and check-vs-route races; crash at each boundary; lost create response zero/one/multiple/truncated results; exact async confirmation; no timeout unlock | HLD §5.4, §7.1–7.2 |
| R07 | Fixed output for every state, retries, comments and fallback issues; malicious inputs; no names/counts/private metadata; fallback issue contains only SHA, generic state and portal link; conflict sole exception | `REQ-CHECK-1,5`; `REQ-PORTAL-3..6`; `REQ-SEC-8` |
| R08 | Complete overlap validation; remove-then-bind move; new selector match; unmatched versus unverifiable; token/project mismatch; no evidence changes | `REQ-CONFIG-1,3,5`; HLD §7 |
| R09 | Real Worker/SQLite gate integration; stale/missing KV; all gate states; quota/error denial; signing-key-only rollover; rebuild with held publication | `REQ-CONFIG-3`; `REQ-OPS-2`; HLD §7.2 |
| R10 | All partial pending/activation/publish failures; activation-abandon race; stale restore/commit; authority loss; exact retry and first-bind absent row | `REQ-SEC-6`; HLD §7.1 |
| R11 | Rename/transfer/delete/restore/install restriction, missed webhooks, project partial transfer; no-project fixed output for conflict/pending/unavailable; conflict-only current-admin probe; token/repository mismatch and lower-permission inspection denial; no project/records authority | `REQ-CONFIG-3`; `REQ-VERIFY-2`; HLD §7 |
| R12 | Actual M3 repair integration with authenticated unavailable proof and exact publication evidence; missing proof denies; daily sweep and originating-PR callback; incident shared-App/root fan-out, token-only scope, missing containment evidence, live old tokens after successor install, full rebuild/open-PR sweep and stale conditional restoration | M3 §5–6; HLD §5.4, §7.2, §8.1.2 |
| R13 | Credential/binding configuration checks, narrower service API, missing/retained keys and rotation; approved Issues-write installation reach plus exact-repository minimal tokens; no-project restrictions; self-hosted topology without hidden shared dependency | `REQ-SEC-2,6,9,10`; `REQ-OPS-1,2,6` |
| R14 | Resource-limit/error/fan-out tests, redacted logs, safe retry/runbook, Free-baseline verification and release measurement seams | `REQ-OPS-3,5`; `REQ-VERIFY-1,2`; HLD §9, §11 |

Offline contract tests, deterministic GitHub transport fixtures and actual
Worker/SQLite gate integration tests establish different facts and must be
identified separately. Controlled, separately authorized hosted/live checks
remain necessary for platform/API/containment claims that fixtures cannot
prove. No provisioning or live credential probe is authorized by this design
request. M7 assembles complete release traceability; it must not have to
reconstruct missing M4 acceptance evidence after delivery.

## 5. Detailed-design and estimate acceptance

The HLD must settle concrete interfaces, trust boundaries, normal/failure
journeys and the public contract before detailed planning. The plan must resolve
load-bearing platform assumptions against primary documentation and, where
needed, bounded disposable probes. It must name actual prerequisites and
cross-milestone responsibilities, including M3 integration and the M4 coordinator
foundation required by M5. A future component name is not proof it exists.

Every slice needs an owning result, paths, dependencies and observable
completion checks. Provide separate production and test LOC ranges, per-slice
and milestone totals, and a combined M4–M7 total when all four plans exist.
Estimates describe incremental final delivered nonblank physical lines,
excluding comment-only lines and counting docstrings/multiline statements
physically. Production includes shipped runtime configuration, packaging and
instructions. Tests include test-only helpers, configuration, generators and
integration drivers. Exclude development designs, static fixture data, images,
generated output, locks, dependencies and disposable probes.

Ground ranges in inspected source and named concrete changes. Count shared
runtime/test foundations once in the owning prerequisite; dependent milestones
count only extensions and integration. Include platform, concurrency, failure
and recovery testing. State uncertainty and scope sensitivity. Do not use
added-plus-removed edit churn, omit work to shrink a range, or convert to hours
or productivity. Do not create an estimator service or another progress ledger.

No new owner requirement decision is known within the locked M4 scope.
Remaining work is engineering: map interfaces and reuse, verify platform
feasibility, specify exact failure/recovery ordering and produce grounded
slice estimates. A genuinely new scope, trust or public-contract decision must
return explicitly to the owner. Architecture and final-plan approvals remain
required; this scoped document is not implementation or release authorization.
