# M7 — Product surfaces and release verification requirements

## 1. Complete outcome and governing scope

An authorized records reader uses the private dashboard to filter the current
minimal index. Contributors reach the correct project through accessible static
badges and canonical links. A second independent project, with a different
immutable legal recipient and independent repository arrangement, works through
normal installation/configuration. Release acceptance joins every required
behavior with current evidence and closes the real A2, A3 and A6 gates.

The [product requirements](../requirements.md),
[global architecture](../high-level-design.md),
[M3 design](../lld/m3-control-reconciler.md),
[M4 architecture](../m4/high-level-design.md),
[M5 architecture](../m5/high-level-design.md) and
[M6 architecture](../m6/high-level-design.md) govern. Carry their complete
requirements and acceptance, including parent prose, rather than treating the
short M7 roadmap list as a smaller product scope. Existing architecture,
controller, approval, exact-copy and separate healthy-activation decisions stay
settled. This is a prospective requirements specification, not implementation,
release approval or evidence that a live gate passed.

M7 does not create another frontend application, authentication system, private
proof, records database, replay/writer, bulk-decryption API, dynamic badge service,
per-project Worker or deployment topology. Initial-release non-goals remain in
force. No new local administrative/legal mutation path follows from this work.

## 2. Existing foundations and milestone ownership

| Foundation | Actual state and M7 boundary |
|---|---|
| M1/M3 | Native crypto, canonical records, 96 private shards, pure derived/read validation, export/control/reconciliation are existing foundations. Preserve completed source, IDs and review/delivery history. |
| M4 | Production Worker/HTTP/SQL harness, routing/gates, writer, ordinary/merge checks, incident containment and measurement seams are reviewed planned prerequisites. M7 reuses their real entrypoints and drivers; a future filename is not implemented code. |
| M5 | One dashboard/portal asset tree, sessions, exact private-read issuance/pages, graded PR disclosure and browser integration are reviewed planned prerequisites. M7 adds the dashboard surface and release assembly to that app, not duplicate backend authority. |
| M6 | Installer, shared/selfhost configuration, exact copying, healthy activation and installed/adopter drivers are reviewed planned prerequisites. M7 joins them with its sample, UI and release evidence. |
| Existing A2/A3 work | The old plaintext microbenchmark and partial capacity calculator are historical lower-bound evidence. They do not measure encrypted production paths, cold objects or the complete current workload. M7 owns the missing measurement/model/acceptance integration. |

Count shared runtime, protocol, fixtures and drivers once in their owning
milestone. M7 owns concrete extensions and joined acceptance, not another charge
for existing M1/M3 or planned M4/M5/M6 foundations.

## 3. Required behavior

### M7-R01 — A working private dashboard in the existing application

Deliver the dynamic dashboard through the same released M5 application and
project resolution. Use actual owning private-read services and native derived
formats. A detached renderer, fake backend success response or static screenshot
cannot satisfy this outcome. Public shell assets contain no private project data.
Keep contributor own-status, reader dashboard and administrator mutations as
separately authorized capabilities.

### M7-R02 — Current records-reader authorization on every private read

Require GitHub authentication and the current canonical records-reader union.
Repository read permission alone grants no dashboard plaintext. Readers without
repository access can use their actual individual, snapshot or continuous-team
source. Reuse the exact M5 proof classes/scopes, session/actor/project/generation
binding and source selection. Recheck canonical reader generation on every page
and exact live records-App membership for a continuous source before disclosure.
A failed source can obtain a fresh proof from another valid source; no old proof
or browser cache becomes authority. Apply the existing uniform unauthorized/
unknown-project response and fail closed on unavailable evidence.

### M7-R03 — Minimal, authenticated index pages

Reuse the existing fixed index-shard page API and native generation/envelope/
digest/profile validation. Return only the approved index fields: stable GitHub
user, login snapshot/as-of, agreement/version, enforcement scope, status and
acceptance/revocation dates. Include the existing exempt distinction without
folding it into signed current coverage. A corrected acceptance replaces its
single index row; full historical evidence remains in canonical records/exports.
No legal name, email, confirmation text, raw data key or arbitrary path/ref/
subject/decrypt selector enters this API. Exact named status uses its own
existing proof, never an index-proof scope bypass. Responses are private,
no-store and cannot be cached by a service worker or public asset mechanism.

### M7-R04 — Correct browser filtering and sorting

Support all required filters: GitHub user, project/repository enforcement scope,
agreement/version, current/revoked/superseded/indeterminate status, Individual
coverage and acceptance/revocation date. Preserve exempt as its own state.
Initial unsupported Entity coverage must not be presented as implemented.
Filtering/sorting runs immediately over the safely loaded minimal index; it must
not request every evidence record or send per-row identity lookups to GitHub.

Bound page loading and client memory with the tested release profile. Show
loading, partial, complete, empty and unavailable results distinctly. A partial
load or truncated page is not a complete empty search result. Never silently
combine incompatible source generations or label a stale/indeterminate row
current. Define deterministic filter/date/null/order behavior in the detailed
plan, without changing canonical status semantics.

### M7-R05 — Refresh, authorization loss and honest browser state

Reuse canonical mutation-driven index materialization and actual current page
responses. Refresh/poll is allowed; streaming is unnecessary. Refresh must be
bounded and stop or back off on hidden/unloaded pages, errors and expired
sessions as specified by the detailed design. A failed update cannot leave a
false successful-current claim or silently use an old generation as new data.

On observable authorization failure, logout, project/session change or invalid
source/generation, remove affected private display and in-memory state and
require fresh authorized reads. Persist no private index in localStorage,
IndexedDB, URLs, analytics, console output or public/static caches. Do not promise
retroactive erasure of data a previously authorized reader already received.
Retain useful nonprivate source/as-of and partial/unavailable explanations.

An earlier in-flight private index or status response must not repopulate display
or private memory after that state is invalidated. Only reads started under the
current project, session and authorization/generation state may commit results.
Verify this observable race by holding an authorized response, performing each
invalidation above, then releasing the response. It must make no private display
or memory change. Also reverse completion order for pages from two generations;
the obsolete response must not overwrite or combine with the current result.

### M7-R06 — Static badges and canonical project links

Ship the existing four approved static SVG states: generic sign-or-check,
satisfied, action-required and temporarily-unavailable. Serve them as public
static assets through the accepted static hosting role, with no dynamic
per-view coverage endpoint, subject identity/count or hidden Worker request cost.
The contributing-guide badge is viewer-independent and links to the existing
owner-qualified project route. Do not infer a viewer from an image request.

Keep canonical links correct under supported owner/project naming, rename and
independent deployment configuration. PR links carry the complete numeric
repository/PR context through existing validated M5 routing. Reuse the single
updated-in-place bounded M4 PR comment and M5 graded disclosure; add no second
feedback writer, public signer lookup or unauthenticated coverage oracle.
All states have meaningful text/alt text and do not rely only on color.

### M7-R07 — Safe, usable product output

Use the same existing release origin/CSP/cookie/asset separation and safe output
primitives. Render hostile login, agreement, configuration, scope and dashboard
values as data in every supported surface. Preserve approved minimal disclosure
at each PR tier. Public markup, SVG, URLs and metadata contain no signer PII,
proof/context, token or key. Contributor wording must not characterize the legal
meaning of an agreement or imply copyright transfer.

Deliver keyboard-operable labeled filters, readable state/error/partial results
and accessible text alternatives. Use the existing browser harness and real app
routes to verify behavior; tests must fail when a critical authorization,
escaping, generation or disclosure check is removed.

### M7-R08 — A genuinely independent second sample project

Use the same released installer, Apps, configuration and ordinary Connect/
agreement/scope operations for a second project with a different immutable legal
recipient and independent private role repositories. No source edit, hardcoded
project branch, shared canonical evidence or recipient replacement qualifies.
The two projects can coexist in the shared deployment with correct project
routes and ciphertext/key isolation. Reuse M6 installation and adopter drivers.

Demonstrate normal signing/check/revoke/re-sign, dashboard and export behavior
for both projects, and denial of cross-project read/write/App/proof/route input.
Exercise the accepted independent self-hosted configuration without canonical
conversion. Real accounts, consent, credentials and deployments are future
separately authorized execution, not actions of this design campaign.

### M7-R09 — Every-MUST release traceability

Provide a current traceability matrix for every in-scope MUST clause, including
parent prose and complete REQ-VERIFY-2 scenarios. Map each to its owning
implementation/test and an automated assertion or explicitly recorded manual
verification. A heading-only inventory, file existence, old suite count or
claimed percentage is insufficient.

Bind acceptance to the exact source/release/profile/assets/workflow and actual
executed evidence. Distinguish passed, failed, skipped, unavailable and unrun.
An unmet or unverified MUST prevents release unless the governing requirements
explicitly defer it. No new deferral is authorized here. Reuse existing validation
and release evidence; do not introduce a new approval authority, truth store or
workflow engine to make missing checks look complete.

### M7-R10 — Complete joined acceptance

Join the real M4/M5/M6 owning services, installed wheel/CLI, browser, protected
control and native engines. Cover every initial-release demonstration and the
complete required scenarios in product section16, including authorization loss,
all administrative rows, overlapping scopes/transfers and unaffected tenants,
concurrent append/idempotent no-op/conflict, key rotation, exact disclosure tiers,
malicious render/CSV values, queue-entry decision timing/rebuilds, actual first
Connect, shared/selfhost upgrade/rollback, recovery and the GitHub Free baseline.

Do not replace underlying child tests; add the cross-milestone journey that
establishes the parent outcome and binds retained child evidence to the current
release. Fault at real process/service boundaries and prove failure sensitivity.
Skipped live cases, fake providers or a prepared driver cannot count as passing.

### M7-R11 — A2 complete encrypted-path measurements

Measure the actual released production paths on authorized real accounts:
ordinary encrypted checks; each merge-group queue entry; mutations and bounded
bulk fanout; proof issuance/private index and exact-status pages; hosted export
plus local portable limits; maximum configured continuous-team materialization/
live membership; and warm/cold/reconstructed Durable Objects and gate lifecycle.
Use exact current encrypted fixtures, key unwrap/crypto, source/envelope parsing,
authorization, publication/readback and real owning adapters.

Record provider CPU separately from wall/I/O wait, cold/startup costs, requests,
subrequests, payload bytes, pages, object requests/row reads/writes/storage/
duration and actual Actions job resources where applicable. Exercise normal,
profile maximum, error and sensitivity cases. Existing plaintext development
numbers remain labeled historical lower bounds; they establish no current
production capacity or binding constraint. A measured bound violation blocks
that profile/envelope and invokes the approved fail-closed direction.

### M7-R12 — A3 complete workload and resource model

Extend the actual calculator with measured and clearly labeled assumed inputs.
Include event-wide pull-request, merge-group, check_run and push deliveries,
ignored-event requests, fallback/fanout, two daily maintenance roles, signing/
mutation/team/private proof/page/full-index-scan/export traffic and static badge
zero dynamic requests. Charge routing-gate calls/publication/transition writes,
object duration/row reads/writes/storage, current CPU/subrequests, repository
counts and adopter-owned scheduled/dispatch/retry/repair Actions work.

Keep per-account shared Worker/DO quotas and per-adopter Actions allowance
separate. Compute for arbitrary project counts, normal and full-dashboard/
queue/check-run/push/fallback sensitivities, with units and uncertainty. Use
current dated primary provider limits/pricing and the actual released profile.
Report every relevant resource and the limiting one; do not reuse old constant
CPU arithmetic or omit an expensive term to preserve a target envelope.
The approved hosted target remains measurement-gated. Reduce the stated envelope
or retain an unmet release gate when evidence does not support it.

### M7-R13 — A6 actual reach, containment and recovery

Reuse M4 all-token incident and M5/M6 lifecycle/recovery drivers to verify
complete dedicated/shared transport-App assignment and controller reach,
least-privilege/exclusion negatives, successor keys and potentially exposed
App/root/token behavior. Include tokens not known to the cleanup process,
outstanding issuance, cutoff, permanent invalidation or full maximum lifetime
plus live-tested clock/propagation margin. Removing a key or temporary suspension
alone does not prove containment. Keep affected routes unavailable until the
accepted barrier and current proofs actually pass.

Verify rotation and retained historical decryptability, exact raw backup copying
including equally broken state, separately requested healthy same/new-repository
activation under all first-install checks, full projection/normal-reader/export/
dashboard recovery and bounded open-PR recheck. Imported unfinished work is not
silently repaired or activated. Newer quarantine defeats stale restoration.
No backup/key controller is promised protection against its own independent
fork, retroactive history erasure or inaccessible later source events.

### M7-R14 — Authentic release and execution identities

Bind assembled and sample evidence to authentic published release/publisher,
installed dependencies, assets/config/profile and actual executing protected
control source/repository/workflow. Exercise compatible upgrade/rollback and
exposed deployed release identity through accepted M6 operations. A local wheel,
mutable tag, package self-declaration, successful dispatch or old approval cannot
substitute for required independent verification/current execution proof.
No design review, offline validation or local fixture authorizes live credentials,
provisioning, deployment, publication or production acceptance.

### M7-R15 — Honest guidance, preservation and cleanup

Ship current dashboard/link/sample/verification/capacity/incident/recovery
instructions and useful nonprivate source/resource/generation diagnostics.
Preserve historical benchmark observations but correct unsupported conclusions;
wording alone does not close missing measurement or behavioral acceptance.
State actual tested limits, unavailable evidence and finite next actions.

Future drivers clean up only exact run-owned verified resources under their
actual authority and record residual resources. Preserve retained histories,
keys/evidence, other projects, completed M1–M3 plans/source/IDs/approvals, unrelated
WIP/shelves and consumed review/delivery budgets. This campaign's final navigation
cleanup is prospective for M4–M7; it does not relabel old completed slices or
delete historical proof.

### M7-R16 — Complete engineering and credible estimates

The HLD/LLD must assign every requirement, parent scenario and joined outcome to
real prerequisites, concrete interfaces and coherent independently verifiable
ordered slices. Resolve important platform/failure/recovery/resource behavior;
missing engineering cannot be hidden by naming a future helper or listing tests.

Provide source-grounded separate production/test ranges per slice and milestone
and combined M4–M7 totals. Use incremental final-delivered nonblank physical
lines, excluding comment-only and physically counting docstrings. Shipped
runtime/configuration/packaging/instructions are production; test-only helpers,
configuration, fixture generators and integration/live drivers are tests.
Exclude designs/static/generated/dependencies/lockfiles and disposable probes.
Count shared foundations once; include actual platform/integration/failure and
live-driver work. Do not substitute added-plus-removed churn or time estimates.
State uncertainty and retain external acceptance gates honestly.

## 4. Observable acceptance and readiness

| Requirement | Required observable result |
|---|---|
| R01–R03 | Actual existing app/owning services return only authorized minimal current index/status results; repo access alone, changed session/source/generation or cross-project input deny with no raw keys/private evidence. |
| R04–R05 | Browser filters/sorts all required fields immediately after bounded load; partial/empty/unavailable/current states remain distinct; source changes refresh safely and observable denial/logout removes private state. Held private index/status responses released after logout, project/session change or source/generation invalidation cannot mutate private display or memory; reversed two-generation completion cannot overwrite or mix the current result. |
| R06–R07 | Four accessible static assets and canonical links work for both projects/deployments without an anonymous dynamic oracle; actual browser malicious-value and disclosure-tier tests fail on removed protections. |
| R08 | Different immutable recipients/independent role IDs operate through released configuration only; actual installed shared/selfhost and cross-project negatives are recorded. |
| R09–R10 | Every MUST clause and complete section16 scenario has current exact executed evidence; any unrun/failed/skipped requirement blocks release. Joined real entrypoints expose actual integration failure. |
| R11–R12 | Complete encrypted/warm/cold/provider measurements feed the actual dimensional model; all resource units/normal/stress inputs and account/adopter ceilings reproduce the claimed tested envelope. |
| R13 | Actual unknown-token/cutoff/rotation/copy/healthy activation/read/export/dashboard/sweep and newer-quarantine probes meet existing all-token/first-install standards; missing evidence keeps gates closed. |
| R14–R15 | Authentic release/executing pins, compatible rollback, honest historical/current guidance and exact run-owned cleanup are proven without exposing private data or altering unrelated/completed work. |
| R16 | Every owning slice has concrete acceptance and separate source-based production/test ranges; combined totals count prerequisites once and retain genuinely unrun external gates. |

No new requirements question or scope deferral is pending. Browser page/refresh
contracts, exact model inputs/measurement interfaces, finite driver/resource
budgets, evidence binding, slices and estimates are the bounded HLD/LLD work.
Requirements authoring does not establish those implementations, clean design
review or product release readiness. All M7 product and live acceptance remains
future execution work until actual evidence exists.
