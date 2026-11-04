# M7 — Product surfaces and release verification architecture

## 1. Selected structure and scope

Extend the existing M5 application with a private dashboard, the approved static
badges and canonical entry links. Join the actual M4/M5/M6 services and installed
drivers for the independent sample, complete release acceptance and A2/A3/A6.
Complete the existing capacity calculator using measured production inputs.

The [M7 requirements](requirements.md) govern this architecture. Their linked
authorities remain governing transitively, including complete parent prose and
section16 scenarios. This is a prospective architecture, not proof that the
planned prerequisites, implementation, measurements or live gates exist.
Completed M1–M3 source, formats, IDs and approval history stay intact.

| Responsibility | Owner and M7 extension |
|---|---|
| Authentication, origins, project routing, sessions, action forms | Existing M5 portal. M7 uses the same routes, cookies, safe render primitives and session lifecycle. |
| Reader-source union, proof issuance, fixed private pages | Existing M5 service over native M1/M3 validation. M7 adds the dashboard client and the safe page-source metadata needed to reject mixed observations. No new proof or query class. |
| Current private-index materialization and repair | Existing single M4 writer and M3 protected reconciler. M7 observes their output, never rewrites canonical/derived data from the browser. |
| Badge and project entry output | Static assets in the same released M5 asset tree; existing canonical project/PR link builder and bounded M4 PR comment. |
| Independent sample and execution setup | Existing M6 released installer/configuration/adopter driver. M7 supplies a second independent configuration and joined assertions. |
| Test/runtime/provider boundaries | Existing M4 HTTP/SQL/Worker harness, M5 browser/service harness and M6 installed/release/live drivers. M7 composes them and fills explicit missing journeys. |
| Measurements and capacity | Existing `api/bench/` and `core/capacity.py`, extended to production paths and all resource dimensions. Existing plaintext results stay historical. |
| Acceptance and guidance | Existing repository validation/release evidence and human-readable requirements matrix. M7 adds exact assertion/evidence mapping, checks and current operating guidance. |

There is one frontend application, one private-read authority, one canonical
writer and one capacity model. A separate dashboard backend, snapshot service,
database, dynamic badge endpoint, telemetry service or approval/evidence engine
would duplicate an existing owner without solving a required new invariant.

## 2. User interfaces and observable defaults

The existing owner-qualified project shell exposes Dashboard to an authenticated
records reader. It remains a view of that project, not a cross-project directory.
The existing contributor own-status view remains available under its separate
authorization. A failed reader request cannot fall back to that view to read
other people. Administrator actions and exports retain their existing explicit
interfaces and checks.

Use the accepted interfaces without new caller-selected refs, providers or paths:

| Interface | Dashboard use and result |
|---|---|
| `GET /p/<owner>[/<slug>]` | Existing project resolution and public app shell; Dashboard navigation stays inside the same application. No private data in HTML or asset metadata. |
| `POST /api/projects/<project_id>/read-authorizations` | Existing `reader_index` plus project scope for an index scan; existing exact `reader_subject_status` scope for an explicitly requested named status. Proof remains memory-only and session bounded. |
| `GET /api/projects/<project_id>/index/<shard>` | One of the fixed32 shard pages, one existing proof in the authorization header. Return approved minimal rows and safe validated source identity, never raw evidence or keys. |
| `GET /api/projects/<project_id>/subject-status` | Existing exact proof supplies the subject; no added user-ID query or index-proof bypass. |
| `POST /logout` | Existing same-origin logout. Clear private application state and invalidate pending completions locally before waiting for the response. |
| Existing `/pr/<number>` and `pr-view` | Retain complete numeric repository/PR context and the existing maximum permitted disclosure tier. Dashboard access does not change public PR output. |
| Existing exports | Explicit separate reader export action with its own snapshot identity and current download authorization. A dashboard scan is not an export or retained snapshot. |

A normal journey is: open the project shell, authenticate, select Dashboard,
obtain the exact index proof, load bounded pages, filter/sort the minimal rows,
then explicitly refresh or use an existing authorized action. Repository read
permission alone cannot obtain the proof. A valid individual/snapshot reader
without repository access can; a continuous source still needs its bound live
records-App membership check for every page.

### 2.1 Filter, ordering and reset behavior

Initial filters include all statuses and scopes and all available agreements and
dates. Entity coverage is not offered as an implemented option. Individual
coverage and exempt remain distinguishable. Within a multi-select field use OR;
across populated fields use AND. Empty selection means no restriction, not no
matches. GitHub-user input matches a stable numeric ID exactly or a login
snapshot case-insensitively; no live per-row GitHub lookup occurs.

Agreement/version and project/repository scope selectors use the actual loaded
row values and canonical numeric repository identity where applicable. Names
are display labels, never authority. Date bounds are UTC calendar dates;
inclusive From/Through days include the complete final day. Null dates do not
match an active date bound. Invalid or inverted bounds show a local validation
error and do not silently broaden the query. Different acceptance/revocation
bounds combine by AND.

Default ordering is acceptance date descending, null last, with stable numeric
GitHub ID and agreement/version ties. Every supported column has deterministic
ordering and the same stable ties. Render a bounded client page of100 rows,
with accessible next/previous controls; filter or sort changes reset that client
page to the first page. This is local presentation pagination, not another
server cursor. The detailed plan fixes exact string/date/null comparators.

Reset clears only local filter/sort/client-page choices to these defaults. It
does not change project, authorization, canonical data or server page selection.
Filters and rows stay in volatile application state. Do not place private search
criteria in URLs, analytics, logs or persistent browser storage.

### 2.2 Loading, refresh and failure presentation

Show loading, partially loaded, complete, complete-empty and unavailable as
different states. Show matched counts as partial until all32 pages are verified;
never turn a truncated/failed scan into a complete empty result. An empty valid
page is still one successfully loaded shard. Rows marked exempt, superseded,
revoked or indeterminate keep those semantics and labels.

Use an explicit Refresh control, with one scan active at a time. There is no
background polling or streaming subscription. A hidden/unloaded view cancels
the scan and drops private application state; returning to the visible dashboard
requires fresh authorized reads. Refresh replaces the previous scan rather than
merging its rows. Show source/as-of identity for displayed results and make no
claim that an already received screen is a continuous authorization monitor.

Authentication expiry uses the existing safe reauthentication journey. Uniform
private404 means the data cannot be shown, without distinguishing an unknown
project from an unauthorized viewer. Dependency503, network/parse errors,
inconsistent generations, profile overflow or unproved completeness stop the
scan and clear private results; show safe retry guidance. Do not show provider
exceptions, old successful-current claims or a silent stale-cache fallback.
User-initiated Refresh can retry; it cannot bypass a profile or authorization
failure. Preserve useful nonprivate error/source/as-of information.

## 3. Private-page and browser trust boundary

All authority stays on the M5 service. Each request authenticates the live
session, re-resolves canonical reader generation, validates exact proof scope,
and checks the proof-bound continuous membership through the records App when
needed. Source union selection and proof renewal remain the existing service
operations. Browser filtering or a previously rendered row grants no permission.

The service uses native selected-class validation: project/key identity,
canonical and derived class generation, selected envelope digest, installed
profile and current operation/lifecycle/active-agreement guards. A page carries
only the approved index row fields. Subject-status output uses its exact
existing result class; full historical/legal evidence stays in exports.

### 3.1 Coherent scans without snapshot authority

M7 exposes a closed safe source-identity wrapper around each existing index-page
and exact-status result. It identifies the exact observed canonical `events` OID,
immutable records `derived` OID, validated immutable coverage commit OID,
canonical reader generation, validated index generation and installed
release-profile identity used to produce those rows. The coverage commit binds
the actual source, active agreement, in-flight marker and decision fence used
for status evaluation. Resolve those controls and every required selected shard
at that one authenticated coverage observation; all rows in a page use it.
Do not substitute the records head for this independent observation. These are
provenance fields, not caller input or an authorization grant. The service
supplies them from its validated observation; a client timestamp or unverified
token decode cannot supply them. LLD fixes the wire codec and binds it at the
existing M5 endpoint/consumer seam. No new read route or private proof is needed.

A scan accepts pages only when that complete tuple matches its first accepted
page and current project/authentication context. A separately requested exact
status cannot be combined with displayed index rows under a different tuple;
refresh the observation within the same budget or report unavailable. Live heads can move between
requests. On a mismatch, discard the scan and restart from current authority
within a fixed total request/restart/time budget. If it cannot complete, report
unavailable or explicitly partial, with no mixed complete result. Do not pin
server reads to a browser-selected old ref, reuse obsolete authorization or
create a server-side snapshot store to improve availability. An unrelated head
change may force a conservative reload; the bounded availability cost is simpler
than adding authority/cache/retention machinery.

Coverage can open or close a subject-scoped or project-wide mutation fence while
records `events` and `derived` heads stay fixed. Acceptance holds a page, changes
each such coverage/fence state at those fixed records heads, then releases the
page in both completion orders. The mismatch must discard/reload the scan or
stop it partial/unavailable; it cannot produce a complete mixed-status result.
Include exact-status/index mixing in the same check.

Two page requests may run concurrently, but every page remains a separately
authorized service request and is charged as such. Enforce response bytes,
parsed rows, total decoded bytes and client memory/DOM bounds from the release
profile before accumulation. The UI renders only the bounded local page. A
profile too large for its tested browser budget remains unsupported rather than
silently truncating records. LLD assigns numeric scan/decode budgets and tests
their maximum against the existing installed shard bounds.

### 3.2 Rejecting late completions

One local monotonically changing view/scan epoch binds project, session identity,
proof/source generation and scan identity. Invalidate it before logout, project
or session switch, observed denial, invalid source/generation, hidden/unloaded
view or a replacement refresh. Clear private rows, proof, filters containing
private input and pending status output. Cancel outstanding requests as a
transport optimization; cancellation alone is not the safety check.

Every asynchronous completion must compare its captured context with the current
one before accepting headers/body and again before any application-state or DOM
commit. A stale completion cannot replace an error, append rows, update counts
or restore private status. Timers and callbacks have the same guard. A fresh
request under the current context is required to repopulate data. This is local
coordination inside the existing client, not a new server session or proof.

Acceptance holds an authorized index/status response, performs each required
invalidation, releases it and proves no private application-state/display change.
Reverse responses across two generations and across a replacement refresh as
well. Prove sensitivity by disabling the commit guard in the browser harness.
This does not promise erasure of browser/network copies already received by an
authorized reader or global immediate server logout beyond the M5 contract.

### 3.3 No Service Worker or private asset-cache path

The privileged portal origin registers no Service Worker. Private index, status,
proof, authenticated action and export responses are never handled or persisted
by an asset/offline cache. Retain `Cache-Control: private, no-store` and explicit
no-persistence rules for localStorage, IndexedDB and Cache Storage; response
headers alone do not prevent a Service Worker from storing a response.

Private initialization requires no controlling worker or registration whose
scope can intercept these routes. An unexpected existing registration is an
unsupported browser/deployment state: block private requests/rendering, clear
private application state and show nonprivate guidance to remove that origin's
registration and retained caches and reopen the supported release. An
`unregister()` result alone does not prove that an already controlled page is
safe; require a fresh uncontrolled page before fresh authorized reads. Do not
silently delete unrelated origin data, serve old private responses or add an
offline-compatible migration path. A controller change invalidates the current
view/scan epoch and stops private work by the same rule.

Browser acceptance verifies no registration by the supported app and no private
index/status/proof bytes in persistent stores or asset caches before and after
logout, denial and project/session change. Seed a prior controlling registration
and private-cache response: the app must make no private read or display until
the supported clean reload, and must never replay that response. A later need
for a Service Worker requires an explicitly reviewed separation from all private
routes; this design supplies no such feature or authority.

## 4. Static badges, links and disclosure

Ship only the four approved static SVG assets: `cla-sign-or-check.svg`,
`cla-satisfied.svg`, `cla-action-required.svg`, `cla-unavailable.svg`. Their text
and accessible alternatives identify those states without depending on color.
They contain no injected project/user/subject data, script, external fetch or
event handler. Public static hosting and the existing released asset manifest
serve them without a per-view Worker request. Count static bytes/hosting costs
where applicable; zero dynamic badge requests does not mean all hosting is free.

The contributing-guide badge is the viewer-independent sign-or-check asset and
links to the existing owner-qualified project route. Dynamic check/PR output
selects its already permitted fixed state and link; M7 does not add another
comment writer. Use the existing M5 canonical link builder, including complete
numeric repository/PR context, configured deployment origin and rename handling.
Never guess among same-number PRs or expose private repository enumeration.

Retain M5 graded disclosure: anonymous/public generic guidance, own permitted
reason, collaborator aggregate and reader-authorized GitHub identities only
under their exact existing conditions. No dynamic public signer lookup or
coverage-count badge follows from Dashboard. Render all login/agreement/scope/
configuration values through existing safe text/URL primitives. Existing
origin/CSP/cookie protections apply. Agreement wording remains factual and
does not explain away legal effect or imply copyright transfer.

## 5. Second project and deployment independence

Use one ordinary M6 configuration for the existing sample and another with a
different immutable legal recipient, independent records/coverage/control IDs,
root/key arrangement and normal contributing repository. Install from the same
authentic release, select the accepted shared/default or self-hosted deployment
profile and complete normal first Connect. Do not edit source, swap an existing
recipient, reuse canonical evidence or claim that two repository names prove
independence. Protect sample credentials and avoid private identities in public
example configuration.

The existing M6 driver owns provisioning/authentication/lifecycle mechanics.
M7 owns joining both projects through signing/check/revoke/re-sign, dashboard,
export and deployment identity, plus cross-project proof/App/route/read/write
denials. Run the same accepted code against an independent self-hosted setup,
without canonical-format conversion or per-project code changes. Tenant A
failures, transfer, restore and quarantine cannot mutate tenant B.

Live resources require separate execution authorization. Future drivers must
track exact verified run-owned resources and clean up only those under their
actual authority; record residual resources and preserve retained evidence.
A design fixture or prepared live driver is not a successful sample deployment.

## 6. Release traceability and joined acceptance

Maintain the repository's existing human-readable verification material with
one row per normative MUST clause, including parent prose and the complete
REQ-VERIFY-2 scenarios. Each row identifies its owning implementation, exact
assertion or approved manual procedure, execution layer and current evidence.
An automated completeness check detects missing/duplicate/unmapped clauses and
stale source anchors. It does not interpret prose as passed or become another
workflow/approval engine. LLD specifies the finite enumeration and check.

Bind evidence to exact source revision/content, authentic release/publisher,
installed wheel/dependencies, assets/profile/config and executing protected
control repository/workflow identity. Preserve actual command, test identity,
result and bounded safe diagnostics. Distinguish passed, failed, skipped,
unavailable and unrun. Missing or stale evidence keeps the corresponding release
gate closed. Do not grant approval from a matrix row, old suite count, driver
existence, successful dispatch or package self-description.

### 6.1 Acceptance layers and ownership

| Layer | Required contribution |
|---|---|
| Native deterministic | Retain M1/M3 vectors, crypto/read/export/recovery evidence and add only genuine missing M7 assertions. |
| Owning runtime/services | Reuse M4 Worker/HTTP/SQL/fence/CAS/incident, M5 actual session/form/read/PR/browser and M6 installed/release/controller drivers. Child evidence must match the current assembled code. |
| Joined offline integration | Drive real owning entrypoints/process boundaries; cover the full initial-release journeys, multi-project isolation, every administrative row, overlap/transfer/unaffected subjects, append/no-op/conflict, rotation, hostile values and failure/recovery. Fake providers can test decisions but cannot satisfy live platform claims. |
| Browser | Use real released app routes for all filters/loading/reset/accessibility, malicious rendering, disclosure tiers, authorization withdrawal, held/reversed-response races and fixed-records-head coverage transitions. Assert no Service Worker/private persistent cache, safe prior-registration handling, output and absence of forbidden state. |
| Authorized hosted/live | Actual GitHub Free/private control, shared/selfhost install/Connect/upgrade/rollback, queue rebuilds/timing, protected execution identity, A2 measurements and A6 all-token/recovery probes. Never count skipped/unrun as passed. |
| Release assembly | Resolve every MUST and required parent scenario to current executed evidence; fail closed on missing/unverified behavior, provenance or resource support. |

Join rather than duplicate all child unit tests. The cross-milestone test must
establish the parent outcome through real adapters and fault boundaries, with
observable sensitivity if an important authority, generation, routing, escaping,
cleanup or containment check is removed. LLD enumerates the complete scenario
matrix and each owning slice; names such as "integration tests" alone are not
an implementation plan.

## 7. A2 measurement architecture

Extend the existing benchmark entrypoints to invoke released production handlers
and native formats through M4/M5/M6 measurement seams. Generate authenticated
encrypted fixtures with existing native builders; do not replace production
decryption, key unwrap, canonical/envelope parsing, membership or gate calls
with a plaintext timing stub. Keep old observations as dated historical lower
bounds and correct unsupported current-capacity conclusions in shipped guidance.

| Family | Required normal, maximum and failure measurements |
|---|---|
| Enforcement | Ordinary PR check; every merge-group queue entry, rebuild and fallback; actual crypto, source/coverage validation, decision, publication and readback. |
| Mutation/materialization | Signing/revoke/admin/Connect, bulk fanout, visibility/team observation and repair; bounded failure and indeterminate publication. |
| Private read | Proof issuance, each index page, complete32-page scan, exact status, maximum reader rules/membership pages, authorization loss and size limits. |
| Export | Hosted protected-job production and reauthorized download; portable installed CLI streaming and documented local limits. |
| Objects/gates | Warm/cold/reconstructed SQL object, read/reserve/confirm/transition/rebuild, requests/rows/storage/duration and latency. |
| Platform work | Actual protected Actions schedules/dispatch/retries/reconcile/export/recovery and their job resources. |

Record provider CPU separately from wall/I/O wait, startup, requests/subrequests,
payload/decoded bytes/pages, gate/SQL operations, storage and billed duration.
Bind each measurement to the exact handler/fixture/profile/provider/region and
warm/cold condition; record sample count and uncertainty. Instrumentation emits
safe aggregates and source identities, never decrypted rows, proofs or keys.
Use a finite test/run budget and fail on incomplete measurement, not a silently
smaller fixture. Authorized real-account runs are required for provider claims.

A bound violation blocks the unsupported profile/envelope. It cannot be fixed
by dropping a measured term, treating I/O time as CPU or reusing the old1.26ms
plaintext number. LLD fixes executable measurement interfaces and finite case
budgets; no live credential/deployment action occurs during design.

## 8. A3 workload and resource model

Extend `core/capacity.py` directly. Replace its incomplete arithmetic with one
explicit dimensional model over measured values and labeled assumptions. Retain
its arbitrary project-count interface and useful human output; do not preserve
a competing old capacity answer or introduce another calculator/service.

Inputs distinguish per-project activity, per-request operations, account quotas,
per-adopter repository/Actions work and published profile bounds. Account for
event-wide PR/check-run/push deliveries, ignored deliveries, merge-group entries/
rebuilds, fallback extra requests, both daily maintenance roles, signing and all
mutations/team work, private proof/page/scan/refresh traffic, exports, route/gate
reads/reserve/confirm/transition/rebuild, SQL row operations/storage/duration and
actual CPU/subrequests. Badges add no dynamic Worker requests. The manual full
dashboard scan costs each of its authorized pages; conservative restarts,
reproofs and return-to-view refreshes are explicit sensitivity inputs.

Distinguish event delivery from resulting extra invocations and service/gate
calls, so neither is omitted or counted twice. Actions uses actual owning
protected-job schedules/dispatch/retries and per-job billing, not the old
assumption that every signing triggers a reconciler push run. Shared account
limits and adopter-owned minutes/storage/concurrency stay separate. Mixed
projects can have different repositories, traffic and team configurations.

Outputs show units, normal case and full-scan/queue/check-run/push/fallback/team/
export/recovery sensitivities, every relevant resource and the limiting one.
Check daily, monthly and instantaneous/per-invocation bounds independently;
daily averaging cannot prove a burst, CPU, page or subrequest bound. Missing
measurements remain unknown and cannot yield a verified capacity. Use current
dated primary provider limits/pricing and distinguish free allowance, included
paid capacity and configured spend protection. No specific provider value is
newly asserted by this architecture.

The hosted target is measurement-gated. If the complete model does not support
it, publish the smaller evidenced envelope or retain an unmet release gate.
Do not change accepted topology or expand public/service trust silently. A2
measurements feed this existing calculator; the calculator cannot certify its
own assumptions. LLD resolves exact formulas, units, zero/unknown behavior,
rounding and reproducible fixture inputs.

## 9. A6 containment, exact copying and activation

Reuse the M4 all-token incident barrier and M5/M6 lifecycle/installed drivers.
Test dedicated/shared transport Apps, complete controller reach, required role
assignment and least-privilege/exclusion negatives, especially no transport
reach to control. Include tokens unknown to cleanup and outstanding issuance.
Recovery requires current cutoff and permanent invalidation or full maximum
lifetime plus the live-tested clock/propagation margin. Removing a key,
temporary suspension or an operator's `contained:true` assertion is insufficient.

Affected routes stay unavailable until the accepted barrier, current App/key/
source proofs, full publication/readback and matching conditional gate restore
pass. A newer quarantine or state change defeats stale recovery. Exercise
rotation with retained historical decryptability and the normal export/read/
dashboard paths; root possession does not promise protection against the
controller's independent fork, erased history or inaccessible later events.

Raw repository mirroring copies the source state exactly, including a broken or
unfinished state. It repairs nothing, creates no missing ref and binds no live
replacement route. Copy verification compares actual preserved refs/objects and
application state, without claiming the source was healthy. Separate explicit
same/new-repository activation requires an already consistent healthy idle
source and all original first-install checks. An unhealthy source has zero
Git/secret/job/registry/current-route effects from activation; replacement targets
remain unbound. Imported pending operations are not continued. Only activation's
own newly accepted rebind can retry under the existing contract.

The joined recovery journey proves both cases: equally broken copied state
remains equally broken, and a healthy copied source activates only through the
accepted M6 checks and M4/M5 gates, then normal read/export/dashboard and bounded
open-PR sweep succeed. Offline fixtures establish rejection/protocol behavior;
actual hosted/live acceptance remains separate and required.

## 10. Delivery boundaries, estimates and finite detailed work

Order the M7 work around observable outcomes: authorized/coherent dashboard;
filters/refresh/failure/races; static links/disclosure; independent installed
sample; complete joined traceability/acceptance; production measurements;
dimensional model and evidenced operating guidance. Shared prerequisites remain
in their owning M4/M5/M6 slices. M7 owns real extensions and cross-milestone
outcomes, including server metadata and client integration where needed.

The LLD must resolve, without adding a second mechanism:

- Exact private-page/status provenance wrapper and validation/consumer wiring, including the single immutable coverage/control observation, preserving existing proof/route/status authority and operation/active-state semantics.
- Numeric client response/row/decoded-memory/scan/restart/time budgets and their release-profile compatibility, all async commit guards, no-Service-Worker/private-cache checks, deterministic comparators and accessible result rendering.
- Complete every-MUST/section16 scenario enumeration, actual driver boundaries, exact source/release/evidence binding and finite failure-sensitive execution/cleanup.
- Executable A2 case/metric interfaces and bounded real-provider drivers, A3 complete formulas/current primary limits and unknown/rounding behavior, A6 live evidence and exact copy/healthy activation joins.
- Concrete ordered independently verifiable slices and source-grounded separate production/test ranges, with all platform/integration/failure work included and shared foundations counted once.

These investigations can invalidate concrete claims. If page-source metadata
cannot bind the actual evaluated rows, the dashboard cannot claim coherent
completion until that existing service seam is corrected. If the maximum
installed profile exceeds browser or provider budgets, that profile has no M7
acceptance; an untested truncation or larger allowance is not a workaround.
If a real platform probe disproves release identity, Free/private execution,
controller reach or the all-token barrier, retain that failed gate and return
any necessary material contract change to the owner before dependent work.
No unsupported platform assumption is converted into an approved requirement.

Use incremental final-delivered nonblank physical LOC, excluding comment-only
lines and counting docstrings physically. Shipped runtime/config/packaging/
instructions are production; test-only helpers/config/generators/integration/
live drivers are tests. Exclude design/static/generated/dependencies/lockfiles,
disposable probes and edit churn. State uncertainty, M7 totals and combined
M4–M7 totals. No LLD inventory or numeric LOC claim is supplied by this HLD.

| Requirements | Architecture and required acceptance |
|---|---|
| R01–R03 | Sections1–3: actual one app/owning service, exact source-union proof, minimal authorized pages, per-page live checks, no raw evidence/key output or Service Worker/private asset-cache path. |
| R04–R05 | Sections2–3: all filters/sorts/reset/partial states, bounded coherent scan including the actual coverage/fence observation, explicit refresh, purge, held/reversed-response and fixed-records-head coverage-transition rejection. |
| R06–R07 | Sections2/4: four static accessible assets, canonical complete links, safe output and existing disclosure tiers, no public dynamic oracle. |
| R08 | Section5: different immutable recipient and independent configuration, installed shared/selfhost journeys and cross-project negatives. |
| R09–R10 | Section6: every MUST/complete section16 mapping, actual owning entrypoints and current executed joined evidence, failure sensitivity and no skip-as-pass. |
| R11 | Section7: all encrypted production/warm/cold/export/team/object/platform measurements, independent CPU/wall/resource dimensions. |
| R12 | Section8: one completed dimensional arbitrary-count model, every workload/resource term, current primary limits, honest unknowns and tested envelope. |
| R13 | Section9: actual complete reach/all-token containment/rotation and exact-copy/separate healthy activation with current normal-reader outcomes. |
| R14–R15 | Sections5–9: authentic release/execution identity, current evidence/guidance and exact owned cleanup; histories, unrelated work and spent budgets preserved. |
| R16 | Sections1/10: once-only foundations, finite engineering, coherent detailed slices and separate source-based production/test/combined totals. |

The selected structure preserves the settled architecture and adds only owned
UI, measurements/model and joined verification. No new material owner decision
is proposed. This draft still requires its actual HLD review; detailed planning,
implementation, provider/resource feasibility and all production gates remain
unproven. Design review does not authorize implementation or live execution.
