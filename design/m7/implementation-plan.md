---
plan_key: m7
slice_convention: hierarchical-v1
slice_inventory: {"executable": false, "path": "slices.json", "sha256": "d4c11f0c07955ad07286e3a57f8ca9681dc9bbd428e9347e7e9cc2f44fd463fb"}
---

# M7 — Product surfaces and evidence-based release acceptance

## 1. Current scope, prerequisites and completion

Implement the complete [requirements](requirements.md) under the settled
[architecture](high-level-design.md). One M5 portal serves the authorized minimal
index; four static badges and complete project links use existing routing. A
second independently configured recipient works through M6 installation and
normal Connect. Complete every-MUST and product §16 joined acceptance, actual A2
encrypted-path measurement, the one A3 resource model and A6 containment/recovery.
Design review is not implementation, live authorization or product acceptance.

The sole ordered inventory, paths, dependencies, completion checks and per-slice
ranges are [slices.json](slices.json). No duplicate embedded inventory exists.
The [engineering and estimate basis](supporting/implementation-plan/engineering-basis.md)
explains source analogs, component budgets, current provider evidence and
uncertainty. The [complete clause/scenario catalogue](supporting/implementation-plan/acceptance-catalogue.md)
retains each normative MUST token and §16 demonstration/scenario with its owning
assertion family. These are specifications for future evidence, never passes.

M4/M5/M6 are **reviewed planned prerequisites**, not existing runtime. M4/1 owns
Worker/HTTP/SQLite harness, /2 typed transport credentials, /3 coverage, /15 writer,
/12 protected control, /13 all-token barrier, /14 enforcement/resource driver.
M5/2 owns the one app/build/browser harness, /9 private proof/pages, /17 portal
live/resource driver. M6 owns released installer/controller/profile/bootstrap,
exact-copy/healthy activation and /17 assembled plus /18 live/adopter/cleanup.
Each M7 slice begins only with its named owning behavior actually available and
validated. Reuse their engines/clients/fixtures, counting only M7 extensions and
joined outcomes. Complete M1/M3 IDs, formats, source and old evidence stay intact.

No new backend, read authority, database, proof, crypto, snapshot store, queue,
telemetry service, scheduler or approval/evidence engine is introduced. If a
required prerequisite is absent at delivery, retain a blocker in its actual
owner; do not implement an imitation inside a test. New material scope/trust/API
changes return to the owner. Ordinary details below are engineering choices.

## 2. Existing private endpoints: closed row and provenance codecs

Use unchanged M5 routes, proof header/scope, current session and canonical reader
union. The service separately authorizes **every** index page and named-status
request, including current live records-App membership for the bound continuous
source. Repository permission alone grants no private read. Denial remains the
uniform private404; unavailable evidence503. Use private,no-store responses.

Wrap the existing safe index result in canonical UTF-8 JSON:

```text
{v:1,project_id,source:{events_oid,derived_oid,coverage_oid,
 reader_generation,index_generation,profile_sha256},observed_at,shard,rows}
```

All objects are closed and duplicate-free. IDs/times/Unicode use existing native
and M5 codecs. OIDs reuse the native full-Git-OID codec: exactly40 or64 lowercase hex; generation IDs use native canonical
32-byte base64url encoding; profile_sha256 is `sha256:` plus64 lowercase hex over
unchanged native release-profile canonical bytes. observed_at is service UTC
whole-second RFC3339, outside the equality tuple. project_id must equal routed
project; shard is an integer0..31. Reject unsafe integers, wrong shard
`github_user_id % 32`, duplicate user/agreement rows, unknown/invalid fields,
noncanonical/oversized/truncated input; reuse M5 bounded parsing, not another
permissive JSON path. Empty rows is a valid page, not proof of the whole scan.

Rows contain only `{github_user_id,login_snapshot,login_as_of,agreement_id,
version,enforcement_scope,status,accepted_at,revoked_at}`. Nullable snapshots,
versions/dates follow native absent-fact rules. `enforcement_scope` is the native
ordered set of repository/organization selectors with stable numeric identity
and snapshots. Status is exactly current/revoked/superseded/indeterminate/exempt.
Use the validated initial-release one-agreement presentation; include exemption-
only subjects even without acceptance facts. With no configured agreement show
the explicit no-agreement state through existing M5 presentation, not a fabricated
agreement ID or a misleading complete-empty index. No legal name/email/basis/
private event/confirmation/key enters the index. Existing exact-status result
gets `{v:1,project_id,source,observed_at,result}` using the same source codec;
its exact existing proof supplies subject, never a new caller query selector.

Resolve native `source.enc.json`, active agreements, inflight and decision fence
at **one immutable authenticated coverage commit C**. Bind its source to selected
canonical events E; validate selected derived D/class/shard/envelope/profile and
actual reader generation. Every row in a page uses that same C. Reuse M5's
native partial-read parity adapter and M3 status semantics. Coverage fences may
change C while E/D stay fixed; those changes must change the wrapper. No per-row
GitHub lookup, browser-supplied ref or alternate stale read is allowed.

There is no compatibility branch for bare old responses: these not-yet-shipped
M5/M7 interfaces release as one M6-built client/server unit. A release mismatch
fails closed. Existing native v1/S2 histories and private proofs are unchanged.

## 3. Bounded scan, coherent commit and browser lifetime

Freeze browser constants in the same released client and service tests. They
are not new fields in closed M1/M4 profiles and have no user runtime override:

| Budget | Bound and enforcement |
|---|---|
| Pages/concurrency | Exactly32 fixed shards, at most2 requests in flight; no pagination cursor or arbitrary server selection. |
| Response/proof | At most1MiB UTF-8 bytes per page,4096 bytes source wrapper,8192 bytes proof; stream-count before parse/retain. Stricter owning runtime limits win. |
| Rows/data | At most2048 rows/page,65536 total,32MiB total received/retained serialized UTF-8 private data; enforce before append, never truncate. |
| Presentation |100 DOM rows, bounded fixed row fields; maximum fixture heap-growth target256MiB on the named supported release browser, measured rather than falsely equated to byte accounting. |
| Scan/restarts |120s total,10s per request, at most3 passes/96 page requests/3 proof issuances, including failed/restarted work. No retry loop resets total budget. |
| Proof lifetime | Existing server TTL/authorization always wins; conservative local monotonic cleanup deadline at most300s from request start and no longer than returned exp-iat. Late issuance cannot extend it. |

Native32 index shards each have65536-byte ciphertext bounds (including AEAD tag;
envelope/base64 overhead separate); reader shard262144, state32768 and other
native limits remain unchanged. Row/byte limits are defensive above the native
initial single-agreement minimum row size, not a new cap on canonical history.
Test the combined maximum actual native/profile dataset; individual maxima are
not a promise every cross-product fits. Larger untested combinations are explicit
unavailability/unsupported profile, never silently shortened history or raised
provider allowance. Client heap bound is tested in named release browser;
unsupported telemetry/browser cannot claim the maximum profile passed.

A scan captures project, local login-cycle identity, proof, view epoch and scan
ID. First accepted **service-authenticated** page fixes complete source tuple
E/D/C/reader/index/profile. A JWT decode is never provenance or authority; optional
TTL parsing can only shorten local retention. Match every page and any combined
exact status against the tuple. On mismatch invalidate/drop all private rows,
renew through existing union selection and restart inside the original budget.
At exhaustion show unavailable and no private results. Other errors/denials
stop immediately with safe retry guidance. Partial counts are explicitly partial;
only32 unique verified shards make complete. No complete-empty result from a
failed scan. Safe source/as-of diagnostics do not contain row/search values.

Invalidate epoch **before** logout, project/login-cycle/session change, observed
denial, invalid source/generation, hidden/unloaded page, controllerchange and
replacement Refresh. Clear rows/proof/status/private filters and cancel requests.
Each callback checks captured epoch/context before headers/body and again before
state/DOM/count commit; timers follow the same rule. Abort is only optimization.
Explicit Refresh replaces, never merges; no background polling. Visible return
requires fresh authorized reads. Other-tab revocation is observed by actual
server authorization on the next read; no global instantaneous erasure promise.
Use same-origin credentials, cache:no-store, redirect:error and proof header;
no private URL query, console, analytics or persistent store.

Before private initialization require no controlling Service Worker, no origin
registration able to intercept private paths and no retained Cache Storage
entries at this privileged dedicated origin. Inspection failure blocks. The app
never registers a worker/caches private data. An unexpected registration or cache
requires operator origin cleanup and a **fresh uncontrolled page**, not automatic
unregister-success/replay or deletion of unrelated data. controllerchange uses
the same epoch purge. Existing CSP/output/origin controls remain in force.
No offline compatibility path, new worker, or cross-tab auth protocol is needed.

## 4. Filters, sorting, accessible output and badges

Operate on safely loaded allowed row values only. OR within a selected field;
AND across fields. Empty selection is unrestricted. User input is at most512
UTF-8 bytes: canonical positive integer matches ID exactly, otherwise trimmed
case-insensitive login-snapshot substring. A missing snapshot cannot match text.
Agreement/version values are opaque strings, not semantic versions. Scope filter
matches actual loaded native selector kind/numeric ID; snapshots label it. An
organization selector stays organization-wide, not a falsely enumerated repository
list. No membership/identity request is added to expand scope for presentation.
The selected project is fixed by route. Existing exact repository selectors match
numeric repository identity; names never grant authority.

Date inputs are strict valid Gregorian YYYY-MM-DD, UTC inclusive From/Through
using canonical timestamp day comparison, with no local DST or year9999 next-day
arithmetic. Null dates fail only an active bound. Invalid/inverted inputs show
local validation and hide result/count claims until corrected/reset. Status has
five exact options; Individual coverage is all/has-current-Individual/no-current-
Individual, with only current acceptance qualifying. Exempt stays a distinct
state and does not become a signed Individual. Entity is not enabled.

Default acceptance timestamp descending/null last; ties by numeric user ID,
agreement ID/version. Every sortable column uses ordinal ECMAScript string
comparison (no locale-dependent ordering), numeric IDs and UTC timestamps,
null last in either direction, then the same stable ties. Scope compares its
native canonical ordered selector representation. Filter/sort resets local page1;
Reset also clears filters/sort to defaults, never project/auth/data. Keep all
search input volatile. Reuse safe text/URL primitives; no innerHTML or raw SVG
interpolation. Keyboard labels, focus/error/result announcements and100-row
next/previous controls are actual browser acceptance.

Four constant SVG assets have text/alt states, no scripts/external fetch/identity.
Use existing M5 link builder and M6 static asset manifest, configured origin and
owner-qualified route, complete numeric repository/PR context for PR links. Check
actual routing has zero dynamic invocation per badge; static hosting bandwidth
is still modeled. Retain M4 single comment and M5 exact disclosure tiers.

## 5. Every-MUST, joined scenarios and finite evidence composition

The support catalogue enumerates normative MUST tokens in product sections1–19,
with requirement/paragraph/token ordinal and full paragraph SHA256, and each of
11 §16 demonstrations plus29 required scenario bullets. Revision history is
historical, §2 keyword definition is not a behavioral pass, §9 Entity obligations
are explicitly conditional under existing §17; none is silently removed. Parent
M7 R01–R16 and all HLD prose are assigned below and in the scenario catalogue.

At delivery m7/9 writes the finite test-only manifest using these source anchors
and concrete named assertion selectors. A clause may reference several actual
assertions. Every named MUST token must be accounted for; several tokens may
share an assertion only when its observable covers all of them. Ordinary
integration tests invoke actual services; the checker does not infer behavior
from requirement text. The planning catalogue supplies required assertions, not
finished test results. A builder must realize each clause's full observable,
including negative branches, before marking it evidenced.

Each execution record contains requirement/scenario ID, exact command/test ID,
layer, actual result, start/end UTC, source revision/content identities, release/
publisher/wheel/dependencies/assets/profile/config hashes, actual protected
repository/workflow/job identities when relevant, and safe artifact references.
Reuse standard unittest/Vitest/Playwright/native-conformance/owning-driver output,
not a new general result protocol. Manual observations require actual observer,
time, source/release, procedure, observed expected outcome and artifact references;
a prefilled boolean or screenshot alone is insufficient. Use bounded result
parsers (8MiB/file,1024 evidence files,32MiB manifest), reject duplicate IDs,
unknown result tokens, source drift and truncation. No arbitrary executable
command/path from a repository matrix is launched by parsing it.

Statuses are passed/failed/skipped/unavailable/unrun; only actual current passed
assertions satisfy an applicable MUST. Missing/stale/failed/unrun/unavailable/live
skip blocks final acceptance. Preserve original M1–M3 matrix/history and compose
current native results rather than relabeling old PASS as new execution. No new
exception/approval authority, truth store or workflow engine. Documentation of
limits is a representation fix, not proof a missing behavior passed.

| M7 parent | Owning outcome and checks |
|---|---|
| R01–R03 | m7/1–2 actual authorized safe pages, native status/source parity and app navigation; m7/7 joined reader/encryption cases. |
| R04–R05 | m7/2–4 all filters/loading/bounds/epochs/persistence; held/reversed response and coverage-only fence transitions. |
| R06–R07 | m7/3–5 accessibility, safe output/static route/full links, malicious/disclosure assertions. |
| R08 | m7/6 independent immutable recipients/roles/shared+selfhost and cross-tenant negatives. |
| R09–R10 | m7/7–9 complete clause and §16 legal/queue/routing/current execution composition. |
| R11 | m7/10–11 actual encrypted/max/warm/cold/provider and Actions resources, not historical plaintext. |
| R12 | m7/12–13 one full-dimensional model, all current provider/profile/unknown/billing constraints. |
| R13 | m7/14 complete reach/all-token/cutoff/rotation/raw-copy/healthy activation and normal-reader outcome. |
| R14 | m7/6,15 authentic installation/release/deployment/protected identity and upgrades/rollback. |
| R15 | m7/5–6,9–15 shipped current guidance, safe diagnostics, exact owned cleanup/history preservation. |
| R16 | Entire ordered inventory and component basis: full parent scope, actual prerequisites, complete test work and separate incremental LOC. |

## 6. A2 actual measurement and safe provider capture

Use existing M4/14 `api/bench/enforcement.mjs`/live driver, M5/17 portal/resources
and M6/18 installed/deployment/cleanup ports. Add case orchestration, safe counters
and metric extraction, not duplicated provider clients, crypto or Tail service.
Counters distinguish outer requests from nested resources, carrying an inclusion
flag so parent/child are counted once. Extend immutable in-process observation
objects, no private log/event database. Fixture seed/shape/artifact hashes and
actual encrypted production handler/profile bind each case. No fake provider
can satisfy a hosted claim.

Required cases are ordinary check, each queue entry/rebuild/fallback; mutation
sign/revoke/admin/Connect/rotation/bulk32; max continuous exemption32/reader10
rules and512 members under unchanged native profile; proof, each private page,
full32-page scan/coherence restart and exact status; hosted export and installed
portable streaming; route/gate read/reserve/confirm/transition/rebuild/lost-object;
actual schedules/dispatch/retries/repair/export/recovery protected jobs. Cover
normal/max/missing/corrupt/unavailable sources and removed-check sensitivities.
M4/M5 own actual partial-materialization work and team adapter. An unavailable
real max team/account means that required live case is unrun, never simulated PASS.

For each case record CPU-ms separately from wall/startup/I/O, request and internal/
external subrequest counts, bytes/pages, object requests/SQL rows-read/scanned/
written/deleted/index overhead, allocated storage/duration, KV read/write/delete/
list/storage, telemetry/logging usage and actual Actions runner/job duration/
storage/owner. Use ≥100 warm samples and ≥5 **provider-confirmed** cold or actual
reconstructed-object samples per supported case/profile, bounded by a planned
case deadline10min and entire authorized run2h/20,000 outer requests. Deployment/
cold preparation uses existing M6 driver and separate live authorization. If
budgets cannot cover all cases, record incomplete evidence and retain gate;
never silently lower fixture or claim client-cache clearing proves cold.

Use Workers Logs/current provider analytics with exact test-version/time/case
selection, current schema units, sampling/resolution and observed errors. Normalize
only declared units (e.g. provider cpuTimeMs is ms); unknown GraphQL units/schema
must be inspected before conversion, not guessed. Quantiles are not maxima or
unobserved cold proof. Reconcile sample coverage and billable invocation counts.
No additional Tail Worker. Configure/query-redaction and readback through actual
supported provider settings before traffic; verify no query/proof/private body/
headers are captured. Store only allowlisted safe aggregate values/source IDs,
not raw provider invocation payloads. Capture failure retains the gate.

Local measurements are labeled local, lower-bound only for provider CPU/cold/
quota. Actual CPU/subrequest/browser/profile violations block that supported
profile. Preserve historical plaintext benchmark values as dated history and
remove unsupported current-envelope conclusions without calling that a truth fix.

## 7. A3 one dimensional arbitrary-project resource model

Extend `core/capacity.py` directly with strict finite nonnegative Decimal values,
integer counts (bool rejected), explicit units and per-value measured/assumed/
unknown source. Inputs are project groups, account/billing owners, operation
frequencies, inclusive resource vectors, provider/profile snapshot and actual
other-account consumption. Unknown is not0. No second scalar legacy answer.
Only additive flow resources use `F_j = account_root_overhead_j +
sum(project_operation_frequency * flow_vector_j)`. Invocation/peak maxima,
object-active interval union, retained stock/time integrals and per-owner billing
use their distinct §7.1 equations and reject incompatible aggregation classes.

Vectors record whether nested child resources are already included. Root events
include **all** PR deliveries, merge-group entries/rebuilds, check_run across Apps,
all push refs including ignored events, extra fallback invocations, sign/revoke/
admin/Connect/lifecycle/team, proof/page/full32scan/refresh/reproof/exports. A full
scan charges actual32 pages plus proof and explicit restarts up to3 passes, not
old3requests/view. Static badge dynamic requests0 only with verified actual asset
route. Include both daily maintenance roles, route/gate calls and all transitions/
rebuild/publication, session/proof KV, logs and actual GitHub API buckets.

Maintenance roots remain the two owning M4 scheduled roles. Calibrate their real
planner/driver's **inclusive child invocations** at each N=0..256. For each role use
`root + ceil(N * child_invocations_per_project_upper)` with coefficient at least
max observed `(inclusive_children/N)`. Do not count parent-included children again
or create another fanout/scheduler. Outside the256 registry profile compute
mathematics but mark deployment unsupported/unverified. N0 still charges actual
fixed roots. Different project repositories/traffic/teams use different vectors.

Keep Internet Worker requests, internal service invocations and DO requests
separate. Current Workers Standard pricing charges one root request and summed
caller/callee CPU for service bindings; Free daily-quota treatment must be
confirmed by actual current account/docs evidence before verified Free envelope.
Until then show unknown and a conservative charge-one-per-invocation sensitivity,
not an assumed free hop. DO CPU/duration/SQL limits remain separate regardless.
Duration is union of active intervals per object (allocated128MiB), not sum of
overlapping calls; a conservative sum upper bound may be labeled explicitly.
Count scanned SQL rows/index writes/deletes and every actual object/row/storage.
KV/session churn and logs/configured sampling/retention are explicit resources.

Check per-invocation CPU, released49calls (and stricter role limits), outgoing
connections, body/profile/browser/memory independently of aggregate quota.
Track Free daily and paid monthly included usage/overage separately, actual month
length28..31 and configured spending caps; paid included capacity is not a daily
hard limit. Shared Worker/DO/KV/log pools include other account traffic. GitHub
REST/GraphQL/user/installation/GITHUB_TOKEN buckets retain per-hour/secondary/
peak concurrency checks; daily average alone proves nothing. Actions belongs
to each repository owner and actual protected job schedules/dispatch/retries/
repair/export/recovery: sum ceil(job_duration_minutes)*actual_runner_rate, with
shared monthly owner allowance/other usage and hourly artifact/cache storage.
Do not infer every signing invokes a reconciler push or charge a nonexistent
plaintext export artifact.

Outputs include per-resource value/unit/limit/billing owner/provenance, costs,
normal and each named sensitivity, bound violations and limiting resources/ties.
Saturation for arbitrary heterogeneous groups uses only monotonic constraints
with actual root overhead, reporting unbounded/unknown/unsupported separately.
An operating envelope accepted by the existing release verifier requires every
necessary measured vector/provider/profile/peak/other-usage constraint supported.
The calculator itself reports forecasts/unknowns/unsupported; its input assertions
cannot establish acceptance, as §7.4 enforces.
No guessed CPU, missing KV/log/Actions term or untested profile becomes capacity.

### 7.1 Concrete measurement/model interface and aggregation

Use one bounded local measurement bundle from existing drivers and the one
calculator, not a records format, service API, execution plan or evidence store.
Duplicate/unknown fields reject. Fixed-unit resource IDs below form one finite
registry in `core/capacity.py`; an entry with the wrong aggregation class/unit
rejects. Numeric values are finite nonnegative decimal strings (24 significant,
12 fractional digits maximum), integer counts reject bool, null means unknown,
and observed0 is explicit. No arbitrary URL fetch, callback or command execution.
Bounds:8MiB measurement file/4096 cases,128 resources/case,4096 interval or stock
observations/case,128-byte IDs,1024-byte safe relative evidence references;
1MiB each workload/provider file and4096 project/operation/job entries,256 account
entries. These are parsing limits, not a project-count limit: group `count` is
an arbitrary nonnegative integer, so homogeneous mathematical N is unbounded.
The actual released256-project registry remains a separate deployment limit.

```text
MeasurementBundle = {measurement_version:1,bindings,cases}
bindings = {source_oid,source_manifest_sha256,release_sha256,assets_sha256,
 release_profile_sha256,runtime_profile_sha256,workflow_sha256}
case = {case_id,operation,condition,fixture_sha256,environment,sample_count,
 result,counter_mode,included_children,flows,maxima,activity,stocks,evidence}
condition = warm | cold | reconstructed | error
environment = local | provider; result = passed | failed | unavailable | unrun
counter_mode = root_inclusive
flows/maxima = {resource_id:{value:decimal_string|null,quality,unit}}
quality = measured | assumed | unknown
activity = {quality,intervals:[{object_id,start_seconds,end_seconds,
 allocated_bytes}],duration_upper_bound_gib_seconds:decimal_string|null}
stocks = [{resource_id,owner,object_id,quality,
 observations:[{at_seconds,bytes}]}]
```

Flows include Worker Internet requests, service invocations, DO requests, KV
read/write/delete/list, SQL rows read/written (including index/deletion work),
GitHub REST calls/GraphQL points and log events in count, worker_cpu_ms in ms and
log_ingested_bytes in bytes. Maxima separately contain cpu_ms, external/internal
subrequests, connections, response_bytes and memory_bytes in ms/count/bytes as
named. Stocks contain do_sql_bytes,kv_bytes,log_retained_bytes,artifact_bytes and
cache_bytes, **never per-request additive counters**. Activity is per-object
allocated bytes over seconds;1GiB=2^30bytes. Applicable missing entries remain
unknown; null requires unknown, nonnull requires measured or assumed. All cases share the exact release/profile bindings; selected cases within each
condition mixture additionally share operation, fixture and environment.
Source OID uses native40-or64 full-OID codec. Evidence references are safe files,
not executable input. Local timings cannot become provider-measured CPU/cold data.

Vectors are conservative per-root sample bounds (maximum complete-sample flow
and maximum invocation values), not the sum of100 benchmark samples. Keep actual
sample/metric coverage, warm/cold evidence and resolution; tested bounds are not
universal proof. Provider schema units are converted explicitly before use;
unknown units remain unknown. For each root all nested resource counts are already
included; `included_children` lists operation labels covered by that root, not
additional occurrences. Workload root occurrence categories are unique. A child
occurrence cannot be charged again if included in its parent; separately observed
extra fallback/manual/maintenance roots need a distinct nonincluded occurrence.
Case-type/occurrence/inclusion conflicts reject release-evidence selection;
raw-file calculations never authenticate these input assertions.

Use the following **different equations**, never a universal vector formula:

- Additive flows only: `F_j = account_roots_j + Σ(count * roots_per_day *
  condition_fraction * per_root_flow_j)`. Interval and billable owner are explicit.
- Invocation maxima: `M_j = max(all relevant measured invocation maxima_j)`;
  check against each actual role/profile. Peak/concurrent/hour windows use
  explicit arrival/burst bounds, not daily averages; missing bounds are unknown.
- DO duration: group by object, merge overlapping active intervals, then integrate
  allocatedGiB over their union. Distinct object durations add. A forecast that
  has only per-root duration upper bounds may sum them as a **labeled conservative
  bound**, never claim it equals billed duration or proves peak concurrency.
- Retained stocks: `S_j(t)=baseline_j + cumulative allocations_j(t) - proven
  releases_j(t)`; no inferred deletion/expiry. Check max S against storage cap;
  bill storage via the stepwise time integral `Σ(bytes * retained_hours)` using
  actual owner/retention/rounding. Idle retained storage still costs/counts.
- Actions compute: per actual job or measured conservative job-kind duration,
  `runs * ceil(duration_seconds/60) * runner_rate`; group by repository owner,
  subtract only that owner's remaining monthly included allowance once, then
  add separately integrated artifact/cache storage. Never net owners together.

```text
Workload = {workload_version:1,days,projects,accounts,operations,jobs,storage}
project = {project_id,count,service_account,actions_owner,repository_count}
account = {account_id,other_usage,peak_bounds}
operation = {occurrence_id,project_id|null,account_id,operation_id,roots_per_day,
             condition_mix:[{condition,fraction}],
             condition_cases:{warm:case_id?,cold:case_id?,
                              reconstructed:case_id?,error:case_id?}}
job = {actions_owner,kind,runner_sku,runs_per_month,duration_seconds,
       artifact_byte_hours,cache_byte_hours}
storage = [{account_id,resource,baseline_bytes,new_bytes_per_day,
            retained_days,proven_releases}]
Provider = {provider_version:1,checked_at,effective_from,effective_until,
 sources,account_plans,limits,prices,service_binding_free_factor}
```

Condition fractions sum exactly1; roots_per_day is per represented project when
project_id is nonnull and an account root when null. Every constrained shared
resource needs actual `other_usage` or explicit unknown. Provider limits key the
finite resource, owner plan, aggregation class and invocation/peak/hour/day/month/
storage interval; prices fix unit/rate/allowance and effective date. The Free
binding factor stays null until proved, with separate conservative1 sensitivity.
Unknown/failed/missing case, wrong unit/class, duplicate/included occurrence,
foreign billing owner or mismatched source/release/profile cannot satisfy
release acceptance; the calculator itself does not issue a tested verdict. Forecast preserves assumptions/unknowns. Storage retention or release
is an input with evidence, never an automatic cleanup promise.

The direct API is `model(workload: Workload, measurements: MeasurementBundle,
provider: ProviderProfile) -> CapacityReport`. Strict parsers build immutable
validated dataclasses first. Keep `main()` as the one CLI: no arguments runs the
bundled **assumed** scenario with unknowns, not the old unsupported answer.
Explicit use is `python core/capacity.py --workload WORKLOAD.json --measurements
MEASUREMENTS.json --provider PROVIDER.json --format json` (or text). Exit0 is a
valid calculation even when envelope unknown,2 invalid/incompatible input,1
internal failure. The closed report is `{capacity_version:1,bindings,assumptions,
resources,constraints,envelope,costs}`; resources carry value/unit/owner/provenance,
constraints satisfied|violated|unknown and envelope forecast|unknown|unsupported with limiting IDs. Analysis output grants no release approval.

Producer→consumer tests calculate one scan=one proof+32page observations, inclusive
Worker/service/DO vectors with no duplicate children, N0 roots, mixed project
multipliers and conditions, unknown Free factor, overlapping same/different-object
intervals, idle retained storage/time integrals, peak overload at low daily totals
and actual mixed-owner per-job rounding. Reject schema/unit/class/binding drift,
nonfinite decimals, duplicate occurrences, missing costly resources and local CPU
mislabeled provider measurement. Reconcile normalized counters with actual owning
driver capture before the existing release verifier may accept an operating
envelope; a calculator forecast does not supply that evidence.

### 7.2 Closed nested workload and provider values

Every object below is exact: required keys only, no implicit defaults. Scalars
use §7.1 bounds. `id` is ASCII `[A-Za-z0-9_.:/-]{1,128}`; references must resolve
uniquely. Decimal is the nonnegative finite §7.1 string; UTC timestamps are
whole-second canonical RFC3339. `resource` and `unit` are members of the finite
§7.1 registry, with a fixed aggregation class flow|maximum|activity|stock|billing.
Array order is canonical by the stated identity tuple, duplicates reject; these
are local model inputs, not executable instructions or new runtime authority.

```text
Datum = {value:Decimal|null,quality:measured|assumed|unknown,source_ids:[id]}
Window = {kind:invocation|peak|hour|day|month|storage,
          start_utc:UTC|null,end_utc:UTC|null,seconds:Decimal|null}
OtherUsage = {resource,aggregation,unit,window:Window,datum:Datum}
PeakBound = {resource,aggregation:maximum,unit,window:Window,datum:Datum}
Release = {at_utc:UTC,bytes:Decimal,source_ids:[id]}
Source = {id,kind:provider_document,url:HTTPS,content_path:RelativePath,
          sha256:sha256,checked_at:UTC,
          effective_from:UTC,effective_until:UTC|null}
       | {id,kind:observation,evidence_path:RelativePath,sha256:sha256,
          observed_at:UTC,bindings_sha256:sha256}
AccountPlan = {id,account_id,provider:cloudflare|github,plan_name:id,
               resources:[resource],billing_window:Window,base_fee_usd:Datum,source_ids:[id]}
Limit = {plan_id:id,resource,aggregation,unit,window:Window,datum:Datum}
Price = {plan_id:id,resource,runner_sku:id|null,aggregation:billing,
         unit,currency:USD,rate:Datum,allowance:Datum,
         allowance_unit:unit|USD,window:Window,
         rounding:{mode:none|ceil,quantum:Decimal}}
```

`account.other_usage` is `[OtherUsage]`, `account.peak_bounds` is `[PeakBound]`,
`storage.proven_releases` is `[Release]`. Provider.sources is `[Source]`,
account_plans `[AccountPlan]`, limits `[Limit]`, prices `[Price]`.
Each array is bounded4096 entries except source_ids≤32 and sources≤256.
The other arrays inherit the ≤128-resource bound per owner/interval. Identifying
keys are respectively(resource,class,window), (resource,window), at_utc,
id, id, (plan_id,resource,class,window), and(plan_id,resource,runner_sku,window).
Provider_document URLs are bounded2048-byte credential-free HTTPS documentary references,
never fetched/executed. SHA256 uses existing64hex codec; checked/effective dates
are not assumed current merely because parsing succeeds. Account/resource/price
owners must resolve to one declared account plan and source evidence.

Datum null iff quality unknown. A measured datum requires at least one exact
source/evidence ID; assumed has explicit sources or remains labeled assumption.
Unknown cannot become0. Workload/operator evidence for OtherUsage/PeakBound/Release uses the observation
variant: an existing bounded redacted artifact under the selected safe evidence
root, a canonical relative path with no traversal/symlink and exact SHA256,
observed time and matching binding digest. It needs no upload or public URL.
Document references never cause a fetch; artifact hashes use existing safe file
reads, never an executable command or a new truth/approval store. A Release
can reduce retained stock only when its referenced actual evidence proves bytes
were released at that time; a planned TTL or cleanup instruction is insufficient.
Otherwise retain the stock and mark its later size/cost unknown. Reject a release
before the baseline or a cumulative release exceeding proved allocation; no
negative storage. Stock input baselines/new allocations and releases share unit,
owner and window; a bytes value never subtracts a byte-hours integral.

Window invocation has null start/end/seconds. Peak has positive seconds and null
start/end (explicit arrival horizon); hour/day/month/storage require nonnull
start<end, seconds equal exact interval duration. Hour/day are3600/86400 seconds;
month is the explicit owner's actual billing interval28–31 days, matching days,
not an assumed30. Storage may be any positive explicitly observed bounded period.
Intervals from different owners or billing periods cannot be netted. A provider
limit's unit/class/window must match its fixed resource; missing relevant limit,
price, other usage or peak remains unknown, never an omitted constraint.
Overlapping conflicting provider_document effective intervals reject; selected
execution/billing interval must be covered by each referenced current primary
document. Observation time/bindings must match the actual selected evidence
window; a local observation is not a provider document/limit/pricing authority.

Price.rate is USD per its stated unit and is nonnegative. Allowance is in that
same usage unit or USD as explicitly tagged. A USD compute allowance is pooled
once per actual owner/month after per-runner job charges, never subtracted once
per SKU or per project. Resource allowance is pooled once per owner/resource/
period. mode none requires quantum1 and performs no rounding; ceil requires
positive quantum and rounds **at the documented billing item boundary**: each
Actions job before owner sum, storage by actual provider storage interval, never
only once on a monthly aggregate. `job-minutes` and `byte-hours` are the finite
billing units; all conversions use exact Decimal. Unknown rates/allowances keep
cost/envelope unknown. Missing runner SKU or conflicting overlapping prices
reject; no default Linux rate for a different actual runner.

AccountPlan.base_fee_usd is charged exactly once per provider/account billing
window before metered overage; Free is explicit observed0, not absence. One
account has one selected plan per provider/window, with resource-specific meters
under it; reject duplicate base charges/overlapping plan windows. Its resources
must equal the fixed required resource set for the actual selected supported plan
and deployment roles, never a caller-chosen subset that omits a costly term.
RelativePath is a canonical ≤1024-byte path under the measurement input file's
parent safe evidence directory (packaged sample root for no-argument fixtures),
without absolute paths, traversal, URL query or symlink. Read only bounded regular
one-link ≤8MiB redacted files with exact SHA256. No upload or URL fetch follows.
The existing provider profile parser maps supported provider plan names to these
finite resource/aggregation/window rules and rejects an unknown plan/resource
combination. This is data validation in the same calculator, not another adapter
service. Tests reject foreign plans/owners, missing costly resources/unknown
fields, unit/class mismatches, ambiguous or expired effective intervals, duplicated
allowance, unproved/over-large releases and wrong rounding boundaries.

### 7.3 Explicit condition-to-case mapping

The operation shape in §7.1 binds every condition directly, with these rules.

`operation_id` must equal each selected measurement case.operation. The keys of
condition_cases equal **exactly** the conditions in condition_mix, no missing,
extra or duplicate condition. Fractions are positive and sum exactly1; omit a
zero-weight condition. Each value selects exactly one existing unique case ID,
whose condition equals that key; no implicit lookup or first-match selection.
Cases must share exact bindings, fixture_sha256, profile, operation and environment;
Provider release-evidence selection cannot mix local and provider cases. Do not reuse one case
for several conditions. Different fixture scenarios require separate operation
categories/bundles, not a silently selected same-operation case. All selected
cases must pass and required quantities be known for actual release acceptance.
The calculator has no tested-mode input or output token.

Hand calculation: N=2 represented projects,10 roots/project/day, mix warm0.75/
cold0.25, explicit warm-case flow WorkerCPU2ms and cold-case8ms yields
`2*10*(0.75*2+0.25*8)=70ms/day`, with invocation max8ms checked separately.
Warm1 and cold3 external calls yield30calls/day and per-invocation max3, never
20calls from reusing warm. Tests also reject swapped conditions, missing cold,
foreign environment/fixture/bindings/profile, duplicate case/condition and an
extra unused mapping key. Exact counters and fees still follow their separate
aggregation rules; this example is not measured product capacity.

### 7.4 Provider evidence and the calculator's limited claim

The calculator computes forecasts; it cannot authenticate its own assumptions.
Its public result states are **forecast|unknown|unsupported**, never tested or
release-approved. `quality:measured` in a caller file is an input assertion, not
proof. Keep asserted quantities/provenance visible, including exact input hashes.
There is no CLI flag, JSON boolean, URL/hash/date record or caller-supplied
expected digest that grants a verified status. This correct label alone does
**not** close A3: the existing release verifier must enforce the checks below
before accepting the actual measured operating envelope.

Reuse the existing authentic release/publisher verification and M7 current-evidence
composition. Ship `core/dracla/data/capacity-provider-profile.json` plus the exact
public primary-source content files under `core/dracla/data/capacity-provider-sources/`
as data in the same M6-built artifact. Include them in its existing authenticated
artifact/module manifest and package data; no new signer, profile service, trust
store or records/runtime profile version. The profile is the exact canonical
Provider object in §7.1–7.2, including supported limit/price values and effective
windows. Primary-source entries additionally require `content_path:RelativePath`
inside that authenticated data directory. The producer records the exact fetched
primary bytes and source SHA256, checked date, effective interval, extracted values
and source IDs. These values receive the normal release review, not an automatic
natural-language parser or new approval authority.

The existing M6 verifier authenticates the published artifact against its existing
publisher policy/provenance and reads the profile/content files from that exact
artifact. The M7 acceptance coordinator then compares **every** selected limit,
price, plan, unit, allowance, rounding rule, source ID/effective window and source
content hash against that authenticated snapshot. Whole canonical Provider bytes
must match; a rehashed caller-edited value/source record is not equivalent. Read
bounded canonical regular files, no symlink/traversal; apply §7.1 size bounds and
≤8MiB/source content. Exact source content is needed for reproducibility, but its
hash alone does not authenticate its origin. The expected digest comes only from
the existing authenticated release artifact, never the input being checked.

Before final acceptance the existing provider/source driver verifies that the
selected primary values/windows still apply at the actual execution time, using
its fixed supported primary origins and retained current safe document/provider
observations. This is existing test-only evidence collection, not a network fetch
by the calculator or a new service. Missing, changed, forged, stale/expired or
inapplicable evidence keeps the gate closed. A genuinely changed provider value
requires a corrected reviewed release snapshot/candidate under existing authority;
it cannot be accepted by editing --provider, relabeling assumed as measured or
inventing an undocumented interpretation. Candidate publication precedes final
acceptance as §8 already requires; no circular requirement that final acceptance
must precede publication. No arbitrary additional freshness interval is invented.

CapacityReport.bindings is the measurement bindings plus
`provider_profile_sha256` over the exact canonical Provider bytes actually used.
The assembled release evidence additionally retains the authentic release/artifact
identity and expected provider-profile/source-content digests. The current verifier
requires that report digest and **all** workload/measurement/source/result hashes
match the actual current executed owning-driver evidence, not caller claims or a
prepared script. It checks complete required cases, exact tested release/profile,
real provider metrics/other account usage, independent constraints and actual
standard test/manual results under §5. A fake local observation file or a forged
CPU/sample count cannot authorize the operating envelope just because its hash
matches itself. Raw-file CLI runs remain forecasts even when their mathematical
values happen to equal the authenticated snapshot. The accepted operating envelope
is established by this existing actual release verification, not a calculator
output token or a new evidence/approval engine.

m7/13 owns fixed snapshot loading/binding/report digest and source-content/package
wiring; m7/15 owns the actual current release-verifier join; m7/11 supplies current
primary/provider observations through its existing driver. The producer can ship
before m7/13: it captures the closed §7 source/measurement records and does not
require the later snapshot consumer. The final verifier also checks the actual
executing `core/capacity.py` source against the authentic release source/content
manifest; authenticated provider data cannot authenticate an unrelated local
calculator. No duplicate calculator or entrypoint is packaged. Reuse M6 authentic
artifact verification and the existing §5 result composer. Tests change one limit,
price, effective interval, source body/hash or snapshot digest; remove its original
content; forge measured CPU/source metadata; substitute another release; expire a
source; and supply a fake expected digest/input approval flag. Each must fail
actual release acceptance or stay forecast/unknown, never establish a tested
operating envelope. Positive acceptance requires authentic snapshot equality and
actual current complete driver evidence. This is a design truth fix for the
release evidence gate plus a representation fix removing the calculator's
unsupported self-verification label; it defers no required A3/provider check.

## 8. Authentic release identity and final acceptance

Global architecture already requires exposed deployed release identity. Complete
that missing literal adapter in existing portal/enforce Worker: `GET /health`
returns at most16KiB canonical safe JSON `{health_version:1,service,release,
assets_sha256,profiles,runtime_build_id,worker_version_id}`. service is portal/enforce; release and
profiles are unchanged M6 verified deployment fields; runtime_build_id is the
immutable `sha256:<64hex>` of JCS of the authentic producer's build inputs
`{source_commit_oid,source_manifest_sha256,release,assets_sha256,profiles,
toolchain_sha256}`. This input digest is compiled before output module hashes
exist; the authenticated published build manifest separately records those exact
output module hashes. It has no self-referential hash cycle and is not a caller
deployment input.
Provider `worker_version_id` is the lowercase UUID from the actual nonsecret
`env.CF_VERSION_METADATA.id`; configure the documented version_metadata binding
in **both** existing Worker configurations. Missing/malformed metadata returns a
nonprivate unavailable health result and cannot pass identity acceptance. The
shared encoder is called by both `api/src/portal/index.ts` and
`api/src/enforce/index.ts`; use existing `dashboard/portal/build.mjs`, package and
`dashboard/portal/test` harness. No generic third Worker/build/test tree.

The existing M6 authorized verifier observes each fixed deployment's actual
Cloudflare account ID (32hex), exact script name from installed configuration,
current deployment ID, and complete version IDs/percentages using the documented
script deployments API; it reads each selected version's metadata/content/settings.
Final acceptance requires one **100% active** authentic version per script; a
split/gradual deployment remains pre-acceptance until complete, without changing
normal routing behavior or adding rollout machinery. Re-read the deployment
before/after health and reject movement. Health's Worker Version UUID must match
the exact100% provider version for that account/script/origin, never a human tag.
Provider script content etag is retained as an opaque provider change identity,
not assumed SHA256. The fixed existing M6 deployment driver captures exact outgoing
module names/bytes SHA256, compatibility settings/public bindings and asset-manifest
identity **before** the authenticated version upload; compare that payload with
the independently authenticated publisher build manifest before transmission.
Retain the actual authenticated upload response's immutable version UUID and
script etag. The final read-only verifier independently calls
`GET /accounts/{account}/workers/scripts/{script}/versions/{version}` and requires
its same UUID/etag plus exact settings/public bindings, then the100% current
deployment and health UUID described above. This chain ties published output bytes
to one immutable provider version; a caller-written build label, tag, receipt
boolean, unrelated script content or unvalidated upload result cannot supply it.
The original actual provider transaction evidence is required, not a reconstructed
receipt. It is consumed with current independent provider version/deployment
readback, never as upload-success alone. A rollback uses that old retained verified
transaction/version and authentic old publisher artifact, with fresh deployment/
health readback. Missing evidence remains unverified; no reliance on a nonexistent
per-version script-download API. Current script content/v2 can be a diagnostic,
not substituted for immutable selected-version binding. M6's existing actual
uploader/verifier port is extended in m7/15; no new provider client/trust authority.
Independent asset-manifest/content verification and actual protected numeric
repository/workflow/source proof remain required. These observations prove the
selected deployment within the accepted controller/provider trust model, not
honesty of an adversarial hosting operator.

No private/environment-secret reads, git/config lookup, caller selector, health
mutation or authorization grant. Only compiled public metadata and the provider's
nonsecret version binding are read. Same build manifest binds runtime and static
assets; no additional signing key, trust root or attestation service. See current
[version metadata](https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/),
[version API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/get/)
and [deployment API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list/).


A self-declared /health is **not independent proof**. Existing M6 release verifier,
authentic publisher/attestation/artifact digest, provider current script/version/
asset readback and actual protected job repository/workflow/source proof must
match. Missing provider capability is an unmet acceptance gate. It does not let
an untrusted controller authenticate itself; accepted shared operator trust is
unchanged. Actual upgrade/rollback verifies old/new release/artifact/profile/
assets/control identities, not merely tags or successful dispatch.

Authentic candidate publication/build proceeds under existing authority before
acceptance that requires a published artifact. Final release acceptance/announcement
then requires every applicable current clause/scenario and A2/A3/A6, both projects,
shared/selfhost/Free/private baseline and exposed actual identity. No new automatic
publish/merge/PR/live authority follows from the acceptance command. Unsupported
measurements/live skips keep it closed. Future cleanup uses only exact verified
run-owned resources, preserves old histories/keys/evidence and records residuals;
no broad sweep or rollback of another actor's/newer state.

## 9. Delivery readiness and estimates

All scopes are planned. Implement coherent verticals in canonical inventory order;
continue using full IDs in future commit titles. Do not implement this plan in
the design campaign. Native formats/profiles and already approved architecture
stay fixed. Product defects requiring changed contracts return to the owner,
with consumed budgets and original review history preserved.

LOC uses incremental final-delivered **nonblank physical lines excluding comment-
only**, docstrings/multiline statements physically. Runtime/config/packaging and
shipped instructions are production; test-only helpers/config/generators/assembled/
live drivers are tests. Exclude designs, fixture data/images/generated/dependencies/
locks/probes and add+remove churn. Shared engines/harnesses/clients are charged
only to M4/M5/M6 owners. See exact component budgets and uncertainties in support.

| Package | Production LOC | Test LOC |
|---|---:|---:|
| M4 | 7,330–11,950 | 11,650–18,430 |
| M5 | 9,570–15,200 | 15,810–25,340 |
| M6 | 10,210–16,100 | 19,930–31,800 |
| M7 | 3,950–6,510 | 13,750–22,100 |
| **M4–M7** | **31,060–49,760** | **61,140–97,670** |

These ranges include integration/platform/failure and live-driver work. They do
not include real execution expenditure, time or authorization. Clean design
review means a reviewed plan; actual product behavior and hosted acceptance
remain unproven until the required future work executes.
