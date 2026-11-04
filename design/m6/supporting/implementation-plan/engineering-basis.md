# M6 detailed-plan engineering and estimate basis

Supporting evidence for the [plan](../../implementation-plan.md). Slice definitions,
paths/dependencies/acceptance and canonical ranges live only in
[slices.json](../../slices.json). This file explains composition; it is not a
second inventory, approval record or progress ledger.

## Inspected foundations and actual gaps

Inspection used native Sapling head `ec45c63ad01c197330702bbaefb2c5935333e688`.
The [architecture reuse inventory](../high-level-design/engineering-basis.md#existing-primitives-and-real-gaps)
is the one canonical copy of measured existing physical source counts. Its
247-line administration, 585-line GitHub adapter, 221-line planner and actual
M3 history/append/reconcile anchors demonstrate reuse; these complete files are
not charged as new M6 delivery. Completed M1/M3 source is unchanged in this
design campaign. Current governing reviews/closure are separate operational
evidence; clean design is not runtime or production acceptance.

Load-bearing actual source observations:

- `provisioning.plan_install` remains pure and explicitly adds the unavailable-
  engine blocker for execution. `InstallationVerifier`/`VerifiedInstallation`
  exist but no real provenance/coordinator implementation is present.
- `github_admin.py` has scoped creation/rename/secret/dispatch categories;
  first Contents/root, actual job/proof observation, Actions deny/readback and
  fixed blob transfer still need M6 adapters.
- `history.open_history` reads the mandatory derived head, validates original
  bootstrap IDs against live binding and rejects unconnected replay. Normal
  post-rebind origin/current support therefore needs code, not a renamed input.
- `verify_project` already compares the complete coverage/private materialization
  and operation/fence/marker correspondence without a write. M6 reuses that check
  for healthy-source admission. It does not create a second health engine.
- `MutationEngine` already persists exact event/artifacts, accepted operation,
  fence/marker and readback sequence. `StoredPreconditions` intentionally refuses
  unavailable external facts; M6 provides a fixed admitted rebind provider, not
  a general historical fallback or second writer.
- Current event/envelope identity dispatch is schema 1. S2 needs explicit bounded
  event-only AAD/semantic dispatch, authorization/side-artifact/replay tables and
  shared producer vectors. Existing non-event identities and old events stay v1.
- Current `InstallationCredentials.close()` observes this process's tokens only.
  M4's planned all-token incident foundation is not implemented by that cleanup.
- M5 HLD §7 already defines the browser-authorized opaque installer handoff without
  sharing cookies/GitHub credentials. M6 should not invent device OAuth, loopback
  login, a new ticket store or a second setup service.

The reviewed [M4 plan](../../../m4/implementation-plan.md) owns common runtime,
HTTP/SQLite tests, routes/gates, typed clients, writer and incident engine.
The [M5 plan](../../../m5/implementation-plan.md) owns browser/setup/installed
proofs, first-derived-root/initial Python adapter, ordinary portal/lifecycle and
its browser harness. They remain future prerequisites. M6 counts their actual
extensions and installed integration, never assumes a future filename is code.

## Primary platform evidence and chosen direct paths

Checked public primary documentation on 4 November 2026; no authenticated account,
credential, deployment, workflow or live capacity probe ran for this design.

[GitHub backup](https://docs.github.com/en/repositories/archiving-a-github-repository/backing-up-a-repository)
and [mirror duplication](https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository)
are the operator Git transport. M6 adds exact bounded manifest/equality and
execution-isolation instructions, not another object-copy engine. Source
application health is independent of exact copying. Malformed/missing recorded
Git objects cannot become a claimed complete copy; missing application refs and
invalid application files are preserved, not synthesized.

[Repository Actions permissions](https://docs.github.com/en/rest/actions/permissions#set-github-actions-permissions-for-a-repository)
support administrator disable/readback. Imported control workflows can be push/
schedule/dispatch eligible, so policy denial must precede the first imported ref.
After-import policy cannot attest earlier safety. Inherited resources, existing
runs and inability to isolate current verified code are explicit blocking/live
acceptance cases, never a reason to erase historical refs.

[Git blobs](https://docs.github.com/en/rest/git/blobs) provide fixed self-control
content-addressed transport for the already-approved 1 MiB nonsecret manifest.
Create needs Contents-write; raw retrieval needs Contents-read. SHA256/schema/
size and current numeric repository, not blob existence, bind the input. There
is no indefinite retention claim or new authority store; exact BACKUP remains
an explicit retry input. This avoids new refs/eligible code, a larger Worker
body limit, truncated input or a separate job database.

[Workflow dispatch](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)
currently documents a run-ID response. Use and verify that when available;
lost/empty replies still need exact correlation readback, not another dispatch.
[Workflow inputs](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)
currently allow 25 top-level properties and 65,535 characters. Keep the short fixed
descriptor plus existing inputs below both platform and released M4 limits;
never send the full 1 MiB manifest through dispatch.

[Per-job logs](https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run)
are plain text from a short-lived authenticated redirect. Use only the exact
verified job/attempt, a private credential-free bounded download and M5's signed
proof parser. No whole-run archive parser, arbitrary job log selection, secret
URL logging or caller-controlled redirect is required.

The supported App registration baseline is manual GitHub create/select and
local PEM custody, already allowed by global §6.10.2. Unproved literal-loopback
registration acceptance is not a dependency. No hosted conversion or broader
runtime token compensates for missing consent/scope.

## Protocol and cost separation

Exact copy neither repairs imported operations nor fills missing derived state.
The old speculative snapshot-operation continuation adapter and its positive
recovery cases are removed. Keep direct preservation/zero-effect-denial cases,
and existing-engine retries only for the newly accepted activation.

A normal M5 initial context cannot wrap a claimed project's stored material;
ordinary installed proof expects normal current IDs. M6 must implement its fixed
recovery-only source/authority/context/service/control integration, including
actual normal reader/export call sites and wrapping all retained keys for a new
operator. Count that work explicitly. No additional anti-admin checkpoint or
cross-domain precedence is claimed beyond the approved trust boundary.

Existing control v2 routing fields stay closed. The profile digest goes in
invocation intent and the already intended final nonsecret installation
provenance, which is verified against actual source/proofs and is not independent
authority. Profile public proof keys cannot replace fixed code-publisher trust.
A direct profile change is not a silently authorized migration.

The detailed plan uses existing conditional registry/gates and actual Python
source validation. Source-possession authorization is not another edge replay.
Local source health must pass before service staging and is repeated by verified
control before canonical effects. Never authorize a rebind from a caller boolean,
unsigned receipt, archive possession alone or new-target names/administrator alone.

## Incremental production and test composition

Numbers below are estimates of new final-delivered responsibilities, not observed
future code, whole existing modules or added-plus-removed churn. Nonblank physical
lines exclude comment-only lines; docstrings/multiline statements count physically.
Shipped runtime configuration, packaging and instructions are production. Test
helpers/configuration/generators/integration/live drivers are tests. Design text,
static fixtures/data/images, generated files, locks, dependencies and disposable
probes are excluded. The canonical inventory and main plan contain the totals.

One shared path can receive ordered incremental additions from several slices;
attribute each final responsibility once. Earlier fixture/port foundations are
reused in later drivers. Existing M4/M5 code and tests are excluded from M6 ranges.
No universal slice cap, estimator service or time/productivity conversion is used.

| Slice | New production composition | New test composition | Inspected basis / boundary |
|---|---|---|---|
| m6/1 | Profile/identity/schema 240–380 + local preflight/CLI180–270 + shared budget counters80–140 | Fixture/port150–240 + parse/intent250–380 + denial/effect capture250–380 + shared limit boundaries150–250 | cli/config.py, release.py and provisioning.py; new local profile/parser/composition, not another HTTP or auth framework. |
| m6/2 | First-Contents/admin ports140–220 + role initialization230–350 + readback/instructions80–130 | Scoped HTTP260–400 + lost/raced prefixes300–500 + genesis/default240–350 | Existing GitHubAdmin private-create/rename and scoped RepositoryRef; missing first Contents and exact role initialization. |
| m6/3 | Released control/config/readback200–310 + source-before-secret/job observation150–240 | Provenance/source240–350 + Free/config/dispatch failures410–650 | Existing released workflow/verifier and administrator Actions/secret port; add actual run/attempt/job/text-log readback, not another executor. |
| m6/4 | Manual App/scope clients320–500 + custody/warnings180–300 | Grant/selection430–680 + key custody/permission420–670 | InstallationBinding and scoped tokens exist; real guided local registration/union verification and secret orchestration are missing. |
| m6/5 | Actual-key/service/control client420–640 + closed secure bundle/durable handoff350–560 | Crypto/context substitutions650–1030 + bundle/filesystem/no-leak650–1070 | Native M1 wrapping/HMAC and M5 contexts/three services/control signature are prerequisites; count M6 calls, equality checks and private human handoff only. |
| m6/6 | Initial-transport phase220–340 + K/B/guard publication340–530 + final provenance90–130 | Bootstrap/genesis520–850 + probe/lost-reply/publication630–1000 | M3 ordinary probe requires existing history; new fixed no-history phase and actual K/B/idle construction are genuine M6 work. Reuse existing envelope/operation codecs. |
| m6/7 | Actual provenance inspector/types310–500 + ordered execution/result handling290–460 | Concrete prefix/transition/race matrix800–1310 + actual CLI intent/execution400–640 | M2 supplies pure planner/InstallationVerifier seam but deliberately blocks execution; do not charge existing planner again or trust a local step ledger. |
| m6/8 | Link/result/packaging145–240 + shipped installed guidance155–260 | Actual joined pipeline450–720 + first-operation interruption300–480 | M5m5/12 owns first-derived root, bootstrap acquisition and real M3 recovery; M6 owns packaged installer-to-existing-service assembly. |
| m6/9 | Deployment assets/config validation650–1000 + operator instructions350–550 | Artifact/config620–1000 + two-deployment integration780–1200 | Bench wrangler.toml is not production. Reuse M4/M5 two Workers/static server/service bindings; add concrete same-release operator inputs and checks. |
| m6/10 | Rollover/upgrade adapters280–450 + compatibility/operator guidance220–350 | Interruption/downgrade550–900 + deployment readback300–500 | Existing routing key overlap and guarded transitions are foundations. New work installs compatible actual code/config in the right order. |
| m6/11 | Snapshot codecs/ref/object equality300–480 + isolated mirror procedure300–470 | Manifest/copy cases650–1050 + pre-import execution denial350–600 | Reuse documented Git mirror transport. App-broken content is copied, not replayed; no second Git-copy engine. Actual policy-before-push and equality adapters are counted. |
| m6/12 | Closed event/auth/replay420–650 + AAD/generation dispatch330–500 | Shared vector producer650–1000 + language/package negatives750–1200 | Current validators are schema 1. New S2 branch, seven rows, all-class generation and authenticated event schema selection are real extensions; existing crypto/replay retained. |
| m6/13 | Origin/current history340–540 + real service/export source integration160–260 | Epoch/transport750–1200 + normal post-effect operations350–550 | history._bootstrap/final binding presently require live IDs equal original IDs; extend that exact source seam and real consumers, not a detached alias helper. |
| m6/14 | Trusted source-health admission120–190 + own-new-rebind retry130–210 | Broken-state zero-effect350–600 + own frozen-operation matrix300–500 | verify_project already compares all actual projections/guards read-only. Reuse those comparisons; remove the old imported-operation continuation adapter and its positive repair cases. |
| m6/15 | Fixed context/service-proof/wire extensions540–800 + client/control/blob350–550 + exact registry/rebind orchestration450–700 | Source/wrap/multi-generation substitutions930–1400 + stage/engine crash1100–1700 + blob/job cases650–1000 | M5 initial wrapping rejects claimed material and normal installed proof rejects mismatched IDs. New recovery-only actual source authority/context/control/service integration is counted, with unchanged M4/M3 writer used underneath. |
| m6/16 | Installed lifecycle adapters250–410 + operator/cutoff guidance200–340 | Shared reach/retirement550–900 + operator/profile/data migration450–750 | M4 m4/13 owns all-token barrier, M5 owns key/lifecycle services. Count installed/local wiring, controller proof and actual joined cases, not another barrier engine. |
| m6/17 | Joined diagnostics190–300 + final shipped cross-flow guidance260–400 | Installed-wheel full journeys700–1100 + failure sensitivity550–900 | Reuse per-slice fixtures and M4/M5 Worker/browser/Python harness; test actual package composition and failure detection rather than repeat all endpoint unit suites. |
| m6/18 | Real-run instructions200–350 + bounded production evidence-entry metadata50–100 | Real adopter/deployment driver750–1220 + exact cleanup/evidence350–580 | Driver/config/cleanup assertions are test code; shipped operator guidance is production. Account authorization and authentic release availability remain execution gates. |

Ranges reflect distinct new adapters, parser/protocol branches, shipped guidance
and concrete cross-process/failure cases. They include initial no-history
transport, current raw-key proof equality, actual installed-wheel composition,
full96-shard rebind publication, ambiguity/races and real-account driver code.
Large fixtures/generated vectors are not used to inflate tests. Shared crypto,
source replay, routes/gates, first-Connect writer and all-token containment are
not charged again as if new in each milestone.

The concrete secure bundle/filesystem handoff, typed prefix transition contract,
shared numeric budget counters and complete multi-generation recovery proof wire
are included in the component ranges above. Compared with the first draft,
these inspected additions require390–650 production and730–1,250 test lines;
they are not another copy of M4/M5 foundations. Revised canonical totals are
10,210–16,100 production and19,930–31,800 tests. All other slice ranges stay
unchanged. The shared counter has one owner (m6/1); later clients consume it.
Secure recovery serialization maps directly to existing WrappedKeys, and the
rich inspector has one complete-only M2 compatibility projection. Its internal
partial role IDs fill monotonically from verified readback; bundle/bootstrap/
restart/M2/final objects require complete IDs. These type/transition and creation-
fault checks, the fixed first-null create_next_role effect and complete adjacent-
effect admission checks fit existing m6/2 and m6/7 component ranges; totals do not
change. Creation and phase admission remain in the one coordinator; no extra
progress mechanism is required. No second
verifier, progress store, mandatory App-registration path or new crypto follows.

## Acceptance and uncertainty

Before readiness, review the actual plan plus canonical inventory against all 18
requirements and their parent prose. Resolve source/authority/protocol details
in the main plan; this basis cannot hide an unresolved load-bearing choice.
Coverage is behavioral: actual owning ports/services/crypto/engine, lost replies,
concurrency, source/key/profile substitutions, code-before-key order, exact copy
of broken state and write-free denial, own-new-operation recovery and newer
quarantine. Sensitivity checks must fail when critical checks are bypassed.

Actual published release/adopter pins, private GitHub Free policy, App scopes,
protected source/key execution, provider-token expiry/revival, same-release
selfhost deployment and Cloudflare cold/capacity behavior remain future required
execution evidence. M6 builds its installed/adopter driver; M7 assembles it with
UI/sample/capacity and all-MUST traceability. Fake providers, old suite counts and
unrun/skipped live drivers are not proof those outcomes work. If actual platform
or implementation evidence changes the required scope, replan explicitly rather
than shrinking behavior or relabeling missing evidence as complete.
