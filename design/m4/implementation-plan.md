---
plan_key: m4
slice_convention: hierarchical-v1
slice_inventory: {"executable": false, "path": "slices.json", "sha256": "366c49214782007d6a6812a450fe1918eb2436ecde08a334ce6b3a563b0d423b"}
---
# M4 — Enforcement and routing implementation plan

Status: detailed draft for review. Architecture and public behavior inherit the
existing approval, including the narrow portal coverage-fence service. The
owner's 3 November direction requires a new decision only for a proposed
material change. This plan authorizes no implementation, publication or live
configuration. The canonical ordered slice definitions are in [slices.json](slices.json);
[overview.md](overview.md) renders their status and separate line estimates.

Governing inputs are [requirements](requirements.md) and
[architecture](high-level-design.md), with their verified upstream authorities.
Existing M1–M3 plans, slice IDs, approvals and delivery evidence remain intact.
The [engineering basis](supporting/implementation-plan/engineering-basis.md)
records inspected source, primary platform references and estimate reasoning.

## 1. Deliverable and dependency boundary

Deliver production `worker-enforce`, the routing part of `worker-portal`, the
repository SQLite gate, exact coverage reservations, registry/route maintenance,
ordinary and merge-queue checks, push fallback, and real M3 recovery adapters.
Use the existing Python-authored conformance contracts and shared vectors.
Do not implement another replay engine or current-scope truth store.

M1 cryptography, coverage and operation transitions and M3 authenticated history,
transport and reconciliation exist. Production Worker entrypoints, runtime
GitHub clients, signed route/gate implementation, scope continuity adapters and
Worker/SQLite tests do not. The benchmark Worker is not one of these prerequisites.
Delivery must make the governing stack available through its own admission and
release gates; an unmerged local implementation is not an authentic publication.

M5 owns browser/OAuth identity, consent, authorized admin forms, private views
and hosted exports. It calls M4's coordinator with already authenticated,
action-bound evidence. M6 owns provisioning and installing accepted App grants,
bindings and pinned control artifacts. M7 owns dashboard/badges, second-project
demonstration and assembled release/capacity evidence. M4 owns its actual shared
runtime, protocol and integration drivers, rather than deferring them to M7.

## 2. Modules, capabilities and runtime configuration

Use `api/src/runtime/` for shared bounded HTTP, GitHub credentials, errors,
budgeting and typed configuration. It contains no ambient project selector or
secret-bearing global singleton. `api/src/enforce/` owns ingress, PR/queue
resolution, coverage observation, feedback, fallback and publication completion.
`api/src/routing/` owns registry/route codecs, derivation, gate and transitions.
`api/src/portal/` supplies the portal entrypoint and exact fence service.
`api/src/control/` authenticates protected control calls and drives repair.
`api/src/records/` owns the one Worker canonical-mutation executor shared with
M5; its protocol is the existing M1/M3 protocol, not a second replay engine.
Python integration belongs in `core/dracla/records/routing.py`, reusing the
existing records modules. Do not import legacy plaintext experiments.

Create separate `api/wrangler.enforce.jsonc` and `api/wrangler.portal.jsonc`;
retain `api/wrangler.toml` as explicitly benchmark-only. Pin a tested compatibility
date and package lock. Configure SQLite class `RepositoryGate` with
`new_sqlite_classes`, one namespace in the portal, signed route KV, both origins,
exact App/client IDs, accepted signing/wrapping key IDs and registry identity.
The enforcer has named gate, fence and doorbell bindings, but no namespace,
registry write binding, records key or records App key. The reverse observation
binding points to an enforcer named entrypoint. Public `fetch` never dispatches
an arbitrary RPC method. Validate distinct credentials/origins and all required
binding names at startup; missing configuration cannot enable a partial service.

Use Web Crypto for existing envelope/keyring primitives and App JWT signing.
App JWTs use the configured client ID, bounded lifetime and clock-skew allowance.
Installation-token requests name exact numeric repository IDs and minimum
permissions. Validate returned permissions, selected IDs and expiry; never
substitute a token for another project or App. Keep tokens invocation-local,
redact exceptions, and revoke every minted token on normal completion where
supported. A failed revoke is a safe operator category, not proof of expiry.
Incident containment does not infer that all unknown tokens were revoked.

The runtime selects exact repository identities from validated configuration or
the authenticated route. Names only address GitHub; every reply must match the
numeric identity. Preserve GitHub IDs as canonical decimal strings at HTTP
boundaries. Convert only IDs required by M1 to positive safe integers; reject
lossy conversions. Never parse `fullDatabaseId` through a floating-point cast.

## 3. Closed internal values and serialization

Use closed runtime records: reject missing/unknown fields, unsafe integers,
invalid OIDs/digests, duplicate members, unexpected enums and unbounded arrays.
Use existing canonical JSON and artifact codecs for normative data. The records
below type existing HLD fields; they do not change canonical CLA formats.

- `RouteIdentity`: numeric repository ID, derived state, generation, immutable
  registry OID and unsigned-payload SHA-256. An active payload also binds project,
  current owner/name and one exact installation. Verify the signing `kid` and
  signature separately; signature rotation alone does not change the digest.
- `CheckIdentity`: the M1 deterministic authoritative identity plus repository,
  merge-group head, originating PR and delivery. Its external ID is exactly
  `dracla-authoritative-v1.` plus the existing derived identity. Ordinary IDs use
  the disjoint `dracla-ordinary-v1.` namespace.
- `TerminalCheckObservation`: exact App ID, fixed name, repository, head,
  external ID, numeric check ID, completed status and conclusion. Constructors
  are private to authenticated webhook/GitHub observation code. Neither a
  public request nor a deserialized boolean constructs trusted evidence.
- `CoverageReservationIdentity`: the project/repository/ref, exact reservation
  fence and generation, originating immutable coverage OID and `CheckIdentity`.
  No arbitrary file path, plaintext, token or replacement project is supplied.
- `RepositoryChallenge`: purpose, fresh request nonce, numeric repository and
  installation, expected route/transition identity. The reply repeats all of
  these and provides current owner/name/existence/permission observations.
  Reject a cross-purpose, stale or mismatched reply. These are transient RPC
  values, not another receipt store or canonical business event.

The registry is one private Git repository. Encode complete generation snapshots
with sorted project/repository collections and the HLD's identities, selectors,
request references, installations and derived rows. A prepared generation holds
the request and previous-generation reference but never its future activation
OID. Its immutable commit is the activation input, avoiding circular identity.
Canonical event schemas and child keys remain M1-owned. Registry-only codecs
live in routing; they neither extend canonical events nor enter CLA replay.

`routes/<repository_id>` is the only stable runtime KV selector. Stage through
`prepared/<generation>/<repository_id>`. Verify canonical unsigned bytes before
comparing a gate. Do not enumerate KV to infer the authoritative registry or
create an alias from untrusted owner/name input.

### 3.1 Exact route-signature protocol

Python authors the route codec/vectors in `core/dracla/routing_protocol.py`;
TypeScript implements the same contract. Use native Ed25519 (RFC 8032), not an
HMAC, App JWT key or custom curve implementation. Portal keeps the private key;
enforcement receives public verification keys only. A public key is exactly
32 raw bytes, encoded as strict unpadded base64url. Its `kid` is
`ed25519.` followed by base64url(SHA-256(raw public key)). Signatures are exactly
64 bytes in RFC 8032 R||S form, strict unpadded base64url. Reject malformed,
noncanonical or unsupported encodings/algorithms; native verification and
negative vectors must reject noncanonical/malleable signatures.

The closed envelope is `{route_version:1,kid,payload,signature}`. Payload has
exactly `{domain,repository_id,owner_id,owner_login,repository_name,
installation_id,state,generation,registry_oid,project}`. Numeric IDs use positive
safe integers in this canonical contract, generation is a nonnegative safe
integer, names are bounded nonempty strings, and OIDs use M1 syntax.
`installation_id` may be null only for a non-active state with no verified
installation; that grants no output token. `project`
is null unless active; an active value is exactly `{project_id,project_owner_id,
project_owner_login,project_slug,coverage_repository_id,coverage_installation_id}`.
Those owner/slug values, not the contributing repository's owner, derive the
authenticated project link. Conflict output carries no project list. Pending and
unavailable payloads cannot carry an active project. Registry contains the
complete private administrative data; runtime payload exposes only these facts.

`domain` is `sha256:` plus lowercase hex SHA-256 of JCS bytes for exactly
`{portal_origin,registry_repository_id,gate_namespace:"repository-routing-v1"}`.
Origins are configured canonical HTTPS origins without path/query/fragment and
the registry ID is numeric. Both Workers pin that domain. Signed bytes are
ASCII `dracla-route-v1`, one `0x00` byte, then JCS of
`{route_version:1,kid,payload}`. `route_sha256` remains SHA-256 of JCS(payload)
only, excluding signature and kid. Thus key-only re-sign preserves gate identity.
Reject a foreign domain, unknown version/kid, key/kid mismatch, invalid signature
or unexpected field before gate access. An authentic old payload still needs an
exact current gate match; there is no time-based routing lease.

M6 installs the accepted public-key set before the portal signs with a successor.
Retiring keys remain verify-only for the explicitly configured overlap; remove
them only after all active route bytes use accepted successors and the accepted
configuration is updated. Unknown keys deny, without downloading keys from KV
or following a caller URL. Test forged/cross-domain/cross-schema/malleable
signatures, rotation ordering, missing keys and semantic-digest stability.

## 4. Bounded transport and observations

### 4.1 HTTP and GitHub reads

One injected `GitHubTransport` handles REST and GraphQL with fixed HTTPS origin,
API version, content type, status/error checks, bounded streaming response bytes,
pagination and request accounting. Disallow cross-origin redirects, caller URLs,
unbounded automatic retry and partial GraphQL data accompanied by errors.
Parse rate-limit/retry information as unavailable diagnostics, not authorization.
Use immutable OIDs for every member after a branch snapshot. A `404`, hidden
field, truncated tree/blob or interrupted page is not absence without the exact
endpoint's successful absence contract.

Batch at most eight known coverage paths in one GraphQL request at commit `C`.
Select each `Blob`'s OID, byte size, binary/truncation indicators and text.
Require expected JSON-envelope text, complete bytes and configured total bounds;
reject null/binary/truncated or missing members. Build only fixed aliases and
validated path variables. Batching changes transport cost, not the immutable
observation or the requirement to authenticate each envelope. Keep at most two
batches in flight and no more than the provider's six connections. The bounded
REST fallback may serve small observations; it cannot silently exceed the
budget to fetch every shard separately.

Supply an invocation budget to every HTTP, KV, RPC and DO operation, including
nested service calls, retries and output lookups. Start with the installed
profile's 49-subrequest application ceiling under the provider's 50 limit.
Before calling a child, reserve a fixed child allowance; the child counts its
own external work and returns consumed counts. An untrusted caller cannot
increase limits. Exceeding either local or shared allowance stops non-passing.
No service split resets a logical evaluation's budget or reconstructs a decision
from inconsistent coverage snapshots. The shared bound applies to one
enforcement decision or one conditional transition. A protected control runner
may perform multiple separately authenticated HTTP calls to process a complete
maintenance set; it must join their readbacks and retain matching quarantine
before private writes. Each call keeps the same limits. This is not an
enforcement decision split or a way to claim a partial scan complete.

### 4.2 PR and queue identity

Fetch exact PR facts, head commit/root tree and complete commits (`per_page=100`,
at most three pages and 250 commits). Opener and resolved authors use numeric
user IDs. Require complete page/count consistency and recheck head before
ordinary writes. Account for root-tree reads explicitly if not in the PR query.
Parse co-author trailers under the authenticated policy from that same immutable
coverage observation: advisory by default, blocking only after canonical opt-in.
Ambiguous or unresolved required identities cannot pass. No commit-signature
requirement is introduced.

Queue lookup uses the official `mergeQueue(branch: ...)` for the canonical base
ref and first 100 entries. Read configuration, page completeness, each entry's
head OID and one non-null PR. Require ALLGREEN, supported build window and exactly
one matching entry. Zero, multiple, truncated, HEADGREEN and inconsistent facts
are unavailable. Resolve only that entry's PR; synthetic ref parsing or the
aggregate tree's earlier authors do not identify the subject set.

### 4.3 Authenticated partial coverage

The transport is explicitly two phase at one immutable commit `C`: authenticate
the keyring and five controls first; read the authenticated policy; assemble the
complete blocking subject set; then fetch each needed subject shard once at
`C`. `openCoverageControls` returns an owned validated control observation;
`completeCoverageObservation(controls, requiredSubjects, fetchedShards)` requires
every selected shard and the exact same commit/project/key context. In advisory
mode no trailer-only subject selects a shard. In blocking mode resolve required
trailer IDs before selecting shards; incomplete resolution is non-passing.
Neither phase moves to a new ref or fabricates a member to fill a full projection.

Add `observeCoverage(project, commit, authenticatedMembers, requiredSubjects)`
and `evaluateObservedSubject(observation, subject, agreement, overrideContext)`
to the conformance coverage module. Own immutable copies and validate the five
controls and exactly the required shards with the existing schema/envelope
codecs. A missing marker is represented as authenticated absence only in the
M1-permitted lifecycle; never insert an empty marker or empty unobserved shard.
Validate marker/fence/lifecycle relationships before any decision. Reject
evaluation of a subject whose shard was not observed. Return the existing
`CoverageDecision` shape; output rendering alone reduces it to generic states.

Extract one internal semantic evaluator used by both full and partial coverage
APIs. Full `coverageProjection`, updates and deltas continue to require all 37
members under each supported format. Python is still the reference; add Python-produced vectors for each
new partial-read success/denial case rather than a second TS oracle.
Use source `canonical_sha` as provenance, not a request-time full-history fetch.
Resolve coverage head once, fetch the enforcer-wrapped keyring at its bound
immutable location, validate project/purpose/path/key generation and unwrap
only coverage keys. Authenticate every fetched envelope under those keys.

Apply fence first, then the existing agreement/version, exemptions and exact
repository/PR/subject/root-tree overrides. A success reservation does not block
unrelated ordinary observations; an overlapping mutation is pending. Retired,
succeeded, missing-key and corrupt states cannot fall back to active data.
Never trust an exemption's private source from enforcement or fabricate a clean
full projection from partial members.

### 4.4 Canonical trailer policy and compatible materialization

Implement the already approved project opt-in; advisory remains the default.
The legacy exact five-field `project_configuration` is configuration v1.
Configuration v2 has those same fields plus exactly `configuration_version:2`
and `trailer_coauthors:"advisory"|"blocking"`. Unknown fields/versions reject.
Historical v1 bytes remain unchanged and replay as advisory. After a project
first adopts v2, reject a later v1 configuration update instead of silently
resetting or inheriting a policy the old writer did not express. Current M5
writers emit complete v2 configuration for both initial configuration and edits;
existing current records-admin authority owns the update.

The encrypted `project-config` artifact and `active-agreement` artifact gain
closed `schema_version:2` variants for these v2 values. Other artifact kinds and
the canonical-event envelope remain version1; its nested configuration is
explicitly self-versioned. Extend both identity resolvers with an explicit
schema-version parameter defaulting to1 for existing callers, allowing2 only
for those two fixed artifact identities. Bounded header inspection selects a
supported decoder, but AEAD must authenticate that exact version in existing
AAD before using any value. Unknown versions, v1/v2 mismatches or a v2 value
inside a v1 artifact reject. Update actual M3 read/materialization adapters to
dispatch these known versions rather than assuming every current artifact is1.

The matching active-agreement projection uses `projection_format:2`, the same
32 shards and existing fields, plus exactly `trailer_coauthors`. The full
coverage file set remains 37; no extra per-subject lookup or store is added.
Projection format1 is the historical closed shape and means advisory. A v2
configuration cannot be newly materialized as format1. Policy changes are
project-wide fenced mutations; advance canonical source and this projection
through the existing readback/completion protocol before releasing the fence.
An unsupported reader/writer fails closed. M6 must install compatible pinned
control and both Worker versions before v2 writes; no old writer silently
downgrades an explicitly selected policy. Keep old historical decoders for
retained data, not as an alternate current write path.

Python owns both exact schema variants, replay transitions, materializer and
vectors; TypeScript matches the validators and incremental operation. Record
the format/configuration relationship in the source projection checks and
reference-materialization tests. Do not rewrite historical events or hashes.
Ordinary, queue and fallback decisions read the policy from their same immutable
authenticated coverage observation. Never read records plaintext or accept a
Worker-local/caller/unsigned route policy flag.

In blocking mode, include trailer-declared co-authors under the existing
GitHub identity-resolution rule; an unresolved required identity cannot pass.
In advisory mode, trailers never enter the blocking subject set. Bound advisory
detail separately and expose any truncation only in the authorized view; it
does not turn advisory trailers into a negative CLA decision. M5's opt-in form
retains the existing aggregate-oracle and jamming warning. Add default/opt-in,
unresolved identity, old/new format, downgrade, policy/fence race and all three
enforcement-path vectors and integration cases.

## 5. Repository gate and exact coverage CAS

Implement one bounded row per numeric repository in SQLite, using only HLD §7.2
fields: state/generation/registry OID/digest, exact transition/prepared identity
and prior row while pending, or one publication identity while active. No signer,
scope list or coverage plaintext enters SQL. Perform comparison and conditional
write in `transactionSync`; all external I/O occurs before/after the transaction.
Explicit absent-row first-bind expectations differ from read errors.

| Operation | Required state and effect |
|---|---|
| `compare` | Exact state/generation/OID/digest match; returns match/deny only |
| `begin_pending` | Exact prior row or explicit absent expectation; no publication; stores this transition/prepared identity and prior row |
| `reserve_publication` | Exact active route and no publication, or identical retry; installs only this check identity |
| `confirm_publication` | Exact reservation and trusted terminal check; clears only publication fields |
| `commit` | Matching pending transition and validated activated generation; installs exact derived stable row |
| `restore` | Matching pending transition plus authenticated absence/abandonment; restores only its saved prior row |
| unavailable/quarantine | Conditional exact affected assignment; incident-bound immutable registry generation/OID/digest, with no timeout release |

The gate entrypoint exports only compare/reserve/confirm. Coordinator transitions
are portal-private methods. Identical retries return the existing result; a
different expectation conflicts. A newer transition or incident cannot be
restored by an older call. Timestamps are diagnostic. A gate initialization or
rebuild needs complete registry/live identity facts plus exact coverage-fence
observation; a held success reconstructs publication state, not a clean row.

The portal fence entrypoint independently validates active route and exact
coverage binding, authenticates the idle fence/marker/key at `C`, and uses M1
`reserveSuccess`. Use a branch-wide expected-head `createCommitOnBranch` write
that changes only the fixed encrypted fence path. A conflict returns restart;
indeterminate response reads the exact current/ancestral fence before retry.
Release uses M1 `releaseSuccess`, exact held reservation and trusted terminal
observation. It may release the old project's reservation after a route change,
but it cannot select the new project or clear another operation. Portal tokens
are exact-repository Contents-write; no token or plaintext write API is exported.

## 6. Registry derivation and canonical continuity

The coordinator reads a complete immutable registry snapshot and complete
current GitHub repository/installation observations through the enforcer's
request-bound observation entrypoint. Validate owner/slug claims and all
selectors, including organization-wide future repositories. Exact numeric
identity anchors renames/transfers. Authorized writes reject overlap globally;
a GitHub-created overlap quarantines only affected repositories. Unmanaged is
an explicitly verified result, not missing data or an unavailable installation.

Do not infer current scope from coverage or the last canonical event. For each
registry-referenced request, read its exact deterministic event package at its
recorded immutable source; verify encryption, M1 event/artifact validation,
request/terminal child identity, desired/prior scope and generation equality.
Walk registry predecessor continuity back to an authenticated generation. Check
both deterministic terminal paths: activation and abandonment cannot both land.
A new request is not effective merely because it exists. Follow every prepared
request retained in registry history to its authenticated terminal state.

Use a maximum 16-generation direct-read walk per invocation, bounded by bytes
and API budget. This is a transient acceleration over authenticated history,
not a new truth projection. A cold/unresolved/longer chain remains unavailable
and dispatches the existing pinned M3 control reconciliation. Extend the
precondition provider to obtain M1 `RegistryGenerationBinding`/cross-project
facts from this authenticated adapter; do not teach TypeScript full replay.
The Python control path uses `open_history` and
`effective_enforcement_scope`/`scope_request`, validates the complete chain and
hands back the exact registry-generation result. An assertion file cannot act
as this provider. The coordinator rereads authenticated sources before publish.

For an admin change, M5 supplies the exact validated canonical request and live
authority callback. M4 stages the immutable generation and all changed prepared
KV entries, computes the complete row diff, and puts every changed gate pending.
Recheck the same action authority before using the existing canonical append
protocol to append activation. Publish stable signed routes, revalidate exact
bytes, then commit matching gates and request affected open-PR reevaluation.
The same protocol serves owner migration; a move removes then binds in separate
activated generations. No scope change edits acceptance or legal recipient.

Before activation, restore only after proving no activation/valid abandonment.
After activation, repair forward exactly that generation; rollback is a new
authorized action. Registry head CAS conflicts recompute complete overlap and
claim validation. Key-only route resigning preserves unsigned digest and gate
generation. Unchanged derivation performs no gate/KV writes. Domain isolation
uses separate registry/KV/namespace/origins; cross-domain double-targeting is
unsupported and is not hidden by a precedence rule.

### 6.1 Shared Worker canonical-mutation executor

There is no executable TypeScript canonical writer in the current source.
`api/src/records/mutations.ts` owns the shared executor before the coordinator
uses it; `api/src/records/preconditions.ts` owns authenticated bounded input
acquisition. Reuse M1 `prepareOperation`, `claimAppend`, fence/marker transitions,
event/artifact validation, envelope and incremental materializers. The existing
Python engine remains the full replay/recovery implementation, not executable
Worker code or a later-M5 prerequisite. M5 extends this one executor with its
action handlers rather than building another protocol.

The internal call is `submitMutation(binding, frozenEvent, sideArtifacts,
authenticatedPreconditions): Promise<MutationOutcome>`. Input values are
constructed by trusted action handlers and validated with the existing closed
M1 contracts; HTTP cannot select a precondition provider. Outcome is exactly
`{result:"landed"|"semantic_noop"|"conflict"|"indeterminate",
observed_events_head,canonical_commit}` with M1's existing null/result rules.
There is no success flag that bypasses readback. Routing activation additionally
requires the exact prepared generation and all affected pending-gate evidence.

For an already connected project, snapshot canonical/operations/coverage/derived/
key heads and acquire authenticated current preconditions. For first Connect,
the same executor authenticates the exact README-only events root, K/B and
identical manifests, verified key/challenge bindings and M1's existing
`generations-absence` evidence. Authenticate the independent idle fence/empty
marker and idle operations cell at exact heads without constructing a normal
CoverageProjection. Missing semantic source/shards/derived generations are valid
only for this first event. A partial/changed semantic artifact, unexpected event,
wrong ancestry, non-idle guard or conflicting prepared owner cannot authorize a
new first append. Resume a matching durable operation through its exact frozen
package and existing M3 recovery, rather than treating interruption as absence.
M5 owns these authenticated action inputs; this shared executor owns the durable
transitions. No second writer, lifecycle value or relaxed connected validator.

Freeze the complete event/package in the encrypted
operation cell, CAS the exact project-wide or subject mutation fence, and open
the matching in-flight marker. Acquire the append right with the exact
operations-cell CAS. Append one encrypted event and its exact side artifacts by
non-forced canonical Git commit/ref update; do not use GraphQL replacement on
the canonical history branch. Reconcile uncertain writes by exact package and
ancestry before retry. Terminal children use existing deterministic identities
and conflict exclusion; a terminal no-op/conflict may defeat a delayed writer.

After the genuine first event/config append, materialize the complete normal
coverage (active lifecycle, no active agreement yet) and private derived state.
Connected mutations use the existing bounded incremental contracts. Preserve
source/generation/key bindings in both cases. Read back
every changed projection and source. For a landed operation, close only its
matching marker and read it back before CAS appending to terminal(landed).
Read back that terminal cell, release/read back the exact fence, then clear and
read back only that terminal cell. A prepared semantic-noop/conflict follows
M1's separate terminal-before-marker-close path and never appends. Re-read expected heads before every state-dependent write. Retry at most
the installed M1 profile's three attempts, with existing bounded jitter; never
re-freeze a different event under the same operation identity. Profile overflow
and partial publication retain guards and dispatch exact M3 repair, not a clean
result or edge replay. Publish authoritative routing only after the required
activation outcome is independently established; an indeterminate append keeps
gates pending.

Cross-runtime operation vectors remain Python-authored. Add actual Worker/HTTP
tests for every prepare/fence/marker/append/projection/terminal/release/clear
crash, key selection, retry and child race, plus actual Python recovery of
connected-state persisted operations. The executor's code and common tests are
owned once in M4. Exercise the bootstrap absence/independent-guard branch through
the actual Worker executor with authenticated typed test inputs; expose its
persisted pause fixtures for later caller integration. Before a real connection,
current Python history must remain blocked rather than accept a fake projection.
M4 does not depend on an unbuilt M5 adapter to finish. M5 m5/12 owns the actual
initial-acquisition/Python-engine recovery journey before and after the first
append, using these shared fixtures/harness; M6 adds the real installer journey.
A missing projection cannot enable a regular action or enforcement success.
Later milestones count their integration extensions, not the common executor
or its complete connected-operation crash suite again.

## 7. Enforcement and output state machines

Verify bounded raw webhook bytes with this route's current/retiring SHA-256
secret, constant-time comparison and explicit overlap policy before parsing.
Reject SHA-1, unsupported encodings, oversized bodies and wrong-App events.
Use HLD §4's response codes and supported actions. Delivery IDs are idempotency
inputs, not ordering/freshness timestamps. No durable job receipt is fabricated
from `204`; incomplete transient work returns `503` and a safe category.

Every route-bearing event compares authenticated repository/owner/name and
installation with the signed route and exact gate before project access. A
mismatch invalidates but cannot choose another project. No-project output uses
only the verified installation and exact contributing repository. Conflict
inspection is current-admin-only and permits no resolution write. Failed gate
access or unknown installation never mints a guessed token.

Ordinary flow: resolve PR/subjects/tree; observe immutable coverage; evaluate;
recheck current head; recover or create/update only this App's exact ordinary
check and comment. Bound lookup to one complete page of 100 candidates; a
truncated/ambiguous result is unavailable rather than editing a guessed object.
Verify App author and PR identity before updating a comment; a marker alone is
not permission. GitHub check writes always name the evaluated head. Concurrent
old-head checks cannot overwrite another head's check. Comments carry generic
wording only and may temporarily lag; scheduled repair updates current feedback.

For authoritative success: reserve coverage; reserve exact active route; create
the fixed check directly completed/success while both are held; validate the
GitHub reply; release exact coverage. Retain the gate publication reservation
until an independent authenticated completion delivery or fresh exact GitHub
read proves the terminal check. A self-reported create result cannot clear that
gate. Non-success evaluation creates no authoritative success reservation.

| Failure boundary | Required recovery |
|---|---|
| Coverage reserve conflict | Restart from a new complete immutable observation or return non-passing |
| Lost coverage RPC reply | Read exact fence; identical ownership resumes, other owner blocks |
| Route reserve loses | Establish exact non-passing terminal recovery before releasing coverage |
| Lost GitHub create reply | Keep acquired reservations; bounded exact App/name/head/external-ID lookup |
| Exactly one terminal candidate | Authenticate/read back, release matching coverage, independently confirm gate |
| Zero candidates | Create/read back exact non-passing terminal check, then release/confirm |
| Multiple, partial or in-progress candidates | Keep held state; operator category; no timeout clearing |
| Lost release/confirm response | Retry exact identity/read back; never clear a newer reservation |

A completion webhook validates the entire terminal observation before any RPC.
Ignore other Apps and ordinary namespaces before calling a gate. Daily recovery
uses the same bounded lookup and never turns a missing check into success.

Fixed public wording, check name, authenticated destinations, generic issues,
no annotations/mentions, escaping, retry guidance and reset/offboarding behavior
are exactly HLD §4. The portal origin comes from validated deployment config,
not a redirect parameter. Do not expose private reason codes in GitHub output.

## 8. Push fallback and lifecycle maintenance

After signature and route/gate validation, observe current default branch,
official queue/configuration, active branch rulesets and classic protection.
Use one closed `EnforcementMode` result: required queue, verified no required
queue, or indeterminate. A required queue needs ALLGREEN plus the effective
required `DraCLA` check bound to this App. Its pushes do not reevaluate completed
admission or create fallback issues. HEADGREEN, hidden/incomplete configuration,
GraphQL errors or unproved absence are indeterminate: no project coverage read
or fallback issue. Ruleset reads use Metadata-read; classic-field visibility
and queue absence must pass the installed-grant live matrix before the mode
adapter is accepted. Do not expand App administration permissions to pass it.

In verified no-required-queue mode, enumerate the complete introduced commit
set from immutable before/after OIDs. Require consistent ancestry/count/pages;
deletion, force-push divergence, truncation or budget exhaustion is incomplete.
Do not use the webhook's truncated commit list as evidence. For each commit,
resolve exactly one merged associated PR, or a verified direct push with none.
PR-associated decisions use complete opener/authors and the exact PR/tree;
direct pushes use their resolved author and no PR override. Ambiguous association
is unavailable, not a best-effort subset.

Use a bounded fan-out child evaluation with its own complete immutable coverage
observation and route/gate checks. Count the child invocation in capacity. Never
split a single decision across heads. Immediately before an issue, reclassify
mode and compare route/gate; changed required mode suppresses, indeterminate
mode blocks. Issues are HLD's exact generic SHA/state/link body. One complete
App-authored exact-SHA lookup suppresses normal duplicates, but a lost create
or simultaneous invocation may leave duplicates. Disabled Issues, missing
accepted permission or quota failure leaves the scan incomplete; no settings
mutation or persistent deduplication store is introduced.

Lifecycle doorbells first conditionally invalidate the affected gate, then run
the same full derivation as the daily schedule. Handle rename, transfer, deletion,
restore, installation removal/restriction and missed events. Retain numeric-ID
tombstones; partial project transfers stay unavailable. A restored repository
is rematched from current facts, not an old route alias. Enumerate complete
registry repositories and open PRs on each scheduled scan, passing bounded
continuation values only during the invocation fan-out. No persisted cursor,
queue or index is added. A scan that exceeds the fan-out/page/budget limit emits
incomplete evidence and the safe recovery category, never completed-scan status.

## 9. Protected control and incident recovery integration

M4 adds a fixed authenticated control repair endpoint on the portal, separate
from browser APIs and internal service RPC. Its only operations are quarantine,
read matching quarantine/publication facts, submit bound repair evidence and
conditional restoration. It returns no raw token, key or arbitrary data read.
This implements the already-required protected-control integration, not a new
administrator authorization path. M6 installs the binding; M3 retains its engine.

### 9.1 Closed control protocol and protected configuration

The endpoint is exactly `POST <configured portal_origin>/internal/control/recovery`
with `Content-Type: application/json` and Bearer GitHub Actions OIDC. No public
method dispatcher, redirect, query parameter or caller-selected endpoint is
accepted. Wire body and response are strict canonical JSON bounded to 64 KiB.
Python authors `control/routing-protocol.schema.json`, codecs and shared vectors;
the portal implements the same closed version1 union.

The request has exactly `{protocol_version:1,operation,project_id,incident_id,
execution,source,affected,expected,details}`. `operation` is one of `quarantine`,
`publication`, `registry`, `sweep`, `complete`, `restore`. `incident_id` is an existing
domain-separated 32-byte operation identity, not a caller-selected gate key.
`execution` is exactly `{control_repository_id,workflow_ref,workflow_oid,run_id,
run_attempt}`; IDs and attempts are positive canonical decimal strings on this
HTTP boundary. `source` is exactly `{events_oid,operations_oid,coverage_oid,
derived_oid,keys_oid}`, with OIDs from authenticated M3 heads. `affected` is
exactly `{registry_oid,complete_set_sha256,batch}`. The digest covers the complete
sorted unique `{project_id,repository_ids}` set derived from the immutable
registry and protected incident binding. `batch` contains at most 32 rows from
that set, with sorted unique positive repository IDs. Portal independently
derives the complete set/digest and validates exact batch membership. A batch
never proves complete-set containment. The pinned control runner visits every
member and joins exact authenticated readbacks before private repair; a missing
batch, changed registry/assignment or mismatching incident blocks the join.
This permits large shared incidents without unbounded RPC bodies or a durable
job store. `expected` is a sorted list of exactly `{repository_id,row}`. Row is
the complete closed HLD gate row, including all routing, prepared, prior-row,
publication and diagnostic timestamp fields; every non-diagnostic field must
match, not just a transition ID. `row:null` is explicit observed absence and
requires complete reconstruction facts; a read error is never absence.
`prior_row` may contain one stable row only, so recursion depth is at most1.
Pending and publication fields retain their exact HLD null/ownership rules.

Quarantine uses no new SQL column or unavailable-state transition field. Its
incident binding is an immutable registry generation trigger with exactly
`{kind:"incident",incident_id,complete_set_sha256,credential_binding_id,
exposure_kind}`. The unavailable gate and signed route name that generation's
exact OID/digest; transition fields stay null outside pending. Initial
invalidation alone is not complete quarantine evidence. Normal conditional
publication/transition exclusion remains; a held publication must reach exact
terminal confirmation before that row changes. Private repair waits for every
affected row's verified unavailable identity. Restore derives fresh current
facts and conditionally replaces only that exact incident-bound identity,
never an unqualified `state==unavailable` row or a newer generation.

For the initial quarantine, derive `incident_id` as base64url(SHA-256 of ASCII
`dracla-control-incident-v1`, one `0x00` byte, then JCS of exactly
`{domain,execution,source,complete_set_sha256,exposure_kind,credential_binding_id}`)).
Identical retries keep that ID. Later runs may resume only an already held exact
incident under the same enrolled grant; they compare the held ID and current
sources rather than minting a replacement ID from the new run. A newer incident
changes the held row and defeats old restoration. Operational output may retain
the original ID/preimage for resume, but it is context, not authorization.

`details` is a closed operation-specific object:

| Operation | Exact details and accepted evidence |
|---|---|
| quarantine | `{exposure_kind,credential_binding_id}`; kind is `app`, `root`, `token` or `operational-corruption`; binding names an existing protected assignment, never a raw key/token. Portal computes actual reach and conditionally quarantines every affected row. |
| publication | `{check_identity}` in the existing M1 identity shape; portal obtains independent exact terminal observation from enforcement, operates on the held reservation and returns only bound publication facts. No caller terminal-success boolean. |
| registry | `{event_id,event_sha256,events_head,purpose}`; purpose is `current-scope`, `current-repository-owner` or `successor-project`. Return the exact existing M1 `PreconditionEvidence` records after registry/canonical continuity validation; mismatch or incomplete history blocks. |
| sweep | An inventory request is exactly `{kind:"inventory",repository_id,after_cursor}`; an evaluation request is exactly `{kind:"evaluate",repository_id,pull_request_number,head_oid}`. Only the exact held incident context permits these calls. Inventory returns bounded complete pages; evaluation performs the actual M4 coverage/ordinary-feedback sweep for that current head without authorizing queue success through an unavailable gate. |
| complete | `{rebuilt,containment}`; rebuilt is sorted `{project_id,source,verification_sha256}` using the same source shape after full authenticated readback; containment is null for ordinary operational repair or the closed incident evidence below. |
| restore | `{completion,completion_sha256,sweep}`; completion repeats the closed complete-operation details and digest binds its exact canonical bytes, sources and complete-set digest. It is not a stored authorization ticket. Sweep is `{source_sha256,complete_set_sha256,batch,completed_pr_ids_sha256,complete}` with the exact held affected batch. False complete blocks; true alone never substitutes for authenticated pinned execution and joined complete-set readbacks. |

Responses have exactly `{protocol_version:1,operation,request_sha256,result,
state,evidence}`. Result is `applied`, `already_applied`, `conflict` or `blocked`;
state repeats the complete observed gate identities, and evidence is the
operation's exact publication, M1-precondition, readback or completion record.
Quarantine has null evidence; publication returns exact check/held-fence facts;
registry returns only its typed M1 evidence array. Sweep inventory evidence is
exactly `{kind:"inventory",repository_id,source_sha256,entries,next_cursor,
complete}` with entries `{pull_request_number,head_oid}`; evaluation evidence is
exactly `{kind:"evaluate",repository_id,pull_request_number,head_oid,
source_sha256,decision}` using the fixed generic decision enum. The pinned
runner joins complete inventory pages and matching actual evaluation readbacks
before it can report sweep completion; changed heads require reevaluation and
an incomplete inventory/child cannot supply a complete flag. Complete returns
`{completion_sha256,source_sha256}`; restore returns
`{restored_repository_ids,source_sha256}`. Missing/extra fields, incomplete lists,
wrong operation/request digest or source drift reject. Authentication failures
are `401/403`, conditional conflicts `409`, transient/unavailable `503`; responses
carry only a safe category and no keys/tokens/records plaintext.

Compute `request_sha256` as lowercase SHA-256 hex of the exact canonical body.
OIDC audience is the exact string `dracla-control-v1.<domain hex>.<request_sha256>`;
the domain is §3.1's pinned coordination-domain digest without its `sha256:`
prefix. No caller claim can change project, operation, body or destination under
one token. An identical replay may only repeat the same conditional operation;
gate/incident/source expectations prevent a replay reopening newer state. Do
not add a receipt database or token-replay cache.

Keep `control/production-profile.schema.json` and `control/verify_release.py`'s
release profile at version1: it authenticates released code, not routing input.
Do not add routing fields to that closed profile or own an adopter-generated
`production-profile.json` in the product inventory. Instead add a documented
`control/control-binding.schema.json`: legacy `control_version:1` retains its
exact current fields and blocked external seams; v2 has those same fields,
`control_version:2` and one `routing` value. Routing has exactly
`{protocol_version:1,portal_origin,domain,control_repository_id,workflow_ref,
workflow_oid,runtime_profile_sha256}`. It contains no executable selector,
signing/wrapping key or permission bypass. The existing `control_job` parser
accepts v2 only through this validator and constructs the fixed authenticated
client. M6 installs the protected binding and updates the exact control workflow
SHA allowed by the portal's authenticated Connect/installation contract; request
bodies and OIDC tokens cannot enroll their own source SHA. Add `id-token: write`
to this fixed protected job, without changing the transport App's grant.

### 9.2 Authentication and typed engine integration

Authenticate GitHub Actions OIDC against the fixed GitHub issuer/JWKS, exact
portal audience, expiry/not-before, configured control repository and owner IDs,
private visibility, default-branch ref, approved workflow path and immutable
workflow SHA, and run ID/attempt/event. Permit only protected schedule/dispatch,
never PR/fork events. Verify GitHub-signed claims, not environment-variable
copies. Bind request digest and exact project/incident to the audience; replay
only an identical conditional operation, never a new incident. Unknown signing
keys may trigger one bounded JWKS refresh; discovery is fixed-origin and
cannot follow a request-selected issuer. No shared repair secret is introduced.
The protected workflow adds `id-token: write` for this integration only;
transport App grants and Checks access remain unchanged. Its existing verified
bootstrap still checks exact installed release bytes before project secrets.

The protected v2 control binding pins endpoint/domain, numeric control identity,
accepted workflow SHA and current arrangement. Portal config derives the same
binding from the authenticated project installation contract. Obtain a fresh
OIDC token for each operation digest; a copied output file is never an authorizer.
The existing bootstrap receipt and source OIDs are evidence from approved pinned
code, not a substitute for authenticating that caller. No control key is sent
to the portal and no records/enforcer App key is sent to control.

JWT verification accepts only RS256 and fixed issuer
`https://token.actions.githubusercontent.com`; JWKS comes only from its fixed
HTTPS discovery endpoint, at most eight keys/64 KiB, with one bounded unknown-kid
refresh. Reject duplicate/unknown critical headers, `none`, symmetric algorithms,
issuer/audience mismatch and unverified claims. Require signed `repository_id`,
`repository_owner_id`, `repository_visibility=private`, `workflow_ref`,
`workflow_sha`, `ref`, `event_name`, `run_id`, `run_attempt`, `iat`, `nbf` and `exp`
to match the enrolled project/control/default-branch binding and request execution.
Allow only schedule/dispatch; require `exp>iat`, lifetime at most 600 seconds and
at most 60 seconds clock skew. The exact body-bound audience is one string.
Use the default-workflow source claims, not optional reusable-workflow claims.

`RoutingRecovery` in Python receives an injected authenticated client. Its
runtime value names the exact affected repository set, incident, source OIDs,
gate rows and current pinned execution. The portal independently enumerates the
affected set from current assignments; a caller may not shrink it. Python uses
M1/M3 history validation and complete operation enumeration, not an external
boolean, to decide a repair. Revalidate matching quarantines before private
writes and after rebuild. Extend `MutationEngine` only through an explicit
validated recovery context; absent/malformed/stale context retains today's
`route-unavailable-proof-required` and `check-confirmation-required` failures.
Never add a CLI bypass flag.

For a success reservation, obtain exact independent check observation through
enforcement, release via the portal's existing fence service, then rerun the
unmodified normal M3 guard checks. For malformed operational projections, keep
all affected routes unavailable; enumerate authenticated operation cells and
canonical history, reconstruct the M1-valid fence/marker state, publish under
exact-head CAS, rebuild coverage/derived state and verify readback. Do not
invent an operation, drop unknown cells, overwrite unauthenticated history, or
clear a pending canonical append from a current idle observation alone.

Credential incidents derive scope from the actual exposed App/root or token.
Quarantine every affected assignment before minting/rebuild/restore. Prevent new
minting and prove the all-token containment barrier, including unknown tokens
and clock/propagation margin; successful token cleanup alone is insufficient.
Verify successor App/install/repository bindings, trusted backup refs/history,
and actual successor data keys where decryption authority leaked. Complete full
readback-verified rebuild, then M4's affected open-PR sweep while matching
quarantines remain held. The incident sweep may evaluate only that explicit
context and cannot publish authoritative success through unavailable gates.
Restore only the same incident after all evidence passes. Missing containment,
newer quarantine, incomplete sweep or changed source keeps the incident open.
Retain old canonical history and recovery keys. Live containment is a separately
authorized A6 acceptance gate; an offline fixture never satisfies it.

`AuthenticatedRoutingClient.call(request)` owns TLS origin/JWT/body binding,
closed response parsing and exact current source/assignment comparison. Only it
constructs an invocation-local `AuthenticatedRoutingContext`; files, CLI input
and serialized dictionaries cannot select or instantiate a trusted provider.
`RoutingPreconditions(local, client)` delegates only the three registry/cross-
project purposes above and emits the existing typed M1 binding records.
`reconcile_project(..., routing_context=None)` and
`MutationEngine(..., routing_context=None)` retain current blocked behavior when
absent. When present they revalidate exact project/incident/gates and current
heads before every recovery write; they do not bypass event, cell, key, marker
or fence validators. Context is not reusable across runs or source changes.

Incident containment evidence is exactly `{binding_id,exposure_kind,
minting_cutoff,token_barrier,successor,backup_sha256,rebuilt}`. Cutoff names the
App/installation and verified disabled/retired minting path, server observation
time and authenticated response digest. Token barrier names that cutoff digest,
the longest possible old-token expiry plus explicit clock/propagation margin,
the later trusted server observation and actual known-token probe results.
Temporary suspension or known-token cleanup alone does not establish it. A
successor value binds numeric App/installation/repository IDs and, for leaked
decryption authority, verified successor data-key IDs/commitments. Portal and
the pinned control adapter validate these facts against the enrolled assignment
and accepted live-evidence contract; a caller's `contained:true` is not a field.
Missing or uncertain cutoff, unknown-token bound or time evidence denies
restoration. M4's live driver must establish actual provider expiry/revival
behavior; it cannot infer it from an offline clock or silently choose a shorter
barrier. These records bind the already-required evidence, not a new authority
for the control job to alter unrelated projects or grant itself trust.

Nested cutoff is exactly `{app_id,installation_ids,method,server_observed_at,
response_sha256}`; method is `all_affected_keys_retired` or `installation_removed`.
App/installation administrators perform those existing owner actions; the
Contents-only transport App cannot. The protected operator procedure supplies
the authenticated action/result observations and actual before/after probe
evidence; no control configuration grants itself App administration.
Token barrier is exactly `{cutoff_sha256,maximum_old_token_lifetime_seconds,
margin_seconds,server_observed_at,token_probes}`. Each probe is exactly
`{token_fingerprint_sha256,before_observed_at,before_status,after_observed_at,
after_status,response_sha256}`; require a previously successful exact-scope
probe and later expired/revoked-token denial, not temporary permission loss.
Successor is exactly `{app_id,installation_ids,repository_ids,data_keys}`;
data-key entries are `{capability,kid,commitment_sha256}`. A leaking decryption
capability requires its actual successor commitment; a transport-only incident
does not claim data-key compromise. Rebuilt uses the complete-operation's exact
`{project_id,source,verification_sha256}` shape. All lists are unique/sorted;
IDs, times and digests use the existing closed conventions.

`source_sha256` is `sha256:` plus SHA-256 hex of JCS of exactly
`{project_id,source,registry_oid,complete_set_sha256}`. `completion_sha256` is
`sha256:` plus SHA-256 hex of ASCII `dracla-control-complete-v1`, one `0x00` byte,
then JCS of exactly `{project_id,incident_id,source_sha256,rebuilt,containment}`.
Recompute these from supplied closed records and authenticated readbacks; no
server receipt database or digest-only authorization is implied. Completed-PR
digest covers the sorted evaluated `{repository_id,pull_request_number,head_oid,
source_sha256,decision}` rows from actual sweep responses. The original frozen
control execution and current matching grant authenticate that join.

For the selected installation-token expiry barrier, fix
`maximum_old_token_lifetime_seconds:3600` and
`containment_margin_seconds:300` in the immutable runtime profile. Start from a
verified minting cutoff observed through authenticated GitHub server time,
require a later authenticated server observation at or beyond cutoff+3,900
seconds, and require known old-token probes plus the successor binding checks.
The operator keeps every route quarantined and no affected old minting path is
re-enabled in that interval. A temporary suspend/unsuspend is not this cutoff.
If live evidence shows a longer expiry/revival path, the profile fails
acceptance and remains closed pending correction; it cannot shorten the bound.
Waiting occurs in the protected control runner/operator procedure, not by
holding a Worker invocation or expiring a gate reservation.

Portal enrollments bind each accepted control repository/workflow to exact
project and credential-assignment IDs. Adopter control may repair only that
approved arrangement/transport assignment. It cannot claim a shared service App
or wrapping root as its own incident scope. Shared-service incidents require
the already trusted hosted operator's separately enrolled protected execution
source, which may use an existing operator-controlled private operations repo;
there is no new adopter repository requirement or self-enrollment endpoint.
M6's operator setup records this source in protected service configuration.
Every batch restores only after that fixed trusted execution attests the
complete-set join, source rebuild and sweep, and the portal repeats current
batch/incident/source comparisons. A stale join cannot restore newer rows.

## 10. Budgets, observability and acceptance

### 10.1 Concrete runtime maxima

One shipped immutable `conformance/runtime-profile-v1.json` supplies the exact
values below, loaded and closed-validated by Python and bundled TypeScript.
Its fields are the snake_case names in the table plus `runtime_profile_version:1`.
It is separate from the unchanged M1 projection/operation release profile;
neither an environment variable nor a request may raise it. Package/source
verification binds its actual bytes. A changed envelope needs a newly reviewed
tested release, not a runtime override. These are runtime work limits, not
new limits on retaining canonical CLA history.

| Field | Exact maximum |
|---|---:|
| webhook_body_bytes | 1,048,576 |
| http_response_bytes | 1,048,576 |
| control_message_bytes | 65,536 |
| route_bytes | 16,384 |
| keyring_bytes | 65,536 |
| coverage_control_bytes | 16,384 per plaintext control |
| coverage_envelope_bytes | 65,536 per encrypted shard envelope |
| coverage_observation_bytes | 3,145,728 aggregate encrypted input |
| blob_aliases | 8 per request |
| github_page_items | 100 |
| pr_commits | 250, at most 3 pages |
| commit_message_bytes | 16,384 parsed trailer bytes per message; advisory overflow marks authorized detail incomplete only |
| blocking_subjects | 512 |
| advisory_trailers | 512 retained details per PR; overflow cannot make them blocking |
| queue_entries | 100, at most one complete page |
| output_candidates | 100, at most one complete page |
| branch_rules | 256 active rules, at most 3 pages |
| push_commits | 250, at most 3 complete pages |
| registry_projects | 256 |
| registry_repository_rows | 4,096 |
| registry_selectors | 4,096 across the complete snapshot |
| registry_bytes | 4,194,304 complete immutable snapshot |
| direct_registry_generations | 16 |
| identifier_bytes | 512 for origin/path/name/project identity strings |
| open_prs_per_repository | 1,000, at most 10 complete pages |
| scheduled_child_invocations | 32 per invocation, maximum depth 4 |
| scheduled_total_invocations | 16,384 in one complete scan, including roots |
| scheduled_total_repositories | 4,096 |
| control_batch_repositories | 32 |
| jwks_bytes | 65,536 |
| jwks_keys | 8 |
| jwks_refreshes | 1 per invocation |
| oidc_lifetime_seconds | 600 |
| oidc_clock_skew_seconds | 60 |
| maximum_old_token_lifetime_seconds | 3,600 |
| containment_margin_seconds | 300 |
| subrequests | 49 per invocation/decision as above |

Validate Content-Length when present and stream into a bounded reader before
JSON allocation; absence of that header never disables the byte counter. Check
counts before inserting/appending and before a next-page/child call. Use an
ephemeral shared scan budget with expected registry OID, remaining invocations,
depth and next page/row. Named service invocations receive sealed internal
continuations, not public bearer cursors. Exhaustion denies complete-scan status.
A protected control runner may finish a large incident through bounded HTTP
batches; none of those calls can authorize a partial-set restore.

Coverage is not truncated or silently resharded when an envelope/work limit is
exceeded: return unavailable and retain canonical data, with an operator path
to a larger separately tested profile. The initial envelope is a measurement
candidate, not a claim it meets hosted CPU. Test every byte/count limit at minus
one, exactly, and plus one; include missing lengths, dishonest sizes, nested
debits and repeated denied calls. Advisory trailer-detail overflow affects only
that authorized detail's completeness; complete opener/author evaluation remains
the default blocking rule. Blocking-mode subject overflow fails non-passing.

### 10.2 Accounting and acceptance layers

Enforce the installed release-profile limits, endpoint completeness bounds and
the provider envelope before work. Batch immutable reads to create headroom
for actual PR rechecks, comments, cold token acquisition, named service calls
and independent portal validation; the parent HLD's old scalar request count
is not a substitute for an instrumented trace. For 32 required shards, at most
five batches cover five controls plus shards. Budget keyring/ref, contribution
facts, output lookups/writes and every nested operation separately. Reserve
budget for a failure response before optional retries. Do not promise a numeric
worst-case CPU result from the pre-encryption benchmark.

Expose only safe category, delivery/correlation ID, source OIDs, operation state,
request/RPC/DO counts, complete/incomplete scan flag and timing. Never log tokens,
keys, webhook bytes, subject IDs/logins, emails, legal names, scope lists or
private plaintext. Validate redaction through captured error paths. Feed the
one HLD §9.2 capacity model with ignored event traffic, actual pushes, fallback
fan-out, gate operations, rows read/written, daily scans and private Actions
minutes. No second capacity calculator or per-project durable counter is added.

Tests have four distinct layers:

1. Python-produced vectors and pure TS conformance for shared semantics.
2. Deterministic HTTP/RPC transport scripts that verify exact requests, complete
   pages, byte limits, budget debits, credentials and injected failure points.
3. Actual local Workers with named bindings and SQLite gates using the current
   Cloudflare Vitest integration. Exercise SQL transactions, rollback, separate
   repository identities, retained state/restart, service export isolation and
   gate errors. A JS object mock alone does not establish these facts.
4. Separately authorized hosted/API acceptance drivers: cold 32-shard crypto,
   queue/classic/ruleset visibility, GitHub actual permission acceptance,
   lost-response recovery, self-hosted separation and real containment. M4
   delivers runnable drivers; M7 binds results to authentic release artifacts.

| Requirement | Owning slice(s) and integrated completion evidence |
|---|---|
| R01 | m4/1, m4/2, m4/8: signature-before-parse, wrong-App/namespace denial, stale-head/reordered events |
| R02 | m4/16 then m4/8: canonical policy default/opt-in, full subjects/tree, 250 limit, unresolved identity and exact override |
| R03 | m4/3: immutable batched coverage, every shard, corrupt/missing/unobserved-member parity |
| R04 | m4/3, m4/9: complete fence/marker pair cases including unrelated mutations and lifecycle |
| R05 | m4/9, m4/10: two-entry ALLGREEN, preserved completed decision, direct/squash/rebase pushes, mode/access/route races |
| R06 | m4/4, m4/9: actual CAS/gate, every crash/lost reply and independently authenticated terminal completion |
| R07 | m4/8, m4/10: exact generic output and malicious text/no-private-data assertions |
| R08 | m4/5, m4/6, m4/15: complete selector overlap, canonical continuity, durable canonical writer, remove-before-bind, cold-history recovery |
| R09 | m4/4, m4/5: real SQLite rows/transactions, stale/missing KV, key-only rollover, gate reconstruction |
| R10 | m4/15 then m4/7: every prepared-operation/pending/activation/publish boundary, mutual terminal exclusion, authority loss and stale restore |
| R11 | m4/8, m4/11: lifecycle/tombstones/missed events, bounded no-project output and admin-only conflict probe |
| R12 | m4/11–13: daily recovery, actual M3 blocked-seam integration, incident fan-out, containment/rebuild/sweep/restore |
| R13 | m4/1, m4/2, m4/4, m4/12: exact configuration and token/RPC/control boundaries plus independent deployment |
| R14 | m4/14 and each behavior owner: full budget/error trace, redaction, Free-profile drivers and incomplete scans |

Each behavior slice owns its cases using shared harnesses. The final slice owns
assembled journeys and measurement drivers, not a duplicate copy of every unit
test. A regression must fail when its relevant guard is removed; retain focused
sensitivity evidence for route/gate match, exact completion and control binding.

## 11. Slices, estimates and readiness

The canonical inventory is the sole source of IDs, ordered responsibilities,
owned files, prerequisites, acceptance and per-slice ranges. All IDs are full
`m4/N` identities and commit titles must begin with their exact bracketed ID.
There is no prospective migration of completed M1–M3 definitions.

Estimates are incremental final delivered nonblank physical lines excluding
comment-only lines. Count docstrings/multiline statements physically. Production
includes runtime configuration, packaging and shipped operational Markdown;
tests include test-only configuration, helpers, generators and integration/live
drivers. Exclude design documents, static fixtures, generated output, lockfiles,
dependencies and disposable probes. These are not fixed-base edit churn or time
estimates. [The basis](supporting/implementation-plan/engineering-basis.md)
maps each range to concrete changes; the generated overview sums each category.

Readiness is for design review, not delivery admission. No additional owner
decision is known within the approved architecture. The following external
facts remain explicit execution/production gates, with their owning slices:

- m4/10 must establish queue/classic-protection absence and visibility using the
  existing App grant on controlled accounts before claiming functional fallback
  there. Hidden nulls are not accepted. If the platform cannot support this
  contract, return the material permission/behavior choice; do not ship a
  permanently unavailable fallback as completion.
- m4/9 and m4/14 must pass complete cold 32-shard and nested-CAS CPU/request
  accounting. Failures block the affected Free-profile acceptance; do not drop
  authors, tests or cryptographic validation to fit.
- m4/12–13 must bind an authentic pinned control run and separately authorized
  real containment evidence. Fixtures prove rejection and protocol behavior,
  not hosted correctness or all-token cutoff.

The detailed review must assess these executable gates and estimates against
the full scope. Only a genuinely new material decision returns to the owner;
derived document levels do not restart approval. After reviewed packages exist,
clean stale prospective navigation and status while preserving original plans,
slice history, approvals and spent budgets. Product work remains a separate
delivery campaign.
