# M4 engineering and estimate basis

This supports the [current plan](../../implementation-plan.md). It is evidence
and estimate reasoning, not an additional normative architecture or progress
ledger. Source inspection was against Sapling head
`ec45c63ad01c197330702bbaefb2c5935333e688` plus the exact reviewed M4 documents.
Input SHA-256 values and absent-output preimages are retained in the existing
design campaign's `m4-detailed-authoring-preimage.json` artifact.

## Existing code inspected

| Source | Physical source lines, including comments/blanks | Reuse and missing work |
|---|---:|---|
| `api/src/conformance/coverage.ts` | 263 | Full immutable projection, subject decisions, updates/deltas exist. Partial authenticated observations and I/O are absent. Extract shared decision logic, preserve complete-update validation. |
| `api/src/conformance/operations.ts` | 483 | Pure closed fence/marker/cell transitions and exact check identity exist. No GitHub CAS, reservation service or gate. |
| `api/src/conformance/envelope.ts` | 194 | Web Crypto envelope/AAD validation exists; use it rather than new encryption. |
| `api/src/conformance/keyrings.ts` | 197 | Closed keyring and wrap/unwrap binding exists; runtime acquisition and exact capability selection remain. |
| `api/test/conformance.test.mjs` | 2,110 | Existing Node tests/corpus consumers; preserve and extend semantic coverage. Not a Worker/SQLite integration harness. |
| `api/bench/worker.mjs` | 75 | Old plaintext benchmark only. It cannot prove encrypted cold-path production CPU or proper bindings. |
| `core/dracla/records/github.py` | 607 | Concrete Python immutable transport, exact-head writes and protected control dispatch. Reuse for control; TS still needs a runtime client. |
| `core/dracla/records/append.py` | 738 | Real mutation engine and explicit external-proof blocked states. Add narrow authenticated integration, not another engine. |
| `core/dracla/records/reconcile.py` | 432 | Replay/materialization/precondition and repair-forward orchestration. External registry/check/quarantine proofs remain blocked. |
| `core/dracla/conformance/replay.py` | 2,899 | Effective scope and exact request/terminal history exist. Edge full replay must not be budgeted or implemented. |
| `core/tests/test_records_5.py` | 1,195 | Substantial real bootstrap/release/engine fixture infrastructure; reuse its fixtures and add routing cases. |
| `core/tests/test_records_6.py` | 354 | Restore/installed-engine tests explicitly distinguish fixtures from authentic release/live recovery. Preserve that limit. |

These source counts are inspection anchors, not the estimate units or a scaling
formula. Estimates below count only incremental delivered nonblank,
non-comment-only physical lines; Python docstrings and multiline statements
count physically. Existing source is not charged again. Moving a shared helper
does not make its unchanged contents a new feature estimate.

## Platform evidence and choices

Primary references checked on 3 November 2026:

- [Worker RPC entrypoints](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/)
  support named service boundaries. Use fixed bindings and reject public dispatch;
  absence of a binding is denial. This supports the approved two-Worker split.
- [Worker Web Crypto algorithms](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/#supported-algorithms)
  support standard Ed25519. Route signatures use it with Python-authored exact
  canonical/domain-separated bytes and verification-only enforcer keys; no
  non-standard curve implementation or shared signing secret is introduced.
- [SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
  provides synchronous local transactions. Keep network observations outside
  the transaction; atomically compare and mutate one bounded repository row.
- [Worker limits](https://developers.cloudflare.com/workers/platform/limits/)
  retain the selected Free 10 ms CPU, 50 subrequests, 128 MB and six-connection
  envelope. Application accounting uses the installed profile's stricter 49.
  Service calls and their nested work are explicit costs, not a loophole.
- [Durable Object limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
  and [pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
  permit SQLite-backed Free objects with separate account resource dimensions.
  Account-level quotas remain shared; no per-tenant allowance is invented.
- [Workers Vitest integration](https://developers.cloudflare.com/workers/testing/vitest-integration/)
  and [SQLite testing](https://developers.cloudflare.com/durable-objects/examples/testing-with-durable-objects/)
  identify the current `@cloudflare/vitest-plugin` approach, including local
  runtime bindings and multiple Workers. Do not copy an obsolete pool setup.
  During delivery lock a compatible tested toolchain; preserve existing Node
  conformance tests rather than replacing them with the new integration suite.
- [GitHub Blob fields](https://docs.github.com/en/graphql/reference/git#blob)
  expose OID, byte size, binary/truncation facts and text. Fixed alias batching
  of immutable JSON envelopes reduces request count without changing shard or
  cryptographic semantics. A truncated/null member never becomes an empty shard.
- [Official queue schema](https://docs.github.com/en/graphql/reference/pulls)
  supplies queue entries and ALLGREEN configuration. Use exact official head/PR
  association; synthetic ref parsing is not an alternative mapper.
- [Active branch rules](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
  are available with Metadata-read and include active rulesets across levels.
  [Ref protection](https://docs.github.com/en/graphql/reference/git#ref) and
  [required checks](https://docs.github.com/en/graphql/reference/branches#requiredstatuscheckdescription)
  are separate classic observations. Schema presence does not prove current
  installation visibility. The controlled-account driver must prove required
  queue versus absent/inaccessible configurations with the existing grant.
- [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)
  identify the run, numeric repository/owner, audience and workflow source.
  They provide authentication for the already-required protected control
  integration without sharing a new long-lived secret or the transport App key.
  Bind exact approved workflow and operation audience; this does not prove
  arbitrary caller-supplied repair evidence or replace release verification.
- [Installation-token lifetime](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
  is documented as one hour. The initial control profile adds a fixed 300-second
  containment margin after verified minting cutoff, backed by authenticated
  server observations and known-token probes. This is not proof that suspension
  revokes or prevents revival; the actual live driver must verify those facts.

No private API, credential or live account was probed for this design. The
chosen runtime primitives are documented; actual grant visibility, hosted CPU
and real containment remain explicit execution gates in their owning slices.
There is no claim that a schema page established those live facts.

## Per-slice range reasoning

The canonical numerical ranges live once in `slices.json`; this table explains
their composition. Each item includes its failure paths and test extensions.

| Slice | Production basis | Test basis and uncertainty |
|---|---|---|
| m4/1 | Two entrypoints, typed configuration/error boundary, two production configs, closed immutable runtime maxima and package wiring | One reusable actual-Worker/SQLite harness, exact limit boundaries, configuration and RPC isolation tests. Tooling setup is new; later slices reuse it. |
| m4/2 | Bounded HTTP/GraphQL, exact credential acquisition, pagination and nested budget accounting | One reusable HTTP script driver plus endpoint/error, scope, expiry, redaction and budget cases. No second Python client. |
| m4/3 | Partial immutable observation, shared evaluator extraction and encrypted batch reader over existing crypto | Python-produced parity cases, unobserved/malformed members, immutable-head drift and all-32-shard transport cases. Existing full coverage is not re-estimated. |
| m4/4 | Bounded SQL gate transitions, exact fence service and minimal portal exports | Real transaction/restart/conditional-race tests and exact reserve/release/lost-response/capability cases. This is more than an in-memory map. |
| m4/5 | Python-authored operational registry/route codecs, concrete Ed25519/domain/kid protocol, complete derivation and signed projection | Complete selector/claim inventories, Python/TS signature/negative vectors, exact bounds, observation challenges, stale KV and key rollover. Existing canonical JSON remains reused. |
| m4/6 | Direct canonical continuity, registry external facts and Python full-replay bridge | Terminal-child/history/generation and cold-chain regressions across TS and actual M3 preconditions. No full TS replay is counted. |
| m4/7 | Conditional multi-repository prepare/pending/activate/publish/commit orchestration | Fault injection at every durable boundary, authority loss, concurrent changes, stale restore and migration. It reuses m4/4–6. |
| m4/8 | Raw webhook auth, PR subject/tree resolution and generic output rendering | Reordered/wrong-App/stale-head/full-page and no-private-output tests. Shared HTTP/budget infrastructure is not charged again. |
| m4/9 | Official queue mapping, reservation ordering, output recovery and independent completion | Two-entry association, every lost response, zero/one/multiple candidate handling and mutation/route races. Both coverage and routing reservations need coverage. |
| m4/10 | Queue/rules/classic mode, complete push association, child evaluation and issues | Direct/squash/rebase/force/disabled-Issues, mode/route races and a controlled-account visibility driver. More uncertainty lies in API visibility than in rendering. |
| m4/11 | Lifecycle invalidation, complete daily scans and exact originating-PR callback | Missed events, transfer/tombstone/install restrictions, reconstruction and incomplete-scan limits. No queue/cursor subsystem is estimated. |
| m4/12 | OIDC verification, closed request/response/digest/batch protocol, fixed repair endpoint, protected control-binding schema/parser/workflow and typed Python integration | Cross-runtime protocol/claim tampering, complete-set joins, adopter/operator scope plus actual M3 engine repair/readback/blocking tests; reuse verified release fixtures. The existing release-profile schema remains unchanged; no absent adopter-created JSON is counted as source. |
| m4/13 | Incident scope/containment orchestration, conditional restoration and shipped recovery guidance | App/root/token reach, unknown-token barrier, successor/key/source mismatch, held-quarantine sweep and live driver. No duplicate token or replay engine. |
| m4/14 | Shipped enforcement guidance and capacity/package integration | Assembled runtime journeys, cold encrypted measurement drivers, redaction and failure-sensitivity evidence. Existing individual tests and base harness are not re-counted. |
| m4/15 | Concrete shared Worker prepared-cell/fence/marker/append/projection completion executor using M1 semantics | Every durable crash/lost-write/key/terminal-child boundary and actual Python recovery. This runtime did not exist: pure TypeScript functions and a Python engine were insufficient prerequisites. Count once here, not again in M5. |
| m4/16 | Python-first compatible configuration/project-config/active-agreement v2 policy, replay/materialization/identity/AAD support and M3 adapter dispatch; same 37 files/32 shards | Historical-byte parity, default advisory/explicit opt-in, unsupported/downgrade/mismatch denial and all three enforcement paths. No duplicate policy store or default/authority change. |

M4 totals are **7,330–11,950 production lines** and **11,650–18,430 test lines**.
The wider test range reflects new runtime/storage/HTTP/control integration and
recovery races. It is not a blanket ratio. Bounds sum the whole agreed scope,
including configuration, shipped guidance, platform drivers and failure tests.

M5 may count only its OAuth/session/private-read/portal mutation and UI extensions
over these runtime, credential, route and test foundations. M6 counts installer
adapters and integration, not a second provisioning or runtime foundation. M7
counts dashboard/badge/demo and release assembly extensions, not another M4
queue/containment driver. Publish the combined total only when all four plans
exist. No unstarted historical M4 path is silently adopted as an implementation.

Ranges allow endpoint validation/detail and regression growth within these
responsibilities. A new store, credential grant, replay path or protocol change
is not hidden inside the high bound. If execution evidence requires that change,
return the material decision and re-estimate affected work through the retained
workflow without resetting history or spent allowances.
