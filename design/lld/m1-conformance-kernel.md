# M1 low-level design — conformance kernel

Status: Draft for review
Date: 27 August 2026
Requirements baseline: `design/requirements.md` (Locked, revision 13)
HLD baseline: `design/high-level-design.md` (Locked, 25 August 2026)
Roadmap milestone: `docs/roadmap.md` M1

## 1. Purpose

M1 turns the revision-13 byte, schema, identity, replay, and bounded-state
contracts into transport-independent libraries and one shared conformance
corpus. It does not operate a portal, call GitHub, write repository refs,
publish checks, or provision infrastructure.

The kernel is the trust boundary below those drivers:

```text
untrusted bytes / request values
             |
             v
strict decode -> closed schema -> relation checks -> replay/transition
             |                                      |
             +---------- validated values ----------+
                                  |
                 later repository and Worker drivers
```

The requirements and HLD remain normative. This LLD chooses code organization,
public interfaces, test corpora, and review boundaries. If implementing one of
those choices requires a new wire value, enum, state, transition, authority,
or behavior not determined by the HLD, work stops for design review rather
than encoding the implementer's guess.

## 2. Scope and decisions realized

M1 directly realizes HLD D4a, D5's projection contract, D6, D7's
one-recipient/one-agreement data rules, D8, D9, D10's supersession flag, D14,
D15, D17's coverage fence, D18's prepared-operation cell, and the data portions
of D2 and D16. Its governing HLD sections are:

- §4 encrypted artifacts, identities, wrapped keys, and capability separation;
- §5.1 closed event union, named objects, authorization vocabulary, and
  identifier derivation;
- §5.3 coverage schema and deterministic shard rules;
- §5.4 authenticated action forms, prepared-operation cell, in-flight marker,
  and decision fence;
- §5.5 project and successor lifecycle;
- §6.5 agreement publication/activation folds;
- §6.6 bounded records-derived schemas and generations;
- §6.8 exemption, reader, override, and authorization semantics; and
- §6.10.6 conformance, seam, race, crash, and rejection obligations.

The requirement families cited by the slices below are `REQ-CONFIG-1..5`,
`REQ-AGR-1..4`, `REQ-SIGN-2..5`, `REQ-REV-1..5`, `REQ-CHECK-1..5`,
`REQ-REC-1..8`, `REQ-SEC-1..4`, `REQ-SEC-6..10`, `REQ-DASH-1..5`,
`REQ-PORTAL-5`, `REQ-OPS-1`, `REQ-OPS-3`, `REQ-OPS-6`, and `REQ-VERIFY-1..2`.
Each slice section lists the exact subset it carries evidence for. Later
milestones supply the authentication, GitHub, user-interface, installation,
deployment, and release-scenario evidence those requirements also need.

### 2.1 Explicit non-goals

M1 does not implement:

- GitHub repository reads, commits, branch-head CAS, non-forced ref updates,
  installation tokens, or live authorization checks;
- OAuth, sessions, browser rendering, portal endpoints, webhook handling,
  check runs, comments, routing KV, or Durable Objects;
- hosted wrapping services, root rotation orchestration, key-controller
  runbooks, bootstrap discovery, or recovery user experience;
- the CLI, Hydra composition, administration surface, installer, workflow,
  reconciler driver, or export streaming;
- Entity CLA events or coverage. The reserved Entity event names remain invalid
  revision-13 values; and
- a second projection format, configurable shard count, live resharding,
  compression, alternate algorithm, or schema-version negotiation.

## 3. Delivery map and status

These headings and titles are exact delivery selectors. One slice is one
reviewable commit and pull request unless its boundary is remapped in this LLD
and `docs/roadmap.md` before implementation is split.

| ID | Status | Depends on | Review boundary |
|---|---|---|---|
| M1-1 — Canonical JSON and artifact identities | Landed in PR #12 | M0 | Existing implementation summary only |
| M1-2 — Version 1 encrypted-artifact envelope | Landed in PR #13 | M1-1 | Existing implementation summary only |
| M1-3 — Wrapped-key copies and canonical keyrings | Ready after LLD review | M1-1, M1-2 | Python keyring bytes, validation, and vectors |
| M1-4 — Event identity and authorization vocabulary | Planned | M1-1 | Python identity/authorization primitives and vectors |
| M1-5 — Closed revision-13 event schema and semantic validation | Planned | M1-2, M1-4 | Complete local event validation and vectors |
| M1-6 — Canonical replay foundation and project/contributor lifecycle | Planned | M1-5 | Replay engine plus foundational lifecycle folds |
| M1-7 — Administrative, scope, exemption, reader, and override replay | Planned | M1-6 | Complete revision-13 replay fold |
| M1-8 — Authenticated action forms and replay-stable no-op bindings | Planned | M1-4, M1-5, M1-7 | Action-form bytes, verification, and terminal binding |
| M1-9 — Prepared-operation, in-flight, and decision-fence contracts | Planned | M1-2, M1-5, M1-8 | Pure persisted-state models and transitions |
| M1-10 — Coverage projection contracts and bounded shards | Planned | M1-7, M1-9 | Deterministic coverage materialization and validation |
| M1-11 — Records-derived contracts, generations, and release profile | Planned | M1-7, M1-9, M1-10 | Private derivatives, generation checks, numeric profile |
| M1-12 — Shared conformance corpus and vector generator | Planned | M1-3, M1-5, M1-8, M1-10, M1-11 | Corpus relocation, manifest, and Python generator |
| M1-13 — TypeScript byte foundations and artifact envelopes | Planned | M1-12 | JCS, base64url, identity, AAD, envelope, profile |
| M1-14 — TypeScript wrapped-key creation, unwrap, and keyrings | Planned | M1-13 | Edge wrap/unwrap and keyring bytes |
| M1-15 — TypeScript event and side-artifact package validation | Planned | M1-13 | Edge write-path event contract |
| M1-16 — TypeScript action forms and operation-state contracts | Planned | M1-13, M1-15 | Edge form verification and persisted-state validation |
| M1-17 — TypeScript incremental coverage updates and subject decision | Planned | M1-13, M1-16 | Edge coverage read-modify-write and decision |
| M1-18 — TypeScript incremental records-derived updates and portal reads | Planned | M1-14, M1-17 | Edge derived update and read validation |
| M1-19 — Cross-runtime conformance gate and M1 closure | Planned | M1-15, M1-18 | Full corpus agreement, packaging, traceability |

Implementation order is M1-3 through M1-19. M1-3 and M1-4 have no logical
dependency on each other after the landed foundations, but remain sequential
commits in one stack so review and vector organization stay linear.

M1-3 through M1-11 are the Python authoring slices. M1-12 freezes the corpus
they produced. M1-13 through M1-18 are the TypeScript edge implementations, each
consuming that corpus and adding no contract of its own. M1-19 closes M1. A
TypeScript slice that finds a contract missing, ambiguous, or unvectorized stops
and returns to its authoring slice rather than inventing the edge behavior.

## 4. Package architecture

### 4.1 Python ownership

Revision-13 implementation lives under `core/dracla/conformance/`, isolated
from the pre-design modules in `core/dracla/events.py`, `append.py`,
`projection.py`, `githost.py`, and `github.py`.

| Module | Slice | Responsibility |
|---|---|---|
| `canonical.py` | M1-1, landed | Strict RFC 8785 encode/decode and shared JSON-number boundary |
| `encoding.py` | M1-1, landed | Canonical unpadded base64url |
| `artifacts.py` | M1-1, landed | Closed artifact namespace, path relations, agreement tokens, override keys |
| `envelope.py` | M1-2, landed | A256GCM artifact AAD, envelopes, strict plaintext/CSV checks |
| `keyrings.py` | M1-3 | Wrapped-key objects, wrap AAD, canonical keyring parsing and encoding |
| `event_identity.py` | M1-4 | Actor identity, nonce domains, authorization vocabulary, event identities and paths |
| `events.py` | M1-5 | Closed event/nested-object validation and locally decidable semantic relations |
| `replay.py` | M1-6, M1-7 | Ordered canonical fold and history-dependent semantic validation |
| `action_forms.py` | M1-8 | HS256 action-form bytes, temporal/context validation, terminal no-op binding |
| `operations.py` | M1-9 | Prepared-cell, in-flight, decision-fence models, cross-bindings, pure transitions |
| `coverage.py` | M1-10 | Coverage schemas, deterministic 32-shard materialization, validation and deltas |
| `derived.py` | M1-11 | Records-private schemas, deterministic 32-shard materialization and generations |
| `release_profile.py` | M1-11 | Checked-in, closed numeric Free-profile limits and size enforcement |
| `vectors.py` | M1-12 | Corpus generator, manifest, and before/input/after triple emission |

Public exports that are needed by another milestone are re-exported from
`dracla.conformance`. Internal validators remain module-private. A delivery
slice may factor private helpers differently, but may not move revision-13
behavior back into the legacy modules.

Python is the authoring runtime. `coverage.py` and `derived.py` provide the
reference materializers, which are full functions of validated state. They are
the oracle for the incremental edge path rather than a second implementation of
it: M1-12's generator emits before-state, input, and after-state triples by
running the reference materializer at each end, and the TypeScript incremental
update must reproduce the after-state byte for byte.

### 4.1.1 TypeScript ownership

Edge implementation lives under `api/src/conformance/`, one module per shared
contract, mirroring the Python module boundaries so a reviewer can diff them.

| Module | Slice | Responsibility |
|---|---|---|
| `canonical.ts`, `encoding.ts` | M1-13 | RFC 8785 encode/decode and unpadded base64url |
| `artifacts.ts`, `envelope.ts` | M1-13 | Identity resolution, AAD, A256GCM envelopes, strict decrypt |
| `releaseProfile.ts` | M1-13 | Closed profile parsing and size enforcement |
| `keyrings.ts` | M1-14 | Wrap AAD, `wrap_key_copy`, unwrap, keyring parse/encode |
| `events.ts` | M1-15 | Write-path event and side-artifact package validation |
| `actionForms.ts` | M1-16 | Action-form verification and Table 5.4-A registry |
| `operations.ts` | M1-16 | Prepared-cell, marker, and fence validation and transitions |
| `coverage.ts` | M1-17 | Incremental coverage update, validation, subject decision |
| `derived.ts` | M1-18 | Incremental records-derived update and portal read validation |

TypeScript implements no replay fold, no full materializer, no export, no
reconciler, and no vector generator. Routing state, the signed KV projection,
and the Durable Object gate are M4's and are deliberately absent from this
table: they are Worker-side but are not shared byte contracts.

### 4.2 Value model

The kernel has two boundaries:

- byte contracts accept `bytes` and return exact `bytes` or immutable validated
  values; and
- semantic contracts accept already parsed JSON data and reject Python values
  outside the shared JSON model before canonicalizing them.

Closed schemas use explicit validators rather than a serializer that might
coerce values or select a non-JCS representation. In particular, `bool` is not
accepted as an integer, all cross-runtime integers are within JavaScript's safe
range, sets are duplicate-free and ordered by the lexicographic byte order of
each member's JCS encoding, and unknown members fail before any derived value
is trusted.

Validated top-level models are frozen dataclasses. Each retains the validated
semantic value and exact JCS bytes needed by downstream identity, replay, and
transition code. Callers do not construct a trusted model without running its
validator.

### 4.3 Error boundary

Each module exposes one base `ValueError` subclass and narrow subclasses where
callers must distinguish format, context, unknown-key/version, authentication,
conflict, or corruption outcomes. Error messages are diagnostic, not protocol
tokens. Tests assert exception classes and state effects rather than depending
on prose. Secret key bytes, plaintext signer values, and complete untrusted
payloads never appear in messages.

### 4.4 Vector organization

Until M1-12, Python vectors remain in `core/tests/vectors/` beside the landed
corpus. Each slice adds one or more versioned JSON files:

| Slice | Vector file |
|---|---|
| M1-1 | `artifact-identities-v1.json` (landed) |
| M1-2 | `artifact-envelope-v1.json` (landed) |
| M1-3 | `wrapped-key-v1.json` |
| M1-4 | `event-identities-v1.json`, `authorization-vocabulary-v1.json` |
| M1-5 | `events-v1.json` |
| M1-6/M1-7 | `replay-v1.json` |
| M1-8 | `action-form-v1.json` |
| M1-9 | `operation-state-v1.json` |
| M1-10 | `coverage-projection-v1.json` |
| M1-11 | `records-derived-v1.json`, `release-profile-v1.json` |
| M1-12 | `manifest.json`, plus the before/input/after triples for M1-17 and M1-18 |

M1-12 moves the complete corpus without changing vector content to
`conformance/vectors/` and adds the generator and manifest; M1-13 onward consume
that one location from TypeScript.
Fixed keys, nonces, timestamps, and IDs are test material only. Production APIs
obtain randomness from a CSPRNG and never expose a deterministic-nonce option;
tests replace the randomness provider at the boundary, as the landed envelope
tests do.

Every vector file carries a format version and named cases. Rejection cases
identify the expected error class, not an implementation-specific message.

## 5. Slice specifications

## M1-1 — Canonical JSON and artifact identities

Status: Landed in PR #12.

### Implemented surface

- `canonical_json` and `parse_canonical_json` provide exact RFC 8785 bytes,
  reject duplicate members and alternate encodings, preserve Unicode code
  points without normalization, and enforce the shared safe-number model.
- `base64url_encode` and `base64url_decode` enforce the sole unpadded RFC 4648
  URL-safe representation and optional decoded length.
- `ArtifactIdentity` and `resolve_artifact_identity` implement all 16 rows of
  HLD §4, including dynamic event, shard, and export paths and their
  repository/branch relations.
- `segment` and `override_key` implement the exact path and projection-key
  derivations.

### Evidence

`core/tests/test_conformance_artifacts.py` consumes
`core/tests/vectors/artifact-identities-v1.json` and covers every identity row,
dynamic relation failures, JCS rejection, segment bytes, and override-key
binding. Later slices must reuse these primitives rather than recoding JSON,
base64url, path, or digest rules.

### Deferred boundary

Encryption, semantic payload schemas, repository transport, and TypeScript
parity were intentionally excluded. M1-2 owns encryption; M1-4 onward own
semantic contracts; M1-13 onward own the edge implementation and M1-19 the
cross-runtime gate.

## M1-2 — Version 1 encrypted-artifact envelope

Status: Landed in PR #13.

### Implemented surface

- `artifact_aad` derives exact metadata bytes from a caller-derived
  `ArtifactIdentity`.
- `encrypt_artifact` and `decrypt_artifact` implement A256GCM with a 32-byte
  data key, 16-byte `kid`, 12-byte random nonce, and ciphertext-plus-tag bytes.
- JSON helpers require exact JCS plaintext; CSV handling requires exact UTF-8,
  structural validity, no BOM, and formula-neutralized cells.
- Format, context, unknown-key, and authentication failures are distinct public
  exception classes. Key mappings are used only after exact membership checks;
  mapping fallback behavior cannot invent a key.

### Evidence

`core/tests/test_conformance_envelope.py` consumes the independent fixed-key
`artifact-envelope-v1.json` vector, round-trips every artifact identity, and
rejects malformed, non-canonical, padded, wrong-length, wrong-context,
wrong-key, and tampered inputs.

### Deferred boundary

Wrapped keys and keyring ordering are M1-3. Payload semantics are M1-5,
M1-10, and M1-11. Hosted key custody and rotation workflows belong to M5/M6;
the edge keyring implementation belongs to M1-14.

## M1-3 — Wrapped-key copies and canonical keyrings

Status: Planned. Depends on M1-1 and M1-2.

Governing references: HLD §4 “Wrapped key copies,” §6.10.2, and §6.10.6
wrapped-key vector obligations; `REQ-REC-1`, `REQ-REC-7`, `REQ-SEC-2`, and
`REQ-SEC-9`.

### Owned surface

Add `keyrings.py` with immutable `WrappedKeyCopy` and `Keyring` models and:

- `wrap_key_copy(data_key, *, project_id, capability, data_kid, wrapper_id,
  wrapper_generation, wrapping_key) -> WrappedKeyCopy`;
- `wrapped_key_aad(copy) -> bytes`;
- `unwrap_key_copy(copy, *, expected_project_id, expected_capability,
  wrapping_keys) -> bytes`;
- `encode_keyring(copies) -> bytes`; and
- `decode_keyring(data, *, expected_project_id, allowed_capabilities,
  allowed_wrappers, known_generations) -> Keyring`.

`wrapping_keys` is an exact mapping keyed by `(wrapper_id,
wrapper_generation)`. Lookup has no default or fallback. Decoding validates
structure and context; unwrapping additionally authenticates one selected copy.

The capability enum is exactly `records | coverage`. Wrapper IDs are exactly
`portal-records`, `portal-coverage`, `enforcer-coverage`, `control`, and
`recovery`. The HLD names the wrapper enum and states each holder's
capability in prose rather than as a pair table; this LLD closes the derived
pairing so a wrong `(capability, wrapper_id)` binding is rejected by
construction:

- records: `portal-records`, `control`, `recovery`;
- coverage: `portal-coverage`, `enforcer-coverage`, `control`, `recovery`.

The wrapped plaintext is exactly 32 bytes. Key and key-ID lengths reuse the
landed envelope constants. Keyring entries sort by lexicographic byte order of
their individual JCS encodings and reject duplicate `(capability, data_kid,
wrapper_id)` identities even when generations differ.

### Acceptance evidence

`test_conformance_keyrings.py` and `wrapped-key-v1.json` must prove:

- exact wrap AAD, fixed-nonce ciphertext-plus-tag, individual object bytes, and
  multi-entry keyring bytes;
- records and coverage round trips through every valid wrapper pair;
- rotation with multiple data `kid` values and wrapper generations;
- canonical ordering independent of input order;
- rejection of unknown/extra/missing fields, algorithms, versions, wrappers,
  capabilities, and generations;
- rejection of duplicates, wrong project/capability/wrapper relation, padded or
  wrong-length encodings, non-canonical bytes, unknown keys, and tampering; and
- no raw data or wrapping key in encoded keyrings or exception text.

Run the focused keyring tests and the complete Python suite. Create
`design/verification-matrix.md` if it does not yet exist, record the landed
M1-1/M1-2 evidence, and add M1-3's automated rows.

### Non-goals and PR boundary

No service-root storage, network unwrap endpoint, bootstrap manifest, data-key
rotation transaction, recovery prompt, or repository write. The PR contains
only the Python keyring contract, exports, vectors, tests, and traceability.

## M1-4 — Event identity and authorization vocabulary

Status: Planned. Depends on M1-1.

Governing references: HLD §5.1 identifier derivation and complete
event/action-to-authorization table, §6.8 authorization matrix, and §6.10.6;
`REQ-REC-4`, `REQ-REC-8`, and `REQ-SEC-6`.

### Owned surface

Add `event_identity.py` with immutable `EventIdentity` and
`AuthorizationEvidence` models and:

- `stable_actor_identity(actor) -> dict`;
- `new_operation_nonce() -> str` using exactly 16 CSPRNG bytes;
- `derive_automation_nonce(rule_event_id, subject_user_id, result,
  prior_materialization_event_id) -> str`;
- `derive_github_retry_nonce(repository_id, check_kind, check_identity,
  github_delivery_id) -> str`;
- `derive_scope_terminal_nonce(request_event_id, terminal_type) -> str`;
- `derive_event_identity(project_id, operation_nonce, actor, event_type,
  target, payload, confirmed_canonical_oid) -> EventIdentity`;
- `event_path(event_id) -> str`; and
- `validate_authorizations(event_type, target, payload, actor,
  authorizations) -> tuple[AuthorizationEvidence, ...]`.

`EventIdentity` carries canonical `operation_nonce`, `idempotency_key`,
`operation_sha256`, `event_id`, and event path. Domain labels and zero bytes are
literal HLD values. Login snapshots, recording time, DraCLA version, and
authorization evidence are excluded from the stable operation digest exactly
as specified.

Authorization validation uses one checked-in literal table. It does not infer
an operation from an event-name prefix or accept GitHub UI labels. Connection
and owner-transfer events require their exact seven evidence rows;
key activation requires one row per affected project repository; scope chains
retain one exact operation/resource identity. Set members use JCS lexical order.

### Acceptance evidence

Vectors cover both actor variants, random and all deterministic nonce domains,
the request/activation/abandonment pairwise-distinct rule, every literal
operation/resource/authority row, all scope alternatives, stable-login
behavior, exact digests and paths, and changed-payload key reuse. They reject
unknown tokens, wrong pairings, unordered/duplicate evidence, actor violations,
unsafe IDs, caller-supplied child identities, and an injected child-digest
collision.

The focused identity/authorization tests and complete Python suite must pass;
traceability gains exact automated evidence rows.

### Non-goals and PR boundary

No target/payload union, chronological replay, GitHub authority query, event
encryption, or append. The PR owns only identity and closed authorization
vocabulary primitives, vectors, tests, exports, and traceability.

## M1-5 — Closed revision-13 event schema and semantic validation

Status: Planned. Depends on M1-2 and M1-4.

Governing references: HLD §5.1 in full, §5.2 step 0 and side-artifact table,
§5.5 local lifecycle fields, §6.5 snapshot relations, and §6.10.6 event
vectors; all event-bearing requirement families listed in §2.

### Owned surface

Add `events.py` with `ValidatedEvent`, named nested-object models, and:

- `validate_event(value, *, expected_project_id=None,
  expected_path=None) -> ValidatedEvent`;
- `parse_event_jcs(data, *, expected_project_id=None,
  expected_path=None) -> ValidatedEvent`; and
- `required_side_artifacts(event) -> tuple[SideArtifactRequirement, ...]`.

The validator implements all 27 HLD §5.1 event rows and every named nested
object. It validates exact top-level fields, actor rules, authorization rows,
confirmed-head rule, event-specific target/payload members, scalar formats,
ordered sets, configuration fields/confirmations, repository and bootstrap
relations, and the reserved Entity rejection.

It recomputes identity through M1-4 and requires `operation_nonce`,
`idempotency_key`, `operation_sha256`, `event_id`, and optional path to agree.
Locally decidable cross-field relations are checked here. Relations requiring
prior canonical state—such as publication existence, one scope terminal,
successor state, source withdrawal, and current configuration—are checked by
M1-6/M1-7 replay and never guessed locally.

`required_side_artifacts` returns the closed §5.2 set for agreement publication,
project connection/configuration, and affected materialization generations. It
specifies kind and deterministic path; M1-9 freezes and validates the bytes.

### Acceptance evidence

`events-v1.json` contains at least one valid event for every type, both actor
variants where legal, every named object alternative, all authorization shapes,
and each side-artifact declaration. Negative cases change one relation at a
time: missing/extra/cross-row fields, wrong actor/authorization/head, malformed
scalar or set, identity/path mismatch, wrong snapshot/config relation, invalid
UTF-8/JCS, unsafe numbers, and both reserved Entity names.

Focused event tests and the complete Python suite pass. A corpus-coverage test
compares the vector event-type set to the implementation's closed registry so a
new or omitted row cannot pass unnoticed.

### Non-goals and PR boundary

No chronological fold, transport, encryption orchestration, projection bytes,
or repository write. The PR contains the complete local event contract and no
partial “common events first” parser.

## M1-6 — Canonical replay foundation and project/contributor lifecycle

Status: Planned. Depends on M1-5.

Governing references: HLD §§5.1, 5.2 ordering, 5.3 tuple cutoff, 5.5, 6.1,
6.2, and 6.5; `REQ-CONFIG-1..4`, `REQ-AGR-1..2`, `REQ-SIGN-4..5`,
`REQ-REV-1..5`, and `REQ-REC-3..6`.

### Owned surface

Add `replay.py` with immutable `CanonicalEventRecord`, `ReplayState`,
`ReplayResult`, and:

- `initial_replay_state(project_id, base_commit_oid) -> ReplayState`;
- `apply_event(state, record) -> ReplayState`;
- `replay_events(project_id, base_commit_oid, records) -> ReplayResult`; and
- explicit query helpers for project lifecycle, current configuration, active
  agreement/accepted versions, and the latest contributor tuple decision.

`CanonicalEventRecord` binds one `ValidatedEvent` to its commit OID and single
parent OID. Input order is canonical commit ancestry supplied by the caller;
each parent must equal the replay state's current head before the event is
applied. This lets replay validate contributor `confirmed_canonical_oid`
against the immutable state actually confirmed without performing Git I/O.
Replay never sorts by timestamp, event ID, or path. It rejects a wrong project,
broken ancestry, duplicate event ID, idempotency-key/fingerprint conflict,
invalid event, impossible transition, and any history-dependent relation
failure as corruption rather than filtering the event.

This slice implements project connection and owner transfer, successor closure,
configuration and key activation, agreement publication/activation,
acceptance, revocation, supersession, immutable recipient/one-agreement rules,
active/accepted-version semantics, and forward-looking tuple cutoff.

`ReplayResult` distinguishes a valid fold from corruption and carries the exact
last event identity needed by projection generations. It does not claim a Git
commit OID unless the caller supplies an event/commit binding.

### Acceptance evidence

Replay vectors cover empty/pre-connect state, initial connection, configuration
and key changes, multiple publication/activation modes, acceptance,
revocation, immediate re-signing, correction supersession, recipient and tuple
isolation, owner transfer, successor closure, and allowed post-successor
maintenance. They prove timestamps cannot reorder outcomes and replaying the
same valid sequence is deterministic.

Negative sequences cover duplicate/conflicting identities, activation before
publication, inactive signing, wrong recipient/project/agreement, acceptance
before connection, invalid supersession, non-current confirmed state, illegal
post-successor activity, conflicting successor, and version revival after a
superseding activation.

### Non-goals and PR boundary

Administrative source unions, scope terminals, readers, exemptions, and
overrides are M1-7. No Git history traversal, commit creation, projection
serialization, or recovery driver enters this PR.

## M1-7 — Administrative, scope, exemption, reader, and override replay

Status: Planned. Depends on M1-6.

Governing references: HLD §§5.1, 5.3, 5.5, 6.8, and 7.1's canonical scope
truth; `REQ-CONFIG-3`, `REQ-CONFIG-5`, `REQ-CHECK-2`, `REQ-REC-8`, and
`REQ-SEC-6`.

### Owned surface

Complete `ReplayState` and `apply_event` for every remaining revision-13 type:

- requested/activated/abandoned enforcement scope and exactly one terminal per
  request;
- individual, bot, snapshot, and continuous-team exemption source unions;
- individual, snapshot, and continuous-team records-reader source unions;
- standing-rule configuration, materialization observations, and independent
  source/rule withdrawal;
- head-specific multi-subject overrides and whole-grant withdrawal; and
- retry requests and remaining audit-only events.

Add query helpers that return the effective scope, source-aware exemption,
source-aware reader authority, active override entries, current standing rules,
and the exact event/source identities supporting each result. Effective booleans
are derived from source unions, never independently stored truth.

Automation transitions validate their standing rule, subject, team,
membership evidence, prior materialization identity, deterministic nonce, and
result. Scope terminal events repeat the request's exact desired scope,
operation token, resource identity, and authorization relation. Override
entries retain every tuple input needed for M1-10 to recompute the key.

### Acceptance evidence

Table-driven vectors cover every remaining type, every authorization operation,
all scope operations, multi-source addition/withdrawal, selected-member
snapshots, continuous-team add/withdraw/add, independent batch-source
withdrawal, override grant/withdrawal, and succeeded-project allowed/forbidden
actions. Full replay and incremental `apply_event` must produce identical
states.

Negative sequences include two scope terminals, mismatched repeated scope,
unknown or withdrawn source/rule, stale materialization predecessor, wrong
team/subject/evidence, partial batch identity, boolean-overwrite behavior,
wrong override grant relation, and any forbidden post-successor event.

### Non-goals and PR boundary

No live GitHub team query, registry mutation, projection encoding, form signing,
or repository write. This PR closes the Python canonical fold; later slices
consume it without adding business-event semantics elsewhere.

## M1-8 — Authenticated action forms and replay-stable no-op bindings

Status: Planned. Depends on M1-4, M1-5, and M1-7.

Governing references: HLD §5.4 action-form object and Table 5.4-A, §6.8, and
§6.10.6 contributor/administrative idempotency and form-envelope vectors;
`REQ-SIGN-2`, `REQ-SIGN-5`, `REQ-REV-1`, `REQ-REV-5`, and `REQ-SEC-4`.

### Owned surface

Add `action_forms.py` with `ActionForm`, `VerifiedActionForm`,
`ActionFormContext`, and:

- `encode_action_form(payload, *, key) -> str`;
- `verify_action_form(token, *, keys, context) -> VerifiedActionForm`;
- `validate_terminal_noop(form, event, *, expected_project_id,
  expected_confirmed_oid) -> None`; and
- `form_action_spec(event_type) -> FormActionSpec` over the closed Table 5.4-A
  registry.

`ActionFormContext` supplies current time, parent session absolute expiry and
JTI, authenticated user, project, expected action type, operation nonce,
confirmed canonical OID, and recomputed operation digest. Key eligibility is an
exact mapping of active or still-eligible predecessor `kid` values; no fallback
lookup is allowed.

Encoding is exactly one dot joining unpadded base64url JCS payload and a
32-byte HMAC-SHA-256 tag over the HLD domain label plus payload. Verification
requires canonical bytes before constant-time tag comparison, then exact
session/actor/project/operation/head/time binding. Expiry is absolute and
bounded by both 7h55m from issuance and the parent session.

Terminal no-op validation accepts only the event types and exact desired
effects allowed by the registry. A scope action validates the repeated desired
scope directly on `enforcement_scope_activated`. Internal automation and
terminal-only event types are not form actions.

### Acceptance evidence

Vectors cover every Table 5.4-A row and terminal alternative, fixed JCS/tag
bytes, active/predecessor keys, exact expiry boundaries, constant-time
verification path, and old no-op forms after later state changes. They prove a
non-no-op form requires the exact current head while a bound terminal no-op
returns the same result and never becomes preparable.

Reject wrong separator count, padding, length, canonical bytes, version,
algorithm, key, tag, context, time, event/action pair, terminal type/effect,
internal automation type, and stale non-no-op head.

### Non-goals and PR boundary

No OAuth cookie, session store, HTML form, canonical event read, authorization
query, or mutation driver. Repository/portal code later fetches the bound event
and passes it to these pure validators.

## M1-9 — Prepared-operation, in-flight, and decision-fence contracts

Status: Planned. Depends on M1-2, M1-5, and M1-8.

Governing references: HLD §5.2 side-artifact package, §5.4 in full, and
§6.10.6 mutation serialization/crash vectors; `REQ-CHECK-3..5`, `REQ-REC-3`,
and `REQ-REC-6`.

### Owned surface

Add `operations.py` with closed frozen models for every persisted state:

- prepared cell: `idle`, `prepared`, `appending`, `terminal`;
- decision fence: `idle`, `mutation`, `success_reserved`;
- in-flight marker: zero or one subject-scoped or project-wide operation; and
- side artifact: exact kind, path, bytes, and SHA-256 relation.

Expose strict encode/decode validators plus pure transition functions for
prepare, append claim, terminal result, cell clear, mutation-fence acquire and
release, success reservation and release, marker open and close, and
cross-binding validation. Each transition accepts the complete validated prior
state and exact owner identity and returns a new immutable state or a typed
conflict/corruption error. It performs no I/O.

The append claim uses the exact HLD domain and JCS fields. Side artifacts are
path-sorted, duplicate-free, complete for their event, digest-bound, and carry
exact plaintext bytes. A non-idle state cannot be replaced by another
operation. Identical retries return the existing state. Generation increments
occur only on the HLD transitions that specify them.

Cross-binding requires exact agreement among operation ID/fingerprint/event,
prepared commit/blob/generation, marker scope, and mutation fence. Age and
`started_at` are display evidence only and authorize no transition. Size
validation accepts a numeric profile supplied by M1-11; until then tests use an
explicit finite fixture rather than a production default.

### Acceptance evidence

Pure state-machine vectors cover all valid transitions, identical retries,
every terminal result, append-right ownership, subject/project-wide scopes,
marker started-at preservation, and all cross-bindings. Crash fixtures model
every HLD pause by persisting one state tuple and asking which transitions are
legal next.

Negative cases prove another operation cannot replace Alice or create a second
marker, a terminal no-op/conflict defeats a delayed append claimant, appending
must repair forward, stale/mismatched identities fail closed, malformed scope
fails, and no timeout clears anything.

### Non-goals and PR boundary

No GraphQL `createCommitOnBranch`, Git Database append, retry loop, scheduler,
Worker driver, or check publication. M3/M5 bind these pure transitions to exact
branch heads and remote writes.

## M1-10 — Coverage projection contracts and bounded shards

Status: Planned. Depends on M1-7 and M1-9.

Governing references: HLD §§4, 5.3, 5.4 ordinary-check scope, 6.5, 6.8, and
§6.10.6 override/scope vectors; `REQ-CHECK-1..5`, `REQ-REC-6`,
`REQ-SEC-1..2`, and `REQ-PORTAL-5`.

### Owned surface

Add `coverage.py` with validated models for coverage source, active agreement,
exemption fold, in-flight marker, decision fence, and packed user shard, plus:

- `materialize_coverage(state, operation_state, *, canonical_oid, built_at,
  dracla_version) -> CoverageProjection`;
- `coverage_delta(before, after) -> CoverageDelta`;
- `validate_coverage_projection(projection, *, expected_project_id,
  expected_canonical_oid=None) -> None`;
- `coverage_shard(github_user_id, *, shard_count) -> int`; and
- `evaluate_subject(projection, subject, agreement_id,
  override_context=None) -> CoverageDecision`.

`CoverageProjection` always has exactly 32 user shards, format 1, one source,
one active-agreement object, one exemption fold, one marker, and one fence.
`operation_state` is the validated M1-9 marker/fence pair; it is not inferred
from canonical replay. `built_at` and `dracla_version` are the only
`source.enc.json` members not derivable from replay, so callers supply them
explicitly and vectors fix them; materialization has no wall-clock or
package-version default. Materialization is therefore a pure function of valid
replay state, that explicit operational state, and those supplied source
values. `shard_count` is the value read from the same committed
`agreements/active.enc.json` revision as the shard layout, never inferred from
which files exist; format 1 requires 32 and any other value fails closed. The
semantic plaintext contains no legal name, email, confirmation, exact reason,
exemption provenance, reader authority, or Entity coverage.

The tuple cutoff, accepted-version fold, source-aware exemption, and active
override relation follow the HLD exactly. Override keys and repeated identities
are recomputed. A malformed entry cannot be ignored in favor of an otherwise
covered row. `CoverageDelta` identifies affected logical files/shards but does
not write them.

### Acceptance evidence

Vectors materialize deterministic empty and populated projections, all 32
shard boundaries, multiple agreement versions, revocation/re-signing,
superseding/non-superseding activation, exemptions, overrides, lifecycle
successor state, subject/project-wide marker effects, and idle/reserved fences.

Negative cases cover wrong format/count/shard, missing/unknown fields, unsafe or
duplicate IDs, malformed scope, source/event mismatch, invalid override key or
repeated tuple, forbidden private fields, missing lifecycle relation, and every
fail-closed marker/fence inconsistency.

### Non-goals and PR boundary

No encryption orchestration, GitHub blob reads, branch writes, subject
resolution, routing, check output, or publication reservation. The PR owns
plaintext contracts and deterministic bytes before M1-2 envelope wrapping.

## M1-11 — Records-derived contracts, generations, and release profile

Status: Planned. Depends on M1-7, M1-9, and M1-10.

Governing references: HLD §§4, 5.1 side artifacts, 5.4 retry-exhaustion and
marker state, 6.6 dashboard/derived contracts, 6.10.4 reader authority, 6.10.6
shard/generation obligations, and §9.2 capacity envelope; `REQ-REC-5..6`,
`REQ-DASH-1..5`, `REQ-SEC-1..3`, and `REQ-OPS-3`.

### Owned surface

Add `derived.py` with closed models for project configuration,
materialization-generations, derived state, dashboard index rows, exact status
detail, reader-authority sources, and request-scoped export metadata. Expose:

- `materialize_derived(state, operation_state, *, profile) -> DerivedPlaintext`;
- `assemble_derived_projection(plaintext, *, canonical_oid, generations,
  encrypted_shards, profile) -> DerivedProjection`;
- `derived_delta(before, after) -> DerivedDelta`; and
- `validate_derived_projection(projection, *, generations,
  encrypted_shards, profile) -> None`.

`operation_state` is the same validated M1-9 marker/fence pair M1-10 consumes,
and it is required rather than optional. The §6.6 index status
enum is exactly `current | exempt | revoked | superseded | indeterminate`, and
`indeterminate` has three locked triggers that no single input can supply:

- the subject sits in `inflight.ops` — read from the validated marker, whose
  subject-scoped or project-wide scope selects the affected rows;
- an operation exhausted its retries — §5.4 makes this observable only as that
  operation's still-unsettled `mutation` fence and any marker it opened, never
  as a separate flag or an elapsed-time judgement; and
- replay could not resolve the record — read from the M1-6/M1-7 fold.

Canonical replay alone therefore cannot produce the required status, so the
materializer takes the operational state explicitly and fails closed on it: a
row is `indeterminate` when the marker holds a matching entry or an unsettled
`mutation` fence covers it, and such a row must never keep reporting its
previous `current`, `revoked`, `exempt`, or `superseded` value.

Scope decides which rows are affected, and only these two states affect any.
A `mutation` fence or marker with `project_wide: true` covers every row; a
subject-scoped one covers exactly its listed subjects and leaves every other
row at its replayed status. `success_reserved` is a non-idle fence that is
deliberately not a trigger: §5.4 requires `inflight.ops` to be empty under it
and leaves coverage unchanged, so an authoritative merge-group publication in
progress must leave every row at its exact replayed status. Treating any
non-idle fence as indeterminate would wrongly blank the dashboard during each
successful merge-group check.

Status detail carries the same result with its exact reason; the index keeps
only the enum value. Missing or malformed operational state is a rejection, not
an implicit idle.

There are exactly 32 shards for index, status detail, and reader authority.
Index/status shard selection is `github_user_id % 32`; reader-source selection
uses the first five bits of the source-event-ID digest. Semantic materialization
is a deterministic function of the replay fold and that explicit operational
state. The assembler receives the exact already-created M1-2
encrypted envelope bytes for all shards, then creates the derived-state
plaintext carrying each class generation and the SHA-256 of every encrypted
shard envelope. It does not re-encrypt or regenerate a shard while calculating
its digest. Validation requires canonical and derived generations, selected
envelope sizes, shard digests, format, and counts to agree.

Add `release_profile.py` and checked-in `release-profile-v1.json`. The schema is
closed and contains finite positive numeric limits for at least:

- complete prepared-operation cell bytes;
- coverage, index, status-detail, and reader-authority shard ciphertext bytes;
- members per reader source;
- bulk shards/fan-out per operation;
- bounded mutation retries per operation, which §5.4 requires to be finite so
  exhaustion is an explicit unresolved outcome rather than an unbounded wait;
- total subrequests per request, which §9 requires to stay below 50 and §5.3
  relies on to keep an ordinary check under the Workers Free ceiling; and
- active continuous reader rules, fixed to 10.

It also fixes all shard counts to 32 and format/schema versions to 1. No value
may be `unlimited`, omitted, zero, or an unevaluated placeholder. Values not
fixed numerically by the HLD are selected conservatively from checked-in
boundary tests and capacity evidence in this PR. The retry and subrequest
limits are the remaining two members of §9's installed-profile list; §9.2's
capacity model is their evidence, and a subrequest limit at or above 50 is
rejected rather than recorded. If a value changes a locked product behavior
rather than bounding the documented behavior, stop for design review.

Bulk derived publication remains fail closed until all affected shards and the
final generation are complete. Ordinary subject and reader deltas identify
only their bounded affected shards plus state. Acceptance/revocation canonical
and coverage truth do not become capped by private-derived overflow.

### Acceptance evidence

Vectors cover each closed schema, all shard boundaries/classes, source unions,
all dashboard statuses, exact/private data separation, canonical/derived
generation agreement, envelope digest tables, affected-only deltas, incomplete
bulk publication, and every profile limit at `limit-1`, `limit`, and `limit+1`,
including the retry and subrequest ceilings.
Status fixtures pair one replay fold with each operational state and prove that
an open subject-scoped marker makes only its own subjects `indeterminate`, a
project-wide marker or mutation fence makes every row `indeterminate`, an
unsettled `mutation` fence after retry exhaustion holds that status until the
operation settles, and that both an idle fence with an empty marker and a
`success_reserved` fence with an empty marker return the exact prior statuses
including `current` and `revoked`.

Negative cases cover a stale `current` or `revoked` row published under a
matching marker entry or covering `mutation` fence, a row wrongly blanked to
`indeterminate` under `success_reserved` or outside a subject-scoped mutation's
listed subjects, `success_reserved` presented with a non-empty `inflight.ops`,
missing or malformed operational state, a marker whose
scope does not match the rows it affects, an unknown status value, stale
generations, missing/extra/oversize shards, digest
mismatch, wrong class/count/profile, private fields in the index, incomplete
fan-out, too many continuous rules, and non-finite/placeholder profile values.
Capacity evidence and chosen limits are recorded in traceability.

### Non-goals and PR boundary

No dashboard endpoint, proof JWS, live reader membership check, export
renderer/streamer, hosted job, repair driver, or repository write. M3 owns
rebuild/export engines; M5 owns private-read authorization; M7 owns UI and final
capacity acceptance.

## M1-12 — Shared conformance corpus and vector generator

Status: Planned. Depends on M1-3, M1-5, M1-8, M1-10, and M1-11.

Governing references: HLD D8 and §6.10.6 shared-vector obligations;
`REQ-OPS-1` and `REQ-VERIFY-1`.

### Owned surface

Move the complete unchanged corpus from `core/tests/vectors/` to
`conformance/vectors/`. Vector content does not change in this slice; only its
location and the code that reads it do. Add a manifest containing each file's
SHA-256 and declared contract version. Python tests fail if the manifest, the
files, or the case registries disagree.

Add `vectors.py`, the Python generator that produces every checked-in file from
the authoring modules. Generation is deterministic: fixed test-only keys,
nonces, timestamps, and IDs are inputs to the generator, never production
defaults. Re-running the generator on an unchanged tree reproduces
byte-identical files, and a `--check` mode fails when a checked-in file differs
from what the current implementation would emit. This is what keeps the corpus
honest as later slices change behavior.

For every incremental contract the edge will execute, the generator emits
before-state, input, and after-state triples by running the M1-10 and M1-11
reference materializers at each end. It records no incremental implementation of
its own. These triples are the sole oracle for M1-17 and M1-18.

### Acceptance evidence

Tests prove the relocation preserved every case byte for byte, the manifest
digests match, `--check` fails on a mutated vector and on a mutated
implementation, and every triple's after-state equals a full reference
materialization from the same replay state. A registry test proves each
authoring slice's contract has at least one file and that no file is orphaned.

### Non-goals and PR boundary

No TypeScript, no packaging change, no contract change. If generating a vector
reveals a missing or ambiguous contract, the fix belongs to that authoring
slice, not here.

## M1-13 — TypeScript byte foundations and artifact envelopes

Status: Planned. Depends on M1-12.

Governing references: HLD D8 and §4 in full; `REQ-SEC-1`, `REQ-SEC-9`, and
`REQ-OPS-1`.

### Owned surface

Create `api/src/conformance/` with `canonical.ts`, `encoding.ts`,
`artifacts.ts`, `envelope.ts`, and `releaseProfile.ts`. Implement RFC 8785
encode/decode with the shared safe-number model, unpadded base64url, the
complete §4 identity table with dynamic path tokens, artifact AAD, A256GCM
encrypt/decrypt over Web Crypto, and closed release-profile parsing with size
enforcement.

Add deterministic `test:conformance` and `typecheck` scripts to the `api`
package. No test shells out to Python, and Python does not shell out to
TypeScript. The checked-in corpus is the only shared oracle.

### Acceptance evidence

Both runtimes consume every applicable case. Exact byte cases compare
byte-for-byte; rejection cases compare stable error categories. Mutation cases
change project, purpose, path, kind, schema, canonical encoding, padding, and
ciphertext/tag, and both runtimes reject every one.

### Non-goals and PR boundary

No keyrings, events, forms, projections, routing, or Worker wiring.

## M1-14 — TypeScript wrapped-key creation, unwrap, and keyrings

Status: Planned. Depends on M1-13.

Governing references: HLD §4 wrapped key copies and §6.10.2 bootstrap;
`REQ-REC-1`, `REQ-REC-7`, `REQ-SEC-2`, and `REQ-SEC-9`.

### Owned surface

Add `keyrings.ts` implementing the wrap AAD, `wrap_key_copy`, `unwrap_key_copy`,
and canonical keyring parse/encode against M1-3's contract.

Creation is included deliberately, not only validation and unwrap: §6.10.2 sends
each raw project key to the portal and enforcer services, which return their
capability-specific wrapped copies. Those services are Workers, so the wrapping
byte contract executes at the edge and must agree with Python exactly.

### Acceptance evidence

Both runtimes reproduce the fixed-nonce wrapped-key bytes, every valid
capability/wrapper pair, multi-entry keyring ordering, and rotation across data
`kid` values and wrapper generations. Both reject unknown wrappers, wrong
capability pairing, duplicates, wrong project binding, unknown generations, bad
lengths, and tampering. Tests prove no raw data or wrapping key appears in
encoded output or error text in either runtime.

### Non-goals and PR boundary

No bootstrap orchestration, service root storage, network endpoint, or rotation
transaction. Those are M5 and M6 drivers over this contract.

## M1-15 — TypeScript event and side-artifact package validation

Status: Planned. Depends on M1-13.

Governing references: HLD §5.1 in full, §5.2 step 0 and side-artifact table,
and §5.4 validation-precedes-every-write; `REQ-REC-3..4`, `REQ-REC-8`, and
`REQ-SEC-6`.

### Owned surface

Add `events.ts` implementing M1-5's contract for the write path: the closed
event union, every named nested object, actor and authorization rules,
identity recomputation through the M1-4 derivations, and
`required_side_artifacts`.

This exists because §5.4 makes the portal Worker the canonical writer and
requires an event and its complete side-artifact package to be fully validated
before the prepared cell is written. §9 places Python in Actions and the CLI,
so there is no synchronous Python boundary for that Worker to call.

TypeScript validates one event against supplied context. It does not fold
history: relations requiring prior canonical state stay Python-only, and the
edge treats them as inputs it is given rather than facts it derives.

### Acceptance evidence

Both runtimes accept every valid case for all 27 event types and reject every
negative case, including cross-row fields, wrong actor or authorization,
malformed scalars and sets, identity or path mismatch, invalid JCS, unsafe
numbers, and both reserved Entity names. A registry-agreement test proves the
TypeScript closed event set equals the Python one, so a row added on one side
fails the other.

### Non-goals and PR boundary

No replay, transport, append, encryption orchestration, or history-dependent
relation.

## M1-16 — TypeScript action forms and operation-state contracts

Status: Planned. Depends on M1-13 and M1-15.

Governing references: HLD §5.4 in full and Table 5.4-A; `REQ-SIGN-2`,
`REQ-SIGN-5`, `REQ-REV-1`, `REQ-REV-5`, and `REQ-SEC-4`.

### Owned surface

Add `actionForms.ts` implementing M1-8's encode/verify, the closed Table 5.4-A
registry, and terminal no-op binding, and `operations.ts` implementing M1-9's
prepared-cell, in-flight-marker, and decision-fence validation and pure
transitions.

Both are edge-executed: the portal Worker verifies the submitted form and then
drives the prepared-cell, fence, and marker transitions itself.

### Acceptance evidence

Both runtimes agree on every Table 5.4-A row and terminal alternative, fixed
JCS and tag bytes, active and eligible-predecessor keys, exact expiry
boundaries, and constant-time verification. Both reject wrong separator count,
padding, length, version, algorithm, key, tag, context, time, event/action pair,
terminal type, and internal automation type. State fixtures agree on every legal
transition, identical retry, and crash-pause case, and both prove age clears
nothing.

### Non-goals and PR boundary

No OAuth, session store, HTML rendering, GitHub CAS transport, or retry driver.

## M1-17 — TypeScript incremental coverage updates and subject decision

Status: Planned. Depends on M1-13 and M1-16.

Governing references: HLD §5.3 in full, §5.4 step 7 and ordinary-check scope;
`REQ-CHECK-1..5`, `REQ-REC-6`, and `REQ-SEC-1..2`.

### Owned surface

Add `coverage.ts` implementing the coverage schemas, `coverage_shard`, subject
decision, and the incremental read-modify-write update the Worker performs.

§6.6 states the normal Worker path never performs a full replay, and §5.3
requires a shard write to be read-modify-write against one immutable coverage
head. The edge therefore needs an incremental contract, which M1-10's reference
materializer defines by equivalence rather than by a second algorithm: applying
the update to a validated before-state must produce exactly the after-state the
reference materializer produces from the corresponding replay state.

A malformed existing shard is never partially preserved. The update validates
the whole before-state, applies only its own keys, and revalidates the result
before it is encoded.

### Acceptance evidence

Every M1-12 triple round-trips: TypeScript applies the input to the before-state
and reproduces the after-state byte for byte. Cases cover all 32 shard
boundaries, multiple agreement versions, revocation and re-signing, superseding
and non-superseding activation, exemptions, overrides, successor state, and
subject-scoped versus project-wide markers. Negative cases cover wrong
format or count, malformed before-state, invalid override key, forbidden private
fields, and every fail-closed marker and fence inconsistency, including a
`success_reserved` fence with a non-empty in-flight map.

### Non-goals and PR boundary

No GitHub blob read or branch write, no subject resolution, no routing, no check
output. M4 and M5 bind this contract to real commits.

## M1-18 — TypeScript incremental records-derived updates and portal reads

Status: Planned. Depends on M1-14 and M1-17.

Governing references: HLD §6.6 dashboard and derived contracts, §6.10.4 reader
authorization; `REQ-DASH-1..5`, `REQ-REC-5..6`, and `REQ-SEC-1..3`.

### Owned surface

Add `derived.ts` implementing the incremental records-derived update the Worker
performs on the `derived` branch and the portal read validation of §6.10.4.

The update covers one ordinary subject mutation touching at most one index
shard, one status shard, and the state file; one reader-source mutation
touching one source shard and the state file; and bounded bulk fan-out that
publishes its new class generation only in the final state commit and fails
closed until then.

Read validation covers the derived state file, all 32 reader-authority shards,
canonical-versus-derived generation agreement, envelope digests, and profile
size limits, denying on any mismatch.

### Acceptance evidence

Every M1-12 derived triple round-trips byte for byte, including
`indeterminate` rows produced under a covering marker or `mutation` fence and
exact prior statuses preserved under `success_reserved`. Cases cover all shard
classes and boundaries, source unions, every dashboard status, affected-only
deltas, and incomplete bulk publication. Negative cases cover stale generations,
missing, extra, or oversize shards, digest mismatch, private fields in the
index, and incomplete fan-out.

### Non-goals and PR boundary

No proof issuance or signing, no live membership check, no export renderer, no
hosted job, no repair driver. M5 owns the authorization flow over this contract.

## M1-19 — Cross-runtime conformance gate and M1 closure

Status: Planned. Depends on M1-15 and M1-18.

Governing references: HLD D8, §6.10.6 in full; `REQ-OPS-1`, `REQ-OPS-6`,
`REQ-SEC-10`, and `REQ-VERIFY-1`.

### Owned surface

Add the gate that runs both runtimes over the complete corpus and fails if any
applicable case is unconsumed by either side. A manifest coverage test proves
every HLD §4 identity row, wrapper pair, Table 5.4-A row, event type, and
edge-owned closed schema is represented and claimed by both runtimes.

Required commands are:

```text
.venv/bin/python -m unittest discover -s core/tests -t . -v
.venv/bin/python -m dracla.conformance.vectors --check
npm --prefix api run typecheck
npm --prefix api run test:conformance
```

The slice also runs a wheel build/install smoke test proving the Python
conformance package imports and exposes its declared public surface. Shared
vectors remain source-test assets unless packaging metadata explicitly declares
otherwise.

### Acceptance evidence

Cross-runtime mutation tests change project, purpose, path, kind, schema,
capability, key and generation, payload-to-path relation, canonical encoding,
padding, ciphertext and tag, action context, projection format and count, and
supported version. Both runtimes reject every mutation. M1 traceability has no
unowned M1 contract and no missing automated evidence.

### Non-goals and PR boundary

No Worker webhook, routing, OAuth, portal, GitHub API, Pages asset, or deploy
configuration. This PR adds the gate, packaging checks, and closure evidence
only.


## 6. Verification policy

Every slice runs its focused tests and then:

```text
.venv/bin/python -m unittest discover -s core/tests -t . -v
```

Every TypeScript slice from M1-13 additionally runs:

```text
npm --prefix api run typecheck
npm --prefix api run test:conformance
```

From M1-12 every slice also runs `.venv/bin/python -m
dracla.conformance.vectors --check`, so a behavior change that silently
invalidates a checked-in vector fails in the slice that caused it. M1-19 adds
the packaging smoke test. Tests
must include positive, rejection, and relation cases appropriate to the slice;
a round trip alone is not conformance evidence because encoder and decoder can
share the same mistake.

Each PR is reviewed against its parent and against this LLD. Before submission:

- inspect the complete diff and generated/vector changes;
- prove legacy plaintext modules did not gain revision-13 behavior;
- prove no private test value appears in logs or public artifacts;
- update `design/verification-matrix.md` with requirement/HLD references,
  automated command, test/vector case, and result; and
- update this document's status only from landed repository evidence.

## 7. Review and stop conditions

The M1 LLD is ready to lock when review confirms:

- every roadmap M1 slice has one exact heading and coherent PR boundary;
- all HLD §4, §5.1, §5.3, §5.4, and relevant §6.10.6 contracts have an owner;
- landed M1-1/M1-2 summaries match code and tests without overclaiming;
- no later milestone behavior has leaked into M1;
- every contract a Worker executes has both a Python authoring slice and a
  TypeScript implementing slice, and routing state remains M4's; and
- the Python/TypeScript ownership split is sufficient to exercise the edge
  without duplicating canonical replay, full materialization, or vector
  generation.

Implementation stops and asks for design guidance when:

- a locked HLD relation has two plausible wire encodings or state outcomes;
- a required enum, event member, identity input, transition, or error outcome
  is absent from the locked design;
- a proposed release-profile value would cap acceptance/revocation or otherwise
  narrow a stated requirement rather than bound an implementation artifact;
- one slice cannot remain reviewable without splitting an atomic contract; or
- a dependency requires hosted credentials, external infrastructure, or a
  later milestone behavior to make an M1 test pass.

An internal helper name, algorithmic optimization, or equivalent factoring is
not a design stop when public bytes, validated values, errors, and tests remain
unchanged.

## 8. M1 completion

M1 is complete only when M1-1 through M1-19 are landed, all required commands
pass from a clean checkout, the generator reproduces every checked-in vector,
the shared corpus agrees across runtimes, and the verification matrix contains
evidence for every M1-owned contract. Python-only success, a draft TypeScript
port, an edge contract with no implementing slice, or unmeasured placeholder
limits do not close the milestone.
