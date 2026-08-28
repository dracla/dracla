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
  expected_path=None) -> ValidatedEvent`;
- `required_side_artifacts(event) -> tuple[SideArtifactRequirement, ...]`;
- `required_preconditions(event, *, expected_head)
  -> tuple[PreconditionRequirement, ...]`; and
- `validate_side_artifact_package(event, artifacts, *, preconditions,
  expected_head) -> None`.

The validator implements all 27 HLD §5.1 event rows and every named nested
object. It validates exact top-level fields, actor rules, authorization rows,
confirmed-head rule, event-specific target/payload members, scalar formats,
ordered sets, configuration fields/confirmations, repository and bootstrap
relations, and the reserved Entity rejection.

It recomputes identity through M1-4 and requires `operation_nonce`,
`idempotency_key`, `operation_sha256`, `event_id`, and optional path to agree.
Locally decidable cross-field relations are checked here. Relations requiring
prior canonical state — such as publication existence, one scope terminal,
successor state, source withdrawal, and current configuration — are never
guessed locally: `required_preconditions` names the authenticated state that
decides each, and M1-6/M1-7 replay independently rechecks all of them.

`required_side_artifacts` returns the closed §5.2 set for agreement publication,
project connection/configuration, and affected materialization generations. It
specifies kind and deterministic path.

`validate_side_artifact_package` is what makes §5.4's "fully validated before
the prepared-operation cell is written" true of the package contents, not only
its shape. M1-9 binds bytes to paths and hashes structurally; that proves the
package is internally consistent, not that it says what the event says. Each
required artifact carries one of two content relations:

- **event-determined bytes.** Where the event and authenticated prior state fix
  the artifact exactly — the project configuration, which is the JCS of
  `payload.project_configuration`; the agreement metadata, whose closed schema
  is fixed below; and the materialization generations — the validator derives
  the expected bytes and requires byte equality. A caller cannot substitute
  different content that merely hashes consistently.
- **recomputed-digest relations.** The agreement snapshot content is fetched
  external text, so its bytes are not derivable from the event. Every digest
  over them is still recomputed rather than compared between two supplied
  copies: the validator computes the SHA-256 of the exact snapshot bytes and
  requires it to equal `snapshot_sha256`, and independently computes the
  agreement content digest over those same bytes and requires it to equal the
  event's `digest`, which the requirements define as the cryptographic digest of
  the agreement content. `digest` and `snapshot_sha256` are separate members
  covering the same bytes, so checking only one would let a publication bind an
  agreement identity to content that never hashed to it. The path must equal the
  `segment`-derived `snapshot_content_path`, and `ref` and `content_commit_oid`
  must match the event.

`preconditions` is the resolved evidence from `required_preconditions` at the
confirmed head, and it is required rather than optional because the event and
package alone cannot decide every relation. Materialization generations are the
case that proves it: the new artifact must advance exactly the classes this
event changes and preserve every unaffected class's prior event ID, and those
prior IDs exist only in `config/materialization-generations.enc.json` at the
confirmed head. Without them a self-consistent package could reset, drop, or
fabricate an unaffected class's generation and still be prepared for permanent
append. The validator derives the expected successor from the authenticated
prior value and requires byte equality against it.

The artifact's plaintext is the RFC 8785 bytes of a closed object with
`generations_version` fixed to 1 and one member per derived class —
`derived_index`, `status_detail`, and `reader_authority` — each an event ID.
The class names are §4's artifact kinds for those shards, so the three
vocabularies cannot drift. All three members are always present; §5.2 sets each
affected class to the event's own `event_id` and carries every unaffected class
forward unchanged. This slice fixes the schema because M1-5 must derive and
byte-compare the artifact and M1-15 must reproduce the same bytes, both before
M1-11 runs.

`project_connected` is the genesis case and has no prior value to carry
forward: §5.2 has that event *create*
`config/materialization-generations.enc.json`. Every class is therefore
affected at creation, so the genesis artifact sets the dashboard-index,
status-detail, and reader-authority generations all to the `project_connected`
event's own `event_id`, by the same rule §5.2 states for affected classes. Its
precondition requirement asserts the artifact's absence at the confirmed head
rather than reading a prior value, so Connect is neither rejected for a missing
input nor free to invent generation values. Every later event uses the
carry-forward rule above.

An artifact whose bytes disagree with the event or with that authenticated prior
state fails closed, as does a missing, extra, misordered, or duplicate entry.
This is the contract M1-15 ports, so the Worker proves the package before
preparing rather than trusting its own assembly.

**Agreement metadata plaintext schema.** §4 requires this file to carry only
non-private reference metadata and §5.1 makes the canonical event authoritative
over it, but neither fixes its object shape, so both runtimes would otherwise
invent one. The `.meta.json` side artifact is exactly the RFC 8785 bytes of a
closed object with `metadata_version` fixed to 1 and `agreement_id`, `version`,
`recipient`, `ref`, `content_commit_oid`, `digest`, and `snapshot_sha256` copied
verbatim from the `agreement_published` event. That is what "the metadata and
canonical event retain the original strings and digest" requires, and an unknown
member is rejected.

The exclusions are why this is fixed here rather than left to the implementer.
The file is plaintext, so a repository reader holding no key sees it. It
therefore carries no actor or `login_snapshot`, no `authorizations`, no
`event_id`, `idempotency_key`, `operation_nonce`, or `operation_sha256`, no
`recorded_at`, and no snapshot path members — the paths are derivable through
`segment`, so repeating them adds nothing a reader cannot compute. Serializing
the whole event into this file would disclose the publishing administrator's
identity and is forbidden.

This is an LLD-closed derivation from §4's non-private-metadata rule and §5.1's
event fields, not an HLD amendment. If review prefers a different shape it
changes here and in the M1-5 vectors before any TypeScript slice consumes it.

`required_preconditions` is the contract that makes §5.4's pre-write semantic
validation enforceable without a replay fold. For each event type it returns the
closed set of history-dependent relations that must hold, and for each one the
exact authenticated artifact or deterministic event path that decides it at the
confirmed canonical head — `config/project.enc.json` for the current
configuration, the active-agreement file, coverage shards, exemption fold,
project lifecycle in `source.enc.json`, reader-authority shards, status-detail
provenance, or a direct read of a derived event path such as the two
scope-terminal children of §5.1. Each requirement names the artifact, its §4
identity, and the relation to verify.

`config/project.enc.json` is named explicitly because no projection carries the
configuration. An acceptance rendered before a configuration change must not be
accepted after it: validating the submitted `fields` and `confirmations` against
the current configuration requires decrypting that artifact at the confirmed
events head, and its requirement carries that head binding so a stale read
cannot satisfy it.

`expected_head` is the events head the evidence must have been read at, and it
is an explicit parameter because the event alone does not carry it. §5.1 makes
the event's `confirmed_canonical_oid` a Git object ID only for acceptance and
revocation and `null` for every other v1 type, while the §5.4 form payload
carries `confirmed_canonical_oid` for every Table 5.4-A action. Without the
parameter an administrative submission would have no head to bind to, and a
caller could supply authenticated but stale configuration, lifecycle, or
projection evidence — read before a project succeeded, for example — that no
check could distinguish from evidence read now.

Every `PreconditionRequirement` therefore names how its evidence binds to
`expected_head`, because not all of it lives on the records `events` branch and
those object IDs are unrelated. There are exactly three binding modes:

- **events-head** — evidence read from the `events` branch, such as
  `config/project.enc.json`, `config/materialization-generations.enc.json`, or a
  direct event-path read. Its commit must equal `expected_head`.
- **generation** — evidence from the records `derived` branch. It binds through
  the authenticated generation chain rather than a commit: the class generation
  recorded in `derived/state.enc.json` must equal the canonical generation named
  for that class in `config/materialization-generations.enc.json` at
  `expected_head`, which is the same relation §6.6 already requires readers to
  enforce.
- **canonical-sha** — evidence from the coverage repository. It binds through
  `source.enc.json`, whose `canonical_sha` §5.4 step 7 advances to the canonical
  commit; that value must equal `expected_head`.
- **cross-project** — evidence from another project's repository set, which
  `project_succeeded` needs because §5.5 has the portal verify the successor's
  `project_connected` event and active agreement before the old project closes.
  Those artifacts have no relation to `expected_head`, so this mode binds to the
  successor instead: the requirement names the successor project ID, the
  successor's own events head that its evidence was read at, and the
  registry-resolved repository set that head belongs to. Validation requires the
  event's `target.successor_project_id` to equal that project ID and the
  successor's `project_connected` payload to carry `successor_of` equal to this
  project's ID, so the two projects name each other and neither side can be
  swapped for an unrelated one.

M1 validates that relation over supplied registry-resolved evidence; resolving a
project ID to its current owner-qualified route through the signed registry is
M4's, as §5.5 states.

Requiring commit equality for all three would reject every valid administrative
action touching coverage or derived state, while merely labelling evidence with
the events head would prove nothing. Each mode is an authenticated relation the
locked design already defines. Where the event carries a non-null
`confirmed_canonical_oid`, it must equal `expected_head` too, so the two
bindings cannot disagree.

This is what a writer checks at step 0 and re-checks at step 4 against the head
it holds. A caller never asserts a precondition and no reader infers one from
absence: a required artifact that is missing, unreadable, read at another head,
or inconsistent fails closed. Replay remains the independent authority — M1-6
and M1-7 recheck the same relations by folding history, and a valid precondition
set can never make replay accept an event replay would otherwise reject.

### Acceptance evidence

`events-v1.json` contains at least one valid event for every type, both actor
variants where legal, every named object alternative, all authorization shapes,
and each side-artifact declaration. Negative cases change one relation at a
time: missing/extra/cross-row fields, wrong actor/authorization/head, malformed
scalar or set, identity/path mismatch, wrong snapshot/config relation, invalid
UTF-8/JCS, unsafe numbers, and both reserved Entity names.

Head-binding vectors cover an administrative event whose evidence was read at an
earlier head, an acceptance whose `confirmed_canonical_oid` disagrees with
`expected_head`, and evidence read before a lifecycle transition that the
current head has already passed; all fail closed. Cross-project vectors accept a
`project_succeeded` whose successor evidence names this project back, and reject
one whose successor `project_connected` carries a different or absent
`successor_of`, one naming a project other than the event's
`target.successor_project_id`, and one whose evidence was read at a head outside
the registry-resolved repository set.

Package vectors cover every side-artifact kind in both relation classes: a
correct package accepted, event-determined bytes altered while their hash stays
self-consistent, a wrong successor generation, a reset or fabricated generation
for a class this event does not change, a `project_connected` genesis artifact
whose classes do not all equal its own `event_id`, a genesis package presented
when the artifact already exists, a generations object missing a class member or
carrying an unknown one, a snapshot whose recomputed SHA-256
matches `snapshot_sha256` while its recomputed content digest disagrees with
the event's `digest`, and the reverse, a snapshot whose path, `ref`, or
`content_commit_oid` disagrees with the event, missing, extra, or duplicated
entries, and the exact metadata bytes for a published agreement. A privacy case
asserts the metadata object contains no actor, authorization,
operation-identifier, or timestamp member.

Vectors also cover every `required_preconditions` row: each event type's exact
requirement set, the artifact identity that decides each relation, and negative
cases where the artifact is missing, stale against the confirmed head, or
inconsistent. A test proves every history-dependent relation M1-6/M1-7 enforce
by replay has a corresponding precondition requirement, so the edge gate and the
fold cannot diverge.

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

Corruption and irresolution are different outcomes and only one of them is
whole-fold. A rejected event, broken ancestry, duplicate identity, or failed
relation is corruption: the fold stops and produces no state, because §6.6's
third `indeterminate` trigger cannot be an excuse to serve a partially replayed
projection. Separately, a fold can succeed while leaving a specific record
undecided, and that is the case §6.6 calls "replay could not resolve the
record."

`ReplayState` therefore carries a record-scoped `unresolved` set naming each
`(subject, agreement)` tuple a fold completed without deciding, together with
the event identity that left it undecided. M1-11 materializes exactly those
records as stored `indeterminate` and every other record as its resolved
status. Without this the materializer would have only a valid state or no state
at all, and would have to fail the whole projection or invent a second state
model.

**M1's own replay never populates it.** Every relation M1-6 and M1-7 define is
decidable over a complete valid history: each produces a decision, and each
failure is corruption. A complete valid fold therefore always returns an empty
`unresolved` set, and M1 asserts that rather than inventing a case to fill it.

The populating conditions belong to partial and repairing replay — a fold over
history that is intact in ancestry but incomplete in content, such as the
recovery and rebuild paths §9.1 defines. The index assigns §9.1 to M3, so M3
owns when a tuple enters and leaves this set, using the representation M1 fixes
here. M1 proves the representation and the materializer honor it by
constructing a state with a non-empty set directly. A projection may never add
to the set.

### Acceptance evidence

A dedicated case asserts every complete valid fold returns an empty
`unresolved` set, so an implementation cannot quietly start populating it.

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

- requested/activated/abandoned enforcement scope, with **at most** one
  terminal per request. §7.1 appends the request first and permits registry
  preparation before either child lands, so a request with no terminal yet is a
  valid durable pending state that replay represents rather than rejecting.
  Corruption is two terminals for one request, whether both kinds or two
  different events of the same kind;
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

Sequences prove a request with no terminal yet replays as a valid pending scope
change and that its later activation or abandonment settles it.

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
- `validate_terminal_noop(form, event, operation, *, expected_project_id,
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
effects allowed by the registry. `operation` is the validated submitted target
and payload — the desired effect itself. It is required because the form token
carries only `operation_sha256`, and §5.4 explicitly allows the bound prior
event to differ in actor, nonce, idempotency key, and operation digest. Form,
event, project, and head alone therefore cannot tell an older `config_updated`
carrying a different configuration from the one that establishes this form's
effect.

Validation runs in two steps. It first recomputes `operation_sha256` from
`operation` and requires it to equal the form's, which binds the submitted
effect to the authenticated token. It then requires the bound event to carry the
target and payload fields that establish exactly that effect, as §5.4 requires.
A same-type event that establishes a different effect is rejected rather than
returned as a no-op. A scope action validates the repeated desired scope
directly on `enforcement_scope_activated`. Internal automation and terminal-only
event types are not form actions.

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

**Pre-activation active-agreement representation.** §5.3 enumerates only the
activated shape of `agreements/active.enc.json`, but §5.4 has install create an
empty projection before any `agreement_activated` exists, and the §6.3 check
path reads this file unconditionally. The pre-activation encoding is therefore
required and is closed here rather than left to each implementation:
`agreement_id`, `active_version`, and `activation_event_id` are `null`,
`accepted_versions` is `[]`, `projection_format` is 1, and `shard_count` is 32.
No member is omitted.

This follows §5.1's stated convention that `null` is explicit rather than
represented by omission, and it needs no new enum or sentinel string.
`project_configuration` carries no agreement identifier, so `agreement_id` has
no pre-activation value to borrow. The encoding is also self-checking against
the locked evaluation rule: with `accepted_versions` empty, §6.3's
`version ∈ accepted_versions` test makes every subject uncovered, which is
exactly what "inactive versions are never signable" requires. A non-null
`active_version` with an empty `accepted_versions`, or any activation member
present without the others, is rejected.

This is an LLD-closed derivation from the locked conventions, not an HLD
amendment. If review prefers a different representation, it changes here and in
the M1-10 vectors before any TypeScript slice consumes it.

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

**Source-aware transitions take an explicit union input.** §5.3 stores only
`{active: true}` in `exemptions.enc.json` and derives `active` as "sources
non-empty," and §4 keeps exemption provenance out of the coverage capability
entirely. A coverage before-state therefore cannot say whether a withdrawn
source was the subject's last one, so an incremental update driven by the event
and coverage state alone would either clear a still-valid exemption or retain a
withdrawn one.

The incremental contract this slice defines by equivalence therefore takes the
affected subjects' **prior** source union as an explicit authenticated input and
applies the event's own delta to it. The input is the pre-event union read at
`expected_head` — the `exemption_sources` of the subject's status-detail row and
the equivalent reader-source records — and the update subtracts the withdrawn
source or adds the new one itself.

Binding the *prior* union rather than the resulting one is what makes the
ordering work. §5.4 updates coverage at step 7, before the `derived` branch is
rewritten, so a post-event derived row would not exist yet; requiring one would
make coverage depend on private derivation succeeding, and §6.6 requires the
opposite — canonical evidence and coverage complete even when a private derived
class overflows and fails closed. The pre-event union is already authenticated
at the head the operation is bound to, and the event supplies the only change to
it.

Only `worker-portal` writes coverage and it holds both keys, so this needs no
new capability; `worker-enforce` reads the derived boolean and never performs
these transitions. Materializing the union into coverage instead is forbidden:
it would put provenance inside the enforcement capability.

The tuple cutoff, accepted-version fold, source-aware exemption, and active
override relation follow the HLD exactly. Override keys and repeated identities
are recomputed. A malformed entry cannot be ignored in favor of an otherwise
covered row. `CoverageDelta` identifies affected logical files/shards but does
not write them.

### Acceptance evidence

Vectors materialize deterministic empty and populated projections, including
the pre-activation encoding above and the first activation that replaces it,
all 32 shard boundaries, multiple agreement versions, revocation/re-signing,
superseding/non-superseding activation, exemptions, overrides, lifecycle
successor state, subject/project-wide marker effects, and idle/reserved fences.

Negative cases cover wrong format/count/shard, missing/unknown fields, a
partially populated activation set, a non-null `active_version` with empty
`accepted_versions`, unsafe or duplicate IDs, malformed scope, source/event
mismatch, invalid override key or repeated tuple, forbidden private fields,
missing lifecycle relation, and every fail-closed marker/fence inconsistency.

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
detail, and reader-authority sources. Expose:

- `materialize_derived(state, *, profile) -> DerivedPlaintext`;
- `assemble_derived_projection(plaintext, *, canonical_oid, generations,
  encrypted_shards, profile) -> DerivedProjection`;
- `derived_delta(before, after) -> DerivedDelta`; and
- `validate_derived_projection(projection, *, generations, encrypted_shards,
  profile) -> None`; and
- `resolve_read_status(row, operation_state) -> ResolvedStatus`.

The §6.6 index status enum is exactly
`current | exempt | revoked | superseded | indeterminate`, and `indeterminate`
has three locked triggers. They divide by lifetime, which decides where each is
computed:

- **durable** — replay could not resolve the record. This is a property of the
  fold, so it is materialized and stored.
- **live** — the subject sits in `inflight.ops`, or an operation exhausted its
  retries, which §5.4 makes observable only as that operation's still-unsettled
  `mutation` fence and any marker it opened, never as a separate flag or an
  elapsed-time judgement. §6.6 states both in the present tense, and the state
  that decides them lives in the coverage repository rather than on the
  `derived` branch.

**Materialization stores only the durable status; the live triggers are
overlaid at read time.** `materialize_derived` therefore takes no operational
state and is a pure function of the replay fold: it emits `current`, `exempt`,
`revoked`, or `superseded`, or `indeterminate` when replay could not resolve the
record.

Persisting a live trigger is not merely redundant, it deadlocks the dashboard.
§5.4 releases the marker only after the projection effect and read-back
complete, so a mutation's own derived write necessarily happens while its own
marker is still open. A materializer that consulted the marker would write
`indeterminate` on every ordinary mutation, and §6.6 specifies no second derived
write once the marker closes, so that row would stay `indeterminate` until
reconciliation. Adding a post-close re-materialization would also break §6.6's
budget of one index shard, one status shard, and the small state file per
ordinary mutation. Overlaying at read time costs nothing extra and is what
§6.6's present-tense definition already describes.

Because no live trigger is ever stored, a stored `indeterminate` row always
means replay irresolution and is served as it stands. There is no
stale-`indeterminate` state to detect.

Status detail carries the same result with its exact reason; the index keeps
only the enum value. `ResolvedStatus` therefore carries both the served enum
and the served reason, and a read overlays both: when an open `inflight.ops`
entry names a subject, the served status detail reports `indeterminate` with
the operational reason for it, never the stored terminal reason. The trigger is
an open marker entry alone, never the decision fence, for the reason given
under **Reads overlay live operational state on the stored status** below.
Overlaying the index enum alone would let an exact-status response contradict
itself by pairing `indeterminate` with "covered, signed version 2". The
operational reason names the in-flight or unsettled condition, not the subject
or any signer value, and status detail is records-key encrypted, so carrying it
discloses nothing new.

**Status-detail and reader-authority plaintext schemas.** §4 and §6.6 name these
artifacts, fix their sharding, and say what class of data they hold, but neither
defines their bytes. Both are closed here so the reference materializer, the
M1-18 incremental updater, and the shared vectors agree.

A status-detail shard maps `github_user_id` to a subject record with three
members, because the kinds of evidence have different scopes:

- `login_snapshot` and `login_as_of`, the recorded GitHub login and the instant
  it was observed. §8.1 requires the pull-request-scoped named-subject view to
  show GitHub numeric IDs and login snapshots from records-key-decrypted
  status-detail data, and §6.6 has an exact-status read fetch only that
  subject's status shard, so the snapshot must live here. Persisting it also
  keeps the view from substituting a current login for the one recorded, and
  `login_as_of` is what makes that distinction checkable. Both mirror the
  index row's `login_snapshot` and `login_as_of`.

  The advance rule is deterministic and narrow: only an event whose `actor` is
  the subject itself — `actor.kind` is `github` and `actor.github_user_id`
  equals the subject — updates these members, taking `actor.login_snapshot` and
  setting `login_as_of` to that event's `recorded_at`. The latest such event in
  canonical order wins, and canonical order is ancestry, never timestamp. An
  event that merely names the subject in its target or payload, such as an
  exemption or override recorded by an administrator, carries someone else's
  login and never advances it. Both members are `null` until the subject first
  acts. Without this rule a full replay and an incremental update could each
  pick a different historical login and still satisfy the field schema,
  producing divergent shard bytes;
- `exemption_sources`, the subject-scoped provenance §4 assigns to the records
  key. It is a map keyed by `source_event_id`, which is unique per source and is
  what `exemption_source_withdrawn` names alongside the subject, so a withdrawal
  addresses one entry directly and no ordering rule is needed. Each value is the
  closed object `{"source_kind", "team", "basis", "instrument_ref",
  "rule_event_id"}`, with every member always present; and
- `agreements`, a map from `agreement_id` to that agreement's status entry,
  carrying the `status` enum, a `reason_code` from the closed vocabulary below,
  the deciding `event_id`, `version`, and `accepted_at` and `revoked_at` as
  timestamps or `null`.

`source_kind` is exactly `bot`, `individual`, `snapshot`, or `continuous_team`,
the four ways §5.1 creates an exemption source. The other members are fixed by
kind, and the rules are exhaustive so both runtimes encode identical bytes:

| `source_kind` | `team` | `basis` / `instrument_ref` | `rule_event_id` |
|---|---|---|---|
| `bot` | `null` | both `null` | `null` |
| `individual` | `null` | both strings | `null` |
| `snapshot` | object | both strings | `null` |
| `continuous_team` | object | both strings | the rule's event ID |

`team` is the object `{"organization_id", "team_id"}` for the two team-derived
kinds. `null` is explicit rather than represented by omission, so presence never
varies and the shard digest is stable. `basis` and `instrument_ref` are nullable
only for `bot`, matching §5.1's "string or `null` for `bot`". `rule_event_id`
lets a rule withdrawal find every entry it materialized, which is the identity
`exemption_materialized` already carries.

Exemption provenance sits at subject level rather than inside an agreement
entry because §5.1's exemption events are project- and subject-scoped and carry
no agreement identifier. A rule configured after `project_connected` but before
any agreement is published would otherwise have nowhere to persist, and the
incremental coverage contract that consumes this union as its authenticated
prior input could not evaluate a later withdrawal without inventing an agreement
key. The `agreements` map is empty in exactly that state, and the subject record
still exists.

The `reason_code` vocabulary is exactly:

| Detail `reason_code` | Index `status` | Coverage `decision` | Coverage `reason_code` |
|---|---|---|---|
| `accepted_current_version` | `current` | `covered` | `signed` |
| `exempt_source_active` | `exempt` | `covered` | `exempt` |
| `revoked_by_contributor` | `revoked` | `uncovered` | `revoked` |
| `no_acceptance_recorded` | `revoked` | `uncovered` | `not_signed` |
| `version_not_accepted` | `revoked` | `uncovered` | `version_not_active` |
| `superseded_by_later_acceptance` | `superseded` | `uncovered` | `superseded` |
| `superseded_by_activation` | `superseded` | `uncovered` | `version_not_active` |
| `operation_in_flight` | `indeterminate` | `uncovered` | `indeterminate` |
| `replay_unresolved` | `indeterminate` | `uncovered` | `indeterminate` |

§5.3's user row carries `decision` and `reason_code` as separate members, so the
last two columns are separate too. Collapsing the generic code onto the decision
would duplicate one field and destroy the other: §8.4 restricts the generic code
to "the fixed class needed to select check copy or produce authorized aggregate
counts", and §8.1 requires an insufficient agreement version to stay
distinguishable from an ordinary unsigned subject. `version_not_active` exists
for exactly that distinction, and the enforcer selects check copy from this
column without ever seeing the exact reason.

Coverage's generic vocabulary is exactly the fourth column — `signed`,
`exempt`, `revoked`, `not_signed`, `version_not_active`, `superseded`,
`indeterminate` — and carries no free-form explanation. Each detail row is one
decision path §5.3, §6.5, and §6.6 already distinguish, and the mapping is
total: every stored detail row projects onto exactly one generic code, and no
detail code exists without a status. `operation_in_flight` is the only code
`resolve_read_status` substitutes during an overlay; `replay_unresolved` is the
only one materialization stores for an `unresolved` record. Because the
projection is fixed here, the two vocabularies cannot drift. §8.1 permits
GitHub numeric IDs and login snapshots here and forbids legal names, email
addresses, signer fields, and raw evidence, so the schema admits none of those.

A reader-authority shard maps `source_id` — the `event_id` of the canonical
source-creating event, which §6.6 also fixes as the sharding input — to a closed
source record. Every record has exactly these members, with no omissions and no
kind-dependent presence:

- `kind`: `individual`, `snapshot`, or `continuous_team`;
- `team`: `null` for `individual`, and otherwise the object
  `{"organization_id": <positive integer>, "team_id": <positive integer>}` for
  `snapshot` and `continuous_team`; and
- `subjects`: a map keyed by the decimal `github_user_id` string, whose value is
  the closed object `{"added_event_id": <event ID>}` — the
  `records_reader_snapshot_authorized` or `records_reader_authorized` event for
  the first two kinds, and the `records_reader_materialized` event that added
  this membership for `continuous_team`.

`team` is always present and explicitly `null` for an individual source rather
than omitted, following §5.1's convention that `null` is explicit rather than
represented by omission. Presence rules that vary by kind would change the JCS
bytes and therefore the shard digest, so the schema fixes one member set for all
three kinds. `added_event_id` is the smallest value that keeps each membership
attributable, which a continuous-team source needs so a later withdrawal names
the observation it reverses.

The nested `subjects` map is what keeps per-account withdrawal working. §6.10.4
freezes a snapshot's complete selected set in one
`records_reader_snapshot_authorized` event and materializes it as independently
withdrawable per-account sources, so every one of those sources shares that
event's single `event_id`. Keying the shard directly by `source_id` with one
singular subject would collide and force the materializer to overwrite readers,
and a `records_reader_withdrawn` naming `(source_event_id, subject)` would have
nothing to target. An `individual` source simply has exactly one entry in that
map, and a `continuous_team` source's entries are the memberships its
`records_reader_materialized` events added.

Withdrawal removes the named subject's entry rather than setting a false flag,
and removing the last entry removes the source record, matching the
source-union rule that no boolean overwrite can hide another source. Because
the source ID stays the event ID, one source's accounts always live in one
shard, which is what makes a reader mutation touch one reader shard. Persisted
evidence and the proof projection are deliberately different shapes. The record
stores `team` for both team-derived kinds, because
`records_reader_snapshot_authorized` carries the team the set was taken from
and that is canonical evidence worth retaining. §6.6's proof is narrower:
individual and snapshot sources set both team fields to `null`, and only a
continuous-team source carries the stable organization and team IDs. The proof
projection therefore copies `source_id` and `kind` from the record and fills
`organization_id` and `team_id` from its `team` only when `kind` is
`continuous_team`, nulling both otherwise — which is also why a snapshot proof
needs no live membership recheck. A proof can only name a source this shard
contains, and issuing one additionally requires the authenticated user to
appear in that source's `subjects`.

Both are LLD-closed derivations from §4's capability split, §6.6's proof
payload, and §8.1's disclosure limits, not HLD amendments. If review prefers a
different shape, each changes here and in the M1-11 vectors before any
TypeScript slice consumes it.

There are exactly 32 shards for index, status detail, and reader authority.
Index/status shard selection is `github_user_id % 32`; reader-source selection
uses the first five bits of the source-event-ID digest. Semantic materialization
is a deterministic function of the replay fold and the profile alone. It takes
no operational state, and operational state belongs exclusively to
`resolve_read_status`, so no marker-induced status can reach stored bytes. The
assembler receives the exact already-created M1-2
encrypted envelope bytes for all shards, then creates the derived-state
plaintext carrying each class generation and the SHA-256 of every encrypted
shard envelope. It does not re-encrypt or regenerate a shard while calculating
its digest. Validation requires canonical and derived generations, selected
envelope sizes, shard digests, format, and counts to agree.

Add `release_profile.py` and checked-in `release-profile-v1.json`. The schema is
closed and contains finite positive numeric limits for at least:

- complete prepared-operation cell bytes, which §5.4 explicitly bounds and
  rejects before preparation;
- index, status-detail, and reader-authority shard ciphertext bytes — the
  records-derived classes §9 means by "maximum encrypted derived-shard bytes";
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

**Coverage shards carry no rejecting size limit, by design.** §5.3 states that
successful acceptance and revocation are not capped, because any finite cap can
trap a contributor either covered or uncovered — the append guard revision 11
removed. §9 makes the asymmetry explicit: when a private derived shard reaches
its profile, "canonical evidence and coverage complete, the affected private
class stays fail-closed." Coverage is enforcement state that must always
complete, so the profile bounds only the records-derived classes above, and no
coverage write is ever rejected for size. The enforcer's read cost is bounded by
the fixed 32-shard count, not by a byte cap. A profile that rejected a coverage
write would trip this document's own stop condition on capping
acceptance/revocation.

Bulk derived publication remains fail closed until all affected shards and the
final generation are complete. Ordinary subject and reader deltas identify
only their bounded affected shards plus state. Acceptance/revocation canonical
and coverage truth do not become capped by private-derived overflow.

**Reads overlay live operational state on the stored status.**
`resolve_read_status` decides what a reader is served:

- a subject named by an open `inflight.ops` entry is served `indeterminate`,
  with the operational reason replacing the stored one in status detail,
  whatever the stored row says. Generation agreement cannot substitute for
  this: between marker open and canonical append the canonical and derived
  generations still match, so digest and generation checks alone would serve
  the previous `current` or `revoked` row;
- every other subject is served its stored status unchanged, including a stored
  `indeterminate` that records replay irresolution; and
- `success_reserved` with an empty marker covers nothing, so an authoritative
  merge-group publication in progress changes no row.

**The overlay reads the marker, not the fence.** §6.6 names `inflight.ops` as
the dashboard trigger, and §5.4 leaves ordinary windows in which the fence is
`mutation` while the marker is legitimately empty — between fence acquisition
and marker open at steps 2 to 3, and between marker close and fence release at
steps 8 to 9 — with no retry exhausted. Overlaying from the fence would blank
rows in both windows, including immediately after marker closure, which is
exactly when the dashboard should show the new terminal status.

The §6.3 check path deliberately reads the fence instead and treats an absent
marker entry as the bounded pre-open/post-close state. That is a different
surface with a stricter rule: a check must never pass optimistically, while a
dashboard read may show a settled status. This LLD keeps both rules as the HLD
states them rather than unifying them.

Retry exhaustion needs no separate signal, because §5.4 keeps any opened marker
non-idle until the operation settles. An exhaustion before step 3 opened a
marker appended nothing, so the stored status is still correct.

Scope decides which rows an overlay touches. A marker entry with
`project_wide: true` covers every row; a subject-scoped one covers exactly its
listed `subjects` and leaves every other row alone.

The reader resolves one immutable coverage head for that state alongside the
`derived` head, exactly as the §6.3 check path resolves one coverage commit.
Missing, unreadable, or schema-invalid operational state denies the read. The
overlay never writes: it changes what this response reports, never the stored
projection, so reading does not consume the ordinary mutation's shard budget.

### Acceptance evidence

Schema vectors fix the exact status-detail and reader-authority bytes for every
status, reason code, exemption-source kind, and reader-source kind, including a
subject exempted before any agreement is published whose `agreements` map is
empty and whose later source withdrawal still evaluates. A named-subject case
proves the view renders from the stored `login_snapshot` and `login_as_of`
alone, with no index read and no current-login substitution. A login-advance
case replays several events for one subject with differing logins and proves
only self-acted events advance the pair, that the latest by ancestry wins, that
an administrator-recorded event naming the subject does not advance it, and that
both stay `null` until the subject first acts. Exemption-source byte cases fix
all four `source_kind` encodings with their exact null patterns and reject a
`bot` entry with a non-null `basis`, an `individual` entry with a `team`, and a
`continuous_team` entry with a null `rule_event_id`. A snapshot case
authorizes several subjects in one event and proves each is independently
withdrawable: withdrawing one leaves the others authorized under the same
`source_id`, and withdrawing the last removes the source record. Other cases
prove a withdrawn reader is absent rather than present with a false flag, and
that a proof naming a source cannot be issued for a user outside its
`subjects`. Byte cases fix the exact encoding of all three source kinds,
including an `individual` source's explicit `"team": null`, and reject a record
that omits `team` or any other member. A privacy case asserts no status-detail
row carries a legal name, email address, signer field, or raw evidence member,
and a mapping case asserts every reason code projects onto the generic coverage
code for the same subject.

Vectors cover each closed schema, all shard boundaries/classes, source unions,
all dashboard statuses, exact/private data separation, canonical/derived
generation agreement, envelope digest tables, affected-only deltas, incomplete
bulk publication, and every profile limit at `limit-1`, `limit`, and `limit+1`,
including the retry and subrequest ceilings. A dedicated case drives a coverage
shard past the largest records-derived limit and proves the acceptance and
revocation still complete, the coverage write is not rejected, and only the
affected private derived class fails closed.

Read fixtures pause a mutation at each step and prove a read never serves a
stale status: after marker open but before canonical append the row reads
`indeterminate` even though generations still agree; after canonical append but
before the derived write the class fails closed on generation mismatch; and
under `success_reserved` with an empty marker every stored status is served
unchanged. One fixture runs a complete ordinary mutation and proves the
dashboard returns the new terminal status immediately after the marker closes,
with no second derived write and no reconciliation, because no live trigger was
ever stored.

Unresolved-record fixtures construct a state with a non-empty `unresolved` set
and prove exactly those records materialize as stored `indeterminate` while
every other record materializes its resolved status.

Overlay fixtures pair one stored projection with each operational state and
prove that an open subject-scoped marker makes only its own subjects read
`indeterminate`, a project-wide marker makes every row read `indeterminate`, an
open marker after retry exhaustion holds that result until the operation
settles, and that an idle fence, a `success_reserved` fence, and a `mutation`
fence with an empty marker all return the stored statuses unchanged, including
`current` and `revoked`. The two ordinary empty-marker windows of §5.4 steps 2
to 3 and 8 to 9 are covered explicitly. Every overlay
case asserts the served index enum and the served status-detail reason agree,
so an exact-status response can never pair `indeterminate` with a terminal
reason. A materialization fixture proves the stored projection is identical
under every operational state, so no live trigger can leak into stored bytes.

Negative cases cover a stale `current` or `revoked` row served under a matching
marker entry, a row wrongly blanked to `indeterminate` under
`success_reserved`, under a `mutation` fence with an empty marker, or outside a
subject-scoped marker's listed subjects, `success_reserved` presented with a
non-empty `inflight.ops`, missing or malformed operational state, a marker
whose scope does not match the rows it affects, an unknown status value, stale
generations, missing/extra/oversize shards, digest mismatch, wrong
class/count/profile, private fields in the index, incomplete fan-out, too many
continuous rules, non-finite/placeholder profile values, and any profile that
declares a coverage-shard size limit at all. Capacity evidence and chosen
limits are recorded in traceability.

### Non-goals and PR boundary

The request-scoped export payload model is deliberately not defined here. §4's
identity table fixes the `export-json` and `export-csv` paths and M1-1 already
implements them, but neither the HLD nor this LLD defines the export payload's
members or encoding, and the index assigns the replay/export engine to M3. M3
therefore owns that schema and its vectors; M1 would have to invent a wire
format, which this document's stop rule forbids.

No dashboard endpoint, proof JWS, live reader membership check, export
renderer/streamer, export payload schema, hosted job, repair driver, or
repository write. M3 owns
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
identity recomputation through the M1-4 derivations, `required_side_artifacts`,
and `validate_side_artifact_package`, including the closed agreement-metadata
schema and the authenticated prior-generation comparison.

Package content validation is included deliberately. Returning kinds and paths
alone would let a Worker prepare a package whose bytes disagree with the event
it accompanies, and §5.2 commits the event and its side artifacts in one commit
or none — so an unvalidated package becomes permanent canonical history. The
edge derives the event-determined bytes and compares them, and recomputes every
digest over the fetched agreement snapshot from its exact bytes.

This exists because §5.4 makes the portal Worker the canonical writer and
requires an event and its complete side-artifact package to be fully validated
before the prepared cell is written. §9 places Python in Actions and the CLI,
so there is no synchronous Python boundary for that Worker to call.

TypeScript also implements `required_preconditions` checking. The edge does not
fold history, but it does not accept a history-dependent relation as an
assertion either. For each requirement the contract names, the Worker reads the
exact authenticated artifact or deterministic event path at the confirmed
canonical head and verifies the relation itself, exactly as §5.4 step 0 and the
step 4 re-check require. Withdrawing an already-withdrawn source, adding a
second scope terminal, activating an unpublished version, or acting on a
succeeded project therefore fail at the edge before the prepared cell is
written.

A missing, unreadable, stale, or inconsistent precondition artifact fails
closed; absence is never read as permission. What stays Python-only is the fold
itself: M1-6 and M1-7 recheck every one of these relations by replaying history,
so the edge check is a pre-write gate rather than the authority, and an edge bug
cannot make replay accept an impossible event.

### Acceptance evidence

Both runtimes accept every valid case for all 27 event types and reject every
negative case, including cross-row fields, wrong actor or authorization,
malformed scalars and sets, identity or path mismatch, invalid JCS, unsafe
numbers, and both reserved Entity names. A registry-agreement test proves the
TypeScript closed event set equals the Python one, so a row added on one side
fails the other.

Side-artifact package cases run in both runtimes from the same fixtures, with
byte equality required for event-determined artifacts and digest relations for
the snapshot.

Precondition cases run in both runtimes from the same fixtures: each event
type's requirement set, a satisfied precondition accepted, and every unsatisfied
or unreadable one rejected, including an already-withdrawn source, a second
scope terminal, an unpublished activation, and a succeeded-project action.

### Non-goals and PR boundary

No replay fold, transport, append, or encryption orchestration. The edge
verifies the named preconditions; it does not reconstruct history to do so.

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

Source-aware transitions additionally take the affected subjects' prior source
union as an explicit authenticated input and apply the event's delta, for the
reason M1-10 states: coverage stores only the derived boolean, so an exemption
or reader withdrawal cannot be resolved from coverage alone. The Worker supplies
the pre-event union read at `expected_head` and never infers it from the
coverage before-state or waits on the `derived` branch.

A malformed existing shard is never partially preserved. The update validates
the whole before-state, applies only its own keys, and revalidates the result
before it is encoded.

### Acceptance evidence

Every M1-12 triple round-trips: TypeScript applies the input to the before-state
and reproduces the after-state byte for byte. Cases cover all 32 shard
boundaries, multiple agreement versions, revocation and re-signing, superseding
and non-superseding activation, exemptions, overrides, successor state, and
subject-scoped versus project-wide markers. A multi-source exemption case
withdraws one of several sources and proves the subject stays exempt, then
withdraws the last and proves the entry is removed. A crash fixture completes
the coverage update with the `derived` branch still unwritten and proves the
result is correct, so coverage never waits on private derivation. A missing or
stale union input is rejected rather than guessed. Negative cases cover wrong
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

It also implements M1-11's `resolve_read_status`. The Worker resolves one
immutable coverage head for the marker and fence alongside the `derived` head
and overlays that live state on every row it serves, because §6.6 makes the
in-flight and retry-exhaustion triggers present-tense conditions whose deciding
state lives in the other repository. A subject named by an open `inflight.ops`
entry reads `indeterminate`, with the operational reason in status detail,
whatever the shard stores; every other row is served as stored. The overlay
reads the marker rather than the fence, so the ordinary empty-marker windows of
§5.4 do not blank the dashboard. The
incremental update writes only the replay-derived status, so the overlay never
has to repair what materialization wrote. Matching generations and digests are
necessary but never sufficient.

### Acceptance evidence

Every M1-12 derived triple round-trips byte for byte. Because stored bytes
carry no live trigger, the triples are identical under every operational state,
and a separate overlay suite drives the read path through each one. Cases cover
all shard classes and boundaries, source unions, every dashboard status,
affected-only deltas, and incomplete bulk publication. Negative cases cover
stale generations, missing, extra, or oversize shards, digest mismatch, private
fields in the index, and incomplete fan-out. Cross-branch fixtures run both
runtimes through the crash windows above and require identical served statuses
and identical fail-closed decisions.

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
