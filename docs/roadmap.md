# Development milestones

This roadmap follows the locked revision-13 requirements and the reviewed
high-level design. The requirements and HLD are authoritative when this summary
is incomplete; implementation does not silently resolve a design conflict.

`REQ-VERIFY-1` makes an unverified `MUST` a release blocker, so the release
traceability matrix grows with the implementation rather than being
reconstructed at the end.

---

## M0 — Reviewed baseline and owner prerequisites

| | |
|---|---|
| **Status** | Design complete; external setup remains |
| **Closes** | No release-scope item directly; every implementation track depends on it |

- [x] Requirements locked at revision 13
- [x] High-level design locked, adversarially reviewed, and cleanly attested
- [x] Legacy protocol and GitHub-transport spikes retained as experiments
- [x] A1 edge platform, A4 merge-queue baseline, and A5 coordination model closed
- [x] Hosted shell/API origin selected: `https://dracla.cli.dev`
- [ ] Cloudflare account resources: Workers, Pages, Secrets, KV, and Durable Objects
- [ ] Three GitHub Apps created per `docs/github-apps.md`

The existing `core/` code is a plaintext protocol spike, not the revision-13
implementation. Its transport and test techniques may be reused selectively;
its event, projection, shard, and trust assumptions are not release code.

---

## Track A — implementation without hosted-account dependencies

These milestones can start before Cloudflare and the Apps exist. They produce
testable libraries, local tools, and the pinned control artifact, but they do
not claim that end-to-end installation or signing is available.

### M1 — Conformance kernel

| | |
|---|---|
| **Needs** | M0 reviewed documents |

- Revision-13 event schemas, semantic validation, replay, idempotency, and
  authorization-operation vocabulary (§5.1–§5.4)
- Canonical JSON, identity/AAD construction, authenticated envelopes, wrapped
  key files, prepared-operation cells, decision fences, and bounded shards (§4)
- Checked-in fixed-key golden vectors shared by Python and TypeScript, including
  tamper, wrong-context, non-canonical, and payload-to-path rejection (§6.10.6)
- Focused replacement of legacy spike behavior only where the reviewed design
  defines the conforming successor

#### M1 execution slices

The rows below are the durable implementation and pull-request boundaries for
M1. Requirements and HLD sections remain authoritative; a slice does not
silently broaden or narrow them. Each slice adds focused negative vectors and
updates release traceability for the behavior it owns. A proposed boundary
that cannot remain coherent at reviewable size is remapped here before its
implementation is split.

| ID | Slice | Needs | Acceptance boundary | Explicit non-goals |
|---|---|---|---|---|
| **M1-1** | Canonical JSON and artifact identities — **landed in #12** | M0 reviewed documents | Strict RFC 8785 parsing/encoding; the complete §4 repository/branch/path identity table; agreement, event, shard, export, and override tokens; checked-in positive and rejection vectors | Encryption, plaintext schemas, repository transport |
| **M1-2** | Version 1 encrypted-artifact envelope — **landed in #13** | M1-1 | Exact AAD and canonical envelope bytes; AES-256-GCM round trips; strict project, purpose, path, schema, key-ID, encoding, JSON, and formula-neutralized CSV rejection; fixed-key vectors | Wrapped keyrings, semantic payload schemas, hosted key custody |
| **M1-3** | Wrapped-key copies and canonical keyrings | M1-1, M1-2 | Exact wrap AAD and 32-byte key wrapping; the closed wrapper/capability vocabulary; canonical keyring ordering; duplicate and wrong project/capability/generation rejection; fixed-key rotation and multi-wrapper vectors | Hosted wrapping services, bootstrap orchestration, root rotation, recovery UI |
| **M1-4** | Event identity and authorization vocabulary | M1-1 | Stable actor identity; exact operation/resource/required-authority pairs; canonical set ordering; random, automation, retry, and scope-terminal nonce derivation; idempotency key, operation fingerprint, event ID, and event path vectors | Event target/payload schemas, replay, GitHub authorization calls |
| **M1-5** | Closed revision-13 event schema and semantic validation | M1-2, M1-4 | Every §5.1 v1 event type and named nested object; exact actor, authorization, scalar, set, target, and payload rules; recomputed identity/fingerprint/path agreement; required side-artifact declarations; valid vectors for every type and rejection of unknown, cross-row, malformed, and reserved Entity values | Chronological replay, append transport, projection materialization |
| **M1-6** | Canonical replay foundation and project/contributor lifecycle | M1-5 | Ordered replay with corruption and idempotency conflict detection; project connection/succession, configuration, key activation, agreement publication/activation, acceptance, revocation, supersession, and recipient/tuple invariants; deterministic replay-state vectors | Scope transitions, overrides, exemptions, readers, projection bytes |
| **M1-7** | Administrative, scope, exemption, reader, and override replay | M1-6 | Complete remaining v1 fold; exactly one scope terminal; authorization-operation consistency; source-union addition/withdrawal; continuous-team materialization evidence; override lifecycle; succeeded-project closure; full-replay equivalence and rejection vectors | Live GitHub authority or membership checks, derived artifact encoding, writes |
| **M1-8** | Authenticated action forms and replay-stable no-op bindings | M1-4, M1-5, M1-7 | Exact JCS payload and one-dot base64url/HMAC encoding; active and eligible-predecessor key handling; session, actor, project, operation, digest, and absolute-expiry binding; the closed Table 5.4-A action/terminal registry; immutable terminal-event validation; vectors proving an old no-op cannot become a later write | OAuth/session storage, portal rendering, authorization acquisition, mutation writes |
| **M1-9** | Prepared-operation, in-flight, and decision-fence contracts | M1-2, M1-5, M1-8 | Closed idle/prepared/appending/terminal operation states; exact frozen side-artifact package and append claim; closed idle/mutation/success-reserved fence; one-operation marker and cross-binding rules; pure transition and crash/race vectors proving that age never clears state | GitHub CAS transport, Worker/reconciler drivers, routing-gate or check-run publication |
| **M1-10** | Coverage projection contracts and bounded shards | M1-7, M1-9 | Closed source, active-agreement, exemption, in-flight, fence, and user-shard schemas; exactly 32 deterministic packed shards; tuple cutoff and accepted-version fold; override-key validation; generic-reason-only/PII exclusion; deterministic materialization and fail-closed vectors | GitHub branch writes, check publication, routing, records-private derivatives |
| **M1-11** | Records-derived contracts, generations, and release profile | M1-7, M1-9, M1-10 | Closed project config, materialization generations, derived state, index, status-detail, and reader-authority schemas; operational-state-driven `indeterminate` dashboard rows; exactly 32 bounded shards per class; canonical/derived generation and envelope-digest agreement; source-union detail and checked-in numeric profile limits; affected-shard and incomplete-bulk fail-closed vectors | Export rendering/streaming, private-read proofs, hosted jobs, reconciler repair |
| **M1-12** | Cross-runtime conformance and M1 closure | M1-3, M1-5, M1-8, M1-10, M1-11 | One checked-in corpus drives Python and TypeScript for every §4 identity row, dynamic path token, AAD, envelope, wrapped-key file, and action form; TypeScript validates only the byte, form, and coverage contracts required by the thin edge; tamper, non-canonical, wrong-context, payload-to-path, and unsupported-version cases agree across runtimes; complete M1 traceability passes | Worker routing/webhooks, portal flows, CLI, GitHub transport, reconciliation |

The implementation order is `M1-3` through `M1-12`. M1-3 and M1-4 are
logically independent after the landed foundations but remain sequential PRs
in one review stack. M1 is complete only when every row is landed and the
cross-runtime gate passes; passing a Python-only vector suite does not close
M1-12.

### M2 — CLI and administration seams

| | |
|---|---|
| **Needs** | M1 artifact contracts |

- Restore the `dracla` package entry point and client-side Hydra composition
  with release-declared provenance and dependency constraints (§6.9)
- A substitutable GitHub administration surface, separate from the append-only
  records transport: account/repository discovery, creation, visibility,
  branches, deploy keys, Actions secrets, and workflow dispatch (§6.10.5)
- Exact owner/project-slug normalization and plans for the records, coverage,
  and control repositories (§6.10.3)
- `dry_run=true` with zero writes, explicit confirmation/force behavior,
  idempotent resume state, and collision refusal
- Cross-module tests proving every generated CLI command exists and every
  emitted artifact satisfies the shared contracts

This milestone builds the CLI framework and repeatable provisioning planner.
It does not call a placeholder reconciler or pretend the hosted key-wrap and
challenge paths exist.

### M3 — Pinned control workflow and reconciler

| | |
|---|---|
| **Needs** | M1; M2 administration seam for integration tests |
| **Closes** | §16 item 8 when integrated and verified |

- Real pinned reconcile command, workflow, provenance manifest, digest pins,
  upgrade/rollback contract, and verification manifest (§9)
- Canonical replay; projection, index, reader-state, marker, and decision-fence
  verification and repair
- Explicit hosted export jobs and local streaming JSON/CSV export, including
  formula neutralization (`REQ-SEC-8`)
- `dracla verify` and `dracla reconcile` using the same replay rules
- Recovery from every persisted crash point and installer transport-key probes

---

## Track B — hosted paths and GitHub Apps

### M4 — Enforcement and routing

| | |
|---|---|
| **Needs** | M0 Cloudflare resources and Apps; M1; M3 recovery path |
| **Closes** | §16 items 3, 4, and 6 |

- Enforcer Worker webhook verification, bounded subject resolution, coverage
  evaluation, check publication, and generic PR comment
- Per-pull-request merge-group evaluation and fresh rebuilt-entry behavior
- Signed routes, repository-bound routing gates, publication reservations,
  decision fences, freshness checks, and fail-closed overlap handling
- Overrides and exemptions without exposing exact private reasons

### M5 — Portal, Connect, signing, and administration

| | |
|---|---|
| **Needs** | M0 Cloudflare resources and all three Apps; M1; M3; M4 |
| **Closes** | §16 items 1–2, 5, and 7 when connected to a provisioned project |

- OAuth with browser-bound state, encrypted sessions, logout, and scoped
  private-read proofs
- Bootstrap wrapping and repository-bound portal, enforcer, and control
  challenge endpoints; no general key-wrap oracle
- Connect with exact App/repository evidence, `project_connected`, encrypted
  configuration, initial reader intent, and registry publication last
- Agreement publication/activation, signing, revocation, re-signing,
  exemptions, overrides, readers, and enforcement-scope administration
- Re-evaluation of an originating pull request after signing

### M6 — End-to-end installer

| | |
|---|---|
| **Needs** | M2, M3, M5, and all three App installation pages |
| **Closes** | Provisioning portion of §16 item 1; foundation for item 11 |

- Execute the complete idempotent §6.10.3.1 sequence against a real account:
  three empty private repositories, mandatory README root, branch layout,
  pinned control artifact, transport credentials, verified project keys,
  bootstrap manifests, encrypted empty state, and three App links
- Prove adopter recovery of both actual data keys before the first private
  write and discard installer-held raw/recovery material after handoff
- Refuse unrelated name collisions and any release without the real reconciler,
  provenance, constraints, and allowed-artifact manifest
- Complete App installation and Connect without treating install as a signable
  or routable project

The installer is integrated here rather than treated as the first independent
component: revision 13 requires it to verify real control code and live hosted
wrapping paths, not placeholders.

### M7 — Product surfaces and release verification

| | |
|---|---|
| **Needs** | M3–M6 |
| **Closes** | §16 items 9–11 and `REQ-VERIFY-1..2` |

- Private dashboard and authorizing index proxy
- Static badges, canonical project links, and PR-scoped graded disclosure
- A second sample project with a different immutable legal recipient, installed
  through configuration rather than source edits
- Complete traceability matrix and every required acceptance scenario
- Close A2 encrypted-path/continuous-team/Durable Object measurements, update
  the A3 model with measured dimensions, and run the A6 write-deploy-key reach
  and recovery probe before release

---

## Critical path

```text
M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7
                    ^      ^
Cloudflare + Apps --+------+
```

The M1 implementation stack began with the landed canonical-artifact and
encrypted-envelope foundations and continues through the execution map above.
The first CLI stack follows with the administration protocol and a no-write
planner; repository mutation arrives only after the M1 contracts are tested.

## Pre-release gates still open

- **A2:** measure the complete encrypted enforcement, mutation, private-read,
  export, continuous-team, and Durable Object paths on real accounts.
- **A3:** add measured Durable Object and final workload dimensions to the
  capacity model and reproduce the published envelope.
- **A6:** probe write-deploy-key integrity reach and complete the exposure,
  rotation, restore, replay, repair, and open-PR recheck exercise.
