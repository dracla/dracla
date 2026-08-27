# DraCLA low-level design index

Status: Draft index
Date: 27 August 2026
Requirements baseline: `design/requirements.md` (Locked, revision 13)
Architecture baseline: `design/high-level-design.md` (Locked, 25 August 2026)

This document is the implementation index for the locked DraCLA design. It
maps the complete HLD into milestone-sized low-level designs without repeating
the normative protocol. Detailed implementation work is selected from one
milestone LLD at a time.

The requirements and HLD remain authoritative. An LLD may choose modules,
interfaces, validation boundaries, test organization, and delivery slices. It
may not add a wire value, weaken a rejection rule, change a state transition,
or silently resolve a conflict in the locked documents. Such a conflict stops
implementation and returns to design review.

## 1. Document set

| Milestone | LLD | Maturity | Implementation status |
|---|---|---|---|
| M0 — reviewed baseline and owner prerequisites | This index and `docs/github-apps.md` | Operational checklist; no implementation LLD | Reviewed design complete; Cloudflare resources and three GitHub Apps remain external prerequisites |
| M1 — conformance kernel | [`design/lld/m1-conformance-kernel.md`](lld/m1-conformance-kernel.md) | Detailed draft | M1-1 and M1-2 landed; M1-3 through M1-12 planned |
| M2 — CLI and administration seams | `design/lld/m2-cli-administration.md` | Planned | Not started |
| M3 — pinned control workflow and reconciler | `design/lld/m3-control-reconciler.md` | Planned | Not started |
| M4 — enforcement and routing | `design/lld/m4-enforcement-routing.md` | Planned | Not started |
| M5 — portal, Connect, signing, and administration | `design/lld/m5-portal-connect.md` | Planned | Not started |
| M6 — end-to-end installer | `design/lld/m6-installer.md` | Planned | Not started |
| M7 — product surfaces and release verification | `design/lld/m7-product-release.md` | Planned | Not started |

Only an existing, reviewed milestone document is a delivery source. A planned
path in this table is not an instruction to infer missing detail from its name.

## 2. Authority and change control

When two artifacts differ, use this order:

1. locked revision-13 requirements;
2. locked and cleanly attested HLD;
3. the milestone LLD governing the selected task;
4. `docs/roadmap.md` for sequencing and status;
5. `docs/architecture.md` for orientation;
6. existing implementation and historical review findings as evidence only.

The code under `core/dracla/conformance/` is implementation evidence for the
landed M1 slices. The other current `core/dracla` modules are pre-revision-13
protocol and transport experiments. They may supply a tested technique, but
their plaintext event, projection, shard, and trust models are not defaults.
`design/review-findings.md` is a historical rationale and regression register,
not a source of new requirements.

Each milestone LLD records:

- exact task IDs and titles usable as delivery selectors;
- dependencies and governing HLD/requirement sections;
- owned modules, public interfaces, serialized artifacts, and error boundaries;
- required positive, negative, race, recovery, and cross-runtime evidence;
- explicit non-goals and the next milestone that owns deferred behavior;
- reviewable pull-request boundaries and conditions that require remapping.

The implementation-status sections are descriptive. Marking code as landed
requires repository and test evidence; editing a status label does not make an
underlying requirement true.

## 3. Cross-milestone implementation rules

### 3.1 Runtime ownership

HLD decision D8 controls runtime ownership:

- Python owns canonical event validation, replay, export semantics, the
  reconciler, recovery/reporting logic, and the CLI.
- TypeScript owns thin Cloudflare request paths and implements only the byte,
  authenticated-form, routing, and coverage contracts needed at the edge.
- Shared byte contracts use one checked-in vector corpus. Independent runtime
  tests consume the same input and expected bytes; one runtime's output is not
  the other's test oracle.

### 3.2 Durable truth and projections

Canonical event ancestry is the business-state authority. Coverage, private
derived artifacts, signed routes, and Durable Object rows are bounded,
fail-closed projections. No milestone may introduce a database, queue, cache,
or receipt store that becomes an alternate source of CLA truth.

Repository responsibilities remain distinct:

- records: encrypted canonical evidence, records-private derivatives,
  prepared-operation recovery state, and wrapped records-key metadata;
- coverage: encrypted least-privilege enforcement state, mutation markers, and
  the decision fence;
- control: pinned executable reconciler inputs and project-scoped secrets;
- deployment registry: immutable project/routing generations, with no signer
  evidence or project data keys.

### 3.3 Validation and failure posture

Unknown versions, fields, enums, paths, algorithms, key IDs, capabilities,
cross-bindings, and state combinations fail closed. Schema-valid ciphertext is
not trusted until its path-derived identity, project, capability, canonical
encoding, authentication, and semantic relations all validate.

Age is never authority to clear prepared operations, in-flight markers,
decision fences, or routing reservations. Every recovery transition is owned
by an exact persisted identity and is conditional on immutable repository or
gate state.

### 3.4 Privacy and capability separation

Repository visibility is defense in depth; authenticated encryption and
decryption capability are the private-record boundary. The enforcement runtime
must never receive a records key or exact signer evidence. Coverage remains
private even though it omits names and emails. Paths, refs, commit messages,
logs, workflow artifacts, public assets, and unauthorized responses contain no
private values.

### 3.5 Release evidence

`REQ-VERIFY-1` makes every unmet or unverified in-scope `MUST` a release
blocker. Each delivery slice extends traceability as its behavior becomes real.
M7 assembles the release matrix; it does not reconstruct missing evidence after
the fact.

## 4. Complete HLD ownership map

This table assigns every HLD section to the milestone that turns it into
implementation detail. A section may constrain several milestones; the primary
owner is responsible for the detailed LLD, while dependent milestones cite the
same locked section rather than restating it.

| HLD area | Primary milestone | Dependent milestones | Implementation responsibility |
|---|---|---|---|
| §1 design decisions | M1–M7, by component | All | Preserve D1–D18, including D4a, as cross-cutting constraints; each milestone lists the decisions it realizes |
| §2 deviation from `REQ-OPS-2` | M4 | M3, M7 | Serverless enforcement, fail-closed behavior, and release verification of the declared deviation |
| §3 system context | M4/M5 | M2, M3, M6 | Runtime boundaries, trust flow, project repository set, hosted and self-hosted topology |
| §4 principals and permissions | M5 | M2, M3, M4, M6 | Live service credentials and permission surfaces |
| §4 encrypted artifact identity and envelope | M1 | M3–M7 | Canonical bytes, path-derived purpose, key capability, strict decryption contracts |
| §4 wrapped key copies and access map | M1 | M3, M5, M6, M7 | Keyring bytes in M1; hosted/control/recovery custody and lifecycle in later milestones |
| §5.1 canonical event schema and identities | M1 | M3, M5 | Closed event union, authorization vocabulary, identity derivation, semantic validation, replay |
| §5.2 append-only commit protocol | M3 | M1, M5 | M1 supplies validated frozen inputs; M3 owns Git transport, race handling, and repair |
| §5.3 coverage projection | M1 | M3, M4, M5 | M1 owns schemas and deterministic materialization; later milestones own writes and reads |
| §5.4 freshness guard and action forms | M1 | M3–M5 | M1 owns pure persisted-state/form contracts; M3–M5 own repository, gate, and request drivers |
| §5.5 project/repository-set lifecycle | M1 | M2, M4–M6 | Replay truth in M1; naming, routing, provisioning, and portal behavior later |
| §6.1 signing and §6.2 revocation | M5 | M1, M4 | Portal flow over M1 events/forms and M4 enforcement feedback |
| §6.3 pull-request check and §6.4 merge-group check | M4 | M1, M5, M7 | Subject resolution, projection evaluation, publication ordering, disclosure |
| §6.5 agreement activation | M5 | M1, M3 | User/admin flow; M1 owns event, replay, active-version and state contracts |
| §6.6 dashboard and exports | M7 | M1, M3, M5 | M1 owns bounded schemas; M3 owns replay/export engine; M5 owns authorization; M7 owns product surfaces |
| §6.7 badges and public surfaces | M7 | M4, M5 | Stable public links, accessible wording, bounded disclosure |
| §6.8 administrative flows | M5 | M1, M4 | Live authorization and UI; M1 owns closed evidence, events, forms, and replay effects |
| §6.9 CLI | M2 | M3, M6, M7 | Package entry point and composition in M2; operational commands as their engines land |
| §6.10 install | M6 | M1–M5 | End-to-end orchestration after real contracts, administration seams, reconciler, and hosted challenges exist |
| §6.10.5 module boundaries | M2 | M3, M6 | Separate GitHub administration from append-only records transport |
| §6.10.6 test obligations | M1–M7, by behavior | All | Each milestone owns its listed seam tests; M7 verifies complete release coverage |
| §7 multi-tenancy, registry, and routing state machine | M4 | M5, M6, M7 | Immutable registry generations, signed routes, repository gate, overlap handling, reconciliation |
| §8 security model | M4/M5 | M1–M3, M6, M7 | Threat-specific controls, browser authentication, credential handling, trust disclosure, data protection |
| §8.4.1 observability | M7 | M3–M6 | Redacted event taxonomy, metrics, operational evidence, no private logs |
| §9 deployment | M6 | M3–M5, M7 | Hosted/self-hosted deployment, pins, rollback, secrets, and installation topology |
| §9.1 backup and recovery | M3 | M1, M5–M7 | Replay/repair engine and service-independent recovery; installation and release exercises later |
| §9.2 capacity envelope | M7 | M1, M3–M6 | Checked-in limits originate with owning contracts; final hosted measurements and release envelope close in M7 |
| §10 alignment history | No implementation owner | All | Rationale and declared deviations; implementation must not reinterpret resolved history |
| §11 assumptions and open items | M0/M7 | Owning milestones | External prerequisites close in M0; A2, A3, and A6 remain release gates |
| §12 risks | M1–M7, by mitigation | All | Tests and runbooks must preserve the listed mitigation; residual risk is not silently claimed closed |
| §13 traceability | M7 | All | Incremental evidence from each milestone, assembled into final release traceability |

## 5. Milestone dependency and drafting policy

The implementation critical path is:

```text
M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7
                    ^      ^
Cloudflare + Apps --+------+
```

The next milestone LLD is drafted and reviewed before implementation begins,
using the locked HLD and the actual interfaces landed by its prerequisites.
Later milestone files are not filled speculatively. This keeps interfaces
concrete without allowing implementation drift to amend the HLD by accident.

Within a milestone, the roadmap and LLD use the same task IDs. A normal delivery
request selects one exact heading, for example:

```text
global:swe:deliver-design-stack("design/lld/m1-conformance-kernel.md", "M1-3")
```

The delivery queue includes only dependencies not already evidenced as landed.
If a selected task cannot fit its stated review boundary, implementation stops
and the LLD/roadmap boundary is reviewed before code is split.

## 6. Current next step

Review and lock the M1 LLD, then deliver M1-3 through M1-12 in order. M1-3 and
M1-4 are logically independent after the landed foundations but remain
sequential commits in one review stack. M1 closes only after the shared Python
and TypeScript conformance gate passes.
