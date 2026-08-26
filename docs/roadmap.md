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
M1 -> M2 -> M3 --------------------------\
  \-> M4 -> M5 -----> M6 ----------------+-> M7
Cloudflare + three Apps -> M4 and M5 ----/
```

The first implementation stack should begin with M1's canonical artifact and
golden-vector foundation. The first CLI stack follows with the administration
protocol and a no-write planner; repository mutation arrives only after those
contracts are tested.

## Pre-release gates still open

- **A2:** measure the complete encrypted enforcement, mutation, private-read,
  export, continuous-team, and Durable Object paths on real accounts.
- **A3:** add measured Durable Object and final workload dimensions to the
  capacity model and reproduce the published envelope.
- **A6:** probe write-deploy-key integrity reach and complete the exposure,
  rotation, restore, replay, repair, and open-PR recheck exercise.
