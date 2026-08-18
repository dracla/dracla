# Development milestones

Maps work to the release scope in `design/requirements.md` §16. Each milestone
names the scope items it closes, so "done" is defined by the requirements rather
than by feeling finished.

`REQ-VERIFY-1` makes an unverified `MUST` a release blocker, so the traceability
matrix is filled in as each milestone lands — not reconstructed at the end.

---

## M0 — Foundations

| | |
|---|---|
| **Status** | Mostly done |
| **Closes** | none directly; everything depends on it |

- [x] Requirements baseline locked (revision 2)
- [x] High-level design, reviewed adversarially, 81 findings resolved
- [x] Core: event model, append-only protocol, coverage projection
- [x] GitHub client, verified against the live API
- [x] A2 (edge CPU), A3 (capacity), A4 (merge queue on Free)
- [x] Apache-2.0, public repository
- [x] **Domain / origin** — `dracla.yadan.net`, one origin for shell and API (§9)
- [ ] **Cloudflare account** — Workers, Pages, Secrets, KV
- [ ] **Two GitHub Apps** created per `docs/github-apps.md` (needs the domain
      first, for callback and Setup URLs)

The three unchecked items are the only ones that need the project owner.

---

## Track A — no external dependencies

Runs immediately, in parallel with everything blocked on the domain.

### M1 — CLI: provisioning and configuration

| | |
|---|---|
| **Closes** | §16 item 1 (partly), foundation for item 11 |
| **Needs** | nothing |

- `dracla install` — create the repo pair, seed config, agreement, reconcile
  workflow, coverage deploy key; print the two installation links
- `dracla config` — Hydra composition on the client, resolved JSON committed
- `dracla publish` / `dracla activate` — agreement lifecycle (§6.5)
- Workspace file for multi-project operation (§6.9)
- Integration-tested against a real org, the way `core/` already is

**Why first:** the Workers cannot be tested against anything until a provisioned
pair exists, so this is on the critical path for M3 and M4 regardless.

### M2 — Reconciler

| | |
|---|---|
| **Closes** | §16 item 8 |
| **Needs** | M1 |

- Actions workflow seeded into canonical, daily schedule (§9.2)
- Replay, verify the projection, repair, clear orphaned markers
- Dashboard index and JSON/CSV exports to `derived/` (§5.1)
- CSV formula neutralization, JSON keeping canonical values (`REQ-SEC-8`)
- `dracla verify` runs the same replay locally

Mostly wiring existing core into a workflow.

---

## Track B — needs the domain and Apps

### M3 — Enforcement

| | |
|---|---|
| **Closes** | §16 items 3, 4, 6 |
| **Needs** | M0 complete, M1 for a test target |

- `worker-enforce`: webhook verification, subject resolution, scope evaluation,
  check runs
- Merge-group path, the authoritative decision (§6.4)
- Freshness guard, in-flight marker (§5.4)
- Overrides and exemptions consulted (§6.3)

**Before M4** deliberately: this is the riskier half and where all the protocol
interaction lives. Better to meet surprises early.

### M4 — Signing

| | |
|---|---|
| **Closes** | §16 items 2, 5, 7 |
| **Needs** | M0, M3 |

- `worker-portal`: OAuth with browser-bound state (§8.2), encrypted session,
  KV-backed token store, logout
- Sign, revoke, re-sign; opportunistic orphan clearing
- Re-evaluate the originating pull request after signing
- Static portal: agreement review, own status, the three actions

### M5 — Surfaces

| | |
|---|---|
| **Closes** | §16 items 9, 10 |
| **Needs** | M4 |

- Dashboard shell plus the authorizing index proxy (§6.6)
- Badges as static assets; pull request comment (§6.7)
- PR-scoped view with graded disclosure (§6.3)

---

## M6 — Second project and release verification

| | |
|---|---|
| **Closes** | §16 items 1 (complete), 11; `REQ-VERIFY-1`, `REQ-VERIFY-2` |
| **Needs** | everything |

- Second sample project, **different legal recipient**, installed by
  configuration only — exercises §5.5 and workspace composition
- Traceability matrix: every in-scope `MUST` to a test or recorded manual check
- The `REQ-VERIFY-2` scenarios, including the ones with concrete pass criteria
  already written: authorization loss (§8.2), backup restore (§9.1), budget
  exhaustion (§9)

---

## Critical path

```
domain -> Cloudflare account -> 2 GitHub Apps -> M3 -> M4 -> M5 ─┐
                                                                 ├-> M6
M1 -> M2 ────────────────────────────────────────────────────────┘
```

Track A is unblocked today, and needs no domain at all: the CLI provisions with
the administrator's own credentials and never touches the portal origin.

Track B waits on a Cloudflare account and the two Apps. The origin is settled
as `dracla.yadan.net`; `cli.dev` is assigned but its transfer is pending and may
take months, so nothing is planned around it. Moving later costs two App config
edits plus a permanent redirect — see `docs/github-apps.md`.

## Parked

- Confirming CPU measurement on a real Cloudflare account (A2). The workerd
  figures have an order of magnitude of headroom, so this is confirmation
  rather than a risk.
- Migrating the origin to `dracla.cli.dev` once that transfer completes. Cheap
  before adopters exist, and a single redirect rule afterwards.
