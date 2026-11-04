# M4 — Enforcement and routing

Status: requirements, architecture and the detailed plan/inventory have current
clean general and retained DBB design reviews with verified dependencies. The
[plan attestation](.review/implementation-plan.md) binds the exact reviewed files.
Product delivery and actual installed/hosted/live acceptance remain separate.

M4 makes ordinary PR feedback, authoritative ALLGREEN queue admission and
default-branch fallback use authenticated immutable coverage from the correct
project. It supplies the shared routing and recovery foundation for M5–M7.

The [requirements](requirements.md) define the complete outcome. The
[architecture](high-level-design.md) retains two Workers, signed routes and
repository-local SQLite gates. Enforcement remains read-only for coverage;
the approved narrow portal service performs exact reservation writes. Canonical
GitHub events remain truth. No third Worker, queue or new CLA database is added.

The [implementation plan](implementation-plan.md) resolves module boundaries,
transport/coverage observations, reservation ordering, canonical continuity,
fallback mode, protected control integration, recovery and required tests.
The [canonical inventory](slices.json) owns ordered slice definitions and separate
production/test estimates. The [estimate basis](supporting/implementation-plan/engineering-basis.md)
records inspected source and concrete changes. Shared foundations and their
tests are counted once here; later milestones count only extensions.

The table uses incremental final delivered nonblank physical lines excluding
comment-only lines, including docstrings, shipped config/instructions and test
drivers. It excludes design prose, static data, generated output and locks;
the ranges are not edit churn or time estimates.

<!-- awd:slice-table:start -->
| Status | Slice ID | Short description | Production lines | Test lines |
| --- | --- | --- | ---: | ---: |
| ⏳ Pending | `m4/1` | Production Worker entrypoints and real runtime test harness | 400–650 | 550–880 |
| ⏳ Pending | `m4/2` | Bounded GitHub transport and repository-scoped credentials | 480–740 | 730–1,120 |
| ⏳ Pending | `m4/3` | Authenticated bounded coverage reads with shared decision semantics | 270–440 | 450–740 |
| ⏳ Pending | `m4/16` | Versioned canonical trailer policy and immutable coverage support | 400–680 | 670–1,060 |
| ⏳ Pending | `m4/4` | SQLite routing gate and narrow coverage reservation service | 480–760 | 740–1,140 |
| ⏳ Pending | `m4/5` | Complete registry derivation and signed route publication | 700–1,120 | 950–1,500 |
| ⏳ Pending | `m4/6` | Authenticated canonical scope continuity and control preconditions | 380–640 | 560–900 |
| ⏳ Pending | `m4/15` | Shared Worker canonical mutation and projection executor | 620–980 | 950–1,480 |
| ⏳ Pending | `m4/7` | Conditional routing transitions and repair-forward coordinator | 450–740 | 720–1,120 |
| ⏳ Pending | `m4/8` | Authenticated PR checks and generic comments | 480–780 | 760–1,200 |
| ⏳ Pending | `m4/9` | ALLGREEN authoritative publication and exact completion recovery | 450–740 | 800–1,250 |
| ⏳ Pending | `m4/10` | Mode-aware default-branch fallback and bounded issues | 410–680 | 650–1,040 |
| ⏳ Pending | `m4/11` | Lifecycle invalidation and bounded scheduled recovery | 400–680 | 640–1,040 |
| ⏳ Pending | `m4/12` | Protected control authentication and real M3 routing recovery | 800–1,250 | 1,210–1,880 |
| ⏳ Pending | `m4/13` | Credential incident containment and conditional restore integration | 360–620 | 620–1,020 |
| ⏳ Pending | `m4/14` | Integrated M4 evidence, platform limits and operator guidance | 250–450 | 650–1,060 |
| | **Project total** | Current slices; replaced parents excluded. | **7,330–11,950** | **11,650–18,430** |
<!-- awd:slice-table:end -->

The M4–M7 design campaign is complete. Future delivery uses the canonical
inventory under its existing admission/review rules. Actual installed-grant
visibility, hosted cold limits and credential containment remain execution gates.

Related packages: [M5](../m5/overview.md), [M6](../m6/overview.md),
[M7](../m7/overview.md). Shared foundations remain owned here; later milestones
count only their extensions and joined acceptance. Completed M1–M3 source, slice
IDs and original evidence remain preserved.
