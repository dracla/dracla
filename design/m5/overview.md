# M5 — Portal, Connect, signing and administration

Status: the complete current requirements, architecture, Connect plan and
inventory have clean general and actual DBB design reviews with verified
dependencies. The [plan attestation](.review/implementation-plan.md) binds the
exact reviewed files. Product delivery and live acceptance remain separate.

M5 supplies the complete contributor portal, authenticated administrative
journeys, current private-reader APIs and hosted-export integration. It keeps
two Workers, one static portal, the separate isolated agreement origin and
Git-hosted truth. It reuses M4's writer/runtime/coordinator and M3's renderer/
recovery. Snapshot/advisory defaults, exact forms and scoped private reads remain.

Read the [requirements](requirements.md), [architecture](high-level-design.md),
[implementation plan](implementation-plan.md) and [canonical inventory](slices.json).
The [estimate basis](supporting/implementation-plan/engineering-basis.md) records
inspected source, real missing adapters, provider evidence and uncertainty.
Shared foundations are counted once in their owning prerequisite.

The table counts incremental final delivered nonblank physical lines, excluding
comment-only lines and counting docstrings physically. Shipped configuration/
instructions count as production; test helpers/config/generators/integration/
live drivers count as tests. Designs, static data, generated output/images,
dependencies and locks are excluded. These are not churn or time estimates.

<!-- awd:slice-table:start -->
| Status | Slice ID | Short description | Production lines | Test lines |
| --- | --- | --- | ---: | ---: |
| ⏳ Pending | `m5/1` | Browser-bound GitHub authentication and live sessions | 600–900 | 850–1,350 |
| ⏳ Pending | `m5/2` | Public agreement presentation and isolated portal shell | 500–800 | 900–1,400 |
| ⏳ Pending | `m5/18` | Current resource authority and authorized repository conflict inspection | 730–1,130 | 910–1,400 |
| ⏳ Pending | `m5/3` | Authenticated own status from bounded validated state | 300–520 | 500–820 |
| ⏳ Pending | `m5/4` | Exact assent and correction through the shared durable writer | 620–1,000 | 1,000–1,500 |
| ⏳ Pending | `m5/5` | Revocation, fresh re-sign and exact PR continuation | 300–500 | 500–850 |
| ⏳ Pending | `m5/6` | Live administrative evidence and agreement/configuration actions | 470–740 | 780–1,170 |
| ⏳ Pending | `m5/7` | Explicit exemption and reader snapshots with source withdrawal | 800–1,250 | 1,100–1,800 |
| ⏳ Pending | `m5/8` | Continuous membership observations and missed-event recovery | 650–1,050 | 1,050–1,700 |
| ⏳ Pending | `m5/9` | Current reader proofs and fixed private data pages | 600–950 | 950–1,550 |
| ⏳ Pending | `m5/10` | Purpose-bound permission results and private PR disclosure tiers | 400–650 | 650–1,100 |
| ⏳ Pending | `m5/11` | Authenticated initial wrapping and all service live challenges | 550–850 | 850–1,350 |
| ⏳ Pending | `m5/12` | Complete Connect and guarded first project activation | 880–1,390 | 1,480–2,450 |
| ⏳ Pending | `m5/13` | Owner transfer, legal succession and successor key activation | 500–820 | 850–1,400 |
| ⏳ Pending | `m5/14` | Authorized scope conflicts, exact overrides and targeted retries | 270–420 | 590–950 |
| ⏳ Pending | `m5/15` | Authenticated protected export dispatch and real Python authority | 750–1,150 | 1,200–1,900 |
| ⏳ Pending | `m5/16` | Reauthorized private JSON and CSV snapshot delivery | 350–580 | 650–1,050 |
| ⏳ Pending | `m5/17` | Integrated M5 acceptance, controller lifecycle and capacity evidence | 300–500 | 1,000–1,600 |
| | **Project total** | Current slices; replaced parents excluded. | **9,570–15,200** | **15,810–25,340** |
<!-- awd:slice-table:end -->

The M4–M7 design campaign is complete. Future delivery uses this canonical
inventory under its existing admission/review rules. Actual grants/SSO/roles,
OAuth, authentic execution, hosted resource limits and containment remain
execution gates; design review does not establish them.

Related packages: [M4](../m4/overview.md), [M6](../m6/overview.md),
[M7](../m7/overview.md). Completed source/IDs, historical reports and spent budgets
remain preserved. No new M5 owner decision is open.
