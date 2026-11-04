# M7 — Product surfaces and release verification

Design complete: requirements, HLD, detailed plan, canonical inventory and owned
support have current clean general and retained DBB design reviews. The
[plan attestation](.review/implementation-plan.md) binds the exact reviewed bytes.
All15 implementation slices remain planned; actual product/live acceptance is
separate. No owner decision is pending.

The goal is a working authorized dashboard, accessible static project links,
an independent installed recipient and complete current release/A2/A3/A6 evidence.
Use the one M5 app and existing M4/M5/M6 authority, engines and drivers. Raw copies
preserve broken state exactly; live activation separately requires healthy state.

Read [requirements](requirements.md), [architecture](high-level-design.md),
[detailed plan](implementation-plan.md) and [engineering/estimate basis](supporting/implementation-plan/engineering-basis.md).
The [clause/scenario catalogue](supporting/implementation-plan/acceptance-catalogue.md)
defines future observations; it contains no claimed execution passes.

The four-package design campaign is complete, including its combined estimate
and prospective navigation cleanup. Future delivery uses the canonical inventory
and its existing admission/review rules; this design closeout starts no product
implementation or live operation. [M4](../m4/overview.md), [M5](../m5/overview.md)
and [M6](../m6/overview.md) retain their own foundation ownership.

<!-- awd:slice-table:start -->
| Status | Slice ID | Short description | Production lines | Test lines |
| --- | --- | --- | ---: | ---: |
| ⏳ Pending | `m7/1` | Authenticated coherent dashboard pages | 300–480 | 600–950 |
| ⏳ Pending | `m7/2` | Bounded private dashboard scan and rendering | 400–650 | 700–1,100 |
| ⏳ Pending | `m7/3` | Complete dashboard filters and stable ordering | 220–360 | 450–750 |
| ⏳ Pending | `m7/4` | Safe refresh and private browser lifecycle | 300–480 | 850–1,350 |
| ⏳ Pending | `m7/5` | Accessible static badges and complete canonical links | 200–340 | 500–800 |
| ⏳ Pending | `m7/6` | Independent installed sample across deployments | 180–300 | 1,000–1,600 |
| ⏳ Pending | `m7/7` | Joined signing administration and reader journeys | 120–200 | 1,400–2,200 |
| ⏳ Pending | `m7/8` | Joined queue routing and concurrent recovery journeys | 100–180 | 1,200–1,900 |
| ⏳ Pending | `m7/9` | Every-clause release verification and current evidence | 180–300 | 700–1,150 |
| ⏳ Pending | `m7/10` | Complete encrypted production-path measurement cases | 220–360 | 1,000–1,600 |
| ⏳ Pending | `m7/11` | Hosted CPU resource and billing measurements | 130–230 | 1,400–2,300 |
| ⏳ Pending | `m7/12` | Complete dimensional workload calculator | 400–650 | 650–1,050 |
| ⏳ Pending | `m7/13` | Provider limits and evidenced capacity envelope | 350–600 | 700–1,150 |
| ⏳ Pending | `m7/14` | All-token containment exact copy and healthy activation | 200–330 | 1,300–2,100 |
| ⏳ Pending | `m7/15` | Authentic release identity and complete acceptance | 650–1,050 | 1,300–2,100 |
| | **Project total** | Current slices; replaced parents excluded. | **3,950–6,510** | **13,750–22,100** |
<!-- awd:slice-table:end -->
