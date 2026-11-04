# M6 — Installation, deployment and exact recovery

Status: requirements, architecture and the detailed plan/inventory have current
DBB-backed design review. Product delivery has not started. The
[plan attestation](.review/implementation-plan.md) binds the exact reviewed files.

## Goal

An unrelated adopter provisions verified private records/coverage/control with
the released installer, retains tested recovery material and enters the separate
Connect flow. Shared and self-hosted deployments use the same released code.
Copying a broken backup preserves it exactly; live activation is a separate
request that requires an already consistent source and all first-install checks.

## Design

The [requirements](requirements.md) and [architecture](high-level-design.md)
retain the approved trust model and one local deployment-profile selector.
Reuse M2 administration/planning, M1/M3 crypto/history/writer, and the real M4/M5
runtime, proof and routing prerequisites. M6 supplies the missing local/deployment
adapters and bounded prospective rebind integration. It adds no second writer,
application store or automatic repair during restore.

## Implementation

The [implementation plan](implementation-plan.md) defines concrete protocols;
[slices.json](slices.json) is the sole canonical ordered inventory. The
[engineering basis](supporting/implementation-plan/engineering-basis.md) explains
source reuse, actual new integration and separate estimate composition.
The 18 planned slices total 10,210–16,100 production and 19,930–31,800 test lines in
the agreed incremental final-delivered physical units, with foundations counted
once. These are reviewed planning estimates, not implemented code or live acceptance.

## Next step

Begin future product delivery from the reviewed canonical inventory. The M7
package and combined M4–M7 estimate/navigation check are complete. No owner
question is pending. Existing architecture/profile/exact-copy decisions remain
settled; a genuinely new scope/trust/public-contract decision returns explicitly.

<!-- awd:slice-table:start -->
| Status | Slice ID | Short description | Production lines | Test lines |
| --- | --- | --- | ---: | ---: |
| ⏳ Pending | `m6/1` | Trusted deployment profile and read-only installation planning | 500–790 | 800–1,250 |
| ⏳ Pending | `m6/2` | Private role repositories and exact initial Git roots | 450–700 | 800–1,250 |
| ⏳ Pending | `m6/3` | Verified protected control installation before secrets | 350–550 | 650–1,000 |
| ⏳ Pending | `m6/4` | Administrator-owned transport App scope and key custody | 500–800 | 850–1,350 |
| ⏳ Pending | `m6/5` | Actual data-key proofs and private recovery handoff | 770–1,200 | 1,300–2,100 |
| ⏳ Pending | `m6/6` | Initial transport challenge and exact K/B idle bootstrap | 650–1,000 | 1,150–1,850 |
| ⏳ Pending | `m6/7` | Provenance verifier and executable installer coordination | 600–960 | 1,200–1,950 |
| ⏳ Pending | `m6/8` | Released installer through real separate Connect acceptance | 300–500 | 750–1,200 |
| ⏳ Pending | `m6/9` | Same-release shared and self-hosted deployment assets | 1,000–1,550 | 1,400–2,200 |
| ⏳ Pending | `m6/10` | Compatible upgrade and rollback procedures with readback | 500–800 | 850–1,400 |
| ⏳ Pending | `m6/11` | Exact snapshot manifests and isolated mirror-copy procedure | 600–950 | 1,000–1,650 |
| ⏳ Pending | `m6/12` | Closed schema-2 rebind and generation parity | 750–1,150 | 1,400–2,200 |
| ⏳ Pending | `m6/13` | Strict historical-origin and current repository readers | 500–800 | 1,100–1,750 |
| ⏳ Pending | `m6/14` | Healthy-source admission and exact activation-operation retries | 250–400 | 650–1,100 |
| ⏳ Pending | `m6/15` | Explicit live activation through protected proofs and one rebind | 1,340–2,050 | 2,680–4,100 |
| ⏳ Pending | `m6/16` | Installed controller lifecycle and hosted migration integration | 450–750 | 1,000–1,650 |
| ⏳ Pending | `m6/17` | Assembled offline acceptance and failure-sensitivity evidence | 450–700 | 1,250–2,000 |
| ⏳ Pending | `m6/18` | Real adopter and self-hosted installation acceptance driver | 250–450 | 1,100–1,800 |
| | **Project total** | Current slices; replaced parents excluded. | **10,210–16,100** | **19,930–31,800** |
<!-- awd:slice-table:end -->

The M4–M7 design campaign is complete. Future delivery uses this canonical
inventory and its existing admission/review rules. Actual installer/controller,
shared/selfhost, healthy activation and live acceptance remain execution gates.
Related packages: [M4](../m4/overview.md), [M5](../m5/overview.md),
[M7](../m7/overview.md). No new owner decision is open.
