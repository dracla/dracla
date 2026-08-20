---
document: high-level-design.md
sha256: 8116cfb03b2b4fb5581cad0774574fbf3befa52020fc8dbcaaffde80ea3b5300
algorithm: sha256 over the exact file bytes at the attested revision
review: deep-design-review-loop, rounds 1-3, 2026-08-20; post-loop editorial
  edits verified by remote review, Gitar and Codex round 1; approved mechanical
  design findings from Codex connector round 2 and the CLI sweep applied,
  2026-08-20
verdict: approved mechanical findings fixed; owner-reserved decisions remain open
---

# Review sidecar — high-level-design.md

## Standing decisions

- **Scope-binding consent record (R1-2, 2026-08-20)**: lives per-entry inside
  the registry entry (`bound_by`, `bound_at`, `basis`), written by the portal
  in the same registry commit that adds the entry — chosen over a separate
  consent log so the record and the entry cannot diverge. Do not reintroduce
  bare scope lists.
- **intents.json field set (R1-7, 2026-08-20)**: `digest` was dropped because
  no reader existed; `event_id` is retained solely as the reconciler's join to
  the canonical event (folding and orphan settlement). Re-adding a field
  requires naming its reader.
- **Webhook-secret rotation (R1-5, 2026-08-20)**: verifying two secrets of the
  *same* App on its own route during rotation does not violate §8.1.2's
  single-route rule, which is about cross-App secret confusion.
- **Deploy-key provisioning and rotation (R2-1, 2026-08-20)**: the
  administrator's CLI act — M2 `dracla install` re-run provisions, `dracla
  rotate-key` replaces — never a portal action; the records App never holds
  repository administration. A non-secret fingerprint/generation manifest and
  challenge write verify the otherwise unreadable secret half; missing or
  unverifiable state forces rotation. §4 once said otherwise; do not
  reintroduce.
