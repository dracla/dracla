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
  repository administration. §4 once said otherwise; do not reintroduce.
