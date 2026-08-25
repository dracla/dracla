# Development roadmap

The locked baseline is `design/requirements.md` revision 13 and the reviewed
architecture is `design/high-level-design.md`. Nothing in this repository is a
usable DraCLA release yet.

## Completed foundations

- Requirements revision 13 and the reviewed HLD are locked and attested.
- The GitHub transport and append-only fast-forward behavior have unit and
  opt-in live-integration coverage.
- The old one-shard CPU benchmark remains a documented pre-encryption lower
  bound.
- Merge queue availability on GitHub Free was verified as recorded in A4.

The pre-revision-13 event/projection code under `core/` is a protocol spike,
not a conforming storage implementation.

## Implementation order

1. Implement the versioned AES-256-GCM envelope, wrapped-key formats, canonical
   JSON rules, and cross-language golden vectors from HLD §4.
2. Implement the revision-13 canonical, prepared-operation, decision-fence,
   projection, recovery, and authorization protocols from HLD §5–§6.
3. Implement the pinned reconciler and its release/provenance verification in
   the separate control repository. There must be no placeholder workflow.
4. Implement `dracla install` only after the reconciler and bootstrap services
   exist. It must create three repositories, verify recovery of both actual
   data keys before private writes, and persist the exact release identity.
5. Implement the portal, enforcer, routing gates, dashboard, reporting CLI, and
   recovery/export paths.
6. Complete the `REQ-VERIFY-1` traceability matrix and every release scenario
   in `REQ-VERIFY-2`.

## Open release gates

- **A2:** real-account measurements for encrypted enforcement, mutation,
  private-read, export, continuous-team, and Durable Object paths.
- **A3:** `core/capacity.py` now reproduces the Worker and Durable Object design
  tables; real release measurements and observed delivery multipliers remain
  pending.
- **A6:** disposable-repository write-deploy-key integrity and recovery probe.

These are release blockers. Local arithmetic or documentation changes do not
close the required external measurements.
