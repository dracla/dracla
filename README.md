# DraCLA

A project-neutral, GitHub-native system for administering Contributor License
Agreements.

DraCLA gives a project authenticated signing, durable append-only records, pull
request enforcement, revocation, exports, and a private dashboard — without
operating a signature database. GitHub is the identity provider and the system
of record.

It is software for administering agreements a project supplies. It does not
draft agreements, judge whether one is legally sufficient, or give legal advice.

## Status: locked design and protocol spikes

**Not usable yet.** Nothing here signs a CLA.

What exists:

| | |
|---|---|
| [`design/requirements.md`](design/requirements.md) | Locked requirements baseline, revision 13 |
| [`design/high-level-design.md`](design/high-level-design.md) | Locked, reviewed architecture and protocol design |
| [`docs/architecture.md`](docs/architecture.md) | Human-readable architecture overview and diagrams |
| [`design/review-findings.md`](design/review-findings.md) | Historical findings from the earlier design-review series |
| [`core/`](core/) | Legacy plaintext protocol and GitHub-transport spike — not the revision-13 implementation |
| [`api/bench/`](api/bench/) | Historical pre-encryption edge CPU lower-bound measurements |

What does not exist: the conforming encryption/event implementation, Workers,
portal, reconciler, installer, dashboard, reporting CLI, routing gates, or
badges. See §16 of the requirements and [`docs/roadmap.md`](docs/roadmap.md).

The selected hosted shell/API origin is `https://dracla.cli.dev`.

## How it works

- **Records are git.** Every signature, revocation, and agreement publication is
  one commit on an append-only branch in a private repository the *project*
  owns. Commit ancestry is the authoritative order. Nothing is ever rewritten.
- **Three repositories per project.** Records hold authenticated encrypted
  canonical evidence, coverage holds an encrypted least-privilege projection,
  and control holds pinned reconciler code and project-scoped secrets. The
  enforcer cannot read canonical signer evidence.
- **GitHub remains the durable system of record.** Provider-held KV routes and
  SQLite-backed routing gates are bounded, fail-closed projections that can be
  rebuilt; they do not become a CLA evidence database.
- **The documented GitHub Free baseline is verified.** Public contributing
  repositories can enforce merge queue; private-repository protections may
  require a paid plan, and the release measurements remain explicit gates.

## Design notes worth reading

The design was reviewed adversarially before implementation, and the findings
are public in [`design/review-findings.md`](design/review-findings.md) —
including the ones that were wrong in the first draft. If you are evaluating
DraCLA, that file is the honest account of what it does and does not guarantee.

Two limits are stated rather than solved:

- A public check result is an unavoidable coverage oracle for a determined
  party. Bounded, not closed.
- In the shared hosted deployment, the operator is trusted for confidentiality
  and merge-gate integrity. Self-hosting is the configuration where that is not
  so.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
