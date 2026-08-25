# DraCLA

A project-neutral, GitHub-native system for administering Contributor License
Agreements.

DraCLA gives a project authenticated signing, durable append-only records, pull
request enforcement, revocation, exports, and a private dashboard — without
operating a signature database. GitHub is the identity provider and the system
of record.

It is software for administering agreements a project supplies. It does not
draft agreements, judge whether one is legally sufficient, or give legal advice.

## Status: design and protocol spike

**Not usable yet.** Nothing here signs a CLA.

What exists:

| | |
|---|---|
| [`design/requirements.md`](design/requirements.md) | Locked requirements baseline, revision 13 |
| [`design/high-level-design.md`](design/high-level-design.md) | Locked and reviewed architecture |
| [`core/`](core/) | Pre-revision-13 protocol experiments and GitHub transport |
| [`api/bench/`](api/bench/) | Pre-encryption CPU lower-bound measurements |
| [`docs/roadmap.md`](docs/roadmap.md) | Remaining implementation and release-verification work |

What does not exist: the conforming installer, reconciler, Workers, portal,
dashboard, reporting CLI, or badges. The earlier two-repository installer was
removed because it would write plaintext state and seed executable workflow
content in locations forbidden by the reviewed design.

## How it works

- **Records are encrypted git artifacts.** Every private canonical and derived
  artifact uses authenticated application-layer encryption in repositories the
  project owns.
- **Three repositories per project.** Records, coverage, and protected control
  code have separate custody and capabilities.
- **No database.** A static frontend and stateless serverless endpoints; derived
  state is reproducible from the canonical events.
- **Works on GitHub Free.** Verified, not assumed — including that merge queue
  is available for public repositories on the free plan.

## Design notes worth reading

The design was reviewed adversarially before implementation.

Two limits are stated rather than solved:

- A public check result is an unavoidable coverage oracle for a determined
  party. Bounded, not closed.
- In the shared hosted deployment, the operator is trusted for confidentiality
  and merge-gate integrity. Self-hosting is the configuration where that is not
  so.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
