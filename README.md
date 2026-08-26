# DraCLA

[![ecosystem: cli.dev](https://cli.dev/img/badges/cli-dev-ecosystem.svg)](https://cli.dev)

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
| [`design/requirements.md`](design/requirements.md) | Locked requirements baseline, revision 2 |
| [`design/high-level-design.md`](design/high-level-design.md) | The architecture |
| [`docs/architecture.md`](docs/architecture.md) | Human-readable architecture overview and diagrams |
| [`design/review-findings.md`](design/review-findings.md) | 81 findings from four independent adversarial reviews, all resolved |
| [`core/`](core/) | Event model, append-only commit protocol, coverage projection — 43 unit tests, 9 integration tests against live GitHub |
| [`api/bench/`](api/bench/) | CPU measurements for the edge tier |

What does not exist: the Workers, the portal, the dashboard, the CLI, the
badges. See §16 of the requirements for the release scope.

## How it works

- **Records are git.** Every signature, revocation, and agreement publication is
  one commit on an append-only branch in a private repository the *project*
  owns. Commit ancestry is the authoritative order. Nothing is ever rewritten.
- **Two repositories per project.** Canonical records hold signer data; a
  PII-free projection holds coverage. The component that reads pull requests can
  reach the second and not the first.
- **No database.** A static frontend and stateless serverless endpoints; derived
  state is reproducible from the canonical events.
- **Works on GitHub Free.** Verified, not assumed — including that merge queue
  is available for public repositories on the free plan.

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
