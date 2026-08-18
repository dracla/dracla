# dracla core

Python core for DraCLA: the event model, the append-only commit protocol, and
the coverage projection. Runs in GitHub Actions (the reconciler) and behind the
signing endpoints.

Status: **protocol spike.** This implements and tests the mechanisms that
`design/high-level-design.md` §5.1–5.4 specify, against a deterministic fake
git host. It is not the product.

Why a fake host: the properties worth testing are concurrent — two writers
racing a ref update, a crash between two writes, a lost shard row. Those cannot
be provoked reliably against real GitHub, and each one corresponds to a specific
finding in `design/review-findings.md`. The fake models the one semantic that
matters, `update_ref(force=False)` succeeding only on a fast-forward, so the
tests exercise the real failure mode rather than a mock of it.

Run:

    python3 -m unittest discover -s core/tests -t . -v

No third-party dependencies, by design — stdlib only.
