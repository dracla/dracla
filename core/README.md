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

## Is the fake faithful?

The fake is only useful if its model of GitHub is right — if `update_ref` with
`force=false` behaves differently in reality, every test here passes and
production still loses events. Both semantics the protocol depends on were
therefore checked against the live API (`dracla/dracla`, throwaway ref,
18 August 2026):

| Probe | Result |
|---|---|
| Update ref to a **sibling** commit, `force=false` | `422 Update is not a fast forward` — ref unmoved |
| Update ref to a **descendant** whose tree **drops** a file already at HEAD, `force=false` | **Accepted.** Ref advanced, ancestry stayed linear, single parent, and the dropped file was simply gone from HEAD |

The second row is DR-006 confirmed against real GitHub rather than argued from
documentation. Nothing rejects it, nothing warns, and history looks correct —
which is exactly why `append.py` must rebuild the tree on the reloaded head's
base tree rather than re-parent an already-built one.

The probe ref was deleted; `main` was untouched.

Still unverified: the rest of the client surface (blob/tree/commit creation,
pagination, error taxonomy beyond 422). Those are ordinary integration
concerns, not protocol correctness.
