# dracla core

Python protocol experiments for DraCLA's event model, append-only commit
behavior, coverage projection, and GitHub transport.

Status: **legacy protocol spike.** The current revision-13 HLD replaced the
plaintext event/projection layout, 256-shard projection, and old in-flight
marker protocol represented here. This code is not a conforming storage or
enforcement implementation and must not be used to write project data.

The still-relevant pieces are the Git fast-forward/CAS experiments and GitHub
transport behavior. New implementation must use the encrypted formats,
32-shard profile, prepared-operation cell, and decision fence in the reviewed
HLD.

Why a fake host: the properties worth testing are concurrent — two writers
racing a ref update, a crash between two writes, a lost shard row. Those cannot
be provoked reliably against real GitHub, and each one corresponds to a
concurrency defect identified during design review. The fake models the one
semantic that matters, `update_ref(force=False)` succeeding only on a
fast-forward, so the tests exercise the real failure mode rather than a mock of
it.

Run:

    python3 -m unittest discover -s core/tests -t . -v

No third-party dependencies, by design — stdlib only.

## Integration tests against live GitHub

The fake encodes a *model* of GitHub. If the model is wrong, every unit test
passes and production still loses events, so the same behaviours are also run
against the real API:

    export DRACLA_ITEST_REPO=owner/name
    export GITHUB_TOKEN=$(gh auth token)
    python3 -m unittest core.tests.test_github_integration -v

Opt-in — skipped unless both variables are set. Each test creates its own ref
under `dracla-itest/` and deletes it in teardown; no existing branch is touched.
A run takes a few minutes because every assertion is real API round trips.

Last run: 9/9 against `dracla/dracla`, 18 August 2026, no leftover refs.

What it confirms on the live API:

- a non-fast-forward `update_ref` is rejected with 422, ref unmoved
- a **descendant whose tree drops a file** is accepted — DR-006's premise, so
  the retry really must rebuild on the reloaded head's base tree
- `commit()` builds on the parent's tree, closing that path
- the historical `PUT contents` helper rejects a stale blob sha with 409; the
  revision-13 coverage protocol instead uses branch-wide GraphQL
  `expectedHeadOid`
- `append_event` is idempotent on replay, and recovers both events after a real
  422 forced mid-append

## Client robustness

`github.py` sets a socket timeout and retries transient faults with backoff,
honouring `Retry-After`. This was not speculative hardening: an integration run
lost two tests to connection timeouts, which is the same fault that would
otherwise surface as a failed signature.

Internal retries are safe only where the layer above is content-addressed,
conditional, or explicitly reconciles a lost response. The public transport
therefore retries reads by default but performs mutation requests once unless a
caller explicitly declares its operation-level retry safe. Protocol signals
(404, 409, 422 non-fast-forward) are raised immediately and never retried;
retrying a 422 would mask a lost race rather than recover from it. In the
historical append spike, an event-path probe and blob-sha precondition supply
the narrower safety tested here; revision 13 additionally requires authenticated
operation-fingerprint checks and branch-wide coverage CAS.

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
