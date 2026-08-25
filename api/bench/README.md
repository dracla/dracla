# A2 benchmark — enforcer check path CPU

Status: **historical lower bound only.** This fixture predates revision-13 key
unwrap, authenticated decryption, 32-shard reads, merge-group queue-entry
resolution, decision-fence publication, and continuous-team work. It does not
close A2; the real-account probes listed in HLD §11 remain release blockers.

Answers one question: does the enforcer's per-check CPU fit inside the
Cloudflare Workers Free limit of 10 ms? CPU excludes I/O wait, so awaiting
GitHub is free; what counts is signing, hashing, and parsing.

    node api/bench/a2.mjs                    # Node's V8 + WebCrypto
    npx wrangler dev --local                 # workerd, the real runtime

`wrangler` is not vendored — install it only when re-running the workerd
measurement.

## Result, 18 August 2026 (workerd)

| Operation | CPU |
|---|---|
| RS256 sign, warm key (App JWT) | 0.365 ms |
| HMAC-SHA256 webhook verify | below timer resolution |
| `JSON.parse` 100 commits (215 KB) | 0.190 ms |
| `JSON.parse` 250 commits (540 KB) | 0.470 ms |
| **End-to-end, typical PR (10 commits), warm-isolate token** | **0.26 ms — 3%** |
| **End-to-end, large PR (100 commits), warm-isolate token** | **0.50 ms — 5%** |
| **End-to-end, large PR (100 commits), cold key** | **1.04 ms — 10%** |
| **End-to-end, worst case (250 commits), cold key** | **1.26 ms — 13%** |

Node measured 1.54 ms for the worst case, so the two runtimes agree closely and
workerd is marginally faster.

## What these numbers are not

They are **workerd on a development machine**, not a measurement taken on
Cloudflare. Read them as an estimate with a known bias.

Carried over faithfully: workerd is the production runtime, so V8, the JIT, and
the BoringSSL crypto implementation are the real ones, and the relative costs
and algorithmic shape hold.

Not carried over:

- **Edge hardware is slower per core.** These ran on an i7-13700K boosting to
  ~5.4 GHz. Cloudflare runs server-grade silicon, plausibly 1.5–2.5x slower
  single-threaded.
- **Multi-tenant contention** on a busy edge node.
- **Cloudflare's CPU accounting**, which is their meter rather than a
  wall-clock loop with no I/O.
- **Isolate startup and script evaluation**, which count toward the first
  request into a fresh isolate and are absent here entirely.

Applying a pessimistic 2.5x correction puts the worst case near 3.2 ms — still
under a third of the budget. The conclusion is robust because the headroom is an
order of magnitude, not because the number is precise. At 7 ms this would be
unresolved rather than closed.

**A definitive number requires deploying to a real Cloudflare account** and
reading CPU-time percentiles from Workers analytics under actual traffic. That
remains open.

## What this does and does not establish

For the removed plaintext path, the measured 250-commit fixture used 13% of the
budget. That is useful lower-bound evidence, not a conclusion about the current
encrypted ordinary or merge-group path. Revision 13 adds key unwrap,
authenticated decryption, the 32-shard maximum, publication coordination,
event-wide check-run filtering, and continuous-team work; A2 remains open until
those exact paths are measured on a real account.

A warm isolate may reuse an unexpired installation token from process-local
memory, which avoids re-minting against GitHub's rate limits, but no result may
depend on that reuse. Revision 13 forbids persisting installation tokens in KV
or another durable cache. Cold minting in this historical fixture costs about
0.4 ms.

The payload shapes in `fixtures.mjs` are sized from real GitHub responses; the
numbers are only as good as those shapes, and a genuinely pathological pull
request (very long commit messages) would parse slower in proportion to bytes.
