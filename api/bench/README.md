# A2 benchmark — enforcer check path CPU

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
| **End-to-end, typical PR (10 commits), token cached** | **0.26 ms — 3%** |
| **End-to-end, large PR (100 commits), token cached** | **0.50 ms — 5%** |
| **End-to-end, large PR (100 commits), cold key** | **1.04 ms — 10%** |
| **End-to-end, worst case (250 commits), cold key** | **1.26 ms — 13%** |

Node measured 1.54 ms for the worst case, so the two runtimes agree closely and
workerd is marginally faster.

## What this changes

The design previously called CPU "the binding constraint on Free". It is not:
the worst realistic check uses 13% of the budget, and that is with a cold key on
a 250-commit pull request, which is also the GitHub pagination ceiling.

KV token caching remains worthwhile — it avoids re-minting installation tokens
against GitHub's rate limits — but it is no longer load-bearing for CPU. Cold
minting costs about 0.4 ms.

The payload shapes in `fixtures.mjs` are sized from real GitHub responses; the
numbers are only as good as those shapes, and a genuinely pathological pull
request (very long commit messages) would parse slower in proportion to bytes.
