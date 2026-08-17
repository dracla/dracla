# DraCLA High-Level Design

Status: Draft
Date: 17 August 2026
Requirements baseline: `design/requirements.md` (Locked, 17 August 2026)

This document proposes an implementation architecture for the locked
requirements baseline. Per `REQ` acceptance section 19, it maps major
components to requirement IDs and explicitly identifies every requirement it
deviates from or defers.

---

## 1. Design decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Pull request enforcement runs in the GitHub App's serverless handler, not GitHub Actions | Fork-triggered workflows receive no secrets, so they cannot read a private records repo. Deviates from `REQ-OPS-2`. See §2. |
| D2 | Two private repositories per project: canonical records (PII) and a coverage projection (PII-free) | GitHub tokens cannot be scoped to a path, so a single repo means the enforcement path holds a token that can read signer PII. |
| D3 | Two GitHub Apps: `dracla-records` and `dracla-enforcer` | Two repos buy nothing if one App holds permissions on both. Separation must be at the credential level. |
| D4 | Both repositories live in the **adopting project's** org, auto-provisioned at install | `REQ-CONFIG-1`, `REQ-OPS-6`, principle 6 require project custody. Auto-provisioning removes the setup friction that made central hosting attractive. |
| D5 | Coverage state is materialized into the projection repo synchronously by the signing path; Actions replays canonical to verify it | Gives O(1) coverage lookup with no Actions latency on the hot path, while keeping the projection strictly derived (`REQ-REC-6`). |
| D6 | Staleness is detected via a pending-pointer inside the coverage repo | The enforcer has no canonical access, so it cannot compare against canonical head directly. See §5.4. |
| D7 | One repo pair per **legal recipient**, not per GitHub repo and not per project | A contributor signs once for a scope spanning many repos and orgs (`REQ-CONFIG-3`). An org with a single recipient needs exactly one pair. See §5.5. |
| D8 | Python core owns the event model, replay, exports, and CLI; Cloudflare Workers in TypeScript host the thin serverless tier | `REQ` §1 implies a Python package. Python Workers run on Pyodide with cold-start and package limits unsuited to webhook latency. Keeping the edge thin makes the split cheap and reversible. |
| D9 | Coverage is stored in packed shards, not one file per user | Workers cap outbound subrequests per invocation; a per-subject read approaches that cap on a many-author PR. One shard read replaces N reads. |
| D10 | An agreement version declares whether it invalidates prior acceptances | A typo fix and a new patent grant are not the same event. `REQ-AGR-4` forbids inferring legal meaning from agreement text, so DraCLA must not assume every version bump is substantive. Amends `REQ-AGR-2`. |

---

## 2. Deviation from REQ-OPS-2

`REQ-OPS-2` states that background validation, index generation, exports, and
**pull request enforcement** SHOULD run in GitHub Actions. This design honors
that for the first three and deviates for the fourth.

**Why enforcement cannot run in Actions.** `REQ-REC-1` makes the records repo
private; `REQ-OPS-3` makes the contributing repo public on GitHub Free.
Enforcement must therefore read a private repo while reacting to events in a
different, public one. A workflow in the contributing repo cannot do this:

- `GITHUB_TOKEN` is scoped to the repo running the workflow and cannot read the
  separate private records repo.
- Reaching it requires a stored secret, and **GitHub withholds secrets from
  `pull_request` workflows triggered from a fork**.

Contributors to open source projects contribute overwhelmingly from forks, so
the Actions path fails closed for precisely the population the system exists to
check. The `pull_request_target` workaround runs untrusted PR content in a
context holding secrets and is rejected as unsafe for a component whose job is
ingesting arbitrary PR content.

The GitHub App path has no such problem: the webhook is delivered regardless of
fork status, and the installation token is minted server-side where no
contributor can influence it.

**Requirement change proposed.** `REQ-OPS-2` should be amended to state that
pull request enforcement runs in the GitHub App, and that Actions covers
background validation, index generation, and exports. Filed under section 19 as
a substantive change.

**Latency is not the argument.** A check landing 30s after a PR opens would be
acceptable, and Actions minutes are free on public repos. The credential
boundary is the disqualifier, not speed.

---

## 3. System context

```
                    ┌─────────────────────────────────────────┐
   contributor ────▶│  static portal + dashboard shell        │
                    │  (public assets, no private data)       │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │  stateless serverless tier              │
                    │  OAuth · sign · revoke · webhooks       │
                    │  check runs · index proxy               │
                    └───┬──────────────────────────┬──────────┘
                        │                          │
              dracla-records App          dracla-enforcer App
                        │                          │
        ┌───────────────▼──────────┐   ┌───────────▼──────────────┐
        │ acme/acme-cla-records    │   │ acme/acme-cla-coverage   │
        │ PRIVATE · canonical      │──▶│ PRIVATE · PII-free       │
        │ append-only events + PII │   │ user_id -> coverage      │
        └──────────────────────────┘   └───────────┬──────────────┘
                        │                          │
                Actions (in canonical)             │  read-only
                replay · verify · index · export   │
                                                   ▼
                                        checks on acme/widget
                                        (public contributing repo)
```

---

## 4. Principals and permissions

Three principals, each holding the minimum.

### `dracla-records` App — portal side
- OAuth: contributor login, signing, revocation, dashboard authorization
- `contents: write` on **canonical**
- `contents: write` on **coverage** (materialization + pending pointer only)
- Not installed on any contributing repo; receives no PR webhooks

### `dracla-enforcer` App — check side
- Webhooks: `pull_request`, `merge_group`, `check_run.rerequested`
- `checks: write`, `pull_requests: read`, `contents: read` on **contributing** repos
- `contents: read` on **coverage** only
- **Never installed on canonical** — structurally cannot reach signer PII

### Actions job inside canonical — reconciler
- Runs where PII already legitimately lives
- Replays canonical events, regenerates the projection, and asserts it matches
  what the signing path wrote
- Builds the dashboard index and JSON/CSV exports
- Writes to coverage via a deploy key scoped to that repo

Satisfies `REQ-REC-2` (explicit cross-repository access) and `REQ-SEC-2`
(signer records never reach the enforcement path).

---

## 5. Data architecture

### 5.1 Canonical records repo (private)

```
config/project.json            recipient, scope, required signer fields
agreements/icla/v3.md          exact agreement content
agreements/icla/v3.meta.json   digest, effective_at, scope, supersedes_coverage
events/<aa>/<bb>/<event_id>.json
.github/workflows/reconcile.yml
```

Event envelope (`REQ-SIGN-4`, `REQ-REC-5`):

```json
{
  "schema_version": 1,
  "event_id": "…",
  "idempotency_key": "…",
  "type": "acceptance | revocation | agreement_published | override | exemption",
  "recorded_at": "2026-08-17T12:00:00Z",
  "dracla_version": "0.1.0",
  "subject": { "github_user_id": 1234567, "login_snapshot": "octocat" },
  "agreement": { "id": "icla", "version": "v3", "digest": "sha256:…" },
  "scope": { "orgs": ["acme"], "repos": ["acme-labs/widget"] },
  "fields": { "legal_name": "…", "email": "…" },
  "confirmations": [{ "label": "…", "checked": true }],
  "supersedes": "event_id | null"
}
```

Event files are sharded by `event_id` prefix so existence is a single content
read rather than a history scan.

### 5.2 Append-only commit protocol (`REQ-REC-3`)

One logical event per commit; commit ancestry is the authoritative order.

```
1. read branch head H
2. build tree containing the new event file
3. create commit C with single parent H
4. PATCH ref, force = false
5. on 422 (non-fast-forward):
      reload head H'
      if events/<shard>/<event_id>.json exists at H'  -> done, idempotent
      else                                            -> retry from 2 with H'
```

Bounded retries with jitter. No merge commits are ever created. Timestamps
never resolve ordering.

### 5.3 Coverage projection repo (private, PII-free)

```
source.json                { canonical_sha, built_at, dracla_version }
pending.json               { canonical_sha }
users/<shard>.json         packed: { "<user_id>": { status, agreement,
                             version, digest, scope, since }, … }
agreements/active.json
overrides/<head_sha>.json
```

Contains no legal name, email, confirmation text, or entity evidence. Coverage
is a function of `(user_id, agreement, version, scope, status)` only — signer
PII is never an input to a check.

**Packed shards (D9).** Coverage is sharded by `user_id % 256` rather than
stored one file per user. A check with `N` subjects touches at most
`min(N, 256)` shards and in practice one or two, keeping the enforcer well
inside the Workers subrequest cap. Shards are small enough to fetch and parse
whole, and the sharding function is part of the documented format so the
reconciler and any external reader agree on placement.

### 5.4 Freshness guard (`REQ-CHECK-3`, `REQ-CHECK-4`)

The authoritative merge-group check must evaluate canonical state as observed
when it runs, but the enforcer cannot read canonical. The staleness signal is
therefore placed **inside the coverage repo**:

Coverage is materialized **only after validation**, never straight from the
write, so a malformed or forged event grants no coverage at any point — checks
read the projection, never raw canonical.

**The Worker performs both validation and materialization inline.** Signing is
effective in roughly a second; the reconciler Action is not on the critical
path. If it were, signing from a pull request could not re-evaluate that pull
request promptly, as `REQ-CHECK-4` requires. The Action independently replays
canonical and asserts the projection matches — defense in depth against Worker
bugs and drift, not the mechanism that makes a signature effective.

```
sign / revoke  (Worker, inline):
  1. commit event to canonical            (§5.2)
  2. write pending.json  { canonical_sha } to coverage
  3. validate the event, then write users/<shard>.json
     + source.json { canonical_sha } to coverage   <- effective here
  4. re-evaluate the originating pull request, if any

enforcer, on every check:
  read pending.json and source.json
  if pending.canonical_sha != source.canonical_sha:
        projection is stale -> in_progress, retry; never pass
```

If step 3 fails, the pointers disagree and the check refuses to pass until the
Actions reconciler repairs the projection. This is the only mechanism that lets
the merge-group result honestly be called authoritative.

---

### 5.5 How many repo pairs a project needs

A *project* in DraCLA is a `(recipient, agreements, scope)` tuple, not a GitHub
repository. One pair therefore covers every repository in its scope, and a
contributor who signs once is covered across all of them.

**The boundary is the legal recipient.** A second pair is required only when
the entity receiving the granted rights differs (`REQ-CONFIG-2`), because that
entity holds the rights and because read access to the records repo decides who
sees the signer data. Two recipients sharing a repository would let one
entity's administrators read the other's CLA evidence.

```
one recipient, many repos          ->  one pair
  acme/acme-cla-records
    recipient: Acme Foundation
    scope:     acme/*, acme-labs/widget
    agreements/icla/…                    several agreement ids are fine;
                                         coverage keys on (user_id, agreement_id)

two recipients in one org          ->  two pairs
  foundation/projX-cla-records         recipient: Project X Inc
  foundation/projY-cla-records         recipient: Y Foundation
```

`REQ-CONFIG-1` forbids *requiring* unrelated projects to share a repository; it
does not prevent related projects from sharing one deliberately.

**The recipient is chosen at install and is immutable thereafter.**
`REQ-CONFIG-2` makes it a required configuration input, and the install flow
prompts for it. It cannot later be edited: past acceptances granted rights to a
specific legal entity, and those grants cannot be retroactively reassigned.
Changing recipient is therefore a **new project with a new pair** — the
contributors sign the new agreement, and the existing records remain as
evidence of what was granted to the original entity. Editing it in place would
leave grants to two different legal entities in one repository, the exact
mixing this section exists to prevent.

**Repository naming keys on the project slug**, not the org, so a second
recipient in the same org does not collide. The slug defaults to the org name
for the first project:

```
acme/acme-cla-records     first project, slug defaults to org name
acme/projx-cla-records    second recipient in the same org
```

Costs of combining, both accepted for a single-recipient org:

- Read access to the pair exposes signer data across everything it covers.
- A substantive version activation applies to the whole scope at once. The
  `supersedes_coverage` flag (D10) confines this to genuinely substantive
  changes, but within a pair it is all-or-nothing.
- A later spin-out to a different recipient means splitting records, which is
  harder than transferring a repository.

## 6. Key flows

### 6.1 Signing (`REQ-SIGN-1..5`, `REQ-PORTAL-1`)

1. Contributor opens the project page, authenticates with GitHub via
   `dracla-records` OAuth.
2. Portal renders the complete agreement, recipient, version, scope, required
   fields, and the project privacy policy link (`REQ-AGR-3`, `REQ-SEC-3`).
3. Contributor submits an affirmative action with the required fields.
4. Handler derives a stable idempotency key, commits the acceptance event
   (§5.2), then materializes coverage (§5.4).
5. If a PR context was carried through the OAuth `state` parameter, the handler
   re-evaluates that specific pull request (`REQ-CHECK-4`) — no global rescan.

Corrections require a fresh signing flow producing a new event linked via
`supersedes`; the original is never modified (`REQ-SIGN-5`).

### 6.2 Revocation (`REQ-REV-1..5`)

Same portal, same authentication. The confirmation screen states that
revocation changes coverage for future decisions but neither deletes the record
nor withdraws already-granted rights. A revocation event is appended and the
projection flips to `revoked`. Re-signing appends a new acceptance and never
mutates the revoked event.

### 6.3 Pull request check (`REQ-CHECK-1`, `REQ-CHECK-2`)

```
pull_request opened / synchronize
  -> resolve subjects:
        PR opener
        every commit author        (GitHub-resolved user ID)
        every Co-authored-by:      trailer
     dedupe by numeric user ID
  -> any subject unresolved to a user ID  -> action_required
  -> map subjects to shards, fetch each distinct shard once   (D9)
  -> all covered -> success ; else -> failure / action_required
```

Public surfaces disclose only *CLA satisfied*, *action required*, or
*temporarily unavailable*. Exact reasons appear only in the authenticated
portal (`REQ-CHECK-1`, `REQ-PORTAL-3`, `REQ-PORTAL-5`).

**Co-author resolution limit.** GitHub offers no reliable email-to-user lookup.
`<id>+<login>@users.noreply.github.com` addresses parse directly to a user ID;
other addresses generally cannot be resolved and yield *action required* by
`REQ-CHECK-2`. See risk R1.

### 6.4 Authoritative merge-group check (`REQ-CHECK-3`)

On `merge_group.checks_requested`, the enforcer re-resolves subjects for the
merge candidate, applies the freshness guard (§5.4), and reports on the
merge-group commit. This result — not the ordinary PR check — is the CLA
decision for landing. The PR check is documented as early feedback only.

**Fallback without a required merge queue.** `REQ-CHECK-3` already forbids
claiming a final pre-landing check in this configuration. DraCLA additionally
re-verifies on push to the default branch and, if a commit landed with an
uncovered or unresolved subject, opens an issue identifying the commit and
subjects. This is detection, not prevention, and is documented as such.

### 6.5 Agreement activation (`REQ-AGR-1`, `REQ-AGR-2`, D10)

Publishing a version is an append-only event carrying the content, digest,
scope, and a project-set `supersedes_coverage` flag:

- `supersedes_coverage: true` — substantive change. Every prior acceptance
  stops providing current coverage at activation; contributors must re-sign.
- `supersedes_coverage: false` — editorial. Prior acceptances continue to
  provide coverage.

DraCLA never inspects the agreement text to decide which applies; the project
declares it, consistent with `REQ-AGR-4`. Earlier versions and their
acceptances are preserved either way.

**Staged activation.** A version may carry a future `effective_at`. Between
publication and that time the portal shows affected contributors that a new
version is coming and lets them sign it early; coverage flips at the effective
time. This keeps the blast radius of a substantive change visible in advance
rather than turning every open pull request red without warning (risk R2).

A blanket grace period was rejected: it lets contributions land under an
agreement the project has already replaced, which is the outcome versioned
agreements exist to prevent.

### 6.6 Dashboard and exports (`REQ-DASH-1..5`, `REQ-REC-5`)

Actions in canonical regenerates a private index and JSON/CSV exports on each
push. The static shell fetches the index through a serverless endpoint that
verifies the viewer can currently read the canonical repo (`REQ-SEC-6`,
`REQ-DASH-3`) — never from public static assets. Filtering and sorting run in
the browser. CSV cells derived from untrusted input are neutralized against
formula interpretation while JSON retains the canonical value (`REQ-SEC-8`).

---

## 7. Multi-tenancy and isolation (`REQ-OPS-6`)

One shared stateless deployment serves all projects; no function per project.

```
dracla/dracla · registry/
  project: acme
    records:  acme/acme-cla-records
    coverage: acme/acme-cla-coverage
    scope:    acme/*, acme-labs/widget
    installations: { records: …, enforcer: … }
```

**Runtime lookup.** The repo file is the source of truth; Workers KV is the
runtime index the handlers actually read. Fetching the registry from GitHub on
every webhook would waste a subrequest and CPU on the hot path, and bundling it
at deploy time would require a redeploy per adopter. The install flow writes
both, KV last. KV is fully rebuildable from the repo and is therefore derived,
never authoritative — the same rule the coverage projection follows
(`REQ-REC-6`).

Isolation rules:

- Every request resolves to exactly one project before any repo access.
- Repo handles come from the registry entry, never from request input.
- The installation token used must belong to that project's installation; a
  token/repo mismatch is a hard failure, not a fallback.
- A contributing repo in no project's scope receives no check.

Migration to self-hosting is a no-op for records: the project revokes the
shared Apps, installs its own, and points them at the same repositories, which
never moved (`REQ-OPS-6`).

---

## 8. Security model

| Concern | Mechanism | Req |
|---|---|---|
| Signer PII exposure | Enforcer structurally cannot reach canonical; projection carries no PII | `REQ-SEC-2` |
| Session state | Short-lived signed/encrypted cookies; no application database | `REQ-OPS-2`, `REQ-SEC-4` |
| CSRF / replay | OAuth `state`, double-submit token, `SameSite`, nonce | `REQ-SEC-4` |
| Webhook authenticity | Signature verification; duplicate deliveries idempotent | `REQ-SEC-5` |
| Authorization | Derived from current GitHub read access to the records repo, not a second allowlist | `REQ-SEC-6` |
| Untrusted content | Contextual escaping everywhere; allowlist sanitization under restrictive CSP; CSV formula neutralization | `REQ-SEC-8` |
| Secrets | Never stored in records repos or exposed to browser code | `REQ-SEC-4` |
| Observability | Correlation IDs and failed-event identifiers, no PII or credentials | `REQ-OPS-5` |

### 8.1 Threat model: the authenticated contributor

A contributor has no access to either project repository — both are private and
they are not a collaborator. What authentication grants is the ability to make
the Worker act while it holds the installation token, so the whole surface is
confused-deputy.

| # | Attack | Control |
|---|---|---|
| 1 | **Path traversal** in the event file path — writing `.github/workflows/`, `config/project.json`, or agreement text yields code execution in the records repo and its secrets | Event paths derive from a **server-computed** hash, never a client-supplied id; commit trees built by allowlisted path, never by echoing input |
| 2 | **Unbounded append** — repeated sign/revoke cycles grow a repo that `REQ-REC-3` forbids pruning | Per-user rate limit and cooldown; idempotency key collapses identical resubmission |
| 3 | **Stored injection** via signer fields into dashboard, JSON, CSV | `REQ-SEC-8` escaping and CSV formula neutralization, plus length and charset caps at ingest |
| 4 | **IDOR on identity** — acting as another user | Subject is read from the verified session, never from the request body (§8.2) |
| 5 | **Privilege confusion** — a contributor submitting override or exemption events | Admin events require a separate authorization check against current GitHub permissions |
| 6 | **Cross-tenant aim** — steering the installation token at another project | Repo handles come only from the registry entry (§7) |
| 7 | **Budget exhaustion** — burning the shared daily ceiling | Per-project rate accounting; risk R7 |

**OAuth scope tiering.** Contributors need identity only (`read:user`,
`user:email`). Requesting `repo` scope for every signer would leave the Worker
holding tokens that can write to each signer's own repositories — a severe
liability if the Worker is compromised. `REQ-SEC-6` needs repo read scope only
for dashboard authorization, so elevated scope is requested **on demand when a
maintainer opens the dashboard**, not at signing.

### 8.2 How browser authentication reaches the writer

```
browser -> GitHub    OAuth code + PKCE + state
Worker  -> GitHub    code + client secret (server-side)   -> user token
Worker  -> GitHub    GET /user  -> { id, login }             <-- trust created
Worker               mint session cookie, signed with a Worker-held key
browser -> Worker    POST /sign + cookie
Worker               verify cookie; subject read FROM COOKIE, never body
Worker  -> GitHub    installation token (RS256, KV-cached); commit event
```

GitHub's assertion is converted into a token the Worker itself signed, so the
browser never carries identity as data it can influence. The Worker, not the
contributor, is the author of record; the commit history is the attestation
chain.

**What the record attests** is precisely: *the Worker observed a
GitHub-authenticated session for user N submitting explicit assent to agreement
X at time T.* Not that the contributor cryptographically signed anything. The
evidence fields of `REQ-SIGN-4` are scoped to that claim.

**Decay.** The session cookie is a cached assertion; an OAuth grant revoked
after issuance does not invalidate it. Mitigated by short TTL (15–60 min),
`jti` and expiry to bound replay, re-verification against GitHub for sensitive
actions, and rotatable session keys held in Worker Secrets. `REQ-VERIFY-2`
already requires testing loss of authorization, which is this window.

**Optional hardening.** For projects wanting non-repudiation beyond OAuth,
GitHub publishes users' signing keys (`/users/{login}/ssh_signing_keys`,
`/gpg_keys`), so a CLI-produced signed acceptance could be verified against a
binding GitHub already vouches for. Not the core flow: browsers cannot reach
those private keys, and `REQ-PORTAL-1` requires an in-browser accept flow.

### 8.3 Trust model

Per `REQ-REC-4`: repository administrators are trusted. DraCLA
never force-updates or deletes canonical history and documents that it cannot
detect rewriting by an administrator controlling both the repository and every
backup. Because records live in the adopter's org, that trusted administrator
is the adopter — not the DraCLA operator.

---

## 9. Deployment

**Platform.** Cloudflare, chosen because Workers are stateless by construction
(`REQ-OPS-2` forbids a durable application database), the free tier covers the
target envelope, and nothing about the platform becomes a system of record.

```
Workers        webhook handlers, OAuth, sign/revoke, check runs, index proxy
Pages          static portal + dashboard shell
Secrets        GitHub App private keys, coverage deploy keys
Actions        Python core: replay, reconcile, index, exports
```

The Worker tier is deliberately thin: it authenticates, reads packed coverage
shards, and writes events and check runs. All replay, verification, index, and
export logic lives in the Python core running in Actions, so the edge holds no
coverage rules beyond reading materialized state. This keeps the platform
replaceable (`REQ-OPS-2`).

**Published limits** (verified 18 August 2026):

| | Free | Paid ($5/mo) |
|---|---|---|
| Requests | 100,000/day | no limit |
| CPU per invocation | **10 ms** | 5 min (default 30 s) |
| Subrequests per request | 50 | 10,000 |
| Memory | 128 MB | 128 MB |
| Script size (gzipped) | 3 MB | 10 MB |

How the design sits against them:

- **Subrequests — comfortable.** A check costs token mint (1) + paginated
  commit listing (1–3) + coverage shard reads (1–2) + check run write (1),
  roughly 6–8 against a cap of 50. This is what packed shards (D9) bought; one
  read per subject would have approached the cap on a many-author pull request.
- **CPU — the binding constraint on Free.** Workers bill CPU rather than I/O
  wait, so awaiting GitHub is free, but 10 ms is tight for RS256 installation
  token signing plus `JSON.parse` of a large commit listing. Mitigations:
  cache installation tokens in Workers KV so the RSA signature is amortized
  across their one-hour lifetime, request minimal fields, and bound page size.
  **Must be measured before Free can be claimed** (A2).
- **Requests — a ceiling shared across all tenants** in the hosted deployment.
  At roughly 4–8 webhook deliveries per pull request, 100,000/day admits on the
  order of 10⁴ pull requests per day across all adopters combined (risk R7).

**Limits are per Cloudflare account, not per Worker.** Cloudflare: "Accounts on
the Workers Free plan have a daily request limit of 100,000 requests, resetting
at midnight UTC." This scopes the two deployment modes differently:

- **Hosted shared** — one account, so 100,000/day is divided across every
  adopter (risk R7). This deployment should run on **Workers Paid**: $5/month
  for the account, not per project, including 10M requests and 30M CPU-ms per
  month (~333,000 requests/day) and lifting CPU to 30 s.
- **Self-hosted** — each project runs in its own Cloudflare account and
  receives the full 100,000/day.

**This is how `REQ-OPS-3` is satisfied.** The documented deployment that fits a
published free tier is the **self-hosted, single-project** configuration, where
100,000 requests/day serves one project comfortably. The shared hosted service
is a paid convenience, not the free-tier claim. If A2 shows 10 ms CPU is
unreachable even with KV token caching, the fallback is to document a provider
with a more forgiving free CPU allowance (AWS Lambda) for self-hosters rather
than to amend `REQ-OPS-3`.

**Fail-closed is mandatory.** On exceeding the daily limit Cloudflare either
fails open — "Bypasses the Worker. Requests behave as if no Worker is
configured" — or fails closed with a 1027 error. Fail-open would silently drop
webhooks and leave checks unwritten. Routes MUST be configured **fail closed**,
so GitHub retries delivery and the check remains `queued` rather than
disappearing, as `REQ-CHECK-5` requires.

**Default adoption path.** Shared DraCLA-operated serverless deployment
(`REQ-OPS-1`), with records in the adopter's own org (`REQ-OPS-6`).

```
admin installs dracla-records on their org
  -> prompt: legal recipient, agreement, scope, project slug
  -> provision <slug>-cla-records and <slug>-cla-coverage (both private)
  -> seed config, agreement, reconcile workflow, coverage deploy key
  -> install dracla-enforcer on the repos in scope
  -> write registry entry (last, so a half-provisioned project is
     never routable — R5)
```

Adding a second legal recipient later re-runs the same flow, producing an
additional pair (§5.5). The recipient itself is immutable once chosen.

**`dracla` org holds software and service only — two repositories:**

```
dracla/dracla            monorepo
  core/                  Python: event model, replay, validation, index, exports
  cli/                   dracla command
  api/                   Cloudflare Workers (TypeScript)
  dashboard/             static shell + badge assets (Pages)
  registry/              project routing
  docs/

dracla/dracla-example    sample adopter (release scope item 11)
```

Workers and Pages both deploy from subdirectories, so a monorepo costs nothing
and keeps the Python core and the edge handlers versioned together. The
registry stays a directory until it needs a different change cadence or its own
visibility; it holds installation ids and no signer data. `dracla-example` must
be a separate repository because it has to behave like a real adopter project
under enforcement.

**Optional variants**

- *Self-hosted*: same code, own Apps, single-entry registry.
- *DraCLA-hosted records*: explicit opt-in tier for projects that want zero
  custody. Requires a documented processor relationship and a one-command
  migration out. **Not the default** — see §10.
- *Actions-computed enforcement*: for projects wanting PII never to leave
  canonical, enforcement can be computed by a workflow inside canonical via
  `repository_dispatch`, with the App only relaying and writing the check.
  Costs ~30s latency and metered private-repo Actions minutes; documented
  hardening, not the baseline.

**GitHub Free baseline** (`REQ-OPS-3`): public contributing repo, private
records and coverage repos, required merge queue with the DraCLA merge-group
check required. No durable job queue, reverse PR index, or global rescan.

---

## 10. Requirement changes proposed

| Req | Change | Reason |
|---|---|---|
| `REQ-OPS-2` | Enforcement runs in the GitHub App, not Actions | §2 — fork secret withholding |
| `REQ-AGR-2` | A version may declare that it does not invalidate prior acceptances | §6.5, D10 — `REQ-AGR-4` forbids inferring legal meaning from text, so substantive-vs-editorial is a project declaration, not an assumption |
| `REQ-OPS-3` | **Conditional.** If merge queue proves unavailable for public repos on Free, lines 514–515 must change from "strong final enforcement in the baseline MUST use a required merge queue" to "strong enforcement requires a plan supporting merge queue" | Pending A4. Not proposed unless verification fails. |

No other requirement is deviated from. The DraCLA-hosted-records variant in §9
is opt-in and therefore does **not** amend `REQ-CONFIG-1`, `REQ-OPS-6`, or
principle 6; making it the default would, and is not proposed here.

---

## 11. Assumptions and open items

- **A1 — Edge platform. CLOSED.** Cloudflare Workers and Pages, TypeScript at
  the edge, Python core in Actions (D8, §9).
- **A2 — Workers CPU on Free.** Subrequests are **resolved**: 6–8 per check
  against a cap of 50 (§9, D9). The open item is the **10 ms CPU limit** —
  RS256 token signing plus commit-listing parse must be measured on a
  many-author pull request with KV token caching in place. Paid ($5/mo total)
  removes the constraint, so this gates only the Free-tier claim.
- **A3 — Capacity envelope.** Provider limits, their per-account scope, and
  fail-closed behavior on exhaustion are now stated (§9), and the free-tier
  claim is pinned to the self-hosted single-project configuration. Still
  missing, and required by `REQ-OPS-3`: per-project request assumptions
  (webhook deliveries per pull request, portal and dashboard traffic) and the
  index-proxy bandwidth model. **Partially met.**
- **A4 — Merge queue availability** for public repos on GitHub Free must be
  verified before `REQ-CHECK-3` can be called satisfied in the baseline.
  Verification is cheap: create a public repo in a Free org and add a ruleset
  requiring merge queue. If unavailable, the `REQ-OPS-3` amendment in §10 is
  required and the Free baseline degrades to early feedback plus post-merge
  detection (§6.4).

---

## 12. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | Co-author emails are largely unresolvable to user IDs, so co-authored PRs fail by default | Documented override path (`REQ-CHECK-2`); portal explains the exact cause; guidance to use noreply addresses |
| R2 | A substantive version activation invalidates every contributor at once | `supersedes_coverage` flag keeps editorial changes from triggering it at all; staged activation with a future `effective_at` warns and lets contributors sign early (§6.5, D10) |
| R3 | Non-atomic write across two repos (§5.4 steps 1–3) | Pending-pointer forces fail-closed; Actions reconciler repairs |
| R4 | Index proxy carries all dashboard traffic through the serverless tier | Bound index size; cache with short TTL; include in A3 envelope |
| R5 | Two-repo, two-App provisioning failure leaves a half-installed project | Provisioning is idempotent and re-runnable; registry entry written last |
| R6 | 10 ms Free-tier CPU exceeded on a large pull request (RS256 signing plus commit-listing parse) | Cache installation tokens in KV; request minimal fields; bound page size; run the hosted deployment on Paid, where the limit is 30 s |
| R7 | Cloudflare limits are per account, so on Free one busy adopter consumes the shared hosted ceiling for everyone | Run the hosted deployment on Paid (10M req/mo, ~333k/day); per-project rate accounting in the registry; A3 must state behavior on reaching the limit |
| R8 | Daily limit exceeded silently drops webhooks if routes fail open | Configure routes fail closed so GitHub retries and checks stay `queued` (`REQ-CHECK-5`, §9) |

---

## 13. Traceability

| Area | Requirements | Covered by |
|---|---|---|
| Project config, scope, recipient | `REQ-CONFIG-1..4` | §4, §5.1, §7, D4, D7 |
| Agreement versions and presentation | `REQ-AGR-1..4` | §5.1, §6.1, §6.5 |
| Individual signing | `REQ-SIGN-1..5` | §6.1, §5.1, §5.2 |
| Revocation and re-signing | `REQ-REV-1..5` | §6.2 |
| Entity CLAs | `REQ-ENTITY-1..5` | Deferred by `REQ-CONFIG-4`; event schema reserves the types |
| PR enforcement | `REQ-CHECK-1..5` | §2, §6.3, §6.4, §5.4 |
| Records | `REQ-REC-1..7` | §5.1, §5.2, §4, §6.6 |
| Privacy and security | `REQ-SEC-1..8` | §8, §8.1, §8.2, §4, §5.3 |
| Portal and badges | `REQ-PORTAL-1..5` | §6.1, §6.3 |
| Dashboard | `REQ-DASH-1..5` | §6.6 |
| Deployment and portability | `REQ-OPS-1..6` | §2, §7, §9 |
| Release verification | `REQ-VERIFY-1..2` | Not yet addressed — traceability matrix and acceptance scenarios are a separate deliverable |
