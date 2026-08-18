# DraCLA High-Level Design

Status: Draft
Date: 17 August 2026
Requirements baseline: `design/requirements.md` (Locked, revision 3, 20 August 2026)

This document proposes an implementation architecture for the locked
requirements baseline. Per `REQ` acceptance section 19, it maps major
components to requirement IDs and explicitly identifies every requirement it
deviates from or defers.

---

## 1. Design decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Pull request enforcement runs in the GitHub App's serverless handler, not GitHub Actions | Fork-triggered workflows receive no secrets, so they cannot read a private records repo. Deviates from `REQ-OPS-2`. See §2. |
| D2 | Two private repositories per project: canonical records (names and addresses) and a coverage projection (neither, but still personal data — §8.4) | GitHub tokens cannot be scoped to a path, so a single repo means the enforcement path holds a token that can read signer names and addresses. |
| D3 | Two GitHub Apps: `dracla-records` and `dracla-enforcer` — and only two | Two repos buy nothing if one App holds permissions on both; separation must be at the credential level. A third provisioning App was considered and rejected (D11). |
| D4 | Both repositories live in the **adopting project's** org, auto-provisioned at install | `REQ-CONFIG-1`, `REQ-OPS-6`, principle 6 require project custody. Auto-provisioning removes the setup friction that made central hosting attractive. |
| D4a | **Supersedes D4's "adopting project's org":** the pair goes in a *dedicated* org, never alongside the project's code (§6.10.4) | Base permissions are a floor — repository settings can raise a member's access, never lower it — so an org whose default is `read` exposes signer names and addresses with no per-repository remedy. Custody is unchanged; only which org the adopter provisions into. |
| D5 | Coverage state is materialized into the projection repo synchronously by the signing path; Actions replays canonical to verify it | Gives O(1) coverage lookup with no Actions latency on the hot path, while keeping the projection strictly derived (`REQ-REC-6`). |
| D6 | Staleness is detected via a pending-pointer inside the coverage repo | The enforcer has no canonical access, so it cannot compare against canonical head directly. See §5.4. |
| D7 | One repo pair per **legal recipient**, not per GitHub repo and not per project | A contributor signs once for a scope spanning many repos and orgs (`REQ-CONFIG-3`). An org with a single recipient needs exactly one pair. See §5.5. |
| D8 | Python core owns the event model, replay, exports, and CLI; Cloudflare Workers in TypeScript host the thin serverless tier | `REQ` §1 implies a Python package. Python Workers run on Pyodide with cold-start and package limits unsuited to webhook latency. Keeping the edge thin makes the split cheap and reversible. |
| D9 | Coverage is stored in packed shards, not one file per user | Workers cap outbound subrequests per invocation; a per-subject read approaches that cap on a many-author PR. One shard read replaces N reads. |
| D11 | Provisioning runs in the `dracla` CLI with the administrator's own credentials, not a third GitHub App | A provisioning App would hold `administration`, `workflows`, and `secrets` write in the adopter's org. `workflows: write` retained is a code-execution channel into their PII repo (DR-011), and an uninstall that fails to fire leaves it. `uvx` makes the CLI a single command, so the adoption cost is one command against three consent screens. |
| D12 | The CLI is the reporting and read-out surface, not just an installer | Gives maintainers a zero-infrastructure path for common queries and demonstrates `REQ-REC-5` directly: the records are readable with the same tool an auditor would use. |
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

**This is a declared deviation, not an amendment.** `REQ-OPS-2`'s enforcement
clause is a `SHOULD`, so a justified deviation suffices; see §10.2.

**Two corrections to how this was argued.** First, "cannot run in Actions" is
too strong: §9's `repository_dispatch` variant runs enforcement in a workflow
inside the *private* canonical repo, which the fork-secret rule does not touch.
What is impossible is enforcement in a workflow in the *contributing* repo,
which is the configuration a project would naturally reach for. Second, "Actions
minutes are free on public repos" is true but does not apply to DraCLA's own
Actions usage: the reconciler runs in the private canonical repo, where minutes
are metered on Free (§9).

**Latency is still not the argument.** A check landing 30 s after a pull request
opens would be acceptable. The credential boundary is the disqualifier.

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
              (portal side)               (check side)
                        │                          │
        ┌───────────────▼──────────┐   ┌───────────▼──────────────┐
        │ acme-cla/…-cla-records   │   │ acme-cla/…-cla-coverage  │
        │ PRIVATE · canonical      │──▶│ PRIVATE · no names/emails│
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

Four principals. Each holds the minimum for its steady-state job, and
provisioning privilege never belongs to DraCLA at all (`REQ-REC-2`).

### `dracla-records` App — portal side
- OAuth: contributor login, signing, revocation, dashboard authorization
- `contents: write` on **canonical**
- `contents: write` on **coverage** (materialization, the in-flight marker,
  and activation-intent appends, §6.5)
- Not installed on any contributing repo; receives no pull request webhooks

### `dracla-enforcer` App — check side
- Webhooks: `pull_request`, `merge_group`, `check_run.rerequested`
- `checks: write`, **`pull_requests: write`**, `contents: read` on
  **contributing** repos. Write is required to post the pull request comment of
  `REQ-PORTAL-3`; read alone cannot, and the earlier inventory made that
  requirement unimplementable.
- `contents: read` on **coverage** only
- Not installed on canonical

### `dracla` CLI — provisioning, configuration, reporting (D11, D12)
- Runs locally, `uvx dracla …`, using the **administrator's own** GitHub
  credentials. DraCLA holds no provisioning privilege at any point.
- Creates the repo pair and seeds the reconcile workflow (§6.10). It writes no
  project configuration, publishes no agreement, and creates no deploy key:
  those are portal actions, where each becomes an event with an actor, and the
  key waits for the reconciler that consumes it (M2, §6.10.2)
- Reporting surface thereafter (§6.9)

An earlier draft used a third App for this, holding org `administration`,
`workflows`, and `secrets` write. That is rejected: retained `workflows: write`
on canonical is a permanent code-execution channel into an adopter's PII repo
(DR-011), `administration: write` permits flipping that repo to public, and an
uninstall step that fails to fire leaves both in place. Provisioning is the
administrator's own act, performed with their own credentials, so those
permissions never exist as a DraCLA credential.

### Actions job inside canonical — reconciler
- Runs where PII already legitimately lives
- Replays canonical events, regenerates the projection, and **reconciles** it
  against what the signing path wrote (§5.4)
- Builds the dashboard index and JSON/CSV exports
- Writes to coverage via a deploy key scoped to that repo
- Declares an explicit least-privilege `permissions:` block, and **never**
  interpolates event-derived values into `run:` or `env:`. Signer fields are
  untrusted input (`REQ-SEC-8`) and this job holds a cross-repo write
  credential; a `${{ }}` expansion of a supplied legal name would be command
  execution on a runner that can forge the merge gate. Event data is passed to
  the Python core as files, read by the core, never expanded by the shell.

### What the separation does and does not guarantee

**Unconditional:** the coverage projection contains no names, email addresses,
confirmation text, or entity evidence (§5.3), so the check computation never
reads them, whatever else is true. It is not free of personal data — §8.4.

**Conditional:** the enforcer's inability to read canonical is a GitHub
permission boundary, not an invariant DraCLA can enforce. Installation
repository selection belongs to the adopting org's admin, and flipping the
enforcer to "All repositories" would silently grant it read on canonical. The
reconciler therefore asserts on each run that the enforcer installation's
repository list excludes canonical, and fails loudly if not. Earlier drafts
described this as structural; it is not.

**Not covered:** a compromise of the Worker itself defeats the split entirely,
because both App private keys are reachable from one isolate. See §9 for the
isolation that addresses it and §8.4 for the residual trust statement.

---

## 5. Data architecture

### 5.1 Canonical records repo (private)

```
config/project.json            recipient, scope, required signer fields
                               (resolved on the client; §6.9)
agreements/icla/v3.md          exact agreement content
agreements/icla/v3.meta.json   mirror for human reading; events canonical (§6.5)
events/<aa>/<bb>/<event_id>.json
derived/index.json             dashboard index      (generated, private)
derived/export.json            canonical values     (generated, private)
derived/export.csv             formula-neutralized  (generated, private)
.github/workflows/reconcile.yml
```

**Generated artifacts live in canonical, never in coverage.** The index and
exports contain legal names and emails. Writing them to the coverage repo —
the intuitive home for generated files — would hand `dracla-enforcer` read
access to all signer PII and collapse the boundary of §4 in a single commit.
They are committed to `derived/` on a **separate branch** of canonical, so the
one-logical-event-per-commit rule on the events branch (`REQ-REC-3`) is not
disturbed. They are never written to Actions artifacts, which `REQ-SEC-2`
forbids for signer data.

Event envelope (`REQ-SIGN-4`, `REQ-REC-5`):

```json
{
  "schema_version": 1,
  "event_id": "…",
  "idempotency_key": "…",
  "type": "acceptance | revocation | agreement_published | agreement_activated
           | override | exemption",
  "recorded_at": "2026-08-17T12:00:00Z",
  "dracla_version": "0.1.0",
  "actor":    { "github_user_id": 7654321, "login_snapshot": "maintainer" },
  "subjects": [ { "github_user_id": 1234567, "login_snapshot": "octocat" } ],
  "agreement": { "id": "icla", "version": "v3", "digest": "sha256:…",
                 "ref": "github.com/acme/acme/blob/<sha>/ICLA.md",
                 "content_commit_oid": "…" },
  "scope": { "orgs": ["acme"], "repos": ["acme-labs/widget"] },
  "fields": { "legal_name": "…", "email": "…" },
  "confirmations": [{ "label": "…", "checked": true }],
  "revokes":    "event_id | null",
  "supersedes": "event_id | null",
  "applies_to": { "pr_number": 42, "tree_digest": "sha256:…" }
}
```

Envelope decisions, each closing a specific gap:

- **`subjects` is a list and `actor` is separate.** `REQ-CHECK-2` requires an
  override to identify "the unresolved or uncovered subjects" (plural) and to be
  attributable. A single `subject` field conflated the covered contributor with
  the administrator issuing the override, and could not carry more than one.
- **`applies_to` binds overrides to content**, not to a pull request head SHA
  that does not survive the merge queue's commit rewrite (§6.4).
- **`revokes` is distinct from `supersedes`.** `REQ-REV-3` requires a revocation
  to be tied to the acceptance being revoked; `supersedes` carries the
  `REQ-SIGN-5` correction link. One field could not mean both, and reusing it
  left the revocation tie unstated.
- **`ref` and `content_commit_oid`** record where the agreement came from and
  the Git commit object ID of its content — `REQ-REC-4` requires the latter
  alongside the digest, and `REQ-AGR-1` explicitly permits an immutable content
  reference in place of inlined text (§6.5). The snapshot in `agreements/` is
  what makes the record survive the reference being deleted.
- **`agreement_published` and `agreement_activated` are separate types.**
  Publishing preserves a version; activating makes it required. Keeping them
  distinct is what lets a project correct a typo without invalidating anyone
  (§6.5).
- **`fields` is derived from `config/project.json`, not hardcoded.**
  `REQ-SIGN-3` makes the required set project-configurable and `REQ-SEC-1`
  forbids collecting anything the agreement and policy do not require. The
  schema validates submitted fields against the configured set and rejects
  extras; `confirmations` must carry the exact configured labels with
  `checked: true`, and a `false` is a rejected submission, not a recorded one.

**Naming.** `supersedes` (event linkage) and `supersedes_coverage` (agreement
flag, D10) are unrelated despite the shared word. Implementations should treat
the latter as `invalidates_prior_acceptances`; the requirement-facing name is
kept here only to match D10.

Event files are sharded by `event_id` prefix so existence is a single content
read rather than a history scan.

**Identifier derivation.** Both identifiers are server-computed; neither is
client-supplied, which is also what keeps event paths out of reach of traversal
(§8.1 #1).

```
idempotency_key = H( project, subject_user_id, event_type,
                     agreement_id, agreement_version, agreement_digest,
                     prior_event_id,        <- current head of this subject's
                                               event chain, or "genesis"
                     submission_nonce )     <- server-issued with the signing
                                               form, single-use
event_id        = H( idempotency_key )
```

`prior_event_id` is what makes re-signing after revocation a distinct path
rather than a collision with the original acceptance (`REQ-REV-5`), and the
single-use `submission_nonce` is what makes a repeated delivery of the *same*
submission collapse rather than duplicate (`REQ-SIGN-5`). A derivation using
only content would break the first; one including a timestamp or fresh random
would break the second. `REQ-REC-3` speaks of the idempotency key, and
`event_id` is a pure function of it, so the path existence check in §5.2 *is*
the idempotency-key check.

### 5.2 Append-only commit protocol (`REQ-REC-3`)

One logical event per commit; commit ancestry is the authoritative order.

```
0. validate the event fully                              (§5.4 — before any write)
1. read branch head H
2. build tree = base tree of H  +  events/<shard>/<event_id>.json
3. create commit C with single parent H
4. PATCH ref, force = false
5. on 422 (not a fast-forward):
      reload head H'
      if events/<shard>/<event_id>.json exists at H'  -> done, idempotent
      else
         re-validate the operation against H'         <- may now be a no-op
                                                         or a conflict
         rebuild the tree on the base tree of H'
         retry from 3 with H'
```

Two things this spelling out prevents:

- **Step 2 must rebuild on `H'`'s base tree, not reuse the tree from the
  previous attempt.** Reusing it and merely re-parenting produces a commit
  GitHub accepts as a clean fast-forward while the concurrent event vanishes
  from the tree. Since §5.1 locates events by path existence, every reader
  short of a full history walk would then believe that event never happened.
- **Step 5 must re-validate, not just re-parent.** A revocation of acceptance
  `E1` that loses the race to a re-signing that produced `E2` is no longer the
  same operation against `H'`. Re-validation decides whether it still applies,
  targets the new event, or fails as a conflict — rather than silently
  appending a revocation whose meaning depends on replay rules.

`force: false` is a **fast-forward check, not a compare-and-swap** on `H`. It
guarantees the new commit descends from the current ref, which combined with a
single parent and a tree built on `H'` gives linear history; it does not by
itself guarantee the ref is unchanged since step 1. Earlier drafts labelled
step 4 a compare-and-swap, and the difference is exactly what the tree-rebuild
rule above closes.

Bounded retries with jitter. On exhaustion the operation reports failure to the
caller with an explicit indeterminate marker (§5.4), because the commit may or
may not have landed. No merge commits are ever created. Timestamps never
resolve ordering.

### 5.3 Coverage projection repo (private; no names or emails)

```
source.json          { canonical_sha, built_at, dracla_version }
inflight.json        { ops: { "<idempotency_key>":
                         { started_at, subjects: [user_id, ...] } } }
intents.json         unfolded activation intents (§6.5):
                       [ { agreement_id, version, effective_at,
                           supersedes_coverage, event_id } ]
users/<shard>.json   packed, keyed (user_id, agreement_id):
                       { "<user_id>": { "<agreement_id>": {
                           decision,      "covered" | "uncovered"
                           reason,        for the authenticated portal only
                           version, digest, scope, since,
                           pending_version, pending_effective_at } } }
agreements/active.json
overrides/<key>.json
exemptions.json     { "<user_id>": { kind: "bot" | "human",
                                     basis, instrument_ref,
                                     asserted_by, asserted_at,
                                     event_id } }
```

Contains no legal name, email, confirmation text, or entity evidence.

**Coverage MUST remain private.** Carrying no names or addresses does not make
it publishable: this is a complete `user_id → covered?` directory, exactly the
public signer lookup `REQ-PORTAL-5` forbids and the requirements' §17 lists as
a non-goal. §8.4 gives the reason in full: the harm is aggregation, not
secrecy. Its privacy is checked by the reconciler on each run alongside the enforcer-installation
assertion (§4).

**Keyed by `(user_id, agreement_id)`**, not by user alone. A repo pair may hold
several agreements (§5.5); a single row per user would have let the second
agreement overwrite the first. `pending_version` and `pending_effective_at`
carry an early signature under a staged activation (§6.5), which a single
`version` field could not represent without either uncovering compliant early
signers or passing superseded ones.

**`decision` is precomputed, not derived at the edge.** The reconciler and the
Worker resolve version currency, `supersedes_coverage` chains, `effective_at`,
and scope, and write the resulting boolean. The enforcer compares the PR's
repository against `scope` and reads `decision`; it does not re-implement the
rule engine. This keeps the edge thin as §9 claims — the earlier row shape
would have required a full duplicate evaluator in TypeScript inside a 10 ms
budget, drifting against the Python replay.

The edge performs exactly two bounded evaluations, and this list is closed: the
`pending_effective_at` comparison (§6.5) and the unfolded-intent overlay
(§6.5). Anything beyond those two belongs in the reconciler. `intents.json` is
read on every check like `inflight.json`; it is capped at unfolded intents
(normally zero, rarely one), and an unreadable or overgrown log fails closed.
Install seeds it empty (§6.10.3.1) exactly as it seeds `inflight.json`, so
absence is never ambiguous: a missing file after install is damage, and
failing closed on it is correct rather than a fresh-project outage.

**Packed shards (D9).** Sharded by `user_id % 256` rather than one file per
user, so a check with `N` subjects touches one or two files rather than `N`,
keeping the enforcer inside the Workers subrequest cap. The sharding function
is part of the documented format.

**Shard writes are compare-and-swap.** A shard is a packed file, so a write is
read-modify-write and two concurrent signers in the same bucket would otherwise
lose one row — silently keeping a revoked contributor covered. Every shard
update supplies the blob SHA it read as a precondition and retries on mismatch,
re-reading and re-applying only its own key. This matters most precisely when
it is most likely: the reconciler folding a `supersedes_coverage: true`
activation (§6.5) rewrites all 256 buckets while signing traffic continues to
land in them.

### 5.4 Freshness guard (`REQ-CHECK-3`, `REQ-CHECK-4`)

The authoritative merge-group check must evaluate canonical state as observed
when it runs, but the enforcer cannot read canonical. The staleness signal is
therefore placed **inside the coverage repo**.

**Validation precedes every write.** An event is fully validated before it
touches canonical — not after, as an earlier draft had it. Canonical is
append-only and cannot be pruned (`REQ-REC-3`), so an invalid event committed
first is permanent, and recovering from it would mean teaching every reader to
filter. Validation before the commit means the log only ever contains events
that passed.

**The marker is written before the commit, and it is a set, not a pointer.**

```
sign / revoke  (Worker):
  0. validate fully                                    <- no write yet
  1. add idempotency_key -> { subjects: [user_ids] }
     to inflight.json                       (CAS)      <- marker OPENS here
  2. commit event to canonical              (§5.2)
  3. write users/<shard>.json               (CAS, §5.3)
     write source.json { canonical_sha }               <- effective here
  4. remove idempotency_key from inflight.json (CAS)   <- marker CLOSES here
  5. re-evaluate the originating pull request, if any

enforcer, on every check:
  read inflight.json
  if any of MY subjects appears in inflight.ops:
        that subject is indeterminate -> in_progress; never pass
  else read intents.json (overlay, §6.5) and shards, and decide
```

Opening the marker **before** the canonical commit is the whole point. A crash
anywhere in steps 2–3 leaves the marker open, so the guard fails closed. The
earlier ordering wrote the pointer *after* the commit, which meant a crash
between them left two pointers agreeing on stale state — reporting fresh while
canonical held a revocation. That failed **open**, at the authoritative gate,
and a contributor could induce it by retrying revocation under load.

Making it a **set keyed by operation** fixes two more failures a scalar pointer
could not represent: a failed write later "repaired" by an unrelated signer's
successful write, and two concurrent signers whose pointer updates interleave
so the pair agrees while one signer's coverage was never materialized.

**Scoping to subjects, not the project**, bounds the blast radius. A single bad
or unlucky operation makes *its own subjects* indeterminate, not every check in
the project — which the earlier project-global signal would have turned into a
cheap remote denial of service on the landing gate.

**Ownership is explicit.** Only the Worker that opened a marker entry may
remove it in step 4. The reconciler may clear an entry only after replaying
canonical and confirming that operation's true outcome, and it may never regress
`source.json`. Without that rule the reconciler, regenerating both from its own
replay head, could overwrite a newer marker and make a stale projection look
fresh — passing a contributor who had already revoked.

**Every canonical writer participates**, not just sign/revoke: agreement
publication, overrides, exemptions, and administrator commits all open and
close a marker — a guard that only one code path maintains is a liveness
signal for that path, not a freshness proof for canonical. Activations carry
their own: the intent record (§6.5) is appended to `intents.json` *before* the
canonical commit and settled by the reconciler, exactly the
open-before-commit, orphans-fail-closed lifecycle of this section — an
orphaned intent makes subjects read uncovered, never covered, until replay
confirms or clears it.

**Recovery has two drivers.** An entry orphaned by a crash would otherwise
wedge its subjects indefinitely, and `REQ-OPS-3` forbids a durable job queue.

*Opportunistic, in the Worker.* On any later request touching a subject with an
open marker, the Worker checks whether that operation's event actually landed in
canonical. If it did, the Worker completes the materialization and closes the
marker itself. This costs nothing and clears most orphans promptly.

*Scheduled, in Actions.* The reconciler runs on push to canonical **and** on a
**daily** Actions `schedule:` trigger — a scheduled workflow, not a job queue —
resolving whatever the opportunistic path did not reach, repairing the
projection, re-requesting checks left `in_progress`, and performing the
from-scratch verification replay.

Daily rather than six-hourly because only one scheduled duty is
latency-sensitive at all. Verification is an integrity check; the index and
exports are push-triggered by `REQ-DASH-5`, not scheduled; and due activations
no longer need a clock-driven actor (§6.5). That leaves orphan clearing, which
fails closed and which the opportunistic path already handles in the common
case. §9.2 gives the cost.

That re-drive is a recovery optimization; per `REQ-CHECK-4` core correctness
does not depend on either driver, because the guard fails closed without them.

**Retry exhaustion is explicit.** If §5.2's bounded retries are exhausted the
operation may or may not have committed. The marker stays open, the subject
stays indeterminate, the caller is told the submission is unresolved rather than
failed, and the reconciler settles it on its next run.

This is what lets the merge-group result honestly be called authoritative.

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
  acme-cla/acme-cla-records            <- the DEDICATED org (§6.10.4)
    recipient: Acme Foundation
    scope:     acme/*, acme-labs/widget  <- the CODE repos
    agreements/icla/…                    one agreement, versioned (§6.3);
                                         keying reserves room for more

two recipients in one org          ->  two pairs
  foundation-cla/projX-cla-records     recipient: Project X Inc
  foundation-cla/projY-cla-records     recipient: Y Foundation
```

`REQ-CONFIG-1` forbids *requiring* unrelated projects to share a repository; it
does not prevent related projects from sharing one deliberately.

**The recipient is fixed when the project is connected, and is immutable
thereafter.** `REQ-CONFIG-2` makes it a required configuration input, and the
portal collects it at connect time (§6.10.3) — install prompts for nothing and
takes only where to put the repositories. `recipient.slug` names the pair; the
legal identity behind that slug is recorded as an event with an actor.

It cannot later be edited: past acceptances granted rights to a
specific legal entity, and those grants cannot be retroactively reassigned.
Changing recipient is therefore a **new project with a new pair** — the
contributors sign the new agreement, and the existing records remain as
evidence of what was granted to the original entity. Editing it in place would
leave grants to two different legal entities in one repository, the exact
mixing this section exists to prevent.

**Repository naming keys on the project slug**, not the org, so a second
recipient in the same org does not collide. The slug defaults to the org name
with a trailing `-cla` removed (§6.10.3) for the first project:

```
acme-cla/acme-cla-records     first project; slug defaults to the org
                              with its trailing -cla removed
acme-cla/projx-cla-records    second recipient, same org, explicit slug
```

**Deferred for v1.** `dracla install` provisions one pair and defaults the
recipient slug from the organization name, with a trailing `-cla` removed
(§6.10.3). The multi-recipient case
above is not dropped, and costs nothing to add later: `<recipient-slug>-cla-*`
is the rule either way, so a second recipient is a different value of the slug
rather than a different naming scheme.

Costs of combining, both accepted for a single-recipient org:

- Read access to the pair exposes signer data across everything it covers.
- A substantive version activation applies to the whole scope at once. The
  `supersedes_coverage` flag (D10) confines this to genuinely substantive
  changes, but within a pair it is all-or-nothing.
- A later spin-out to a different recipient means splitting records, which is
  harder than transferring a repository.

## 6. Key flows

### 6.1 Signing (`REQ-SIGN-1..5`, `REQ-PORTAL-1`)

The project page lives at a stable, registry-derived path — `/p/<slug>` — which
is what badges and check outputs link to (`REQ-PORTAL-1`, `REQ-PORTAL-2`).

1. Contributor opens the project page. The agreement, recipient, version, scope,
   and required fields are readable **before** login (§6.6), as `REQ-AGR-3`
   requires; authentication via `dracla-records` OAuth is needed only to see
   personal status or to act.
2. Portal renders the complete agreement, recipient, version, scope, required
   fields, the project privacy policy link (`REQ-SEC-3`), and a retention
   statement — evidence is retained after revocation. `REQ-SEC-7` requires this
   on the signing flow, not only on revocation, and per-project retention and
   correction procedures come from `config/project.json`.
3. Contributor submits an affirmative action with the required fields.
4. Handler validates, commits the acceptance event, and materializes coverage
   (§5.4).
5. If a PR context was carried in the browser-bound `state` (§8.2), the handler
   re-evaluates that specific pull request (`REQ-CHECK-4`) — no global rescan.
   Failure here is retried, and the reconciler's scheduled pass re-drives any
   pull request left unevaluated; the contributor cannot re-request the check
   themselves, since GitHub restricts that to users with write access.

**The status a viewer sees is their own, and is read by session.** The portal
never accepts a user id parameter. `REQ-PORTAL-5` forbids the unauthenticated
version of that lookup outright; this design also declines the *authenticated*
version for viewers without records-repo authorization, on §8.4's aggregation
argument — §6.3's graded disclosure, gated on the same authorization as the
dashboard, is the one deliberate exception. The viewer's subject comes from the
verified session, exactly as on the write path.

**During the materialization window** the portal reads canonical, not the
projection, and labels the state *recorded, taking effect*. `REQ-PORTAL-1`
requires exact status: reading the projection would show "not signed" moments
after signing, and reading canonical without the label would show "signed" while
checks still fail. Naming the intermediate state is the only accurate answer.

Corrections require a fresh signing flow producing a new event linked via
`supersedes`; the original is never modified (`REQ-SIGN-5`).

### 6.2 Revocation (`REQ-REV-1..5`)

Same portal, same authentication. The confirmation screen states that
revocation changes coverage for future decisions but neither deletes the record
nor withdraws already-granted rights, and repeats the retention statement
(`REQ-SEC-7`). A revocation event is appended carrying `revokes: <event_id>` —
the acceptance it revokes, as `REQ-REV-3` requires — and the projection flips to
`revoked`. Re-signing appends a new acceptance and never mutates the revoked
event.

### 6.3 Pull request check (`REQ-CHECK-1`, `REQ-CHECK-2`)

```
pull_request opened / synchronize
  -> resolve subjects:
        PR opener
        every commit author        (GitHub-resolved user ID)
     dedupe by numeric user ID
     Co-authored-by: trailers are collected but NOT subjects  (§6.3.1)
  -> commit listing incomplete (pagination bound or >250)  -> action_required
  -> any subject unresolved to a user ID                   -> action_required
  -> any subject in inflight.ops                           -> in_progress  (§5.4)
  -> drop subjects exempt in exemptions.json — after the
     freshness guard, so a pending exemption change still
     holds its subject                                       (§6.8)
  -> read intents.json: an effective supersedes intent whose
     version differs from a subject's accepted version and
     from their pending early version                        -> that subject uncovered  (§6.5)
  -> map subjects to shards, fetch each distinct shard once   (D9)
  -> for each subject: row = shard[user_id][agreement_id]
        if row.pending_effective_at and now >= it:
              the pending version is operative              (§6.5)
        row.decision == "covered"                          -> ok
        AND this repository ∈ row.scope                    -> ok
     any subject failing either test  -> failure / action_required
  -> all subjects ok -> success
```

**One agreement per project, in v1.** A project has one CLA; change arrives
as *versions* of it (§6.5), not as a second agreement. The check therefore
evaluates each subject against exactly the agreement named by
`agreements/active.json`. The `(user_id, agreement_id)` keying and the event
schema deliberately reserve room for more than one — entity and corporate
agreements are the anticipated case, and they are *alternatives* to the
individual one, not conjuncts — but how several agreements combine is a rule
this design defers along with entity support (`REQ-CONFIG-4`, §13) rather than
one the enforcement gate should improvise.

**Scope is evaluated, not merely recorded.** `REQ-CONFIG-3` requires the
effective scope to be captured with every acceptance, and both the event and
the shard row carry it — but a check that never compares the pull request's
repository against that scope leaves the requirement unimplemented. Widening a
project's scope would otherwise make contributors instantly "covered" for
repositories they never agreed to. Coverage is evaluated against the scope
**recorded with the acceptance**, so a scope expansion does not retroactively
extend consent; §6.5 handles re-consent for scope changes the same way it
handles substantive version changes.

**Any bound fails closed.** `REQ-CHECK-2` requires every commit to be
evaluated, and the GitHub pull request commits endpoint truncates at 250
regardless of intent. Where the listing cannot be completed — pagination bound
from the §9 CPU budget, or the API limit — the result is *action required*, never
a pass on a partially enumerated subject set.

Public surfaces disclose only *CLA satisfied*, *action required*, or
*temporarily unavailable*. Exact reasons appear only in the authenticated
portal (`REQ-CHECK-1`, `REQ-PORTAL-3`, `REQ-PORTAL-5`).

**Exemptions are consulted here.** `REQ-CHECK-2` allows project configuration to
exempt non-human accounts. Exemption events materialize into `exemptions.json`
in the projection (§5.3); the enforcer, which cannot read canonical, drops
exempt subjects before evaluating coverage. Without that projection artifact the
requirement was unimplementable, since a recorded exemption would have been
invisible to the only component that decides.

**Check output carries the retry contract.** `REQ-CHECK-5` requires the result
to explain how evaluation is retried or how an authorized user can request a
retry. The check run's `title` and `summary` are drawn from a fixed string table
keyed only by state — never by subject identity, subject count, or any
record-derived value — and the *action required* and *temporarily unavailable*
texts name the retry path: push a new commit, sign at the portal link, or
re-request the check. Re-request authorization needs no DraCLA control; GitHub
restricts it to users with write access. Annotations and comment bodies use the
same table. Nothing may `@`-mention a subject, which is the convention among CLA
bots and a direct `REQ-PORTAL-3` / `REQ-PORTAL-5` violation.

**Where the exact reason is actually shown.** `REQ-CHECK-1` requires the
authenticated portal to give the exact reason for an action-required result, but
on a multi-author pull request that reason usually concerns *someone else* — an
uncovered co-author, an unresolved identity — while `REQ-PORTAL-1`'s portal
shows only the viewer's own status and `REQ-PORTAL-5` bars turning it into a
lookup for others. There is therefore a **pull-request-scoped authenticated
view** at `/p/<slug>/pr/<number>`, with disclosure graded by what the viewer is
already entitled to see:

| Viewer | Sees |
|---|---|
| Anyone authenticated | Their own subject status in this pull request, and nothing about others |
| Write access on the contributing repo | Aggregate only: counts by reason — *n* uncovered, *n* unresolved identity, *n* awaiting activation |
| Read access on the records repo (`REQ-SEC-6`) | Named subjects and per-subject reasons |

The middle row is what makes the result actionable for a maintainer without
becoming a per-user lookup: a maintainer learns *what to do* (ask the
contributor to sign, or issue an override) without learning any specific
person's CLA status. Naming subjects requires the same authorization as the
dashboard, because it is the same disclosure.

#### 6.3.1 Co-authored-by trailers do not block

A `Co-authored-by:` trailer is unauthenticated commit-message text that any
commit author can write. Treating it as a blocking public subject produced three
defects at once, and `REQ-CHECK-2` revision 2 removes the cause rather than
mitigating each:

- **A coverage oracle.** Naming any GitHub user in a trailer on a throwaway pull
  request made the public check state reveal whether that user had signed —
  functionally the lookup `REQ-PORTAL-5` forbids.
- **A jamming vector.** Naming a contributor who later revoked made every pull
  request carrying those commits unlandable (former risk R10).
- **Failure in the ordinary case.** GitHub offers no reliable email-to-user
  lookup; only `<id>+<login>@users.noreply.github.com` parses directly to a user
  ID, so most legitimate trailers were unresolvable and failed closed (former
  risk R1).

Trailers are still collected and still matter — they are the project's only
signal that someone else contributed:

```
public check          opener + commit authors only
                      -> state cannot be steered by an injected trailer

/p/<slug>/pr/<n>      trailer co-authors listed with coverage status,
                      under §6.3's graded disclosure
                      -> maintainer requires signing, records an exemption,
                         or issues an override
```

**The residual gap, stated plainly:** a co-author declared only by a trailer can
contribute without signing unless a maintainer acts on the surfaced list. That is
the cost of the change, and it is why a project may configure trailers to block
its own checks where its threat model prefers the older behaviour.

**This does not close the oracle entirely.** Commit author email is equally
attacker-controlled: authoring a commit as
`<TARGET_ID+x@users.noreply.github.com>` still makes that user a subject and
still leaks their coverage. The attack now requires authoring a commit under
someone else's address rather than typing a line in a message — more visible,
auditable in the commit list, and blocked outright by repositories requiring
signed commits. Reduced, not eliminated; see the residual risk note below.

**Attribution is as strong as git author metadata, and no stronger.** Commit
author email is attacker-controlled, and a noreply address is derivable from any
public profile, so "GitHub-resolved author" is unauthenticated email matching
rather than proof of authorship. Two consequences are documented rather than
solved, because `REQ-CHECK-2` mandates this resolution rule: a contributor can
attribute commits to a covered user, and a third party can be injected as a
co-author to block a pull request. The honest claim the evidence supports is
*some account whose email appeared in an author field has signed* — §8.2's
attestation language is scoped accordingly. Verified-signature enforcement is
offered as documented hardening for projects that need more.

**The public check remains a coverage oracle, and this is residual risk.** With
trailers demoted (§6.3.1) the cheap path is closed, but an attacker willing to
author a commit as `<TARGET_ID+x@users.noreply.github.com>` still makes that user
a subject and still reads their coverage off the public check state. This cannot
be removed while the check remains useful, because the check's whole purpose is
to publish a boolean about a subject set the pull request author influences.
Mitigations bound it: per-account and per-IP rate limiting on check creation for
pull requests whose opener is not the sole subject, no reason detail on any
public surface, and the fact that forged authorship is visible in the commit list
and blocked by signed-commit rules. Stated as residual rather than claimed
met.

**Concurrent evaluations are conditioned on the head SHA.** Two `synchronize`
deliveries for the same pull request can race, and a late-completing stale
evaluation must not overwrite a newer one. Each check write records the head SHA
it evaluated and is skipped if the pull request has moved on, so the failure
mode is a missing update that the next event repairs, not a stale `failure`
sitting on a covered pull request with nothing to re-trigger it.

### 6.4 Authoritative merge-group check (`REQ-CHECK-3`)

On `merge_group.checks_requested`, the enforcer re-resolves subjects for the
merge candidate, applies the freshness guard (§5.4), evaluates coverage exactly
as §6.3 — exemptions, scope, and the intent overlay included — and reports on
the merge-group commit. This result — not the ordinary PR check — is the CLA
decision for landing. The PR check is documented as early feedback only.

**Subject resolution must map back to pull requests.** `REQ-CHECK-3` requires
evaluating "the merge candidate's current pull requests **and** commits", and a
merge group may batch several. The event supplies base and head SHAs, not a PR
list, so the enforcer resolves the group's pull requests via the API and unions
each PR's opener with the commit-derived authors. Walking the commit range alone
would silently drop every opener — and an opener who authored none of the
commits would then pass at the only blocking gate, defeating `REQ-CHECK-2`.
Budget note: this costs one opener lookup and one commit listing per PR in the
group, which §9's per-PR figures do not model (A3).

**Overrides are keyed to content, not to the PR head SHA.** The merge queue
creates a new commit, so a PR head SHA does not exist at this check. Keying
strictly to it would make an overridden PR permanently unlandable at the only
gate that blocks; keying loosely to the PR number would let an override survive
a force-push that introduced a different uncovered author. Instead an override
is keyed to `(pr_number, subject_user_id, tree_digest)` — the tree the override
was granted against — so it applies across the queue's commit rewrite while
still lapsing when the content changes, which is the binding `REQ-CHECK-2`
intends.

**Fallback without a required merge queue.** `REQ-CHECK-3` already forbids
claiming a final pre-landing check in this configuration. DraCLA additionally
re-verifies on push to the default branch and, if a commit landed uncovered,
opens an issue that carries **only the commit SHA and the generic state**, with
a link to the authenticated portal. It must not name the subjects: on a public
contributing repo that would be a permanent, indexable, public statement that a
named user is uncovered, which `REQ-CHECK-1`, `REQ-PORTAL-3`, and
`REQ-PORTAL-5` all forbid. This is detection, not prevention, and is documented
as such.

**Administrator bypass must be documented.** `REQ-CHECK-3` requires stating
that repository administrators may retain a GitHub-supported bypass capability
(ruleset bypass actors, admin merge). DraCLA cannot prevent it and does not
claim to; adopter documentation states plainly that a required merge-group check
constrains everyone except principals the repository's own rules exempt.

### 6.5 Agreement activation (`REQ-AGR-1`, `REQ-AGR-2`, D10)

**An agreement is published by reference, and snapshotted.** `REQ-AGR-1` asks
for "the exact agreement content **or an immutable content reference**", and the
reference is the better primitive: the project keeps its legal document where it
already lives — a file at a commit SHA in its own repository, or a gist revision
— and DraCLA records a pointer to it rather than becoming its custodian.

```
publish:
  fetch the immutable ref     github.com/acme/acme/blob/<sha>/ICLA.md
  compute and verify digest
  commit agreement_published  { ref, digest, content_commit_oid,
                                effective_at, scope }
  snapshot the text           agreements/icla/v3.md
```

Each of the three does a distinct job:

| | |
|---|---|
| **ref** | Provenance. Immutability is content-addressed, so the pointer cannot drift, and anyone can verify the snapshot against the original. |
| **snapshot** | Durability. A gist or repository can be deleted; a legal record that then points at nothing fails `REQ-REC-5`'s requirement that records be readable without DraCLA. This is where a pointer-only design — CLA Assistant's, for instance — leaves a gap. |
| **digest** | Binding. A later force-push at the source becomes detectable rather than silent. |

The snapshot lands in the adopter's own records repository (D4, D4a), so custody is
unchanged: DraCLA writes it, the adopter owns it. Unlike signer data, the
agreement is public by construction — `REQ-AGR-3` requires contributors to read
it *before* authenticating — so there is no confidentiality reason to route it
around the portal. §6.6's agreement endpoint already serves it unauthenticated.

**Publishing and activating are separate acts.** Publishing records an immutable
version — reference, digest, content commit OID, snapshot, scope — and
invalidates nothing. The OID is the `<sha>` the reference names, recorded as
its own field because `REQ-REC-4` requires it alongside the digest (§5.1); a
reader must not have to parse it out of a URL.
Activating makes a version the one contributors must have accepted. A project
correcting a typo publishes the corrected version and simply does not activate
it, which resolves the editorial case with no flag and no amendment. The
`supersedes_coverage` flag (D10) therefore governs only what an *activation*
does to prior acceptances:

- `supersedes_coverage: true` — every prior acceptance stops providing coverage
  at the effective time; contributors must re-sign.
- `supersedes_coverage: false` — prior acceptances continue to provide coverage.

DraCLA never inspects agreement text to decide which applies; the project
declares it on the `agreement_activated` event, consistent with `REQ-AGR-4`.

**The flag lives in the event, not in `v3.meta.json`.** A coverage-determining
input sitting in a mutable file that the content digest does not cover would let
someone retroactively change who is covered, with no attribution and no
append-only guarantee — undermining `REQ-AGR-1`'s immutability. The `agreements/`
tree is a convenience for human reading; the events are canonical.

**Currency rule.** A subject is current for agreement `A` if their accepted
version is the active version, **or** no activation carrying
`supersedes_coverage: true` has taken effect since their accepted version was
active. This is the rule the reconciler and the Worker apply when computing
`decision` (§5.3); stating it matters because a v1→v2 editorial→v3 substantive
→v4 editorial chain is otherwise readable two ways.

**Staged activation.** An activation may carry a future `effective_at`. Between
publication and that time the portal shows affected contributors what is coming
and lets them sign early — recorded in `pending_version` /
`pending_effective_at` (§5.3), so an early signer is neither treated as
uncovered before the flip nor as still-covered under the old version after it.

**The flip needs no scheduler, and activation is O(1) at the edge.** Nothing
in the Worker or the push-driven reconciler fires at a time, and relying on a
periodic job would leave a window between `effective_at` passing and the shards
being rewritten in which contributors still pass under a superseded agreement —
a `REQ-AGR-2` violation, not merely staleness.

The mechanism is an **intent record**. Activating appends one entry to
`intents.json` in coverage — the version, `effective_at`, and
`supersedes_coverage` flag — *before* committing the `agreement_activated`
event to canonical, the same open-before-commit discipline as the in-flight
marker (§5.4): a crash between the two leaves an orphaned intent that fails
**closed** (subjects read uncovered under an activation that never landed)
until the reconciler settles it against canonical. One small CAS write, so an
activation costs the same at the edge regardless of how many contributors it
affects.

The enforcer overlays unfolded intents at read time, and the comparison is
**identity, not order**: version identifiers are opaque, and the activation
sequence that does define order lives in canonical, which the enforcer cannot
read. Under an effective `supersedes_coverage: true` intent a subject is
covered only if their row's `version` or `pending_version` equals the intent's
version; otherwise they are uncovered — instantly, with no rewrite in the
path. Entries append in activation order, and with more than one unfolded
effective intent the newest governs. The overlay only ever *removes* coverage,
never grants it, so a forged intent — which already requires coverage-repo
write — is an availability nuisance, not a falsified pass. An early signer
is unaffected by the overlay because their row already carries
`pending_version` / `pending_effective_at` (§5.3), and if
`now >= pending_effective_at` the pending version is the operative one. Both
are bounded comparisons, not a rule engine (§5.3's closed set); the full
currency chain of the rule above is still evaluated only in Python.

The reconciler **folds** intents into the shards on its next run — push to
canonical triggers one, so folding is prompt — matching each intent to its
canonical event by `event_id`, the join that folding and orphan settlement
(§5.4) both stand on and the field's only purpose — and removes the folded
entry:
the canonical event remains the durable record, and the log stays transient
signal, exactly like `inflight.json`.
Folding is housekeeping rather than the mechanism: correctness never depends on
it, because the overlay answers until the fold lands.

**Scope changes follow the same path.** Widening or narrowing project scope is
coverage-affecting in exactly the way a version change is, and §6.3 evaluates
against the scope recorded with each acceptance. A scope change is therefore an
activation too: `supersedes_coverage: true` if re-consent is required, otherwise
prior acceptances keep their recorded scope and the new repositories are simply
uncovered until contributors sign.

A blanket grace period was rejected: it lets contributions land under an
agreement the project has already replaced, which is the outcome versioned
agreements exist to prevent.

### 6.6 Dashboard and exports (`REQ-DASH-1..5`, `REQ-REC-5`)

Actions in canonical regenerates a private index and JSON/CSV exports on each
push, committing them to `derived/` on a separate branch of canonical (§5.1) —
never to the coverage repo, and never as Actions artifacts. Filtering and sorting
run in the browser. CSV cells derived from untrusted input are neutralized
against formula interpretation while JSON retains the canonical value
(`REQ-SEC-8`).

**Index schema** (`REQ-DASH-2`, `REQ-DASH-4`). One row per subject per
agreement, carrying only what the mandated filters need:

```
github_user_id, login_snapshot, login_as_of,
agreement_id, version, scope,
status: current | exempt | revoked | superseded | indeterminate,
accepted_at, revoked_at
```

`exempt` means coverage rests on a recorded exemption rather than a signature
(§6.8) and is never folded into `current`; `superseded` means a later acceptance
replaced this one (`REQ-SIGN-5`) or an activation invalidated it;
`indeterminate` means the subject sits in
`inflight.ops`, an operation exhausted its retries, or replay could not resolve
the record. Both statuses are required by `REQ-DASH-2` and neither existed in
the projection before. Legal name, email, and confirmation text are **not** in
the index — they appear only in the exports, which `REQ-DASH-4` keeps separate
by requiring the index carry no more private data than the dashboard needs.

**Index proxy authorization.** The endpoint serves a **fixed, server-computed
artifact path**; it accepts no `path`, `ref`, or filename parameter. The write
side is protected by allowlisted paths (§8.1 #1) and the read side needs the
same discipline, or `?path=events/…` returns a raw acceptance record with full
PII. Authorization is per request, against the **registry-resolved canonical
repo of the requested project**, using a **user-to-server** token — never the
installation token, which would return 200 unconditionally and bypass the check
entirely. No authorization result is cached across projects. Responses are
`Cache-Control: private, no-store`; a shared edge cache keyed without identity
would be `REQ-DASH-3`'s forbidden public asset with extra steps. Unknown project
and unauthorized viewer both return a uniform 404, so the endpoint does not
disclose which organizations are adopters.

### 6.7 Badges and public surfaces (`REQ-PORTAL-2..4`)

Badges are **static assets, not a dynamic endpoint**. A per-pull-request badge
image served by the Worker would be both a coverage oracle (§6.3) and an
anonymous amplifier into the fail-closed request budget (§9). There are exactly
three SVGs plus the project badge, served from Pages:

```
cla-sign-or-check.svg    "CLA: sign or check status"   <- CONTRIBUTING.md badge
cla-satisfied.svg        "CLA: satisfied"
cla-action-required.svg  "CLA: action required"
cla-unavailable.svg      "CLA: temporarily unavailable"
```

The `CONTRIBUTING.md` badge is deliberately viewer-independent: a
GitHub-rendered image cannot identify who is looking at it, so it shows the
generic prompt and links to `/p/<slug>` (`REQ-PORTAL-2`).

The pull request surface is a **comment posted by `dracla-enforcer`**, which is
why that App needs `pull_requests: write` (§4). It carries one of the three
generic states, the same fixed string table as the check output (§6.3), and a
link to the authenticated portal. It encodes no coverage detail, no subject
identity, and no subject count (`REQ-PORTAL-3`, `REQ-PORTAL-5`). The comment is
updated in place rather than appended, so a pull request accumulates one.

**Wording rules** (`REQ-PORTAL-4`). Every state is legible from text alone —
colour is never the only signal, and each badge carries its state in its alt
text. Contributor-facing copy is factual and avoids implying that signing
transfers copyright: the portal says the agreement "grants the rights described
below to <recipient>", with the recipient and the agreement text supplying the
actual claim, since `REQ-AGR-4` forbids DraCLA characterizing what an agreement
means.

### 6.8 Administrative flows (`REQ-AGR-1`, `REQ-CHECK-2`, `REQ-OPS-4`)

Every administrative action is an append-only event with an `actor`, authorized
the same way and through the same portal — there is no separate admin console
and no source-code edit, which `REQ-OPS-4` requires.

| Action | Event | Effect |
|---|---|---|
| Publish a version | `agreement_published` | Records an immutable reference plus digest, and snapshots the text (§6.5); invalidates nothing |
| Activate a version | `agreement_activated` | Sets the required version; `supersedes_coverage` decides re-signing (§6.5) |
| Change scope | `agreement_activated` | Same path; scope is coverage-affecting (§6.5), and the actor must administer the owner of every entry being added (§7) |
| Exempt a non-human account | `exemption` (`kind: bot`) | Materializes to `exemptions.json`; consulted by §6.3 |
| Exempt a human account | `exemption` (`kind: human`) | Same, plus a recorded basis and instrument reference — see below |
| Withdraw an exemption | `exemption_revoked` | Append-only; the original is preserved |
| Override a check | `override` | Keyed `(pr_number, subject_user_id, tree_digest)` (§6.4) |
| Edit project config | `config_updated` | Required fields, privacy policy, retention text (resolved YAML, §6.9) |

**Authorization is concrete**, where §8.1 #5 previously said only "a separate
check". The actor must currently hold **admin** permission on the canonical
records repository, verified per request with a **user-to-server** token via
`GET /repos/{owner}/{repo}` and inspecting `permissions.admin` — never with the
installation token, which would answer unconditionally. `REQ-SEC-6`'s currency
rule applies, so this is re-verified at the moment of the action rather than
read from the session.

**Human exemptions carry an asserted basis.** Exempting a bot is a statement
about identity plumbing — the account holds no authorship claim and the work
belongs to whoever configured it. Exempting a *person* is a legal assertion: that
their grant already exists by another instrument, typically employment or a prior
assignment. The common real case is staff of the recipient entity, for whom a CLA
is redundant.

DraCLA records the assertion; it does not evaluate it, because `REQ-AGR-4`
forbids it inferring legal meaning. The event therefore carries
`basis` (`employment | prior_assignment | other`), a free-text
`instrument_ref`, and the asserting administrator, so an audit can follow the
claim to its source.

**An exemption is reported distinctly from an acceptance**, never merged into
`current`. The dashboard and exports carry `exempt` as its own status (§6.6), so
a records reader is never shown something that looks like a signature but is not
one. `REQ-CHECK-2` requires this separation.

**Rules live in config; evidence lives in events.** `config/project.json` may
express a rule such as "exempt all members of `acme-staff`". Membership is
dynamic and the enforcer cannot query it cheaply or append-only, so the
reconciler evaluates rules and materializes explicit per-account exemption
events. A coverage decision never depends on state that is not recorded as an
event — which is also what keeps the projection rebuildable (`REQ-REC-6`).

**Exemptions are revocable, not erasable.** Withdrawal is a later event; the
original assertion and its author remain in the record.

**The recipient is never editable** (§5.5). `config_updated` rejects any change
to it; changing recipient is a new project.

### 6.9 The `dracla` CLI (D12, `REQ-REC-5`, `REQ-OPS-4`)

Python, distributed on PyPI, run without installation:

    uvx dracla install

The CLI is not merely an installer. It is the reporting surface, and it reads
the canonical repository **directly**, with the
maintainer's own credentials and no DraCLA service in the path:

**The CLI provisions and reports. It does not administer.**

| Command | Purpose | Status |
|---|---|---|
| `dracla install github.org=<org>` | Provision the repo pair and the workflow. One override; everything else is configured in the portal (§6.10.3) | **built** |
| `dracla config show` | Print the resolved configuration the portal wrote | designed |
| `dracla status <user>` | Coverage for one contributor | designed |
| `dracla export --json --csv` | Portable formats (`REQ-REC-5`) | designed |
| `dracla reconcile` / `dracla verify` | Replay canonical and check the projection matches | designed — M2 |
| `dracla audit <pr>` | Why a check decided what it did | designed |
| `dracla rotate-key` | Replace the coverage deploy key (§6.10.2) | designed |

**Agreements are managed in the portal, not here** (§6.8). Publishing and
activating a version are attributable events, and the portal is where
authorization is checked live against current GitHub permissions
(`REQ-SEC-6`) and an `actor` is recorded. A CLI running under a personal access
token is a weaker attribution story for an act with legal weight, and §6.8
already states there is no separate admin console. A CLI surface for agreements
may follow if there is demand; it is not the first-class path.

Only `install` is built. A first attempt was implemented without §6.10 and
removed after review rather than patched; see `design/cli-review-findings.md`.

Two things this buys beyond convenience. `REQ-REC-5` requires records to be
readable **without** DraCLA; a CLI that reads the repository directly is the
strongest demonstration of that, because it is the same tool an auditor would
use. And `REQ-OPS-4` requires installation be driven by configuration without
editing source, which is exactly what `install` and `config` are.

`verify` runs the same replay the reconciler runs (§5.4), so a maintainer can
reproduce the integrity check on their own machine rather than trusting a
workflow's word for it.

**One workspace, many projects.** A maintainer often runs several projects, and
a single organization may hold several repo pairs — one per legal recipient
(§5.5). The CLI works across all of them from one place:

```
dracla status --all              coverage across every project in the workspace
dracla export --all              one export per project, or a merged view
dracla verify --all              replay and check every projection
```

The workspace is a local file listing the projects the maintainer administers.
It grants nothing: every command runs with their own credentials against
repositories they already control, so a cross-project view adds no trust
surface and no DraCLA service is in the path. `REQ-CONFIG-1`'s rule that each
project owns its own configuration and records is untouched — the workspace
*references* projects, it does not consolidate them.

Note the asymmetry with the dashboard: a federated **local** view is fine
because the maintainer holds credentials for each project, whereas a federated
hosted view would mean one surface aggregating several projects' signer PII.

**Config composition.** Those projects share almost everything and differ in
recipient, agreement, and scope. The CLI composes their configurations with
[Hydra](https://hydra.cc) on the 1.4 development line, so a base configuration
is defined once and each recipient is an override rather than a copy — which is
where composition starts paying for itself rather than being ceremony over a
single file. Hydra 1.4 sets the floor at Python 3.10 for the CLI; `core` has no
such constraint, since it depends on nothing.

**Composition stays on the client.** Hydra composes the CLI's *own*
configuration locally (§6.10.3), and whatever reaches `core` is a resolved plain
dict. `config/project.json` is written by the portal as a `config_updated` event
(§6.8), not by the CLI — but the same rule governs it: what is committed is
inert. No `defaults:`, no `${...}` interpolation, no config-group references,
and no dependency on the composition engine to know what it says.

JSON for the committed artifact because it is machine-consumed — the Worker
serves the agreement and required fields from it (§6.6) and parses it natively.
Human readability is `dracla config show`'s job, not the wire format's; that is
precisely what D12 makes the CLI for. It reads that file — it does not write it.

Canonical **events** are JSON for the same reason (§5.1): machine-written,
machine-read, and the format an external reader parses.

**Agreement and config delivery.** The portal is static and the agreement,
recipient, scope, required fields, and confirmation labels live in the private
canonical repo. A read-only Worker endpoint serves them with the records
installation token, without requiring login — `REQ-AGR-3` requires the agreement
be readable before acceptance. It is cached at the edge keyed by
`(project, agreement_version)`, which is safe because the payload is
project-public by construction and contains no signer data. Its traffic belongs
in the A3 envelope.

---

### 6.10 `dracla install` (design before implementation)

A first implementation of this command was written without this section and
removed after review; `design/cli-review-findings.md` records why. Four of its
defects were decisions absent from the design rather than mistakes in code, so
those are decided here first.

#### 6.10.1 Branch layout

**`events` is the records repository's default branch.** In steady state it
holds `config/project.json`, `agreements/`, `events/`, and
`.github/workflows/` — everything the reconciler reads. At install time it holds
the README and the workflow: there are no events yet, no agreement, and no
configuration, because install publishes none of them (§6.10.3).

`auto_init` creates `main`, so install must create `events` and promote it to
default. That is a step, not an assumption — an earlier implementation assumed
the default was `main` and wrote everything to a branch the reconciler never
checked out.

This is forced rather than chosen. GitHub reads a `push:` workflow from the
branch being pushed, but runs `schedule:` workflows only from the *default*
branch. §5.4 requires the reconciler to fire on both — on each event, and daily
for orphan clearing. A workflow satisfying both can therefore live on only one
branch, and that branch must be the default.

It also keeps `REQ-REC-3`'s one-logical-event-per-commit rule intact rather than
straining it, because configuration and agreement changes *are* events
(`config_updated`, `agreement_published`, `agreement_activated`, §6.8). The only
commits that are not events are the branch's bootstrap, which carries the README
and the workflow and predates any event (§6.10.3.1). Baseline revision 3
pins `REQ-REC-3` to exactly this reading — it governs event commits, permits
the pre-event bootstrap, and has consumers identify events by recorded path —
so what §10.3 once carried as a declared interpretation is now the
requirement's own text. It is also invisible to
replay by construction: events are identified by their `events/**` paths in
the tree (§5.1), never by commit position, so nothing that reads the record
needs to distinguish bootstrap commits from anything.

`derived/` (index and exports) stays on a **separate branch**, so regenerating
it never appends non-event commits to canonical ancestry.

| Branch | Holds | Written by |
|---|---|---|
| `events` (default) | README | `dracla install` — first bootstrap commit (§6.10.3.1) |
| | workflow | `dracla install` — second bootstrap commit |
| | config | the portal, as `config_updated` events (§6.8, §6.10.3) |
| | agreements | the portal — the `agreement_published` event and its snapshot (§6.5, §6.8) |
| | events | the signing path (§5.4) |
| `derived` | index, JSON and CSV exports | the reconciler |

#### 6.10.2 The coverage deploy key

The reconciler runs in canonical and must write the projection in coverage. A
deploy key is the right credential because it is per-repository by construction:
it can write that one repository and nothing else.

| | |
|---|---|
| Generated by | the CLI, on the administrator's machine, never leaving it except as below |
| Public half | added to the **coverage** repository as a write-capable deploy key |
| Private half | stored as an Actions secret on the **canonical** repository |
| Rotation | `dracla rotate-key` replaces both halves; the reconciler fails loudly if its key predates the policy window (§8.1.2) |
| Re-install | detects an existing `dracla-reconciler` key and leaves it alone unless `rotate_key=true` is passed |

Storing the private half in canonical's Actions secrets is repository
*settings*, not repository *contents*, so `REQ-SEC-4`'s prohibition on secrets
in records repositories is not breached. That distinction is deliberate and is
recorded in §8.1.2.

**Install must not seed a workflow it cannot satisfy, or a credential nothing
uses.** Until `dracla reconcile` exists (M2), install seeds a placeholder
workflow that states its own absence and creates **no** deploy key. A workflow
invoking a subcommand that does not exist is worse than no workflow, because it
reports failure on the first signature rather than at install time; and a
write-capable deploy key that nothing consumes is a live credential with no
purpose. Both arrive together in M2, when `dracla install` re-run on an existing
pair upgrades the workflow and provisions the key.

#### 6.10.3 What install collects, and what it does not

**One org, one pair, one override.**

```
dracla install github.org=hydra-ecosystem-cla
```

`github.org` names the **dedicated** organization (§6.10.4), not the one holding
the project's code.

Hydra-style `key=value` rather than a positional argument or a flag, uniform
with the rest of the CLI. That is not decoration: it is what makes the deferred
second-recipient case a *value* rather than a syntax change.

```
dracla install github.org=hydra-ecosystem-cla                v1
dracla install github.org=foundation-cla recipient.slug=projx    later, additive
```

Install's inputs are overrides onto a small config tree, of which exactly one
key is required today:

```yaml
github:
  org: ???                                   # required; the DEDICATED org
recipient:
  slug: ${dracla_recipient:${github.org}}    # org minus a trailing -cla
```

`???` rather than a value: there is no sensible default for which organization
gets the repositories, so it is reported as missing rather than guessed. The
slug goes through a resolver rather than a plain `${github.org}` interpolation
because a plain one performs no strip, which is what produced
`acme-cla-cla-records`.

The repositories are `<recipient.slug>-cla-records` and
`<recipient.slug>-cla-coverage`.

**The prefix is the recipient slug, defaulted from the organization name with a
trailing `-cla` removed.** The organization is the dedicated one (§6.10.4), so it
is conventionally `<project>-cla`; the recipient is `<project>`. Without the
strip, `github.org=acme-cla` would produce `acme-cla-cla-records`, doubling a
word the organization name already carries. The strip affects only the
*default* — an explicit `recipient.slug` is taken as given. The suffix is matched
case-insensitively, because GitHub logins are: `ACME-CLA` and `acme-cla` name the
same organization and must not produce different repository names.

The strip is one suffix, not a loop, and does not apply when nothing precedes it.
An organization named exactly `cla` keeps its slug, and `foo-cla-cla` yields
`foo-cla` — both still produce a doubled word. Neither is worth more machinery:
the rule exists for the conventional `<project>-cla` shape, and anything else is
one explicit `recipient.slug` away from whatever the adopter wants.

It is not a disambiguation device that happens to look like one — it is §5.5's
naming rule with the slug defaulted, which is why overriding `recipient.slug` is
the whole of what a second recipient needs:

```
github.org=hydra-ecosystem-cla
  hydra-ecosystem-cla/hydra-ecosystem-cla-records    v1 — slug defaulted
  hydra-ecosystem-cla/projx-cla-records              later — explicit slug
```

No migration, no rename, no inconsistent second case. Deferring multiple
recipients costs nothing later precisely because the naming never assumed one.
It also reads correctly in a local clone directory or a cross-organization
listing, which `cla-records` would not.

Install collects only what requires the administrator's own credentials and
therefore cannot be deferred: **where to create the repositories**. Everything
else is project configuration, and the portal is a better place for all of it:

| Deferred to the portal | Why |
|---|---|
| Recipient legal name | `REQ-CONFIG-2` data, recorded as a `config_updated` event with an `actor` — stronger provenance than a command-line flag, the same argument that moved agreements (§6.5) |
| Scope | The portal can list the organization's repositories to tick, rather than having the operator type them and hope |
| Privacy policy URL | `REQ-SEC-3` needs it before *signing*, not before provisioning |
| Required fields, confirmation labels | Form design, validated live |
| Retention statement | A paragraph of prose; a text area, not a shell argument |
| Agreement | Published by reference in the portal (§6.5) |

**Install therefore writes no `config/project.json`.** The absence of a
`config_updated` event is how the portal recognizes a repository as
provisioned-but-unconfigured, so no stub is needed — and the recipient's
immutability (§5.5) begins at the first configuring event rather than at a flag
someone typed once.

**One recipient per organization, for now.** §5.5 permits several when the legal
recipient differs; v1 provisions one and defaults its slug from the organization
name. The case is deferred rather than dropped, and deferring it is free: both
the naming rule and the routing layer key on the recipient slug, so the second
one is a new value, not a new shape.

#### 6.10.3.1 Sequence

Install is **idempotent and re-runnable**; a partial run is the expected failure
and re-running is the recovery. It is not transactional — GitHub offers no way
to make it so — so each step is individually safe to repeat, and the order puts
the cheapest failures first.

```
1. preflight the organization        may block (6.10.4)
2. confirm with the operator         unless force=true or dry_run=true
3. create both repositories EMPTY    auto_init: false; read back to verify
                                     both are private
4. bootstrap `events` via the        the first ref that ever exists, so there
   Contents API                      is no `main` to delete and no window in
                                     which the default is wrong
5. seed the workflow                 idempotent; identical content is skipped
6. initialize the coverage           its own `coverage` branch: README,
   projection                        source.json, inflight.json, intents.json
                                     (§5.3) — each seeded only when absent, so
                                     live state is never overwritten
7. print the two App install links
```

**Reuse requires provenance, per repository.** Re-running finishes only a
repository this command made: the records repository must carry its `events`
branch rooted at the DraCLA genesis README, and the coverage repository its
`coverage` branch likewise — the branch install creates first, holding the
file it writes first. A name collision without that — whatever branches it
has — is refused, because a branch merely *named* `events` is not provenance
and the repository's existing collaborators would be able to read signer data.

**Why empty rather than `auto_init`.** `auto_init` creates `main`, which would
then have to be demoted and deleted — two extra operations, an interval during
which the default branch is the wrong one, and a stray branch left behind if the
run stops in between. Creating the repository empty and making `events` the
first ref removes the problem instead of handling it: GitHub sets the default
branch to the only branch that exists.

**Bootstrapping needs the Contents API, not the Git Data API.** Every Git Data
endpoint refuses on an empty repository — creating a blob answers
`409 Git Repository is empty` — so the first commit cannot be assembled from
blob, tree, and commit objects. `PUT /contents/{path}` with a `branch` parameter
can create both the branch and its first commit there, and is therefore how the
branch is bootstrapped. Subsequent writes use either.

A consequence: the Contents API writes one path per commit, so the branch begins
with two bootstrap commits rather than one — the README, then the workflow.
Both carry no events, and `REQ-REC-3`'s one-logical-event-per-commit rule
applies to the events that follow them.

**Install does not write the registry entry.** The registry lives in DraCLA's
own organization (§7), and the CLI runs as the adopting administrator, who has
neither the credentials nor any business writing there.

The entry is written when the administrator **connects** in the portal — an
explicit act, not a side effect of installing an App:

```
1. dracla install github.org=acme-cla    repos exist, owned by the adopter
2. install the two Apps                  GitHub consent; the Setup URL callback
                                         records each installation_id as
                                         unclaimed
3. portal: Connect                       the administrator authenticates,
                                         DraCLA verifies they administer the
                                         org the slug names, the org holding
                                         the records, and the owner of every
                                         scope entry (§7), and that both Apps
                                         are installed on repositories of the
                                         right shape, then writes the entry
                                         with a binding record per scope
                                         entry (§7)
4. same session: configure               recipient, scope, privacy policy,
                                         required fields — and publish the
                                         agreement (§6.5)
```

Making this deliberate rather than automatic is what allows the slug claim of §7
to be verified at all. An entry created as a side effect of an App installation
cannot establish that whoever claimed `acme` administers `acme`, which is the
look-alike-portal attack §7 exists to prevent. A connect step can, because there
is an authenticated human whose organization permissions can be checked.

The install links carry no token, and the callback is trusted for nothing:
connect lists the administrator's installations from GitHub and verifies them
there, so an App installed straight from its GitHub page — no CLI-printed
link involved — connects identically.

R5's "registry entry written last" therefore still holds, and holds more
strongly: the project is not routable until someone has proved they own it.

**Install never produces a signable project, by design.** Configuration and
agreement publication happen in the portal, so install finishes by directing the
operator there rather than implying the project is ready. An earlier
implementation exited successfully and printed a portal URL after provisioning
nothing signable; separating the two operations removes that confusion rather
than patching it.

#### 6.10.4 A dedicated organization is required

Install provisions both repositories into an organization created for this
purpose — `<org>-cla` by default — never alongside the project's code.

```
acme            the project: contributing repositories
acme-cla        records and coverage, both private
```

This is a requirement rather than a recommendation because the alternative
cannot be made safe. GitHub base permissions are a **floor**: repository
settings can raise a member's access and never lower it, and there are no
negative permissions. So an organization whose default is `read` exposes signer
names and email addresses to every member, and **nothing can be done about it at
the repository level**. Earlier drafts warned and offered to proceed; that
offered the operator a remedy that does not exist.

A dedicated organization removes the problem instead of reporting it. Base
permission there governs only the people who administer the CLA, which is the
set that should have access anyway.

**Who belongs in it.** With the base permission at `none` (below), it is
**ownership** of the dedicated organization that carries access, not membership:
`default_repository_permission` governs what *members* get by default, while
owners hold admin on every repository in the organization and that cannot be
lowered. So the owner set is the access control that matters once install is
done, and it should be the people who would use that evidence if the agreement
were tested — the legal recipient (`REQ-CONFIG-2`), their counsel, and whoever
administers agreement versions (§6.8) — not the project's maintainers by
default. Being a committer is not a reason to see who signed and with what
address, and `REQ-SEC-6` derives dashboard access from the ability to read the
records repository, so the owner set is the **floor** of that permission — the
part that cannot be lowered. It is not the whole of it: a team granted read
(below) joins the same set, and with it the dashboard and §6.3's named-subject
tier.

**When more people need access than should be owners**, grant a team read on
the records repository rather than adding owners or raising the base
permission. Ownership carries administrative control of the whole organization,
which is far more than reading signer data requires, and raising the base
permission re-opens exactly what §6.10.4 exists to close. A team is the only one
of the three that grants the access without granting anything else:

```
gh api -X PUT /orgs/<org>/teams/<team>/repos/<org>/<slug>-cla-records \
  -f permission=pull
```

Install does not create that team. Who should read signer data is not a
provisioning decision, and creating it would need permissions install otherwise
has no use for.

Install cannot enforce this and does not try; it states it at the moment the
organization is chosen, which is when the decision is actually made.

**Both repositories, not just records.** Keeping coverage in the project's
primary organization is tempting — it would give the enforcer a single
installation — but the coverage projection is a complete
`user_id -> covered?` directory. Exposing it to every member of a large
organization is a smaller leak than exposing names and emails, but it is the
same kind, and `REQ-PORTAL-5` forbids exactly that lookup. "No signer-derived
data in the permissive organization at all" is a cleaner invariant than "only
the booleans leak".

The cost is that `dracla-enforcer` spans two organizations — contributing
repositories in one, coverage in the other — and therefore has two installation
ids. §7 models installations as a set for this reason.

**What install does about it**

Install checks the dedicated organization's base permission and refuses if it is
not `none`, with the one-line fix. There is no override, because in an
organization created for this purpose there is no legitimate reason to decline:

```
gh api -X PATCH /orgs/acme-cla -f default_repository_permission=none
```

A personal account is an accepted shape, not an exemption. A user account has
no organization, no membership, and no base permission: a private repository
there starts with exactly one reader, which is the property the dedicated
organization exists to create. It fits a single-maintainer project; the moment
anyone else needs to read the records, the dedicated organization applies in
full.

**Encryption was considered and rejected.** Encrypting signer fields would hide
them from members with `read`, and `REQ-SEC-2` permits it as an option. It fails
on key custody. Any key must be unreachable by those members yet reachable by
the reconciler, which runs unattended; Actions secrets satisfy both until the
derived artifacts are considered, because `derived/export.json` and the
dashboard index carry legal names and live in the same repository. Encrypting
those too puts the key in the Worker, and in the hosted deployment that means
the operator holds every adopter's key. Either the encryption is pointless or
the custody is worse than what it replaced.

Underneath: unattended automation cannot hold a secret away from whoever
administers the machine it runs on, and a CLA system needs unattended replay.
Key loss would also destroy records whose entire purpose is to remain provable
years later — a failure mode that does not currently exist.

#### 6.10.5 Module boundaries

The removed implementation reached through `GitHubHost` into its private
transport at six call sites, because the `GitHost` protocol (§5.2) models
append-only records and says nothing about creating repositories or reading
organization settings.

Administration is therefore its own surface — repository creation, visibility,
deploy keys, organization settings — separate from the records protocol and
substitutable in tests. Nothing in the CLI mutates `sys.path`; `core` is a
sibling package in the same distribution.

#### 6.10.6 What the tests must cover

The four blocking findings were all **seams**: modules individually plausible
and never exercised together. The workflow template passed five tests while
invoking a subcommand that did not exist. Unit coverage would not have caught
any of them, so these properties are asserted across modules:

- every `dracla` subcommand a generated artifact invokes is registered
- `dry_run=true` issues no write of any kind
- everything the reconciler reads is seeded on the branch it checks out
- a created repository is read back and confirmed private
- the organization gate blocks, and there is no override past it — including
  under `dry_run` and `force`, neither of which is a way through it

---

## 7. Multi-tenancy and isolation (`REQ-OPS-6`)

One shared stateless deployment serves all projects; no function per project.

```
dracla/dracla-registry            <- its own repository, not a monorepo dir
  project: acme
    records:  acme-cla/acme-cla-records      <- dedicated org (§6.10.4)
    coverage: acme-cla/acme-cla-coverage
    scope:                                   <- the CODE repos
      - entry: acme/*
        bound_by: 552883       # user id of the verified administrator
        bound_at: 2026-08-18T…
        basis: administers acme, checked at bind
      - entry: acme-labs/widget
        bound_by: 552883
        bound_at: 2026-08-19T…
        basis: administers acme-labs, checked at bind
    installations:
      records:  [ … ]        # a set, not one id — see below
      enforcer: [ … ]
    claimed_by_org: acme
    claim_verified_at: 2026-08-18T…
```

**The registry is its own private repository.** D2's argument applies to it
directly: tokens cannot be path-scoped, so a credential able to write
`registry/` inside the monorepo could also write `api/` and `core/` — making
security-critical routing data writable by anything that can touch the
codebase. It also must not be public, since it enumerates every adopter, their
private repository names, scope, and installation ids. `CODEOWNERS` and required
review apply to it.

**Slug claims are verified and immutable, at connect time.** The claim is
established when an administrator connects in the portal (§6.10.3.1), not as a
side effect of installing an App — that is the only point at which there is an
authenticated human whose organization permissions can be checked. A slug may
only be claimed by someone who administers the organization it names — which is
the **project's** organization, not the dedicated records one. The two are
different (§6.10.4), and both are checked, for different reasons: the slug names
the project because that is the name a contributor sees in a signing URL and so
the name worth impersonating, while the dedicated organization is merely where
the repositories were put. Claiming `acme` therefore requires administering
`acme`, whatever the records live in.

**What a scope entry means.** An entry in a project's scope routes that
repository's pull requests to this project — a repository in no project's
scope receives no check at all — names this project's agreement as the one
its contributors are asked to sign, and directs their signatures into this
project's records repository. It grants the project no access to the
repository: every permission comes from the enforcer installation, which the
repository's organization controls and can restrict or remove. And it blocks
nothing by itself — merges are gated only once that repository's own
administrators make the check required. Coverage is evaluated against the
scope **recorded with each acceptance** (§6.3), so the project's current scope
decides which repositories are checked, while each signature covers only the
scope that existed when it was given — widening later never stretches consent
retroactively. An entry is therefore effective only where three consents meet:
the organization installed the enforcer, an administrator of the owner bound
the entry (below), and the repository's administrators required the check.

**Scope is bound by the same authority** — required by `REQ-CONFIG-5` since
baseline revision 3, which this section implements. A scope entry is `owner/name` or
`owner/*`; the owner segment is a literal account name, and anything else is
rejected at write — a wildcard owner would leave no one to verify. Binding an
entry requires **administering its owner**, verified at connect and again for
every entry added later; removals need no owner check, since a project may
always narrow itself. Each verification is **recorded attributably in the
entry itself**: every scope entry carries `bound_by` — the numeric user id of
the administrator whose owner-administration was verified — with `bound_at`
and the basis checked, written by the portal in the same registry commit that
adds the entry, so connect records the initial set and every later widening
records its own (`REQ-CONFIG-5`). Removals are ordinary registry commits and
record no consent, because narrowing needs none. An `owner/*` entry is standing consent for present and
future repositories — the same semantics as installing an App on all
repositories — and the organization keeps two continuing controls regardless:
the enforcer installation itself, whose coverage every scope entry requires
and which the org can restrict or remove unilaterally, and per-repository
required-check configuration, without which nothing blocks. Without the owner
check, anyone whose installation access merely *covered* an unclaimed
repository could bind it into their own project and have the App direct that
repository's contributors to sign their agreement at a genuine portal — the
same attack this section closes for slugs, through the side door.

The cost is deliberate and recorded: a federated project whose scope owners
share no single administrator cannot be configured in v1. The pathway for it
is per-org co-confirmation — the owner's administrator approves the binding
from their side — which is real machinery deferred rather than a gap: the
alternative shipped today would be the unverified binding above.

Every org and repository in `scope` must be covered by the enforcer
installation, and claims are first-come and never transferred silently.
First-come is enforced by the write, not by a scan: the portal lands registry
commits under the same fast-forward CAS discipline as §5.2, and a claim that
loses the race re-validates against the new head and fails because the slug
is taken. Without this, self-serve install plus a user-chosen slug
lets an attacker claim `acme` and operate a look-alike signing portal on the
legitimate domain, under a genuine OAuth consent screen, collecting real legal
names and emails into their own repository. §7's token/repo binding rule cannot
catch that on its own, because a poisoned entry naming the attacker's own
installation and repositories is internally consistent.

**Runtime lookup.** The repository is the source of truth; Workers KV is the
runtime index the handlers actually read, because fetching the registry from
GitHub on every webhook would spend a subrequest and CPU on the hot path, and
bundling it at deploy time would require a redeploy per adopter.

To keep KV genuinely derived rather than the de facto authority:

- Entries carry a generation counter and are **signed with a key held in
  Worker secrets**; the Worker verifies the signature and rejects an entry it
  cannot verify. That defends against a principal that can write KV but cannot
  read Worker secrets — a leaked KV API token — and deliberately not against
  Worker compromise, which §8.3 already owns.
- The KV write is driven from a verified registry commit, never directly from
  the install request handler: the registry repository's push webhook wakes a
  dedicated registry-sync route on the Worker, which verifies the delivery
  signature, discards the payload, and re-reads the changed entries from the
  repository over the GitHub API — the webhook is a doorbell, the repository
  is the source — then signs each entry with the key in its secrets and
  writes KV. The reconcile schedule drives the same handler over the full
  registry.
- The reconcile schedule re-derives KV from the repository and repairs drift,
  the same rule the coverage projection follows (`REQ-REC-6`).
- Offboarding deletes the KV entry explicitly; deleting the repository entry
  alone would leave the shared Worker routing for a departed project.
- Rate-limit counters live in a **separate** KV namespace from routing, since
  per-request counters are not rebuildable from git and would otherwise falsify
  the derivation claim.

Isolation rules:

- Every request resolves to exactly one project before any repo access.
- Repo handles come from the registry entry, never from request input.
- The installation token used must belong to **one of** that project's
  installations; a token/repo mismatch is a hard failure, not a fallback.
  Plural because coverage and contributing repositories always live in
  different organizations: §6.10.4 *requires* the dedicated one, so this is the
  standard shape rather than a recommendation for a bad case, and a GitHub App
  installed on two organizations has two installation ids.
- A contributing repo in no project's scope receives no check.
- **Every authorization decision is scoped to the resolved project**, and no
  authorization result is cached across projects. A session carries identity
  only; an `authorized: true` flag reused across a tenant boundary is the most
  likely way to build a cross-tenant read, so authorization is recomputed per
  project per request.
- Scopes across projects must not overlap. A contributing repository resolving
  to two projects is a configuration error rejected at registry write, not a
  precedence rule at request time.

**Multiple recipients in one org share an installation.** §5.5 separates repo
pairs per legal recipient, but the administrator installs `dracla-records` at
org level, so one installation token can reach both pairs and their separation
is software-only — the arrangement D3 exists to reject. This is an accepted
limitation of the hosted model, not a solved problem: GitHub does not offer two
installations of the same App on one org. A project that needs the separation
enforced by credentials rather than code must self-host a second deployment with
its own App. Stated here because §5.5's rationale — keeping one entity's
administrators away from another's evidence — is weaker than it appears at the
credential layer.

Migration to self-hosting is a no-op for records: the project revokes the
shared Apps, installs its own, and points them at the same repositories, which
never moved (`REQ-OPS-6`).

---

## 8. Security model

| Concern | Mechanism | Req |
|---|---|---|
| Signer PII exposure | Projection carries no names or addresses (unconditional; its personal-data position is §8.4); enforcer not installed on canonical (org-controlled, asserted by the reconciler — §4) | `REQ-SEC-2` |
| Session state | Short-lived **encrypted** (AEAD) cookies with `kid`; no application database | `REQ-OPS-2`, `REQ-SEC-4` |
| CSRF / replay | Single origin, `__Host-` prefix, `SameSite=Lax`, browser-bound single-use OAuth `state` (§8.2, §9) | `REQ-SEC-4` |
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
| 7 | **Budget exhaustion** — burning the shared daily ceiling | Per-project rate accounting keyed by user ID; WAF rate limiting; split routes (§9); risk R7 |
| 8 | **Clickjacking** the accept button — defeating `REQ-SIGN-2`'s affirmative action by UI redress | `frame-ancestors 'none'` and `X-Frame-Options: DENY` on the portal, delivered by whichever origin serves the portal assets (§9); the agreement itself renders in a sandboxed frame the portal owns (§9) |

### 8.1.1 Principals beyond the contributor

The table above models only the authenticated contributor. Three further
principals exist and were previously unmodelled:

**Hostile tenant.** Self-serve install creates one for free: anyone can claim a
project and supply agreement markup that the portal renders. On a shared origin
that converts "project admin supplies HTML" from a self-inflicted risk into a
cross-tenant one, reaching every other tenant's session. Controlled by rendering
agreement content on a separate cookieless origin in a sandboxed frame (§9), by
verified slug claims (§7), and by allowlist sanitization plus CSP as defense in
depth rather than as the boundary.

**Compromised Worker.** Covered in §9's two-Worker split; the residual is
stated in §8.3 rather than claimed away.

**DraCLA operator.** Fully trusted in the hosted deployment. See §8.3.

### 8.1.2 Credential and webhook handling

**Webhook verification** (`REQ-SEC-5`). The signature is verified **before** the
body is parsed or routed, using constant-time comparison, with a per-App secret
selected by the receiving route — a single route that tries both secrets would
let the records App's secret inject `merge_group` events. `sha1=` signatures are
rejected. Deliveries are deduplicated on `X-GitHub-Delivery` and rejected
outside a bounded age window; GitHub signatures carry no timestamp or nonce, so
a captured delivery is otherwise replayable forever.

**Cached installation tokens** carry `contents: write` on a project's PII repo.
They are encrypted at rest in KV, namespaced per project, and their KV keys are
derived from registry-resolved values only — never from request input.

**Coverage deploy key rotation** (`REQ-SEC-9`). The deploy key seeded into canonical's Actions
secrets is the one credential that writes the projection outside the App
boundary D3 establishes, and deploy keys do not expire. It is rotated on a fixed
schedule and on any maintainer offboarding, and the reconciler fails loudly if
its key is older than the policy window. Note also that anyone with **write** on
canonical can push a workflow that exfiltrates it — a routine maintainer grant
therefore confers the ability to forge the project's enforcement decision, which
adopter documentation must state. Repo *settings* secrets are not repo
*contents*, so this does not breach `REQ-SEC-4`'s prohibition on storing secrets
in records repositories; the distinction is deliberate and recorded here.
Rotation itself is the **project administrator's** act: DraCLA deliberately
holds no credential that can touch an adopter's settings (§4), so the portal
action that created the key (§6.10.2) is re-run to mint and stage a
successor, and the reconciler consumes it on its next run.

**The other long-lived credentials** — `REQ-SEC-9` obligates every one DraCLA
provisions or requires, not only the deploy key:

| Credential | Holder | Rotation | Departure response | Reach if leaked |
|---|---|---|---|---|
| Coverage deploy key | Adopter canonical Actions secrets | Administrator re-runs the portal key action (§6.10.2); fixed schedule, or on offboarding | Adopter **maintainer** departure rotates it (above) | Forge one project's coverage, hence its merge gate |
| App private keys, both Apps | DraCLA operators | GitHub Apps hold two keys concurrently: add successor, redeploy, revoke predecessor — no downtime | DraCLA **operator** departure rotates both | Mint installation tokens for every adopter |
| Webhook secrets, per App | App config + Worker secrets | Stage the new secret beside the old on the same App's route, update App config, drop the old — two secrets of one App on its own route, so the rule above against a single route trying both *Apps'* secrets is untouched | Operator departure rotates both | Forge webhook deliveries to that App's route |
| KV entry signing key | Worker secrets | Rotate the secret, then the reconcile schedule's full re-derivation re-signs every entry (§7) | Operator departure rotates it | With a KV write path, forge routing entries |

The last column is the reach documentation `REQ-SEC-9` requires; the deploy
key's fuller statement — what a holder could forge and that write on
canonical can exfiltrate it — stands in the paragraph above.

**No OAuth scopes are requested, and no scope tiering exists.** An earlier
draft proposed minimal scopes for contributors and elevated `repo` scope on
demand for dashboard viewers. That is not implementable: `read:user`,
`user:email`, and `repo` are **OAuth App** scopes, and GitHub *App*
user-to-server authorization has no `scope` parameter — permissions are fixed
at App configuration and apply to everyone who authorizes it. There is no
incremental escalation for a GitHub App.

The fallback would have been worse than the risk it named. Verifying read access
to a **private** records repo requires `repo` scope, which is read *and write*
to every private repository the user can access — so the Worker would accumulate
full-write tokens from exactly the high-value accounts (maintainers), and any
curious contributor clicking the dashboard link would be shown a full-write
consent screen for all their private repositories.

`REQ-SEC-6` is instead satisfied with the credential model already chosen: a
**user-to-server token from `dracla-records`** against
`GET /repos/{owner}/{repo}` for the registry-resolved canonical repo of the
requested project. That returns 200 only when the installation **and** the user
both have access, which is precisely the required semantics, and needs no
elevated scope at all (§6.6).

### 8.2 How browser authentication reaches the writer

```
Worker               issue nonce N; set __Host-preauth cookie = H(N)
browser -> GitHub    OAuth authorize, state = signed{ N, project, pr, return }
GitHub  -> Worker    callback: code + state
Worker               verify state signature AND H(state.N) == preauth cookie
                     single-use: delete the preauth cookie      <-- binds to
                                                                    THIS browser
Worker  -> GitHub    code + client secret (server-side)   -> user token
Worker  -> GitHub    GET /user  -> { id, login }             <-- trust created
Worker               mint NEW session cookie (rotate; no in-place upgrade)
browser -> Worker    POST /sign + cookie
Worker               verify cookie; subject read FROM COOKIE, never body
Worker  -> GitHub    installation token (RS256, KV-cached); commit event
```

**`state` must be bound to the browser, and PKCE is not available.** GitHub
does not implement PKCE for OAuth Apps or GitHub Apps; an earlier draft listed
it in this chain, which was false assurance. That matters because §6.1 also
carries pull request context in `state`, which pushes an implementer toward a
Worker-signed blob — and a Worker-signed value proves only that *the Worker*
issued it, not that *this browser* began the flow.

Without the nonce-cookie binding, the attack is: the attacker starts the flow
for **their own** account, does not complete it, and sends the victim the
callback URL. The Worker exchanges the code, reads the attacker's identity, and
mints a session for the attacker's account in the victim's browser. The victim
then signs in good faith, and an acceptance is committed carrying the
**attacker's** user ID with the **victim's** real legal name and email —
append-only and unremovable, and precisely the opposite of what this section
claims the record attests. The `return` path is additionally validated against
an allowlist so the same channel is not an open redirect.

GitHub's assertion is converted into a token the Worker itself signed, so the
browser never carries identity as data it can influence. The Worker, not the
contributor, is the author of record; the commit history is the attestation
chain.

**What the record attests** is precisely: *the Worker observed a
GitHub-authenticated session for user N submitting explicit assent to agreement
X at time T.* Not that the contributor cryptographically signed anything. The
evidence fields of `REQ-SIGN-4` are scoped to that claim.

**Session state.** The cookie is **encrypted** (AEAD), not merely signed, and
carries a `kid` so keys can be rotated without either mass logout or accepting a
revoked key. The user access token is **not** in the cookie — a signed-only
cookie carrying a GitHub token would put it in browser-readable storage, which
`REQ-SEC-4` forbids outright. It lives in Workers KV keyed by `jti` with a
matching TTL. That KV entry is also what makes `jti` mean anything: an
identifier bounds replay only against a store of live sessions, and without one
the earlier draft's claim was decorative. Logout deletes the entry, which is the
only session invalidation the design previously had at all.

**Decay, and where it is not acceptable.** The cookie is a cached assertion, so
a revoked OAuth grant does not invalidate it. `REQ-SEC-6` requires
administrative access be derived from **current** authorization, and a 15–60
minute cached verdict is not current — one request in that window pulls the
whole dashboard index. So the index proxy does **not** rely on the cookie for
authorization: it re-checks repo read against GitHub on every request (§6.6).
The cookie establishes identity only. Actions requiring re-verification are
enumerated, not left to judgement: **sign, revoke, any admin or override event,
and any dashboard read**. Everything else tolerates the TTL.
`REQ-VERIFY-2`'s loss-of-authorization scenario therefore has a concrete pass
criterion: dashboard access must fail on the first request after revocation, and
signing and revocation on the first attempt.

**Optional hardening, and its limit.** For projects wanting non-repudiation
beyond OAuth, GitHub publishes users' signing keys
(`/users/{login}/ssh_signing_keys`, `/gpg_keys`), so a CLI-produced signed
acceptance could be verified against a binding GitHub already vouches for. Not
the core flow: browsers cannot reach those private keys, and `REQ-PORTAL-1`
requires an in-browser accept flow. Note the endpoint is **login-keyed** and
GitHub releases logins when accounts are deleted, so verification must re-derive
the login from the pinned numeric ID at check time, never trust a stored login.

**No decision keys on login, ever.** `REQ-SIGN-1` makes the numeric ID primary
and `login_snapshot` historical, and that rule extends past the envelope to
every surface: legacy `<login>@users.noreply.github.com` addresses must not be
resolved by login lookup; the dashboard and exports render `login_snapshot`
only alongside the numeric ID and its capture date (§6.6). Otherwise a recycled
login misattributes a legal instrument to a different human — the failure a CLA
system exists to prevent.

### 8.3 Trust model

Per `REQ-REC-4`: repository administrators are trusted. DraCLA never
force-updates or deletes canonical history and documents that it cannot detect
rewriting by an administrator controlling both the repository and every backup.

**In the hosted deployment the DraCLA operator is also fully trusted.** An
earlier draft claimed the opposite — that because records live in the adopter's
org the trusted administrator is the adopter, not the operator. That is false on
this design's own terms. Repo custody is not key custody: `dracla-records` holds
`contents: write` on canonical and the operator holds its private key. The
operator can therefore read every signer's name and email across all tenants and
append events that are **byte-indistinguishable** from genuine ones — the Worker
is the sole author of the attestation chain, there is no contributor
counter-signature and no external checkpoint, and the reconciler will faithfully
replay a forged event into coverage. `REQ-REC-4` waives detection of
administrator *rewriting*; it does not waive operator *forgery of new events*,
which is a different and unmitigated threat.

Concretely, hosted adopters trust the operator for signer confidentiality,
evidence integrity, and merge-gate integrity. **Self-hosting is the only
configuration in which that is not so**, which is what product principle 6 is
actually buying. §8.2's "the commit history is the attestation chain" should be
read with this bound: it attests against non-administrator, non-operator
tampering.

Independent event signatures and external checkpoints remain available as the
optional future hardening `REQ-REC-4` anticipates, and they are what would
narrow this.

### 8.4 Data protection

DraCLA collects legal names and email addresses, which are personal data. This
section states the design's position so an adopter's counsel has something to
assess. It is not legal advice, and the lawful basis is the adopter's to
determine.

**Roles.** The adopting project — specifically the legal recipient named in
`REQ-CONFIG-2` — is the **controller**: it decides why the data is collected and
what happens to it. In the shared hosted deployment the operator is a
**processor**, because a contributor types their name into the operator's Worker
before it reaches the adopter's repository. `REQ-SEC-2` anticipates this ("a
hosted serverless endpoint MAY process signer data transiently but MUST NOT
retain it outside the project's records repository") without naming the
relationship it creates: a processing agreement between operator and adopter.

Self-hosting removes the processor entirely — the adopter is controller and
operator both. That is a substantive reason to self-host beyond the trust
argument of §8.3.

**Erasure, and why the records are append-only anyway.** `REQ-REC-3` makes the
records append-only — a rule DraCLA enforces, not a physical impossibility
(§8.3 bounds it) — which collides directly with a right to erasure. The design's position is that a CLA record is retained for the
establishment, exercise, and defence of legal claims — the agreement exists to be
provable years later, possibly in a dispute — and that this is what the common
exemption for such processing is for.

Two things follow, and both are already in the design rather than bolted on:

- Revocation exists and works (§6.2). A contributor can withdraw coverage for
  future contributions at any time; what they cannot do is unmake evidence of a
  grant already made.
- `REQ-SEC-7` requires both the signing and revocation flows to say that
  evidence is retained afterwards, so this is disclosed before consent rather
  than discovered later.

An adopter whose counsel disagrees cannot be accommodated by configuration: the
append-only record is the product. That should be known before adoption, not
after.

**Minimization.** `REQ-SEC-1` collects only fields the agreement and project
policy require, and forbids collecting an IP address merely because a workflow
can observe it. Rate limiting keys on GitHub user ID rather than IP for the same
reason (§8.4.1).

**The coverage projection.** It carries no names or email addresses, which is
what lets the enforcement path answer without reading them (§5.3). It is not
free of personal data, and its privacy does not rest on secrecy — per-subject
coverage is already disclosed publicly. DraCLA writes a check run on the pull
request, and on a public repository that conclusion is world-readable. A
sole-author pull request therefore already reveals its opener's coverage, and
§6.3 documents how a crafted pull request can make anyone a subject.

What privacy protects is **aggregation**. A check run discloses one subject at a
time, only for people who opened a pull request, and only to someone willing to
crawl and correlate. The projection discloses every user against every agreement
in a single fetch, and it is a *superset*: someone who signed early and never
contributed, or who signed and never opened a pull request, appears only there.
It also carries fields no check run exposes — `reason`, `since`, `scope`,
`pending_version`, `pending_effective_at`, and for exemptions `kind`, `basis`,
`instrument_ref`, and `asserted_by`.

That is the recognised aggregation harm: individually available facts become a
different exposure once assembled. It is also what makes §5.3's enforcement rule
principled rather than arbitrary — probe one subject at a time, never enumerate.

**This does not weaken `D2` or `D3`.** Their rationale is what the enforcement
credential can *reach*, not what the projection *contains*. Names, email
addresses, confirmation text, and entity evidence remain absent from coverage,
and that absence is the whole of what the two-repository split rests on.

**Considered and rejected.**

*Moving the projection into canonical*, so there is one repository. GitHub
permissions are per repository with no path scoping, so `dracla-enforcer` — a
public App anyone can install — would gain read on `events/**` and
`derived/export.csv`. That is the mirror image of the rule already stated at
§5.1, and it trades an aggregation exposure for a direct PII one.

*Row-level encryption of the projection* — HMAC-derived shard and row keys,
per-row AEAD, key in Worker secrets. Rejected on cost rather than soundness.
§6.10.4 already closes the live-ACL threat by requiring a dedicated
organization, and the key must also live in canonical's Actions secrets for the
reconciler, so it does not defend against the write-on-canonical population the
deploy key already exposes. The residual benefit is leaked clones and backups
only, bought with a new secret, generation tags in shard files, and history
truncation. Worth recording: rotation would have been cheap, because the
projection is derived and rotating is just a rebuild — that did not carry the
cost.

The tier difference is accepted deliberately: the projection is less protected
than canonical, and that is proportionate, because per-subject coverage is
already disclosed by every public check run. What its privacy protects is the
aggregate (above); names and addresses are not in it at all.

*Encrypting canonical records* to remove the need for a dedicated organization.
Rejected: key revocation is impossible against an append-only log
(`REQ-REC-3`), so a departing administrator keeps the ability to decrypt
permanently, where removing them from the organization is instant. `REQ-SEC-6`
also derives dashboard access from the ability to read the records repository,
which encryption breaks.

**Where the data lives.** Canonical records sit in a private repository in a
dedicated organization the adopter owns (§6.10.4), on GitHub. The portal and
enforcement tiers run on Cloudflare. Both are US-headquartered, so an adopter
subject to transfer rules assesses that against their own obligations; DraCLA
adds no further destination, and adds no storage of its own.

**Breach.** The organization-permission gate (§6.10.4) exists partly here: an
organization default that lets every member read signer names and addresses is
not merely untidy, it is personal data exposed to people with no need for it,
which is the kind of thing that becomes reportable. That is why install refuses
rather than warns.

**Subject access.** A contributor can see their own record through the portal
(`REQ-PORTAL-1`). An adopter answering a broader request has `dracla export`
(§6.9) and the records repository itself, both readable without DraCLA
(`REQ-REC-5`).

### 8.4.1 Observability (`REQ-OPS-5`, `REQ-SEC-2`)

Signer PII passes through the Worker in the sign request body, so the default
posture of every observability tool is the risk. `REQ-SEC-2` forbids signer data
in logs; meeting it requires explicit configuration, not restraint in DraCLA's
own log statements:

- Request-body logging, `wrangler tail`, Logpush, and any error-reporting
  integration must exclude the sign and revoke request bodies. A default-on
  integration violates `REQ-SEC-2` without DraCLA writing a single log line.
- OAuth callback query strings carry `code` and `state` and must be scrubbed
  from access logs (`REQ-OPS-5` forbids credentials in logs).
- The reconciler runs inside the repo where PII legitimately lives; its logs are
  the most likely accidental leak path and must emit identifiers only.
- Correlation IDs propagate Worker → GitHub API → reconciler so a failed event
  can be traced end to end without carrying any field value.

**Data minimization** (`REQ-SEC-1`). Collected fields derive from
`config/project.json` (§5.1); nothing is stored because a workflow could observe
it. Rate limiting (§8.1 #2, #7) is implemented with counters keyed by GitHub
user ID rather than by IP, so the "MUST NOT collect an IP address merely because
a signing workflow can observe it" rule is not defeated by its own mitigation.

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
export logic lives in the Python core running in Actions, and §5.3's `decision`
field is precomputed so the edge compares scope and reads a boolean rather than
re-implementing the rule engine. This keeps the platform replaceable
(`REQ-OPS-2`).

**Single origin.** The shell and the API are served from **one origin** per
deployment — the Worker serves the static assets, or Pages with Functions.
Pages and Workers on separate origins would make the index fetch a credentialed
cross-origin request, forcing `SameSite=None` (deleting the CSRF control in §8's
table) and a CORS policy whose usual implementation reflects `Origin` with
credentials — turning any page a logged-in records reader visits into a
drive-by read of the dashboard index, and any page at all into a forced
acceptance, which fabricates a legal grant. Cookies are `__Host-` prefixed,
`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, with no `Domain` attribute.

**Agreement content renders on an isolated origin.** Tenants supply agreement
markup and the hosted deployment is self-serve, so a hostile tenant is a
principal the install flow creates for free (§8.1). Agreement content is
rendered in a sandboxed frame on a separate cookieless origin, so a sanitizer
gap cannot reach the session cookie or same-origin API of any other tenant.
Allowlist sanitization and CSP remain, as defense in depth rather than as the
boundary.

**Worker isolation.** One deployment holding both App private keys, the session
key, the OAuth client secret, and every webhook secret means a single Worker
compromise defeats the §4 split entirely — the attacker simply uses the other
key, and the highest-value payload is forging `success` on authoritative
merge-group checks across all adopters. The deployment is therefore split into
**two** Workers with disjoint secret bindings:

```
worker-enforce    webhook secret + enforcer App key + coverage read
                  most exposed (anonymous internet), least privileged
worker-portal     OAuth client secret + session key + records App key
```

There is no third Worker because there is no third App: provisioning runs in the
CLI on the administrator's machine (D11), so no isolate holds
`administration`/`workflows`/`secrets` write. The install-flow routes that remain
in `worker-portal` only record installation ids arriving on the Setup URL
redirect, which needs no privilege.

This does not make compromise harmless — `worker-portal` still reaches signer
PII — but it stops the most exposed surface from holding the keys that forge the
merge gate, which the single-isolate design did not.

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
- **CPU — comfortable, measured.** Workers bill CPU rather than I/O wait, so
  awaiting GitHub is free. The check path was measured in workerd on 18 August
  2026 (`api/bench/`): a typical 10-commit pull request costs **0.26 ms**, a
  100-commit one **0.50 ms**, and the worst case — 250 commits, the GitHub
  pagination ceiling, with a cold key — **1.26 ms**, or 13% of the budget.
  Earlier drafts called CPU the binding constraint on Free; that was wrong.
  KV token caching is still worth doing to spare GitHub's rate limits, but it is
  not load-bearing for CPU: cold minting costs about 0.4 ms.

  Read those figures as an estimate with a known bias: workerd is the production
  runtime, but it ran on a development machine, not Cloudflare's edge hardware,
  and they exclude isolate startup and Cloudflare's own CPU accounting. A
  pessimistic 2.5x correction for slower edge silicon still lands near 3.2 ms.
  The conclusion holds because the headroom is an order of magnitude, not
  because the figure is precise.
- **Requests — a ceiling shared across all tenants** in the hosted deployment.
  At roughly 4–8 webhook deliveries per pull request, 100,000/day admits on the
  order of 10⁴ pull requests per day across all adopters combined (risk R7).
- **Actions minutes are metered where the reconciler runs.** §2's "Actions
  minutes are free on public repos" is true and irrelevant here: the reconciler
  runs inside the **private** canonical repo, on every push and on its schedule,
  where GitHub Free meters minutes (2,000/month). Each signature triggers a
  replay, index, and export job. This is a real Free-baseline constraint that
  A3 must budget — keep the reconciler's ordinary path incremental rather than a
  full replay, and reserve full replay for the scheduled pass and for repair.

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
webhooks and let a pull request proceed with no CLA evaluation at all. Routes
MUST be configured **fail closed**, so GitHub retries delivery.

**But be accurate about what exhaustion looks like.** An earlier draft said the
check "remains `queued`". That holds only if a check run already exists. If the
Worker never ran for `pull_request.opened`, **no check run exists** — absent,
not queued. A required-but-absent check does block the merge queue, which is the
safe direction, but it shows the contributor nothing, offers no retry
affordance, and does not self-heal: GitHub's redelivery retries are finite and
`check_run.rerequested` routes to the same dead Worker. The reconciler runs in
Actions, unaffected by the Worker budget, and its scheduled pass (§5.4) detects
in-scope pull requests with no check and creates one carrying the *temporarily
unavailable* state and its retry text. That is what makes `REQ-CHECK-5`'s
explanation requirement satisfiable during a total edge outage.

**Exhaustion is reachable by an outsider, and this is the sharpest availability
risk in the design.** `dracla-enforcer` is a public App, so anyone can install
it on a throwaway org and script pull request churn; and every request counts
against the per-account cap whether or not its webhook signature verifies. With
fail-closed routing that halts checks *and* signing *and* revocation for every
adopter — so the documented remediation ("sign, and the check re-evaluates")
is down at the same moment, and the portal revocation capability `REQ-REV-1`
requires is unavailable for the duration. "Per-project rate accounting" cannot help, because the
exhausted resource is per account and the offending traffic belongs to no
project. Controls: Cloudflare WAF and rate limiting in front of the routes,
signature verification at the very edge, and the §9 route split so exhausting
the webhook surface does not take the portal down with it. Risks R7 and R9.

**Default adoption path.** Shared DraCLA-operated serverless deployment
(`REQ-OPS-1`), with records in the adopter's own org (`REQ-OPS-6`).

```
1. admin runs:  uvx dracla install github.org=<org>-cla   (own credentials)
     -> one argument: the DEDICATED org (§6.10.4). No prompts for recipient,
        agreement, or scope — those are portal actions (§6.10.3)
     -> refuse unless that org's base repository permission is `none`
     -> create <slug>-cla-records and <slug>-cla-coverage, both private and
        both created empty; `events` becomes the records repo's first ref and
        so its default branch, and the coverage projection is initialized on
        its own `coverage` branch (§5.3)
     -> seed the reconcile workflow. No config, no agreement, no deploy key:
        the key waits for the reconciler that consumes it (M2, §6.10.2)
     -> print the two App install links

2. admin clicks:  install dracla-records            (GitHub's own consent UI)
     -> GitHub redirects to the Setup URL, which records the installation_id
        as UNCLAIMED — it writes no registry entry

3. admin clicks:  install dracla-enforcer  on the repos in scope
     -> same redirect; still unclaimed. The slug claim is established at
        connect (step 4), not as a side effect of installing an App (§7)

4. admin connects in the portal: recipient, agreement, scope, policy text
     -> each becomes an event with an actor
     -> the registry entry is written here, last, so a half-provisioned
        project is never routable (R5)
```

**Why the installation links rather than an API call.** A GitHub App cannot
install another GitHub App; installation is a user action through GitHub's own
UI. Offering the link is therefore not a workaround but the intended flow, and
it is better than anything DraCLA could build: GitHub owns the consent screen,
the repository picker, and the permission display. The link needs no privilege
to offer — it is an anchor.

**Why provisioning is the CLI and not a third App** (D11): provisioning needs
`administration` and `workflows` write on the adopter's organization, and
`secrets` write once the reconciler's key exists (M2). Running it as the
administrator means DraCLA never holds those permissions, so there is nothing to leave behind if an uninstall fails.
`uvx` makes it a single command with no environment to manage.

**Org base permissions are checked, not assumed.** Many organizations set
Base permissions to Read for all members, so a newly created private repository
is readable org-wide by default — contractors and later additions included.
`REQ-SEC-2` exempts DraCLA from application-layer encryption **on the basis that
the private records repository is a sufficient access boundary**, and that
sufficiency is conditional on an ACL the provisioner would otherwise never
inspect.

Install therefore reads the base permission and **refuses** unless it is `none`
(§6.10.4). An earlier draft restricted the repositories explicitly and proceeded
with a warning; that remedy does not exist. A base permission is a floor —
repository settings can raise a member's access and never lower it, and GitHub
has no negative permissions — so there is nothing to restrict afterwards. The
check belongs in `REQ-VERIFY-2`'s acceptance scenarios as a refusal, not a
warning.

Adding a second legal recipient later re-runs the same flow, producing an
additional pair (§5.5). The recipient itself is immutable once chosen.

**`dracla` org holds software and service only — two repositories:**

```
dracla/dracla              PUBLIC   monorepo
  core/                    Python: event model, replay, validation, exports
  cli/                     dracla command (uvx-runnable — §6.9)
  api/                     Cloudflare Workers (TypeScript)
  dashboard/               static shell + badge assets (Pages)
  design/  docs/

dracla/dracla-registry     PRIVATE  project routing (§7)
dracla/dracla-example      PUBLIC   sample adopter — a contributing repo
dracla/dracla-example-two  PUBLIC   second sample (release scope item 11)

created by `dracla install`, not by hand — they are adopter repos where
DraCLA happens to be the adopter, and so they live in a DEDICATED
organization like anyone else's (§6.10.4), not beside the code:
  dracla-cla/dracla-cla-records     PRIVATE
  dracla-cla/dracla-cla-coverage    PRIVATE
```

Two samples with **different legal recipients**, so release item 11 also
exercises the multi-recipient case of §5.5 and the workspace composition of
§6.9 rather than testing them as an afterthought. That needs the second pair to
be provisioned with an explicit `recipient.slug`, which is the path §6.10.3
defers for v1 — so this item either follows that deferral or is what lifts it.
It cannot be reached by the defaulted slug alone, since one organization
defaults to one pair.

**DraCLA's own contribution terms are a DCO, not a CLA.** Apache-2.0 §5 already
makes contributions inbound-equals-outbound and carries §3's patent grant, so a
CLA would add only relicensing ability and consolidated enforcement standing —
neither of which this project needs. A tool that recommended CLAs
indiscriminately would be self-serving; dogfooding happens in the sample
projects, which are real installations, rather than by imposing signing friction
on people fixing typos.

Workers and Pages both deploy from subdirectories, so a monorepo costs nothing
and keeps the Python core and the edge handlers versioned together.
`dracla-example` must be a separate repository because it has to behave like a
real adopter project under enforcement. The **registry is its own private
repository** (§7), not a monorepo directory — D2's own argument that tokens
cannot be path-scoped applies to it, and it must not be public.

**Supply chain.** The reconcile workflow seeded into every adopter's canonical
repo consumes the Python core, so a mutable reference would mean one push to
`dracla/dracla` executes attacker-chosen code inside every adopter's private
PII repository, on a runner holding the coverage deploy key — simultaneous
all-tenant compromise of both confidentiality and merge-gate integrity.
Therefore:

- The seeded workflow pins actions and the core by **digest**, never by branch
  or floating tag.
- Releases are signed, publish provenance attestation, and the workflow verifies
  it before running.
- Version bumps are an explicit adopter action (a pull request into their own
  repository), not a silent upgrade.
- The published source of the hosted Worker is attested to the deployed build,
  since open-sourcing the code otherwise provides an adopter no assurance
  whatever about what the operator is actually running (§8.3).

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

This split is not a preference — it is forced, and now measured (A4, §11).
Rulesets carrying `merge_queue` and `required_status_checks` are available on a
**public** repository in a Free organization; the identical ruleset on a
**private** repository is refused with *"Upgrade to GitHub Pro or make this
repository public"*. So enforcement must live where the contributing code is
public, and the records must live where they are private — which is exactly the
two-repository shape D2 arrived at for unrelated reasons.

### 9.1 Backup and recovery (`REQ-REC-7`, `REQ-REC-4`)

`REQ-REC-7` requires a documented backup and recovery procedure for the records
repository and any keys needed to interpret protected content. `REQ-REC-4`
additionally requires backups to preserve commit history **and recorded
branch-head identities**, and `REQ-VERIFY-2` requires a restore-then-rebuild
acceptance scenario. None of this existed in earlier drafts.

**What is backed up**

| Artifact | Why | Where |
|---|---|---|
| Canonical repo, full history, all branches | The only source of truth | Adopter-controlled mirror clone |
| Recorded branch-head identities | `REQ-REC-4`; a mirror alone does not prove which head was canonical when | Signed head log, appended per reconciler run |
| Coverage repo | Derived, but restoring it avoids a full rebuild | Same mirror schedule |
| `config/project.json`, agreements | Inside canonical | — |
| Coverage deploy key, session keys, App private keys | Needed to resume operation, **not** to interpret records | Operator or adopter secret store, never in any records repo (`REQ-SEC-4`) |

No key is required to *read* the records: `REQ-SEC-2` chose repository privacy
over application-layer encryption, so a restored canonical repo is fully
interpretable with git and the documented event format alone (`REQ-REC-5`).
That is the main reason recovery is simple, and it is worth stating as a benefit
of that earlier decision.

**Head-identity log.** A mirror preserves commits but not the claim "head was
`X` at time `T`". Each reconciler run appends `{canonical_sha, observed_at}` to
a log kept outside the repository, so a restore can be checked against the last
recorded head and detect truncation. This does not defeat an administrator who
controls the repository and every backup — `REQ-REC-4` explicitly accepts that —
but it does detect accidental loss and partial restores, which is what backup is
for.

**Recovery procedure**

```
1. restore canonical from mirror (all refs, full history)
2. compare head against the head-identity log; investigate any regression
3. rebuild coverage by full replay             -> §5.4 reconciler, repair mode
4. rebuild derived/ index and exports          -> §6.6
5. re-point the registry entry if repo names changed
6. re-drive checks for open pull requests in scope
```

Steps 3–4 are the same code path the reconciler already runs, which is what
`REQ-REC-6`'s rebuildability requirement buys: recovery is not a special
procedure, it is the ordinary one starting from an empty projection.

---

### 9.2 Capacity envelope (`REQ-OPS-3`)

`REQ-OPS-3` requires the documented deployment to state its request and compute
assumptions, the applicable provider limits, and the behaviour on reaching them.
The model is `core/capacity.py`, parameterised so it answers for any adopter
count rather than depending on one guessed number. Re-run it when an assumption
changes.

**Assumptions**, per project per day unless noted. Each is an input, not a fact:

| | Value | Where it came from |
|---|---|---|
| Pull requests | 5 | assumed |
| Webhook deliveries per pull request | 8 | sampled from live repos: median 3.5 (`astral-sh/uv`) to 10.5 (`cli/cli`) |
| Signings | 2 | assumed |
| Requests per signing | 8 | OAuth start and callback, agreement fetch, POST, status |
| Dashboard views | 5 × 3 requests | shell, authorization probe, index |
| Badge requests | 0 | badges are static Pages assets (§6.7) |
| CPU per check | 1.26 ms | measured, `api/bench/` |

**Deliveries are driven by pull request *activity*, not pull request count.**
GitHub App webhook subscriptions are per event **type**, not per action, so
DraCLA receives all 23 `pull_request` actions and acts on 4. The other 19 —
labelling, assignment, review requests — are discarded on arrival but still cost
a Workers request.

An agreement activation costs **one** intent-record write at the edge
regardless of how many contributors it affects (§6.5); the 256-shard fold runs
in the push-triggered reconciler, which is why activation does not appear in
the per-request budget.

**Result** (Cloudflare requests)

| Projects | Requests/day | % of Free | % of Paid | CPU s/day |
|---|---|---|---|---|
| 10 | 710 | 0.7% | 0.2% | 0.9 |
| 50 | 3,550 | 3.5% | 1.1% | 4.5 |
| 100 | 7,100 | 7.1% | 2.1% | 8.9 |
| 250 | 17,750 | 17.8% | 5.3% | 22.4 |

Cloudflare Free saturates at roughly **1,400 projects**; 520 if every adopter is
as busy as `cli/cli`, and 158 under a deliberately pessimistic combination. The
request ceiling is therefore not a capacity constraint at any plausible adoption
level.

That reframes two risks. **R7** — one busy adopter consuming the shared ceiling
— is unlikely on these numbers. **R9** — an outsider deliberately exhausting it,
which needs no adopters at all — is the real exposure, and is addressed by WAF
rate limiting and the route split (§9), not by capacity.

**The binding constraint is GitHub Actions minutes, not Cloudflare.**

The reconciler runs inside each project's **private** canonical repository, where
GitHub Free meters 2,000 minutes per month against the org's whole private-repo
allowance — not a DraCLA-specific budget. Jobs bill whole minutes, so schedule
frequency dominates:

| Schedule | At 1 min/run | At 2 min/run |
|---|---|---|
| Every 15 min | 2,940 min — **147%, over Free** | over Free |
| Hourly | 780 min — 39% | 1,560 min — 78% |
| Every 6 h | 180 min — 9% | 360 min — 18% |
| **Daily** | **30 min — 1.5%** | **60 min — 3%** |

**Decision: daily.** These minutes bill to the **adopting organization's**
account — Actions bills the repository owner — so they come out of that org's
whole 2,000 min/month, shared with all their other private repos. Spending 39%
to 78% of an adopter's entire CI allowance on a component that is not their
product is an unreasonable adoption cost. Daily is 1.5% to 3%.

Daily is defensible because only one scheduled duty is latency-sensitive:

| Scheduled duty | Cadence needed |
|---|---|
| From-scratch verification replay | Daily or weekly — it is an integrity check |
| Index and exports | Not scheduled at all; `REQ-DASH-5` makes them push-triggered |
| Due activations | Not scheduled at all; the enforcer honours `pending_effective_at` directly (§6.5) |
| Orphaned marker clearing | Minutes, ideally — but the Worker clears opportunistically (§5.4), and an uncleared marker fails closed |

Moving activations off the schedule also *improves* correctness: a periodic
flip left a window in which contributors passed under a superseded agreement,
and the edge comparison closes it to zero.

**Opportunistic orphan clearing** removes most of that latency without spending
minutes: on any later request touching a subject with an open marker, the Worker
checks whether that operation's event actually landed in canonical, and if so
completes the materialization and closes the marker itself. The scheduled pass
then only catches subjects nobody touches again.

**Behaviour on reaching a limit** (`REQ-OPS-3` requires this stated): Cloudflare
routes are fail-closed, so checks stop being written rather than passing
unevaluated, and the reconciler — running in Actions, unaffected by the Worker
budget — creates the *temporarily unavailable* check (§9). Exhausting Actions
minutes stops reconciliation only; signing, revocation, and checks continue,
because none of them depend on it.

## 10. Requirement changes proposed

### 10.1 Amendments — approved and incorporated

Both were approved on 18 August 2026 and are now in the baseline as
`design/requirements.md` revision 2, section 20.

| Req | Change | Where |
|---|---|---|
| `REQ-AGR-2` | Publishing separated from activating; an activation declares whether it invalidates prior acceptances; staged activation permitted | §6.5, D10 |
| `REQ-CHECK-2` | `Co-authored-by` trailers no longer determine a public check result, and are surfaced to authorized viewers instead; exemptions extended to named human accounts with a recorded basis; rule-based exemptions must materialize as events | §6.3.1, §6.8 |

The `REQ-CHECK-2` change narrows who must be covered, so its residual gap is
recorded rather than glossed: a co-author declared only by a trailer may
contribute without signing unless a maintainer acts (§6.3.1). It also does not
close the coverage oracle, only its cheap path (§6.3).

### 10.2 Deviations declared, not amendments

`REQ-OPS-2`'s enforcement clause is a **`SHOULD`**. A justified deviation needs
no baseline change, and an earlier draft escalated it into an amendment
unnecessarily — triggering requirements §19's Draft cycle for nothing. It is
recorded here as a deviation instead.

The argument also overreached. §2 said enforcement **cannot** run in Actions,
which §9's own `repository_dispatch` variant contradicts: a workflow inside the
private canonical repo is not subject to the fork-secret rule. The accurate
claim is that the Actions path costs ~30 s latency, metered private-repo
minutes, and a dispatch hop, so the App path was chosen — not that the Actions
path is impossible.

### 10.3 Previously undeclared deviations, now declared

An earlier draft asserted "No other requirement is deviated from." That was
false. Each item below is either now resolved in the design or is a deviation
that requires acknowledgement:

| Req | Status |
|---|---|
| `REQ-CHECK-1`, `REQ-PORTAL-3`, `REQ-PORTAL-5` | **Resolved** — the post-merge issue no longer names subjects (§6.4) |
| `REQ-SEC-6` | **Resolved** — the index proxy re-verifies per request rather than trusting a cached session verdict (§6.6, §8.2) |
| `REQ-CHECK-2` | **Resolved** — any pagination bound fails closed (§6.3) |
| `REQ-REC-7` | **Resolved** — backup and recovery is §9.1 |
| `REQ-SEC-1` | **Resolved** — fields derive from config; rate limiting keys on user ID, not IP (§5.1, §8.4) |
| `REQ-CHECK-3` | **Resolved** — admin bypass is documented (§6.4) |
| `REQ-OPS-3` | **Deviation acknowledged** — the reconciler consumes metered private-repo Actions minutes on the Free baseline (§9); bounded by incremental reconciliation, and must be sized in A3 |
| `REQ-AGR-2` | **Resolved** — staged activations take effect without a scheduler; the enforcer honours `pending_effective_at` at evaluation time (§6.5) |
| `REQ-PORTAL-5` | **Residual risk, not met in spirit** — the public check is an arbitrary-target coverage oracle by construction (§6.3). Rate-limited and documented, not closed. |
| `REQ-CONFIG-1` | **Limitation acknowledged** — two recipients in one org share an installation, so their separation is software-only in the hosted model (§7) |
| `REQ-REC-3` | **Resolved** — the interpretation this design declared (event commits only; pre-event bootstrap permitted; events identified by path) was ratified into the requirement text by baseline revision 3 (§6.10.1) |
| `REQ-CONFIG-3` | **Constraint acknowledged** — cross-organization scope is definable, but in v1 each entry must be bound by an administrator of its owner, which baseline revision 3 now requires as `REQ-CONFIG-5` (§7); the federated case with no such administrator is deferred, not unconsidered |

### 10.4 Verification resolved — no amendment needed

`REQ-OPS-3`'s merge-queue clause stands as written. A4 verified on 18 August
2026 that merge queue and required status checks are available for public
repositories on GitHub Free, and that the same enforcement on a private
repository requires a paid plan (§11). The conditional amendment previously
noted here is withdrawn: the condition did not occur.

### 10.5 Baseline status

Resolved. The baseline is **Locked at revision 3** and this document is
written against it. Revision 2 incorporated the two amendments of §10.1;
revision 3 ratified rules this design had declared on its own authority —
scope authorization (`REQ-CONFIG-5`, §7), credential lifecycle (`REQ-SEC-9`,
§8.1.2), and the `REQ-REC-3` event-commit reading (§10.3) — through the
requirements review loop rather than a design-proposed amendment, alongside
the derived-data enumerability and per-App boundary amendments. Requirements
section 20 records each change with its rationale, affected IDs, and what it
does not resolve, as section 19 requires.

The DraCLA-hosted-records variant in §9 remains opt-in and therefore does **not**
amend `REQ-CONFIG-1`, `REQ-OPS-6`, or principle 6.

---

## 11. Assumptions and open items

- **A1 — Edge platform. CLOSED.** Cloudflare Workers and Pages, TypeScript at
  the edge, Python core in Actions (D8, §9).
- **A2 — Workers limits on Free. CLOSED, measured 18 August 2026.**
  Subrequests: 6–8 per check against a cap of 50 (§9, D9). CPU: measured in
  workerd, not estimated — 0.26 ms for a typical pull request and 1.26 ms worst
  case against a 10 ms limit (§9, `api/bench/README.md`). Both limits have
  roughly an order of magnitude of headroom, so the Free-tier claim holds on
  compute even under a pessimistic correction for edge hardware
  (`api/bench/README.md`). Two things remain: a **confirming measurement on a
  real Cloudflare account**, reading CPU-time percentiles from Workers analytics
  rather than a development machine, and the shared **daily request ceiling**,
  which is a volume question for A3 rather than a per-request one.
- **A3 — Capacity envelope. CLOSED, modelled 18 August 2026.** §9.2 states the
  assumptions, their provenance, the resulting envelope, and the behaviour on
  reaching each limit, as `REQ-OPS-3` requires. The model is `core/capacity.py`
  and is parameterised, so it answers for any adopter count.

  Two conclusions worth carrying: the Cloudflare request ceiling is **not** a
  capacity constraint (Free saturates near 1,400 projects), and Actions minutes
  in each adopter's private canonical repository — billed to *their* org, not
  DraCLA's — set the reconciler schedule. Daily costs about 4% of an adopter's
  allowance; the alternative cadences cost 9% to 147%.
- **A4 — Merge queue on GitHub Free. CLOSED, verified 18 August 2026.**
  Tested empirically against a throwaway public repository in a Free-plan
  organization (`plan: free`, 1 seat):

  - A ruleset combining `merge_queue`, `required_status_checks`, and
    `pull_request` was created with `enforcement: active` and read back as
    effective on the default branch. Merge queue **is** available for public
    repositories on Free, so `REQ-CHECK-3`'s strong-enforcement baseline holds
    and no `REQ-OPS-3` amendment is needed.
  - Flipping the same repository to **private** immediately returned
    `403 Upgrade to GitHub Pro or make this repository public to enable this
    feature` on the rulesets API — confirming the other half of
    `REQ-OPS-3`'s baseline: ruleset and branch-protection enforcement on a
    private contributing repository requires a paid plan.

  Both halves of the documented Free baseline — public contributing repository
  with enforcement, private records repository without — are therefore verified
  rather than assumed.
- **A5 — Federated scope. OPEN by design.** A project whose scope owners share
  no single administrator cannot be configured in v1 (§7); the pathway is
  per-org co-confirmation. Owner: DraCLA maintainers. Trigger: the first real
  federated adopter request. Until then the deliberate cost stands recorded in
  §7, and `REQ-CONFIG-5` is satisfied by single-administrator binding.

---

## 12. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | ~~Co-author emails unresolvable, so co-authored PRs fail by default~~ **Closed** by `REQ-CHECK-2` rev 2 — trailers no longer block (§6.3.1) | Residual: a trailer-only co-author may contribute unsigned unless a maintainer acts on the surfaced list |
| R2 | A substantive version activation invalidates every contributor at once | `supersedes_coverage` flag keeps editorial changes from triggering it at all; staged activation with a future `effective_at` warns and lets contributors sign early (§6.5, D10) |
| R3 | Non-atomic write across two repos (§5.4 steps 1–3) | Pending-pointer forces fail-closed; Actions reconciler repairs |
| R4 | Index proxy carries all dashboard traffic through the serverless tier | Bound index size; cache with short TTL; include in A3 envelope |
| R5 | Provisioning failure leaves a half-installed project | `dracla install` is idempotent and re-runnable locally; the two App installs are GitHub's own flow and resumable; the registry entry is written last, by the portal when the administrator **connects** (§6.10.3.1 — the Setup URL callback only records installation IDs as unclaimed), so a half-provisioned project is never routable |
| R6 | ~~10 ms Free-tier CPU exceeded on a large pull request~~ **Closed** by measurement: 1.26 ms worst case, 13% of budget (§9, A2) | Residual: a pathological pull request with very long commit messages parses in proportion to bytes; the 250-commit API ceiling bounds it |
| R7 | ~~One busy adopter consumes the shared hosted ceiling~~ **Downgraded** by the A3 model: Free saturates near 1,400 projects, 520 if all are as busy as `cli/cli` (§9.2) | Per-project rate accounting retained as a guard; Paid raises the ceiling 3.3x |
| R8 | Daily limit exceeded silently drops webhooks if routes fail open | Configure routes fail closed (`REQ-CHECK-5`, §9); reconciler creates the *temporarily unavailable* check the dead Worker could not |
| R9 | `dracla-enforcer` is a public App, so an outsider can exhaust the shared per-account budget and halt checks, signing, and revocation for every adopter | WAF and rate limiting ahead of the routes; signature verification at the edge; two-Worker route split so the webhook surface cannot take the portal down (§9) |
| R10 | ~~Revocation-as-griefing via co-authoring~~ **Closed** by `REQ-CHECK-2` rev 2 — an injected trailer cannot block (§6.3.1) | Residual: a griefer who authors commits under their own identity can still revoke, but only affects pull requests containing their own authored work |
| R11 | Reconciler consumes the **adopting org's** private-repo Actions allowance (Actions bills the repo owner), shared with all their other private repos | **Largely dissolved** by the dedicated-organization shape (§6.10.4), which brings its own allowance. Otherwise: daily schedule (~4% including per-signing runs, vs 39–78% hourly); activations moved off the schedule (§6.5); opportunistic orphan clearing in the Worker |

---

## 13. Traceability

| Area | Requirements | Covered by |
|---|---|---|
| Project config, scope, recipient | `REQ-CONFIG-1..5` | §4, §5.1, §7, D4, D7 |
| Agreement versions and presentation | `REQ-AGR-1..4` | §5.1, §6.1, §6.5 |
| Individual signing | `REQ-SIGN-1..5` | §6.1, §5.1, §5.2 |
| Revocation and re-signing | `REQ-REV-1..5` | §6.2 |
| Entity CLAs | `REQ-ENTITY-1..5` | Deferred by `REQ-CONFIG-4`; event schema reserves the types |
| PR enforcement | `REQ-CHECK-1..5` | §2, §6.3, §6.4, §5.4 |
| Records | `REQ-REC-1..7` | §5.1, §5.2, §4, §6.6 |
| Privacy and security | `REQ-SEC-1..9` | §8, §8.1, §8.2, §8.4, §4, §5.3 |
| Portal and badges | `REQ-PORTAL-1..5` | §6.1, §6.3, §6.7 |
| Dashboard | `REQ-DASH-1..5` | §6.6 |
| Administrative flows | `REQ-AGR-1..2`, `REQ-CHECK-2`, `REQ-OPS-4` | §6.5, §6.8 |
| Backup and recovery | `REQ-REC-7`, `REQ-REC-4` | §9.1 |
| Data protection | `REQ-SEC-1..3`, `REQ-SEC-7`, `REQ-REC-3` | §8.4 |
| Observability and minimization | `REQ-OPS-5`, `REQ-SEC-1` | §8.4.1 |
| CLI: reporting, portability | `REQ-REC-5`, `REQ-OPS-4` | §6.9, §6.10 |
| Deployment and portability | `REQ-OPS-1..6` | §2, §7, §9 |
| Release verification | `REQ-VERIFY-1..2` | **Deferred**, and declared as such in §10.3 rather than only here. The traceability matrix and acceptance scenarios are a separate deliverable; §9.1, §8.2, and §9 name concrete pass criteria for three of the `REQ-VERIFY-2` scenarios that previously had none. |
