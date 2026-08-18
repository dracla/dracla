# DraCLA Design Review — Findings Register

Status: Addressed — all findings resolved in the design; see Status column
Date: 18 August 2026
Reviews against: `design/high-level-design.md` (Draft), `design/requirements.md` (Locked)

Four independent adversarial reviews were run against the design with no access
to the author's reasoning: credential boundaries and tenant isolation; protocol
correctness under concurrency; authentication, session, web and webhook
security; and requirements conformance and clarity.

Raw output was ~116 items across the four reports, collapsing to the 81 distinct
findings below (71 in the initial pass, 10 more added during register
verification). Items found independently by two or more reviewers are marked
**⊕** and are treated as confirmed.

Severity:

- **B** — blocking. The design is wrong or exploitable as written; fix before
  implementation.
- **H** — high. Real defect or missing mechanism; fix before release.
- **M** — medium. Underspecified such that reasonable implementers diverge.
- **L** — low.

Status values: `open`, `fixed`, `deferred`, `rejected`.

---

## Architecture verdict

No reviewer found cause to abandon the two-repo / two-App split, the
append-only git records model, or App-based enforcement. All confirmed findings
sit below that level: write ordering, the OAuth flow, permission inventories,
and mechanisms asserted without being specified.

---

## B — Blocking

| ID | Finding | Affects | ⊕ | Status |
|----|---------|---------|---|--------|
| DR-001 | **OAuth `state` is not bound to the browser, and PKCE is cited though GitHub does not implement it.** §8.2 lists "code + PKCE + state" and §6.1 carries PR context in `state`, so `state` becomes a Worker-signed blob proving only that the Worker issued it. Attacker completes OAuth for their own account, feeds the victim the callback URL; the victim's real legal name and email are committed under the **attacker's** user ID, append-only and unremovable. | §8.2, §6.1, REQ-SIGN-2, REQ-SIGN-4, REQ-SEC-4 | | fixed |
| DR-002 | **Scope tiering is not implementable with GitHub Apps.** §8.1's contributor-vs-maintainer scope split assumes OAuth App scopes; GitHub App user-to-server authorization has no `scope` parameter. The OAuth-App fallback requires `repo` (read **and write**) to check private-repo access, hoarding write tokens for maintainers — the exact liability §8.1 rejects for contributors. | §8.1, §6.6, REQ-SEC-6 | | fixed |
| DR-003 | **Freshness guard write order is backwards.** `pending.json` is written *after* the canonical commit, so a crash between them leaves both pointers agreeing on stale state. Fails **open for revocation** at the authoritative merge-group check, and is contributor-inducible by retrying revocation under load. | §5.4, REQ-CHECK-3, REQ-CHECK-4, REQ-REV-4 | ⊕⊕ | fixed |
| DR-004 | **Validation runs after the append.** Invalid events are permanent in a log that cannot be pruned. Because the staleness signal is project-global, one bad or unlucky signature wedges every check for the whole project — a cheap remote DoS on the landing gate. | §5.4, REQ-REC-3, REQ-CHECK-5 | | fixed |
| DR-005 | **Packed coverage shards are read-modify-write with no compare-and-swap.** Two users in one shard writing concurrently: one row silently reverts. A lost revocation keeps a contributor passing. Worst during a `supersedes_coverage` activation, which is by construction a mass-concurrent-write event. | §5.3, §5.4, D9 | | fixed |
| DR-006 | **§5.2's retry can lose events.** "Retry from 2" never states the tree is rebuilt on `H'`'s base tree; reusing the built tree and re-parenting is accepted by GitHub as a clean fast-forward while the concurrent event vanishes from the tree. Compounded by §5.1 locating events by path existence. Also: `force: false` is a fast-forward check, not the compare-and-swap §5.2 labels it. | §5.2, §5.1, REQ-REC-3 | | fixed |
| DR-007 | **Coverage is never evaluated against scope.** §6.3 resolves subjects, reads shards, and passes. It never compares the PR's repository against the scope recorded with that acceptance, though both the event envelope and the shard carry `scope`. | §6.3, REQ-CONFIG-3, REQ-CHECK-2 | ⊕⊕ | fixed |
| DR-008 | **Registry slugs have no uniqueness or ownership verification.** Self-serve install plus a user-chosen slug lets an attacker claim `acme` and operate a look-alike signing portal on the legitimate domain, under a genuine OAuth consent screen, harvesting legal names and emails into their own repo. §7's token/repo binding rule is blind to this because the poisoned entry is internally consistent. | §7, §9, REQ-OPS-6, REQ-CONFIG-1 | ⊕ | fixed |
| DR-009 | **Origin topology is undefined.** Pages + Workers default to separate origins, forcing `SameSite=None` (deleting §8's CSRF control) and a CORS policy whose common implementation reflects `Origin` with credentials — drive-by read of the dashboard index, and cross-site forced acceptance, which fabricates a legal grant. | §3, §6.6, §8, REQ-SEC-4, REQ-DASH-3 | | fixed |
| DR-010 | **Where the dashboard index lives is unspecified.** If an implementer puts it in the coverage repo — the natural home for generated artifacts — `dracla-enforcer` gains read access to all signer PII and the headline structural control collapses in one commit. | §5.1, §5.3, §6.6, REQ-SEC-2 | | fixed |
| DR-011 | **§4's permission inventory is incomplete, and what is missing is dangerous.** The §9 install flow requires org `administration: write`, `workflows: write`, and `secrets: write`, none listed. Retained in steady state (R5 makes provisioning re-runnable), `workflows: write` is a permanent code-execution channel into every adopter's PII repo; `administration: write` permits flipping canonical to public. | §4, §9, REQ-REC-2 | | fixed |
| DR-012 | **Both App private keys live in one Worker isolate**, with the session key, OAuth client secret, and webhook secrets, serving every tenant. D3's "separation at the credential level" does not hold against the realistic compromise: an attacker simply uses the other key. Highest-value payload is forging `success` on authoritative merge-group checks across all adopters. | §9, §4, D3, REQ-OPS-6 | | fixed |
| DR-013 | **The reconciler is exposed to workflow injection.** It runs inside canonical with a coverage-write deploy key and consumes signer-supplied `legal_name`, `email`, and confirmation labels. Nothing forbids interpolating them into `run:`/`env:`, nothing declares `permissions:`. Payload: exfiltrated deploy key → forge the merge gate project-wide, persistently, since the reconciler's output overwrites the Worker's. | §4, §5.1, REQ-SEC-8, REQ-REC-4 | | fixed |
| DR-014 | **Two writers to the coverage repo with no stated ownership of `pending.json`.** If the reconciler regenerates both pointers from its own replay head, it overwrites a newer `pending` set by the Worker, making a stale projection look fresh and passing a revoked contributor. No concurrency protocol is specified for coverage at all. | §5.4, §4, REQ-CHECK-3 | ⊕ | fixed |
| DR-015 | **`event_id` / `idempotency_key` derivation is unresolved and both readings break a MUST.** Nonce-bearing → retries append duplicate acceptances (REQ-SIGN-5). Content-hashed → re-signing after revocation collides with the original path and is silently swallowed (REQ-REV-5). §5.2 also dedupes on `event_id` while REQ-REC-3 specifies the idempotency key. | §5.1, §5.2, REQ-SIGN-5, REQ-REV-5, REQ-REC-3 | ⊕ | fixed |

## H — High

| ID | Finding | Affects | ⊕ | Status |
|----|---------|---------|---|--------|
| DR-016 | §8.3's trust model is false in hosted mode: the operator holds the records App key, so repo custody ≠ key custody. Operator-forged events are byte-indistinguishable from genuine and replay faithfully into coverage. REQ-REC-4 waives detection of admin *rewriting*, not operator *forgery*. | §8.3, REQ-REC-4, principle 6 | | fixed |
| DR-017 | "Enforcer never installed on canonical" is an org-admin checkbox, not a structural property. Flipping the installation to "All repositories" silently grants it read on canonical. Nothing asserts or detects this. *(Reviewers disagreed; adjudicated in favour of this reading.)* | §4, D2, D3, REQ-SEC-2 | | fixed |
| DR-018 | §6.4's post-merge fallback "opens an issue identifying the commit and subjects" — on a public repo that is a permanent, indexable, public statement that a named user is uncovered. | §6.4, REQ-CHECK-1, REQ-PORTAL-3, REQ-PORTAL-5 | | fixed |
| DR-019 | The public check is a per-user coverage oracle. An attacker adds `Co-authored-by: x <TARGET_ID+x@users.noreply.github.com>` to a fork PR; the public check state reveals whether the target is covered. Unauthenticated, arbitrary-target, repeatable — REQ-PORTAL-5's intent defeated while its letter is met. | §6.3, REQ-PORTAL-5, REQ-CHECK-2 | | reduced |
| DR-020 | Commit-email attribution is forgeable in the other direction: setting author email to a covered user's noreply address attributes the commit to them. "GitHub-resolved author" is unauthenticated email matching, which §8.2's "attestation chain" language overstates. | §6.3, §8.2, REQ-CHECK-2 | | fixed |
| DR-021 | Enforcer holds `pull_requests: read`, so DraCLA **cannot post a PR comment**. Badges (REQ-PORTAL-2/3/4) are undesigned beyond one line in the §9 repo tree. Release-scope item 10. | §4, §9, REQ-PORTAL-2..4 | | fixed |
| DR-022 | Overrides are keyed to the PR head SHA, which does not exist at the merge-group check. Strict match → the override never applies and the PR is permanently unlandable; loose match → override laundering across a force-push. | §5.3, §6.4, REQ-CHECK-2 | | fixed |
| DR-023 | Exemptions exist as an event type but have no representation in the projection, and the enforcer reads only coverage. Bot exemptions are unimplementable as drawn. | §5.3, §6.3, REQ-CHECK-2 | ⊕ | fixed |
| DR-024 | The override/exemption event cannot be expressed by the §5.1 envelope: single-valued `subject`, no head-commit field, no administrator attribution. | §5.1, REQ-CHECK-2 | | fixed |
| DR-025 | Coverage row schema contradicts itself: §5.3 is one record per user with singular `agreement`; §5.5 says coverage keys on `(user_id, agreement_id)`. A second agreement overwrites the first. | §5.3, §5.5 | ⊕ | fixed |
| DR-026 | Staged activation has no time trigger. Nothing runs at `effective_at`; the Worker acts on sign/revoke and Actions on push. A superseded version keeps passing until an unrelated push occurs. | §6.5, REQ-AGR-2 | ⊕ | fixed |
| DR-027 | Canonical writers other than the sign/revoke Worker never touch `pending.json` — agreement activation, overrides, exemptions, admin commits, the reconciler. The guard is a liveness signal for one code path, not a freshness proof. | §5.4, §6.5 | ⊕ | fixed |
| DR-028 | Merge-group subject resolution is asserted, not specified. A merge group batches PRs and supplies SHAs, not a PR list; the commit-range reading drops the PR opener, who REQ-CHECK-2 requires be evaluated at the only blocking gate. | §6.4, REQ-CHECK-2, REQ-CHECK-3 | ⊕ | fixed |
| DR-029 | The `in_progress` staleness verdict has no retry driver. No cron, no queue (REQ-OPS-3 forbids one), and merge-group checks are not re-requestable like PR checks. A merge group hitting a staleness window sits until the queue ejects it. | §5.4, §6.4, REQ-CHECK-5 | | fixed |
| DR-030 | Session `jti` bounds nothing without a store, and none is specified. No logout or invalidation exists anywhere. The user access token's fate is unstated — in a signed-only cookie it is a REQ-SEC-4 violation; in KV it is a session store the design does not admit to. | §8.2, REQ-SEC-4 | | fixed |
| DR-031 | Session decay conflicts with REQ-SEC-6's "current" authorization. An offboarded records reader retains index access for up to the TTL, and one request pulls every signer's data. "Sensitive actions" is never enumerated. | §8.2, §6.6, REQ-SEC-6, REQ-VERIFY-2 | ⊕ | fixed |
| DR-032 | The index proxy is a confused deputy over the full PII repo. Unspecified: fixed artifact path vs client-supplied path/ref; that authorization binds to the registry-resolved repo of the *requested* project; that the probe uses a user-to-server (not installation) token; cache keying. | §6.6, REQ-SEC-6, REQ-DASH-3, REQ-OPS-6 | | fixed |
| DR-033 | Auto-provisioned repos inherit the org's base repository permission. Many orgs set Read for all members, so the "private" records repo is org-readable — and REQ-SEC-2 exempts DraCLA from encryption *on the basis* that the private repo is a sufficient boundary. | §9, D4, REQ-SEC-2 | | fixed |
| DR-034 | Hostile tenants are not modeled. Self-serve install creates a principal that supplies agreement markup rendered on the shared portal origin, where every tenant's session cookie lives. §8.1 models only the authenticated contributor. | §8.1, §9, REQ-SEC-8 | | fixed |
| DR-035 | Fail-closed routing plus a per-account cap plus unauthenticated endpoints lets any anonymous party halt every tenant for a UTC day — including signing and revocation, so the documented remediation path is down too, and REQ-REV-1's MUST is unmet. Requests count whether or not the webhook signature verifies. | §9, R7, R8, REQ-REV-1, REQ-CHECK-5 | ⊕ | fixed |
| DR-036 | §9's stated exhaustion behavior is wrong: "the check remains `queued`" holds only if a check run already exists. If the Worker never ran, **no check exists** — absent, not queued, with no retry affordance and no self-healing. | §9, REQ-CHECK-5 | | fixed |
| DR-037 | REQ-REC-7 backup and recovery is entirely absent, as is REQ-REC-4's requirement that backups preserve recorded branch-head identities. REQ-VERIFY-2 mandates a restore-and-rebuild scenario. | — (missing), REQ-REC-7, REQ-REC-4 | | fixed |
| DR-038 | REQ-SEC-1 data minimization is never addressed. The envelope hardcodes `fields: {legal_name, email}` rather than deriving from config, and rate limiting (§8.1 #2, #7) implies retaining edge metadata REQ-SEC-1 singles out. | §5.1, §8.1, REQ-SEC-1 | | fixed |
| DR-039 | Administrative flows are undesigned as a class: publishing and activating a version, setting `supersedes_coverage`, editing config after install, registering exemptions, issuing overrides. §8.1 #5's "separate authorization check" names no permission, repo, or token. | §6.5, §8.1, REQ-AGR-1, REQ-AGR-2, REQ-OPS-4 | | fixed |
| DR-040 | Check run output is undesigned. REQ-CHECK-5 requires the result to explain retry; the design specifies conclusions only, never title/summary/text, and never connects `check_run.rerequested` to that contract. | §6.3, REQ-CHECK-5 | | fixed |
| DR-041 | Two candidate sources of truth for agreement content: the `agreements/` file tree (mutable, records App has write) and the `agreement_published` event. REQ-AGR-1 forbids in-place modification with no mechanism. `supersedes_coverage` lives in the mutable file and is not covered by the content digest. No event records a Git commit OID, which REQ-REC-4 requires. | §5.1, §6.5, REQ-AGR-1, REQ-REC-4 | | fixed |
| DR-042 | "Bound page size" (§9, R6) contradicts REQ-CHECK-2's "every commit." Any pagination bound must fail closed, and the GitHub commits endpoint truncates at 250 regardless. | §9, R6, REQ-CHECK-2 | | fixed |
| DR-043 | Private-repo Actions minutes are metered on Free, and the reconciler runs in the private canonical repo on every push. §2's "Actions minutes are free on public repos" does not apply to it; A3 does not budget it. | §2, §9, A3, REQ-OPS-3 | | fixed |
| DR-044 | §10's "No other requirement is deviated from" is false — eight undeclared deviations (DR-018, DR-031, DR-042, DR-037, DR-038, DR-045, DR-043, DR-026). REQ-VERIFY deferral is filed in §13 and contradicted by §10. | §10, §13, requirements §19 | | fixed |
| DR-045 | REQ-CHECK-3's admin-bypass documentation requirement is omitted from §6.4. | §6.4, REQ-CHECK-3 | | fixed |
| DR-046 | REQ-SEC-7 retention transparency is covered for revocation (§6.2) but not for signing (§6.1), and per-project retention/correction procedures have no config field. | §6.1, REQ-SEC-7 | | fixed |
| DR-047 | Login recycling is unhandled in the surfaces that remain login-keyed: the SSH/GPG hardening idea calls `/users/{login}/…`; legacy `<login>@users.noreply.github.com` invites a login→id lookup; dashboard and exports may surface `login_snapshot` as the user column. | §8.2, §6.3, §6.6, REQ-SIGN-1, REQ-DASH-2 | | fixed |
| DR-048 | Two recipients in one org share a single records App installation, so their separation is software-only — the arrangement D3 exists to reject. | §5.5, §4, D3, REQ-CONFIG-1 | | fixed |
| DR-049 | Workers KV is the de facto authoritative registry: no freshness guard, no reconciler, writable from the request-serving isolate, and R7's rate counters are not rebuildable from git — falsifying the "derived, never authoritative" claim. Offboarding leaves KV entries live. | §7, R7, REQ-REC-6, REQ-OPS-6 | | fixed |
| DR-050 | Supply chain: the reconcile workflow consumes `core/` from `dracla/dracla` with no stated pinning, provenance, or adopter-controlled upgrade. A mutable ref means one push executes attacker code inside every adopter's PII repo. No attestation ties the hosted Worker to published source. | §9, REQ-OPS-6, REQ-SEC-4 | | fixed |
| DR-051 | Putting `registry/` in the monorepo contradicts D2's own argument that tokens cannot be path-scoped: the credential writing `registry/` can also write `api/` and `core/`. Security-critical routing protected only by ordinary code review, with no CODEOWNERS or signing stated. | §9, D2, REQ-OPS-6 | ⊕ | fixed |
| DR-052 | `dracla-enforcer` is a public App, so any GitHub user can install it and generate unbounded webhook load; authorization happens after delivery is charged. "Per-project rate accounting" cannot bill traffic belonging to no project. | §9, R7, REQ-OPS-3 | | fixed |
| DR-053 | §9's "the edge holds no coverage rules" is contradicted by §5.3: deciding coverage from the shard requires comparing signed vs active version, walking `supersedes_coverage`, evaluating `effective_at`, and matching scope — a full rule engine at the edge, duplicated against the Python replay, inside 10 ms. | §9, §5.3, D5 | | fixed |
| DR-054 | Retry semantics do not re-validate the operation against the reloaded head. A concurrent re-sign and revocation can nullify each other depending on replay semantics the design never states. | §5.2, REQ-REV-3, REQ-REV-4 | | fixed |
| DR-055 | Revocation-as-griefing is unbounded: co-author widely, then revoke, and every open PR containing those commits becomes unlandable. REQ-REV-1 grants unilateral revocation and nothing bounds the blast radius. | §6.3, REQ-REV-1, REQ-CHECK-2 | | fixed |

## M — Medium (underspecified; divergent implementations)

| ID | Finding | Affects | Status |
|----|---------|---------|--------|
| DR-056 | Whether coverage is evaluated against scope captured at acceptance or current project scope — two completely different products. Scope changes have no `supersedes_coverage` analogue. | REQ-CONFIG-3 | fixed |
| DR-057 | How "current version" is decided across a `supersedes_coverage` chain (v1→v2 editorial→v3 substantive→v4 editorial). `agreements/active.json` has no schema. | REQ-AGR-2, D10 | fixed |
| DR-058 | Where generated exports and the dashboard index live. Four plausible answers, one of which (Actions artifacts) REQ-SEC-2 explicitly forbids for signer data. | REQ-REC-5, REQ-SEC-2, REQ-DASH-4 | fixed |
| DR-059 | No index schema, and REQ-DASH-2's "superseded" and "indeterminate" statuses appear nowhere in the design. | REQ-DASH-2, REQ-DASH-4 | fixed |
| DR-060 | How the portal obtains agreement text and config from a private repo. The endpoint is never named, its auth requirements unstated, and it is unbudgeted. | REQ-AGR-3, REQ-DASH-3 | fixed |
| DR-061 | REQ-SIGN-3's configurable field set vs the hardcoded envelope; where confirmation labels are configured; whether `checked: false` is rejected. | REQ-SIGN-3 | fixed |
| DR-062 | Whether the reconciler asserts or repairs on mismatch — the two postures differ, and mismatch is the best available compromise detector but is consumed silently. | §4, §5.4, R3 | fixed |
| DR-063 | Session/project binding: nothing says authorization results are scoped per project. A cached `authorized: true` crosses tenants. | REQ-OPS-6 | fixed |
| DR-064 | Portal status read path is unspecified; if it accepts a user-id parameter it is the REQ-PORTAL-5-forbidden lookup, merely authenticated. | REQ-PORTAL-1, REQ-PORTAL-5 | fixed |
| DR-065 | Webhook verification details: constant-time comparison, verify-before-parse, `sha1=` rejection, per-App secrets, `X-GitHub-Delivery` dedupe, rotation. | REQ-SEC-5 | fixed |
| DR-066 | Registry repository visibility is deferred; if `dracla/dracla` is public the registry enumerates every adopter, their private repo names, scope, and installation ids. | REQ-SEC-2 | fixed |
| DR-067 | Installation-token custody in KV: encryption at rest, per-project key namespacing, and that KV keys never derive from unvalidated input. | REQ-SEC-4 | fixed |
| DR-068 | CSP delivery and `frame-ancestors` for the static shell; without it the portal is clickjackable, defeating REQ-SIGN-2's affirmative action. | REQ-SEC-8, REQ-SIGN-2 | fixed |
| DR-069 | Concurrent `synchronize` deliveries race with no head-SHA conditioning; a stale `failure` can overwrite `success` with no re-trigger. | REQ-CHECK-4 | fixed |
| DR-070 | Deploy-key custody vs REQ-SEC-4 (repo *settings* secrets vs repo *contents*), and rotation for the one credential that writes the projection outside the App boundary. | REQ-SEC-4 | fixed |
| DR-071 | Retry exhaustion in §5.2 leaves an indeterminate state; what is true afterwards is unstated, and it is the entry point to the DR-004 wedge. | §5.2 | fixed |
| DR-074 | What the portal shows during the materialization window — canonical ("signed" while checks fail) or coverage ("not signed" immediately after signing). Neither is the "exact status" REQ-PORTAL-1 demands. | REQ-PORTAL-1 | fixed |
| DR-075 | §6.1 step 4's "re-evaluate the originating pull request" has no retry on failure, and the recovery path (`check_run.rerequested`) needs write access the contributor lacks. | REQ-CHECK-4 | fixed |
| DR-076 | Revocation's tie to the acceptance it revokes is never stated as a field. REQ-REV-3 requires the event be "tied to the acceptance being revoked"; `supersedes` is described only as the correction link. | REQ-REV-3 | fixed |
| DR-077 | The stable per-project portal URL scheme is never given, though REQ-PORTAL-1 requires a stable page and REQ-PORTAL-2's badge must link to it. | REQ-PORTAL-1, REQ-PORTAL-2 | fixed |
| DR-078 | No session identifier rotation after login or privilege change; a pre-auth cookie upgraded in place permits classic fixation. | REQ-SEC-4 | fixed |

### Added during register verification (stage 3)

| ID | Sev | Finding | Affects | Status |
|----|-----|---------|---------|--------|
| DR-072 | H | Coverage repo visibility is never mandated. Marketed as "PII-free", it is a complete `user_id → status` directory — exactly the public signer lookup REQ-PORTAL-5 forbids and §17 lists as a non-goal. The design must state it MUST remain private and why PII-free ≠ publishable. | §5.3, REQ-PORTAL-5 | fixed |
| DR-073 | H | Edge observability is unaddressed. The sign POST body carries `legal_name` and `email` through Workers; nothing states that request-body logging, `wrangler tail`, Logpush, and error-reporting integrations must exclude it, nor that OAuth callback query strings (code, state) must be scrubbed. A default-on integration violates REQ-SEC-2 with no log line written by DraCLA. | §8, REQ-SEC-2, REQ-OPS-5 | fixed |
| DR-079 | H | REQ-CHECK-1's "exact reason" surface does not exist, and the natural implementation collides with REQ-PORTAL-5: for a multi-author PR the reason concerns *other* subjects, so showing it requires deciding who may see another subject's coverage in a PR context. The design makes neither the surface nor the decision. | §6.3, REQ-CHECK-1, REQ-PORTAL-5 | fixed |
| DR-080 | L | `supersedes` (event linkage, REQ-SIGN-5) and `supersedes_coverage` (agreement flag, D10) are one word apart with unrelated meanings and will be conflated. | §5.1, D10 | fixed |
| DR-081 | L | Index-proxy error responses distinguishing 404 (no such project) from 403 (no read access) disclose adopter existence. Return a uniform 404. | §6.6 | fixed |

---

## Framing corrections (not defects, but the document argues them wrongly)

- **REQ-OPS-2 is a `SHOULD`.** A justified deviation needs no baseline
  amendment; §2 escalated it unnecessarily and triggers the §19 Draft cycle for
  no reason. §2's "enforcement **cannot** run in Actions" is also contradicted
  by §9's own `repository_dispatch` variant. Honest claim: it costs latency and
  metered private-repo minutes, so the App path was chosen.
- **REQ-AGR-2 / D10.** The amendment rationale inverts the requirement:
  REQ-AGR-2 triggers on the project's deliberate act of *activating*, not on
  DraCLA inferring meaning from text. The design never distinguishes **publish**
  from **activate**, and that distinction resolves the editorial-change problem
  with no amendment at all. If the flag survives, it must live in the immutable
  event, not a mutable meta file (DR-041).
- **REQ-OPS-3 conditional row.** "Not proposed unless verification fails" cannot
  be approved or rejected; run A4 and make it firm or drop it.
- **Baseline status.** With firm changes on the table, requirements §19 requires
  the baseline be marked Draft; the design cites it as Locked.

## Factual errors in the design document

| Location | Claim | Reality |
|---|---|---|
| §8.2 | OAuth uses PKCE | GitHub does not implement PKCE |
| §9 | On exhaustion "the check remains `queued`" | No check run exists if the Worker never ran |
| §2 | "Actions minutes are free on public repos" | The reconciler runs in the private canonical repo, metered |
| §8.3 | The trusted administrator is the adopter, not the operator | False in hosted mode; the operator holds the key |
| §4 | Enforcer "structurally cannot" reach PII | Org-admin-controlled installation setting |
| §5.2 | Step 4 is a compare-and-swap | `force: false` is a fast-forward check |
| §10 | "No other requirement is deviated from" | Eight undeclared deviations |

## Adjudicated disagreement

Reviewers split on whether the enforcer's PII boundary is structural. Resolved
in favour of "not structural" (DR-017): GitHub App installation repository
selection belongs to the adopting org's admin, so DraCLA cannot enforce it.
The narrower claim holds only as far as *names and email addresses*: the
projection contains neither. It is not free of personal data — see §8.4,
which grounds its privacy in aggregation rather than secrecy.

## Properties that survived review

Server-computed event paths closing write-side traversal · subject read from
the verified session (sound in itself; defeated only by DR-001, which is a flaw
in session establishment) · server-side code exchange with the client secret
never reaching the browser · §5.2's commit shape matching REQ-REC-3
clause-for-clause given DR-006 and DR-015 fixed · registry-sourced repo handles
blocking naive cross-tenant token aiming · fail-closed routing as the correct
choice over fail-open · §5.4's honest framing of the reconciler as defense in
depth rather than the mechanism that makes a signature effective · records
never moving, which makes the REQ-OPS-6 migration argument genuinely a no-op.

---

## Post-review requirement amendments (18 August 2026)

Two amendments were approved after this register was closed, changing the
status of three findings.

| Finding | Was | Now |
|---|---|---|
| DR-019 — public check is a coverage oracle | residual risk, mitigated by rate limiting | **reduced.** `REQ-CHECK-2` rev 2 demotes `Co-authored-by` trailers, closing the cheap path. The commit-author path remains and is still residual — forging authorship is visible in the commit list and blocked by signed-commit rules, but not prevented. |
| R1 — unresolvable co-authors fail closed | accepted risk, documented | **closed.** Trailers no longer block. |
| R10 — revocation-as-griefing via co-authoring | accepted, unsolvable in DraCLA | **closed** for injected trailers; a griefer can still revoke coverage for commits they actually authored. |

New residual introduced by the same change: a co-author declared only by a
trailer may contribute without signing unless a maintainer acts on the list
surfaced in the authenticated pull request view (§6.3.1). Accepted deliberately
as the cost of removing the oracle and the false-failure case.

`REQ-CHECK-2` rev 2 also extends exemptions from non-human accounts to named
human accounts with a recorded basis, and requires rule-based exemptions to
materialize as per-account events (§6.8).
