# M5 — Portal, Connect, signing and administration requirements

Status: locked-scope design draft. Existing product and architecture approvals
apply; a new decision is required only for a proposed material scope,
architecture, public-contract, actor, permission or trust change. This document
does not authorize implementation, live operations or publication.

## 1. Outcome and governing scope

Provide the complete initial-release contributor portal and its authenticated
administrative operations. A contributor can read an agreement, authenticate,
inspect their own status, sign, correct their fields by signing again, revoke
and re-sign through that same portal. An authorized administrator can Connect,
manage the agreement and policy, administer coverage and reader sources,
resolve scope conflicts, request retries and obtain an authorized hosted export.

The governing contracts are the [product requirements](../requirements.md),
[global architecture](../high-level-design.md), completed
[M1 formats and semantics](../lld/m1-conformance-kernel.md),
[M3 history, repair and export implementation plan](../lld/m3-control-reconciler.md),
and clean [M4 architecture](../m4/high-level-design.md) and
[detailed plan](../m4/implementation-plan.md). Parent obligations remain in scope
when they appear in prose rather than a table. These M5 requirements refine
them; they do not replace them or declare existing pure codecs to be a portal.

M4 owns the shared production Worker/HTTP/SQLite harness, isolated enforcement,
coverage evaluation, runtime limits, route/gate coordinator, canonical mutation
executor and originating-PR reevaluation service. M5 extends those foundations
with authenticated portal behavior and the minimum purpose-bound interfaces
needed by that behavior. It does not build a second writer, replay engine,
registry, evaluator or test harness. M3 remains the bulk replay/recovery/export
renderer. M6 owns provisioning and installation of the accepted contracts;
M7 owns dashboard presentation, badges, demonstration and release assembly.
M5 supplies their private APIs and required integration, not their UI in advance.

Initial scope has exactly one Individual CLA identifier per project, with
immutable versions. Entity agreements, multiple-agreement combination rules,
scheduled activation, public signer lookup, cross-project revoke-all,
cryptographic contributor signing, new legal interpretation and a records
database remain excluded. Existing completed slices and history are preserved.

## 2. Actors and authority

An authenticated contributor acts as their stable GitHub numeric user ID.
A records reader has current canonical reader authorization; repository read
access alone grants none. Administrative authority is checked for the exact
action and resource at action time, separately from records-reader authority.
The initial minimum matrix is:

| Action | Required current authority |
|---|---|
| Sign, correct by signing again, revoke, re-sign, inspect own status | GitHub-authenticated subject; explicit action and exact tuple where applicable |
| Connect or transfer the three-repository arrangement | Owner control, admin on all three repositories, and all exact App-binding authorizations required by the parent architecture |
| Publish, activate or restore agreement currency; edit policy/fields; administer exemptions or reader sources; close in favor of a legal successor | Admin on the applicable records repository; separately verified successor when needed |
| Activate a verified project-key generation | Admin on every repository whose key material changes; actual live and recovery readiness |
| Change repository enforcement scope | Admin on that contributing repository |
| Change an organization-wide scope selector | Owner of that organization |
| Inspect a routing conflict | Admin on that affected contributing repository; no implied mutation or records-reader authority |
| Grant or withdraw an exact PR override | Maintain on that contributing repository |
| Request an administrative retry | Write on that contributing repository |
| Read another subject's private status, index or export | GitHub authentication and current records-reader sources, with the exact result scope |

The portal uses the actor's user-to-server identity for records-side authority,
not an installation token that answers for the App. Contributing-side authority
is obtained from the isolated enforcer using the approved capability boundary.
No user/installation credential or raw decryption key crosses to the browser
or between the records and enforcement services. Key and deployment controllers
retain the parent architecture's explicitly disclosed trust; encryption does
not protect records from those controllers.

## 3. Required behavior

### M5-R01 — Stable project and public agreement pages

Resolve owner-qualified default and slugged project aliases to the registry's
immutable project identity. Preserve authenticated rename redirects and refuse
ambiguous, pending or unavailable bindings rather than choosing another project.
Before login, present the complete active agreement, legal recipient, version,
digest, required fields and exact confirmation labels, privacy-policy link and
retention/correction information. Public rendering contains no signer evidence.
No active agreement means no signing action; an inactive publication cannot
be signed. Accessible wording must not infer copyright transfer or legal scope.

### M5-R02 — Browser-bound authentication and session lifecycle

Implement the approved GitHub App OAuth flow with signed context, a ten-minute
encrypted browser-bound pre-auth cookie, PKCE S256 and exact callback binding.
Validate the return path against the fixed same-origin allowlist. Trust identity
only after GitHub authenticates the code exchange and `/user` response. Callback
replay cannot create another session. Do not depend on atomic KV deletion.

Use an authenticated-encrypted `__Host-` session cookie with eligible key ID and
an existing live-session KV entry keyed by `jti`. The user token stays server-side;
discard refresh tokens. Cookie and KV expiry are absolute, exactly five minutes
before GitHub's returned access-token expiry, never renewed by activity. The
default eight-hour token therefore permits at most seven hours fifty-five
minutes. Insufficient remaining lifetime creates no session. Logout removes
the cookie and requests KV deletion, with its documented eventual-consistency
limit rather than a promise of immediate global revocation.

Every sensitive action/read revalidates GitHub authentication and its current
action-specific authority. Expiry or `401` restarts OAuth before mutation or
plaintext disclosure. A valid session with `403` or insufficient permission is
denied that action without being promoted or needlessly losing other access.
Session AEAD, OAuth-state, action-form and private-read keys remain purpose
separated, with the parent's bounded successor/predecessor rotation behavior.

### M5-R03 — Complete authenticated action registry and exact confirmation

Every mutating contributor/admin form uses the existing M1 action-form codec
and exact global HLD Table 5.4-A mapping. Bind the live session, actor, project,
canonical operation, target/payload digest, fresh nonce, displayed canonical
head, timestamps and any permitted terminal no-op event. Reject unknown fields,
types, mismatched targets, invalid/expired forms and reused nonces with different
meaning before preparation. Browser data cannot select an authority provider.

A non-no-op form may prepare only while the displayed canonical head still
matches, even if intervening work was unrelated. A stale form requires a fresh
display and explicit confirmation. An event-backed no-op remains that exact
no-op on every retry; it cannot become a later write. Internal activation,
abandonment and membership automation events are not public form types. Retry
of the same submission returns its original result; a new action gets a new nonce.

### M5-R04 — Exact self status and intermediate outcomes

Resolve the viewer's subject from the verified session, never a public or
non-reader arbitrary user parameter. Show the tuple's exact current status and
applicable Sign, Re-sign or Revoke action. Read canonical state during a pending
materialization and distinguish "recorded, taking effect" from completed
coverage. An uncertain or blocked operation is not reported as success or as
absence of its canonical record. Show safe retry/recovery guidance without
private operational payloads. Preserve historical login snapshots beside stable
numeric identity; recycled logins cannot redirect an action or evidence.

### M5-R05 — Assent, correction, revocation and re-signing

Acceptance requires an affirmative action after the complete agreement and
required fields/confirmations were shown. Record the exact existing M1 evidence,
recipient, version/digest, fields/labels, nonce and event identity. A correction
is a fresh explicit acceptance linked to and superseding the previous one; an
administrator cannot edit signer-submitted data.

Revocation identifies exactly the subject/project/agreement/recipient tuple,
cuts off every earlier acceptance by canonical order and applies wherever that
tuple is enforced, including later-added repositories. Confirm that evidence
remains and prior rights are not withdrawn. A concurrent later acceptance
defeats a stale confirmation. Success names the tuple and offers Restore
coverage through the active agreement with fresh assent. Version activation,
restore, scope change or exemption withdrawal must not silently revive a revoked
acceptance. No quota based solely on prior successful signing/revocation may
trap the contributor in covered status.

### M5-R06 — Immutable publication, activation and exact restore

Publish a version from the parent's immutable GitHub repository or gist
reference, retaining its exact content snapshot, content commit OID, metadata,
recipient and verified digest atomically with the event. Publication alone
changes neither coverage nor the signing target. Do not infer legal meaning.

Ordinary immediate activation selects one active version and the exact
accepted-version set from `supersedes_coverage`. It cannot revive retired
currency. Explicit restore names a prior ordinary activation, requires a reason
and reinstates precisely that activation's set. Neither operation revives a
revocation or superseded acceptance. Use project-wide mutation guards and the
existing O(1) active projection update, not rewritten subject history.

### M5-R07 — Canonical policy and configuration

Administer required fields, confirmation labels, privacy policy, retention and
correction text through attributable canonical events. Recipient identity is
immutable; a change requires the parent's distinct or explicit successor project.
Use M4's compatible canonical policy format and current writer behavior, with
advisory co-author trailers as the default. An explicit blocking opt-in shows
the existing aggregate-oracle, fabricated-trailer/jamming and unresolved-identity
warning. Never use an unsigned route flag or deployment-local policy as its
authority. Old data remains readable and unsupported/downgrading writers deny.

### M5-R08 — Exact live administrative evidence

Implement every in-scope row of the parent administrative matrix, including
connection, transfer, succession, key activation, agreement/policy/source
administration, scope, override and retry. Authenticate and recheck each required
resource independently. Preserve all owner, repository-admin and installation
checks, not a representative permission. Canonical evidence records the stable
actor, resource, operation, required authority, observed result and check time.
Current session identity or authority over another resource is insufficient.
Read-only inspection has no mutation form and grants no write authority.

### M5-R09 — Verified wrapping, Connect and project lifecycle

Provide the authenticated capability-specific wrapping/challenge and Connect
endpoints required by the existing installer. Bootstrap requests bind the exact
administrator, install provenance, arrangement, numeric repository IDs and
generation. Return only wrapped values and bound challenge results. Do not
persist raw project keys/challenges, expose roots, or create a general wrapping
or decryption oracle. Show the existing hosted-operator/controller disclosure.

M6 creates and authenticates the exact records README root, K/B, key/wrapped
copies and identical bootstrap manifest copies, and creates and authenticates
the existing independent idle operation cell, coverage fence and empty marker.
These required bootstrap writes follow the installer key/readiness proofs.
Together they are bootstrap material, not a complete semantic coverage projection. Full coverage source/agreement/
shards, private derived generations, config and the first canonical event remain
absent until genuine Connect. No fake active before-state or unconnected
coverage format is allowed.

Before the first private event, verify both actual data keys through adopter
recovery readiness and the current portal, enforcer and protected-control live
paths; validate the exact three manifest copies, key-candidate/bootstrap ancestry,
actual-data-key proof and initial key IDs. The first event pins those identities
as `project_connected`. Only then may canonical activation and M4 registry/route
publication make the arrangement effective. `keys_ready` is transient progress,
not a durable second truth state. A lost reply reruns the same bound checks and
idempotent first append rather than creating another connection.

M5 must acquire authenticated root/K/B/manifests, actual-key and installed
proofs, existing generations-absence and exact independent guard/semantic-absence
observations for the single M4 writer. The real first event/config append
precedes full normal active/no-agreement coverage and private derived
materialization/readback and exact guard completion. M5 owns the fixed initial
acquisition and Python-engine integration needed before and after that append;
current connected-only readers are not claimed to supply it. A partial owned
operation resumes only its exact frozen package/ancestry, while a completed
repeat returns that canonical result without writes. Missing or corrupt normal
state cannot authorize bootstrap or a second project claim. Initial scope
request/activation and route publication remain separate after verified Connect.

A whole-arrangement owner transfer rechecks all three repositories and App
bindings; a partial transfer stays unavailable. Legal succession never rewrites
recipient or evidence. Preserve the parent's succeeded-project allowlist and
its continued revocation, scope removal, reader maintenance, recovery and history.
Project-key activation requires actual successor live/recovery proofs and keeps
old decryption history available. M6 owns generating/installing these materials;
fixtures are not proof that the live producers exist.

### M5-R10 — One durable mutation and materialization protocol

All actions call M4's shared canonical-mutation executor with existing M1
semantics and M3 recovery. Use encrypted prepared cells, exact scope/fence/marker,
append right, one-event non-forced canonical append, bounded conditional
projection updates and readback. The browser is not a recovery dependency.
Never return completed success before the relevant full effect is verified.
Uncertain outcomes retain guards and dispatch exact protected repair. This
includes the first Connect's idle/prepared/appending and appended-but-not-fully-
materialized states, using authenticated initial observations and the existing
engine. Normal readers remain connected-only; no second writer/replay engine,
state format, grant or persisted setup authority is introduced.

Update only affected bounded private derived shards and state/generations; no
ordinary Worker path performs full replay or export. Publish a class generation
only with its complete derived effect. Validate administrative bulk/member/
fanout limits before append. Preserve the parent rule that acceptance and
revocation evidence and coverage complete even when a private derived class
overflows; that class stays unavailable pending repair or a larger tested
profile. Do not introduce a lifetime action cap or a competing projection store.

### M5-R11 — Explicit exemption sources and continuous automation

Support individual/bot sources, selected team snapshots, explicit continuous
rules and withdrawal of one source. Human exemptions record the asserted
basis/instrument and administrator; they are not treated as signatures or legal
findings. Snapshot is the team default: display current members, freeze the
selected numeric identities in one atomic event and preserve them across retries.
Later membership changes do not change that snapshot.

Continuous rules require the parent's explicit delegation warning. Later
membership observations are independently attributable automation events with
their exact rule and GitHub evidence, not actions falsely attributed to the
original administrator. Only bound observable teams qualify. Combine active
sources by union; withdrawal shows every source still providing exemption.
Persisted current coverage changes only after the corresponding event/effect.
Authenticate membership doorbells and provide bounded missed-event reconciliation
without creating another truth or durable job store.

### M5-R12 — Current reader sources and bounded private disclosure

Support individual, selected snapshot and explicitly continuous reader sources,
source-specific withdrawals and their union. Snapshot is the default; continuous
delegation warns about future membership administrators. Neither source changes
GitHub repository ACLs. Reader and exemption authority remain separate.

Use the parent's authenticated 32-shard reader materialization, canonical
generation and exact scoped private-read proof. Verify all source shards before
issuance and require matching current canonical generation on every data page.
Continuous-source proofs additionally recheck that exact stable team's live
membership immediately before every disclosure. Prefer individual/snapshot
sources and let a fresh proof select another remaining source after one is
withdrawn. Loss of the final canonical source or live required membership denies
the next read; a proof's five-minute maximum is not an authorization cache.

Expose only fixed query/result classes and server-derived shard identities.
Allow no arbitrary path/ref/raw-decrypt interface or keys. Return filtered
private results with `private, no-store`; unknown projects and unauthorized
viewers use the parent's uniform response. M7's dashboard uses these same APIs
and sources, not a second allowlist. The subject's exact own-status exception
does not grant bulk or another subject's read authority.

### M5-R13 — Complete PR disclosure tiers

For one exact routed PR, preserve generic public output; show an authenticated
subject only their own status; permit current contributing-repository write
authority to see aggregate reason counts; permit current records readers to see
GitHub identities and exact per-subject reasons. No tier shows legal names,
emails, signer fields or raw acceptance evidence. Trailers/status detail obey
the same tier rather than providing a back door to identity lookup.

For private contributing repositories, keep the permission exchange to the
parent's signed, viewer/repository/expiry-bound yes/no result. Neither records
credentials nor a caller-selected project can acquire enforcement access.
Any additional minimal PR observation/result interface needed to implement
the already-required view must be purpose-bound, authenticated and restricted
to that exact current routed PR and disclosure tier. It must not broaden App
grants, return enforcement credentials, or create an arbitrary user/repository
lookup. The architecture must resolve this real integration requirement rather
than assert the view exists because permission checks exist.

### M5-R14 — Scope, conflicts, overrides and retry

Administer repository bindings and organization selectors with explicit current
owner consent, attributably recorded requested/activated changes and M4's full
non-overlap derivation. App installation alone is not agreement/scope consent.
Moves remove then bind; inspection discloses only the affected repository,
matching projects/selectors and required resolution authority. No precedence
choice, automatic move or signer disclosure is permitted. Recheck authority for
each resolution write. Scope changes alter routing, never legal grants or assent.

An override binds repository/PR/subject/root-tree identity with current maintain
authority; withdrawal is whole-grant and forward-looking. Retry requires current
write authority and targets one named PR/merge group. Neither is a bypass for
stale content, another actor, quarantine or a newer reservation.

### M5-R15 — Originating-PR continuation and repair

Preserve only validated project/PR/return context through browser-bound OAuth
and the authenticated action. After verified signing/revocation or an applicable
administrative effect, invoke M4's exact reevaluation service for that originating
PR. A caller cannot substitute another project, installation or arbitrary target.
Use the shared safe bounded retry; failure leaves an explicit incomplete
callback and the existing scheduled sweep repairs missed work. No global rescan,
durable receipt store or contributor-only GitHub re-request privilege is invented.

### M5-R16 — Explicit authenticated hosted exports

Dispatch only the fixed pinned protected control workflow for an authorized
request with exact project, request identity, source events OID and current or
historical view. Connect an actual authenticated authority adapter to M3's
existing hosted exporter; a file, boolean or unauthenticated dispatch cannot
authorize private access. Recheck current reader policy and continuous-source
membership before production and again before decrypting/delivering a result.
Bind the job to its approved execution identity and immutable request, including
lost response/retry, current-generation drift and unrelated mutations.

Retain only the existing encrypted request-scoped JSON/CSV pair on the derived
branch with its source identity; no Actions artifacts, logs or durable plaintext.
Expose the source OID and snapshot meaning, not a claim of later freshness.
Stream a permitted bounded result with private no-store headers and scoped
read-time authorization; JSON preserves canonical values and CSV neutralizes
untrusted formula cells. An incomplete pair, source/request mismatch, denied
reader or unsupported blob/job limit cannot produce a partial success. Offer
the existing local streaming CLI for larger exports; no Worker full replay is
introduced. Concurrent unrelated exports do not overwrite each other's pair.

### M5-R17 — Safe rendering, isolation and controller lifecycle

Treat agreement markup, labels, fields, project configuration and derived values
as untrusted. Use contextual escaping and the parent's explicit sanitization/
restrictive CSP where markup is supported. Protect all actions against CSRF,
same-origin confusion, callback substitution and credential leakage. Never log
private forms, evidence, tokens, cookies, keys, subject lists or uncontrolled
exception bodies. Operator diagnostics retain only safe categories and required
source/operation identities. Document transient plaintext and unavoidable
metadata limits honestly. Apply capability-specific key rotation and the
parent's incident quarantine/recovery rules; an overlap or logout request is
not immediate all-token containment.

### M5-R18 — Complete integration, bounds and line estimates

Define executable local Worker/HTTP tests for every full journey and important
failure, race, authorization loss, stale form, crash and lost reply. Reuse M4's
real runtime harness and Python-authored shared vectors. Include actual M3
recovery/hosted-export adapters and M4 coordinator/callback integration rather
than accepting mocks alone. Preserve missing-provider denial. M4 owns common
executor/bootstrap-transition fixtures and connected-operation recovery tests;
M5 owns the actual initial-acquisition/engine recovery journey through every
first-append/materialization interruption and write-free completed repeat;
M6 adds the real installer journey. Reuse shared fixtures/harness and count only
each milestone's extensions; M4 cannot depend on an unbuilt M5 adapter.

Use the existing tested M1 profile and M4 bounded runtime envelope; do not invent
unlimited inputs, skip complete pages or silently fit incomplete results.
Prepare separately authorized hosted/OAuth/private-read/Connect/export/cold
resource acceptance drivers; offline fixtures do not establish those facts.
Update the single capacity model with M5 traffic and measured dimensions.

The detailed plan must cover all requirements with ordered coherent slices and
concrete owned changes. Supply separate per-slice production/test LOC ranges,
milestone totals and evidence/uncertainty. Count incremental final delivered
nonblank physical lines, excluding comment-only lines and counting docstrings
physically. Include shipped config/instructions as production and test helpers,
generators/config/integration/live drivers as tests. Exclude designs, static
fixtures, generated/dependency/lock output and disposable probes. Count shared
M4 foundations once, not again in M5; keep edit churn and time estimates separate.

## 4. Observable acceptance and parent coverage

| M5 requirement | Governing parent obligations | Required evidence |
|---|---|---|
| R01 | CONFIG-1..4, AGR-3, PORTAL-1/4/5, SEC-3/7 | Public complete agreement/no evidence, inactive/no-active denial, aliases/rename, clear retention |
| R02 | SIGN-1, SEC-4/6/9, HLD §8.2 | Same-browser PKCE, callback replay/code swap, absolute expiry/no refresh, 401/403, logout/rotation |
| R03 | SIGN-5, REC-3/8, HLD §5.4/Table 5.4-A | Every allowed form pair, tamper/type/no-op/stale-head/retry conflict, forbidden internal events |
| R04 | PORTAL-1/5/6, SEC-2, SIGN-1 | Session-only self identity, canonical intermediate state, recycled-login and unknown/unauthorized tests |
| R05 | SIGN-1..5, REV-1..5, AGR-3 | Assent/correction/revoke/re-sign end to end; tuple-wide cutoff, interleaved acceptance and source history preserved |
| R06 | AGR-1..4, REC-3/4/5/8 | Immutable exact snapshot, publish versus activate, superseding/non-superseding sets and exact restore without revival |
| R07 | CONFIG-2, CHECK-2, SEC-3/7, REC-8 | Immutable recipient, required labels/text, canonical advisory/opt-in v2, warning and downgrade denial |
| R08 | SEC-6, REC-8, HLD §6.8 | Complete positive and negative action/resource matrix; all connection/transfer checks and safe evidence |
| R09 | CONFIG-1/2/5, REC-1/7/8, SEC-9, OPS-4/6 | Verified bootstrap/idle guards before Connect with semantic projections/event/config absent; fresh installed proofs and authenticated initial acquisition; genuine first event before full normal materialization/readback; no premature registry/routes, exact recovery/write-free repeat, transfer/succession and lost reply |
| R10 | REC-3/6/8, CHECK-3/4, HLD §5.4/6.6 | Every persisted writer/projection crash, including owned first operation before/after genuine append; strict ordinary reader boundary, atomic full generation, bounded bulk and acceptance/revoke overflow |
| R11 | CHECK-2, REC-3/8, SEC-6, HLD §6.8 | Snapshot default/subset/nonce, explicit delegation, union/one-source withdrawal, authenticated missed membership event |
| R12 | REC-1, SEC-2/6, PORTAL-6, DASH-3/4 | All source types, all32-shard generation validation, next-read withdrawal/departure denial, proof/context tampering, no key/path oracle |
| R13 | CHECK-1/2, PORTAL-5/6, REC-2 | Every disclosure tier on public/private PRs, bound permission/observation responses, no token/grant/private-evidence leak |
| R14 | CONFIG-3/5, SEC-6, REC-8, HLD §6.8/7 | Overlap rejection, admin-only limited conflict inspection, explicit move, stale content/authority override and targeted retry |
| R15 | CHECK-4/5, initial scope item5 | Bound originating PR after mutation, retry/lost callback and existing sweep recovery, no target substitution |
| R16 | REC-5, SEC-2/6/8, HLD §6.6, M3 export | Authenticated real protected job/adapter, reader loss/source drift, concurrent pairs, current/history JSON/CSV and bounded private delivery |
| R17 | SEC-1/2/4/8/9, OPS-5/6 | Malicious markup/formula/CSRF, captured-error redaction, controller/rotation/quarantine and self-hosted isolation |
| R18 | OPS-1/2/3/5/6, VERIFY-1/2, full parent journeys | Source-bound actual local integration, sensitivity and runnable authorized live drivers; credible complete separate estimates |

The detailed plan must map this entire table and its surrounding prose to
ownership and checks. A fixture is evidence only for its actual boundary.
Authentic release/install, real OAuth/App visibility, hosted resource limits
and real credential containment remain distinct execution/production gates.
No new owner decision is currently identified. If engineering evidence forces
a genuinely different product or trust choice, state that choice explicitly;
do not hide a scope reduction in a claim that M5 is complete.
