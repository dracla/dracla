# M5 — Portal, Connect, signing and administration architecture

Status: architecture draft under the existing approved product direction.
This specifies the full [M5 requirements](requirements.md); it does not claim
implementation, installed credentials, hosted acceptance or a new human
read-through. A new material scope, actor, permission, trust or public-behavior
choice requires the owner. Ordinary derived engineering does not restart approval.

The [global architecture](../high-level-design.md),
[M1 formats and semantics](../lld/m1-conformance-kernel.md),
[M3 recovery/export plan](../lld/m3-control-reconciler.md), and
[M4 architecture](../m4/high-level-design.md) and
[detailed engineering](../m4/implementation-plan.md) govern this design.
The [engineering basis](supporting/high-level-design/engineering-basis.md)
records inspected source, feasibility references, alternatives and finite
remaining engineering. It is supporting evidence, not another architecture.

## 1. Selected structure and responsibilities

Keep the approved static portal shell, one authenticated portal/API origin,
separate cookieless agreement origin, two capability-isolated Workers, existing
session KV and Git-hosted canonical truth. No new Worker, database, approval/job
store, public signer directory, replay engine or canonical mutation protocol.

| Component | Responsibility and boundary |
|---|---|
| Static portal assets under `dashboard/portal/` | Public project shell, sign/revoke/admin/Connect forms, exact own-status and PR views, bounded private-page and export clients. No GitHub token, raw project key or authoritative policy in browser storage. M7 extends this asset tree for dashboard/badges. |
| Portal authentication | PKCE/OAuth callback, encrypted pre-auth/session cookies, existing live-session KV, current GitHub identity and purpose-separated key eligibility. Session identity alone never proves an action or reader permission. |
| Portal presentation and form service | Current canonical/public presentation, exact M1 form issuance and verification, static-shell response models and fixed safe errors. Public agreement data is an explicit allowlist, not a decrypted-record endpoint. |
| Portal action handlers | Build the complete approved event-specific package, recheck live authority, and invoke M4's shared writer/coordinator. They do not own another append or recovery engine. |
| Portal private-read service | Authenticate all reader-source shards and current generation, resolve source union, issue the parent's exact scoped proofs, validate one requested data page and records-App live membership before disclosure. M7 uses the same service. |
| Connect and key adapters | Capability-specific transient wrapping/challenges, complete bootstrap/key-binding proof, exact first connection/owner transfer/succession/key activation and current grants. M6 supplies the installed materials and orchestrates setup. |
| Isolated enforcer extensions | Exact viewer/resource permission results, minimal bound-team and PR facts/results, coverage-only wrapping/challenges and originating-PR reevaluation. No records key, canonical signer evidence or session/OAuth secret. |
| Source automation | Observe authenticated bound team changes, append exact automation events using existing rules and writer, and reconcile missed observations within tested bounds. No authority cache or separate membership truth. |
| Protected export adapter | Bind explicit request, current reader/session and authentic pinned control execution to M3's actual hosted renderer; reauthorize download and stream only the requested encrypted snapshot's plaintext. |

M4's runtime clients, budgets, exact repository/key bindings, actual Worker
harness, route/gate coordinator and durable mutation executor are prerequisites.
They are reviewed plans, not installed production code. M3 remains the bulk
history/replay/repair/export renderer. The current TS codecs and Python renderer
are reuse, not evidence that M5's production adapters already exist.

The simpler existing static-shell/API structure meets the required journeys.
An additional server-rendering framework, generic repository proxy, durable
job queue or alternative signing/recovery path supplies no approved invariant.
Use browser-native controls and small typed clients; the detailed plan owns
concrete packaging and tests without introducing a competing application shell.

## 2. Origins, assets and public content

`portal_origin` serves both the static shell and all browser APIs. The existing
portal Worker asset binding can serve the shell; M7 adds dashboard assets to
that same deployment. Force OAuth callbacks, all APIs and fixed machine
operations through the Worker before SPA/asset fallback. Unknown API routes
return their fixed error, never a successful HTML shell. Public CSS/JS/assets
can remain static. There is no credentialed cross-origin portal API.

Portal cookies retain `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`
and no `Domain`. Deliver the parent clickjacking controls on the shell as well
as APIs: `frame-ancestors 'none'` and `X-Frame-Options: DENY`. Limit scripts and
connections to the controlled origin; allow frames only from the configured
agreement origin. No tenant HTML executes in the privileged shell.

`agreement_origin` is the already-required separate HTTPS cookieless origin.
It uses a strictly public host branch of the existing portal deployment, not
a third privileged Worker. Serve only bounded public agreement content/static
presentation; do not route its requests to OAuth, session, admin, export,
wrapping or private-read handlers. Ignore/discard credential headers there,
never set a cookie, and never log raw request content. The iframe is sandboxed
without same-origin, form or top-navigation privileges. Only the fixed trusted
viewer script may run, under a build-pinned CSP hash; tenant scripts and styles
are forbidden. Apply allowlist sanitization as defense in depth. The frame
cannot read the parent's session/API even if sanitization fails. Serve the
literal immutable agreement bytes as an accessible alternative; never silently
omit their text.

The static viewer fetches only the exact public agreement bytes without
credentials, validates their existing content digest, sanitizes/renders them
and reports readiness for that exact presentation. Its public content endpoint
may use credential-free CORS; private portal APIs may not. The parent accepts
only the expected frame window, fresh view nonce and matching project/version/
digest; an opaque sandbox origin string alone is not authentication. A failed
or missing ready signal leaves assent disabled. Messages contain no private
fields and cannot submit a form or authorize an action. This is display
readiness, not proof that a human read the document; actual assent remains the
explicit authenticated action. The detailed plan fixes the closed message and
renderer/allowlist/header tests.

The public signing presentation contains only the configured public project,
agreement/recipient/version/digest, required field definitions and labels,
privacy/retention/correction text and current presentation source identity.
No stored signer values, reader list, private scope list or evidence is returned.
Cache only public data under the parent's project/version identity. Before
issuing a form, compare its displayed presentation/configuration source with
the freshly authenticated canonical head and current active version/labels.
A stale cached field set must be refreshed, even when the agreement version
did not change. Cache expiry is not the confirmation or authorization proof.

## 3. Concrete browser and machine interfaces

These interfaces implement the approved journeys. They add no public
automation SDK, arbitrary repository proxy or new credential grant. Inputs are
closed and bounded. The detailed plan fixes exact wire fields/codecs and
limits while preserving these identities and effects.

| Interface | Input and observable result |
|---|---|
| `GET /p/<owner>[/<slug>]` | Existing stable project shell. Resolve registry identity/rename; show the public agreement, then authenticated own actions. No active agreement means no sign button. |
| `GET /oauth/start`, `GET /oauth/callback` | Validated project/PR/return context and browser-bound state; exact GitHub exchange on the server; a new session or safe restart/denial. No callback token reaches client JS. |
| `POST /logout` | Same-origin live session; delete browser cookie and request KV deletion, without promising immediate global revocation. |
| `GET /api/projects/<project_id>/signing` | Public allowlisted current presentation; no subject argument or signer status. |
| `GET /api/projects/<project_id>/me` | Current GitHub/session identity supplies the subject. Return own tuple status/reason/actions and proven pending effect, never arbitrary users or historical submitted fields. |
| `POST /api/projects/<project_id>/forms/<type>` | Closed Table 5.4-A operation and displayed source. Return current display plus the existing signed action-form envelope, or require a fresh presentation. Internal automation types reject. |
| `POST /sign`, `POST /revoke` | Existing contributor actions: exact signed form and submitted operation. Corrections/re-signing use `/sign`; no parallel acceptance path. Return exact original event/no-op, completed effect, recorded/taking-effect or conflict/unavailable. |
| `POST /admin/<canonical_type>` | Existing administrative form types only. Exact project/resource/payload comes from the verified form; no generic method name or caller-selected authority provider. |
| `GET /repositories/<repository_id>/control`, `GET /api/repositories/<repository_id>/conflict` | Project-independent conflict shell and read-only bounded inspection. Current admin on that affected repository is required before any matching project/selector or resolution-authority disclosure. No mutation form or records-reader access follows. |
| `GET /api/projects/<project_id>/teams/<team_id>/selection` | Current records-admin authority and a team observable through the accepted bound capability: records App for reader sources; records App or the approved enforcer observation for exemptions. Return a complete bounded numeric selection or unavailable; no public team directory or automatic continuous delegation. |
| `POST /api/projects/<project_id>/read-authorizations` | One of the parent's two result classes and its exact permitted scope. Current reader union authorizes issuance of the original five-minute/session-bounded private-read proof. |
| `GET /api/projects/<project_id>/index/<shard>` | Project-scoped `reader_index` proof, same live actor and current generation; one fixed filtered index shard page. |
| `GET /api/projects/<project_id>/subject-status` | Derive the subject only from the exact verified `reader_subject_status` proof, current generation and bound live membership; one filtered exact-status result. No separate user-ID/path/ref parameter, own-status bypass or raw-record API. |
| `GET /p/<owner>[/<slug>]/pr/<number>` | Existing PR shell. Generated links also bind the numeric contributing repository, carried through the validated browser/OAuth context. A bare project/PR number never selects among multiple repositories by guess. |
| `POST /api/projects/<project_id>/pr-view` | Exact contributing repository/PR and requested maximum tier. Server derives the permitted tier and returns only self reason, aggregate counts or reader-authorized GitHub identities; reader status pages use their exact proofs. |
| `GET /connect` and fixed bootstrap context/wrap/challenge operations | Existing authenticated installer/Connect journey. Exact arrangement/generation/key commitments and current authority; only bound wrapped values and challenge results. No broad provisioning credential or raw key enters browser JS. |
| `POST /api/projects/<project_id>/exports` | Explicit view/source/request identity, current reader authority and session. Dispatch only the fixed protected job; return pending/snapshot identity, not a completed plaintext result. |
| `GET /api/projects/<project_id>/exports/<request_id>?format=json\|csv` | Recheck current reader and request/source/pair identities before decrypting and streaming one permitted result. No path/ref parameter or public download bearer URL. |

The project's PR path stays unchanged. A complete PR identity includes its
numeric repository and PR number. Generated links can carry the repository as
`repository_id` context; signed OAuth state retains it. Validate it against the
current project route/gate. If context is absent and the complete registry does
not establish exactly one contributing repository, return generic unavailable
guidance to reopen the exact check link. Do not enumerate private repositories,
scan all same-number PRs, use `Referer` as authority or introduce a second
repository-selection workflow. M5 owns the corresponding link-builder extension
and M4 integration test; no generic public lookup is added.

All sensitive POSTs require the exact same origin and CSRF/form protections.
Use safe `401`/OAuth restart for expired/revoked authentication; authenticated
insufficient action authority is `403`; stale/changed confirmation is `409`;
dependency, completeness or uncertain processing is `503`. Private unknown and
unauthorized targets keep the parent's uniform `404`. Browser-facing error
text never contains raw exceptions, private records or foreign project data.

## 4. OAuth, sessions and authenticated forms

Generate the pre-auth nonce and PKCE verifier with the platform CSPRNG.
Sign purpose/project/PR/return context, encrypt the browser's pre-auth cookie and require
nonce equality, signature, ten-minute lifetime and exact redirect URI at the
callback. Exchange with S256 verifier on the server, delete the pre-auth cookie
after the response, discard refresh tokens and authenticate `/user` before
minting a session. A duplicate callback cannot successfully exchange the same
code again; KV read/delete atomicity is not the defense.

Keep user tokens only in the existing live-session KV. Cookie and KV expire
at the same absolute token-expiry-minus-five-minutes instant, never a sliding
window. Missing expiry or a token too close to expiry cannot create a conforming
session. Configure expiring GitHub App user tokens; request no unrelated OAuth
scopes. Project-independent conflict inspection and pre-connection bootstrap
use their explicit repository/setup purpose, not a fabricated project or an
arbitrary redirect. The closed context union and return allowlist cover these
already-required journeys. Revalidate GitHub identity on sign, revoke, every administrative action
and private read. Current `401` removes the session and restarts authentication;
`403` denies only the action. Logout and key rotation keep their documented
bounded/eventual limits, not an all-token-containment claim.

The browser obtains an action form only after the complete display and any
required warning/selection. Use the existing M1 `encodeActionForm`,
`verifyActionForm`, closed `FORM_ACTION_TYPES` and terminal-no-op validator.
Recompute the exact target/payload digest and require the live session/actor,
project, type, nonce, confirmed head and eligible key/time to match. No submitted
user ID, permission boolean or arbitrary event type supplies authority.

An exact terminal proof returns that same no-op forever; it cannot later write.
A write-bound form requires the current canonical head to equal its displayed
head before preparation, including unrelated advancement. A lost reply retries
the original form/event identity. Changing target, fields, selected members or
meaning with that nonce conflicts. Rendering again creates a fresh explicit
action; the UI does not silently retarget a stale signed submission.

Session AEAD, action-form and private-read proof keys remain separate. Short
bootstrap/export context envelopes reuse the appropriate existing typed
cryptographic primitives/key family with distinct purpose/domain and closed
scope; they are never valid M1 forms or ordinary private-read proofs. They bind
the original live session and exact request, not a durable permission verdict.
The detailed plan must specify their exact encoding, purpose, expiry and
eligible-key behavior before implementation; unknown or expired context denies.

## 5. Contributor and agreement journeys

1. Resolve the immutable project and fetch the complete public presentation.
   Render agreement markup only in the isolated frame. The privileged shell
   presents recipient/version, labels, privacy and evidence-retention text.
2. Authenticate if needed. Re-read current canonical presentation before
   issuing the action form; changed agreement, fields or head requires review
   and fresh assent. No page visit, login or PR creation is consent.
3. Acceptance freezes the existing event evidence and exact side artifacts.
   Corrections use a new acceptance with `supersedes`; administrators cannot
   edit the original fields. Invoke the single M4 writer.
4. Distinguish canonical event recorded from coverage effect completed. Own
   status uses authenticated canonical/event/operation evidence during a pending
   materialization, not a stale derived row or a full edge replay. An unproved
   state is unavailable and triggers protected repair, not guessed signed status.
5. After verified effect, call only M4's bound originating-PR reevaluation.
   Incomplete callbacks remain explicit; bounded retry and scheduled sweep
   repair missed work without granting contributors GitHub write privileges.

Revocation displays the exact subject/project/agreement/recipient tuple and
explains the future contribution effect, retained evidence and prior-rights
limit. It cuts off all earlier acceptances by canonical position. An acceptance
that lands after confirmation invalidates the stale form. Successful revocation
offers Restore coverage by opening the active agreement for fresh assent.
Activation, restore and later scope changes cannot undo that revocation.

Publishing stores the exact immutable reference, content OID, digest, snapshot
and metadata atomically with `agreement_published`. It never activates a version.
Activation computes the existing exact accepted/retired sets from the explicit
superseding flag. Restore names the exact prior ordinary activation and reason;
it changes currency, not the subject's independent revocation/correction basis.
Project-wide guards and constant-size active controls prevent partial currency.

Configuration uses M4's compatible canonical v2 policy. Advisory trailers remain
the default; the explicit opt-in screen explains fabricated-trailer, aggregate
oracle, jamming and unresolved-identity risks. Required fields/labels, privacy,
retention and correction text are canonical configuration, not environment
flags. The legal recipient is immutable; a different recipient uses the
existing distinct/successor-project flow and new agreement.

## 6. Current administrative authority and durable actions

Use the complete requirements action/resource matrix and global Table 5.4-A.
The current authenticated GitHub identity and the exact checked subject/resource
must agree. Records-side checks use the actor's user-to-server token. An App
installation's own privilege is not the actor's permission. For contributing
resources, use the enforcer's minimum named-user permission/membership result.
Other required arrangement/installation facts are obtained only through the
appropriate already-bound capability and current GitHub-approved setup path.

Connect/transfer retains all seven owner, repository-admin and App-binding
checks. Verify active installation/account/repository IDs and accepted grants,
not an installation URL, secret name or browser assertion. A GitHub policy/SSO
state or unavailable current-operation permission that cannot be proved denies
the action. Do not request provisioning privileges, silently add App grants or
share the installer's general GitHub credential to manufacture that proof.
The detailed plan must name each actual supported observation/provider and its
negative cases; installed-account authority acceptance remains a real gate.

Each administrative event records the actor/login snapshot and all exact
resource/operation/required-authority/result/time evidence. Recheck authority
before state-dependent append and scope activation; losing it leaves the
existing recoverable conflict/guarded state rather than activating another actor's
request. Records-reader authority never follows from admin or inspection alone.

Action handlers use M4 `submitMutation` and the existing M1 prepared-cell,
fence/marker/append/projection/readback protocol. Action-specific builders supply
complete authenticated packages and no alternate append engine. For bounded
bulk work, validate limits before append and publish the derived generation
only after the complete effect. Normal handlers update affected shards only.
Acceptance/revocation retain canonical evidence and coverage even if a private
derived class overflows; that class denies reads and invokes M3 repair. A
private-class limit is not a lifetime cap on contributor actions.

Scope forms produce the existing requested/activated M4 protocol. Moves remove
then bind; GitHub-created overlap quarantines affected repositories only.
Conflict inspection shows only the affected repository, matching projects and
selectors, and required authority; each resolution write is checked separately.
Exact PR/tree/subject overrides require maintain authority and whole-grant
forward-looking withdrawal. Retry requires write authority and targets one PR
or merge group. Neither clears a reservation/quarantine or changes legal assent.

## 7. Connect, wrapping and lifecycle

The installer remains the local administrator's operation. It generates actual
project/control/recovery keys and proves recovery before private writes. The
portal never receives that general provisioning credential or the adopter's
transport App private key. Browser JS receives no raw key. The existing
authenticated bootstrap channel carries only the exact capability's raw key
transiently to its service after the disclosed hosted-controller confirmation.

The browser authorizes the exact setup context under the live portal session:
owner, three numeric repository IDs, project/install generation, installed
release provenance, capability, wrapper identity, kid and actual-key fingerprints,
setup purpose and retry identity. An opaque purpose-bound context lets the installer submit that same request without
copying its GitHub credential or the browser's session cookie. It permits no
wildcard key, project, destination or generation. Every use rechecks the live
session, exact current authority and setup facts; it is not a new approval store.

Use three distinct closed service operations with separate roots and exact
wrapper identities; the approved portal needs both records and coverage keys.

| Receiving service | Capability and wrapper | Required independent live path |
|---|---|---|
| `worker-portal` | `records`, `portal-records` | Records wrapping and records unwrap/challenge |
| `worker-portal` | `coverage`, `portal-coverage` | Portal coverage wrapping and portal coverage unwrap/challenge |
| `worker-enforce` | `coverage`, `enforcer-coverage` | Enforcer coverage wrapping and enforcer coverage unwrap/challenge |

Each operation rejects another capability/wrapper or setup purpose. The
enforcer asks a fixed private portal authorization service to validate the opaque
setup context and current authority before key use. That service returns only
the exact bound authorization result, never HMAC/session keys or raw data keys.
No service forwards a raw key to another service. Reuse M3's actual-data-key
fingerprint/binding format; verify supplied key bytes against the authorized
project/capability/kid fingerprint and bind the wrapping/challenge response to
the exact repository arrangement, generation, wrapper, provenance, live admin/
session, nonce and retry identity. Return only bound wrapped objects and
challenge results, never stored raw keys or a general decrypt/wrap API.

M6's protected control proof uses the installed pinned workflow and exact
non-private challenge/run/generation context. Verify both actual recovery keys,
the distinct portal-records, portal-coverage and enforcer-coverage live paths,
control proof, three bootstrap manifest copies, K/B ancestry,
candidate-key binding proof and current key IDs before the first private event.
For a new first claim, Connect authenticates exact root/K/B/manifests and key
proofs, plus the independent idle operations cell, idle coverage fence and empty
marker at exact branch heads. Require the records README-only root with zero
canonical events, absent project config and materialization generations, and
exact absence of every semantic coverage source/agreement/shard and private
derived generation. Use M1's existing `generations-absence` evidence. A partial,
changed, malformed or foreign artifact cannot stand in for absence. A non-idle
cell or guard cannot authorize a new claim; only the exact owned-operation
continuation below may resume it. No fake active or unconnected full projection.

The single M4 writer freezes `project_connected` and its exact config/generation
inputs, then commits that genuine event plus the encrypted project config and
materialization-generation side artifacts in one canonical commit or none.
The event pins the exact verified bootstrap/candidate/key identities. Only after
that append does it build full normal active/no-agreement coverage and private
derived state, read back every required effect and finish the exact operation/
marker/fence. An active project with no active agreement is not unconnected.
Only verified completion can start the separate requested/activated scope
protocol; the first event publishes no route directly.

M5 owns the narrow initial-observation, authenticated bootstrap key-selection,
absent-derived and fixed `MutationEngine`/reconciliation integration required
by this journey. Current ordinary M3 history/preconditions require connected
state and do not already supply this seam. Keep those normal readers strict;
reuse their engine and M1 formats rather than introducing another writer,
replay model or caller-selected provider. M4 owns common executor/transition
fixtures and connected-operation recovery; M5 supplies and tests actual initial
acquisition/engine recovery, and M6 adds the real installer journey.

Before and after the first append, recovery validates the exact frozen package,
operation owner, parent/commit ancestry, K/B/key bindings and declared persisted
effects. Resume only that accepted operation; an unrelated non-idle owner or
inconsistent partial effect blocks without overwrite or a second claim. A
completed repeat returns its exact canonical result without writes. A new
Connect request repeats current checks; protected continuation after durable
preparation does not require the original browser or a persisted `keys_ready`
permission. Full normal validation resumes after materialization completes.

`keys_ready` remains invocation-local. An interrupted setup reruns current
authority/provenance/challenges and the exact idempotent first append, rather
than trusting a persisted boolean. No partial bootstrap or lost response may
create a second project claim. An actual challenge failure retains the prior
safe state. M6 installs compatible M4 policy/control/Worker versions before v2
writes; an old installed reader/writer fails closed.

Whole-arrangement owner transfer verifies the new owner, all three repositories
and App bindings and then uses M4's bound generation transition. Partial
transfers stay unavailable. Succession verifies the new connection and active
agreement before closing the old project. Preserve the old lifecycle's explicit
revocation, scope removal, reader maintenance, recovery and historical access;
do not silently permit new signing or legal expansion. Key activation proves
the actual successor through every applicable service path, including separate
portal and enforcer coverage challenges, and control/recovery before selecting it,
retaining old history keys. Shared incidents use M4's real containment/restore
protocol; routine wrapping is not proof of all-token or leaked-data-key cutoff.

### 7.1 Later replacement-recovery boundary

Global §9.1.1's new schema2 repository rebind is a separate protected recovery
operation owned by prospective M6 extensions, not another Connect, owner-transfer
form or registry-only alias. M5 provides the existing current owner/resource/App
and independent wrapping/live-key challenge services; M6 composes them with
adopter recovery possession, exact source history and the shared guarded writer.
Raw mirror copy preserves broken/incomplete application state without repair or
continuing imported work. Separate explicit activation requires an already
healthy idle source; only its own newly accepted rebind operation may retry.
New targets stay unbound during copy/health checks and existing source routes
remain unchanged on unhealthy denial. Healthy confirmed activation conditionally
stages current registry/gates and revalidates heads before keys/jobs/rebind.
Every live replacement meets initial-installation privacy, permissions, protected
execution, key and readback standards before routes return. Keep current session
identity separate from those proofs. After rebind, ordinary actions and private
reads require the fully validated current replayed repository set, while old
authorizations retain their historical set. No generic missing-bootstrap fallback,
old-permission grant, second project claim, history conversion or new public form
is added. M5 ordinary acceptance stays independently complete before the later
M6 recovery extension and its assembled tests.

## 8. Exemption, reader and private-read journeys

Individual and bot exemptions use existing explicit sources. Human sources
retain the asserted basis/instrument and administrator; DraCLA makes no legal
finding. Team selection defaults to a snapshot: show current members, freeze
the selected numeric subset in one event and preserve that set on retries.
Continuous requires explicit delegation and its future-membership warning.
Later observations are rule-bound automation events with GitHub evidence,
not repeated acts attributed to the original administrator.

Sources combine by union. Withdraw exactly one source and report remaining
active sources; do not toggle a user-wide boolean. Authenticate records-App
membership doorbells over the raw receiving route's SHA-256 signature before
parsing. Payloads only trigger fresh bound GitHub observations; they do not
choose a project, replace a member set or assert a permission by themselves.
Use daily bounded portal observations for missed doorbells, with the existing
M4 scan/budget infrastructure rather than a second scheduler or durable cursor
store. Protected M3 reconciliation repairs the exact already-prepared operation
before fresh observations proceed; it is not a new Actions membership poller.
M5 owns the actual observation and automation-event producers; naming today's M3 reconciler does not implement them.
Only committed/materialized exemption changes affect coverage. Reader authority
also has individual/snapshot/continuous sources, but its current live membership
rule remains a read-time requirement; repository ACLs and exemptions grant none.

Reader-source team selection and continuous observations use the records App.
Every live private-reader membership check also uses only that App's current
bound organization/team endpoint; the enforcer cannot supply reader authority.
If the required team is unobservable under the accepted records capability,
reject the rule or deny that read, while allowing another independently valid
canonical source. Do not expand grants or fall back to the enforcer.

For exemptions only, use the records capability where it can observe the bound
team; otherwise use the approved fixed enforcer team-observation operation.
It returns only the complete member IDs needed by the authorized exemption
selection/rule. Bind project, installed App, numeric organization/team,
exemption purpose and request identity, with current authority before disclosure.
Reject incomplete/oversized sets before a snapshot append. No arbitrary
organization API or enforcement credential is exported. Preserve the frozen
selected identities and observation context on snapshot retries; later
membership is not an instruction to retarget that submission.

Reader authorization reads one current canonical generation and one immutable
derived source snapshot. Validate all 32 reader-source shards, exact envelope
digests, tested size/rule/member limits and the canonical/derived generation
match. Prefer individual/snapshot sources; when a continuous source is needed,
verify its exact numeric organization/team/user membership now through the
records App. A failed source does not negate another proved source in the union; no proved source denies.

Issue only the parent's exact `reader_index`/project or
`reader_subject_status`/one-subject JWS, with its source, actor/session,
generation and bounded lifetime. Every page reauthenticates, reads current
canonical reader generation, checks the exact proof/scope and, for continuous,
rechecks that bound membership through the records App before returning
plaintext. A withdrawal or missed departure denies the next read. The client can request a new proof that
uses another current source; it cannot renew the old source verdict implicitly.

Data pages use existing selected private-class/shard validation. Add the
owned validated partial-coverage exact-status adapter identified in the basis,
sharing the existing full-status semantics and M4 observation machinery. No
fabricated full coverage projection or second evaluator. Validate current
class generation, encrypted digest, project/key identity and operation/lifecycle
guards. The own-status exception reads only the live subject; it is not an
alternate arbitrary-subject private API. Return no legal names, emails or raw
evidence in own-status, index or PR/status views; explicit reader exports own
that separate disclosure.

## 9. PR disclosure and continuation

Keep the named enforcer permission operation closed: current viewer/repository/
operation/expiry-bound signed yes/no result only. Its signer and verification
material preserve the existing enforcer/portal split; the detailed plan fixes
the codec and key lifecycle. No token or repository payload is hidden in that
permission response.

A separate fixed PR-view observation/result operation serves the already-required
graded view. The portal authenticates the viewer and derives the maximum allowed
tier. For a reader request it resolves current canonical reader authorization
before asking for minimal named-subject observations. The private service call
binds the exact request/project/repository/PR/purpose; a public request or a
serialized client permission flag cannot invoke or construct that authority.

The enforcer independently validates current project route/gate, repository,
installation and complete PR/head/tree/subject facts. Self results disclose only
the viewer's own contextual reason. Aggregate results repeat current write
authority and return counts/classes only. A named result returns only bounded
GitHub subject identity observations to the authorized portal; it contains no
decrypted records evidence. The portal resolves each exact subject's private
reason through the ordinary subject-proof/page service and repeats current
generation and records-App membership checks before disclosure. It does not
reuse an index proof for a different result class or add a bulk authorization cache.

Changed head/route/authority, missing context, incomplete subject listing or
ambiguous identity is unavailable. A lower-tier response never leaks named
subjects, private reasons, raw PR data or lists of projects/repositories. Legal
names, emails, signer fields and audit events appear in no PR view. Source
membership and current reader checks are not cached by the PR shell.

The originating-PR context survives only in validated browser state and the
authenticated operation. After verified mutation effect, M4 reevaluates that
exact current PR through its existing credential/route checks. Safe bounded
retry plus scheduled sweep repairs missed callbacks. No global rescan, guessed
repository, contributor privilege escalation or durable callback receipt store.

## 10. Authenticated hosted-export integration

The portal authorizes an explicit reader request and freezes the existing M3
request identity, source events OID and current/historical view. A purpose-bound
opaque request context binds that selection to the live viewer/session and
current source. It supplies no saved `authorized:true`, GitHub user token,
raw key, arbitrary output path or shell command. It cannot be reused for another
project/view/source/request. Delayed or expired contexts require fresh
authorization; there is no silent token refresh or new durable job registry.

Use the existing trigger-only capability to dispatch the fixed pinned control
workflow. Its actual run, numeric control repository, workflow source SHA,
purpose and request digest authenticate through M4's protected OIDC machinery,
with a distinct fixed export purpose/endpoint rather than adding an arbitrary
method to the closed recovery protocol. Verify the installed release and control
identity before secrets/data-key access. Request data enters Python as inert
files, never event interpolation in `run:`/`env:` or a selected executable.

The Python `HostedExportAuthority` adapter owns the fixed authenticated portal
exchange. `authenticate_request(exact_request)` verifies that authentic job and
request context against current GitHub/session/reader policy before M3 acquires
history keys; `is_team_member` obtains the exact bound current records-App
membership result, never an enforcer observation. Only this trusted invocation constructs that provider. Files, a transport token,
an operator PAT or a deserialized principal cannot select it. Missing adapters
preserve today's explicit `hosted-authorization-required` denial.

M3 keeps its actual renderer, current/historical observation semantics, encrypted
request-scoped JSON/CSV pair, exact source/request conflict checks and final
reader gate. Reuse the existing output/record ceilings. Different requests do
not overwrite a pair; retry of the same request verifies the same retained
snapshot. Signing/admin work never regenerates exports. An incomplete pair,
source mismatch, denied final authority or exceeded job/blob limit is not
success; the UI offers the existing local streaming CLI for larger work.

The portal polls only the exact encrypted pair's current metadata, not an
Actions artifact or new receipt store. Before decrypting/streaming a download,
authenticate the current reader and any continuous membership through the
records App again and validate the selected request/source/pair. Return private/no-store JSON or CSV with its
source OID and snapshot wording. JSON keeps canonical values; CSV neutralizes
formula cells before encryption. Do not persist plaintext in logs, Git,
workflow output, caches or another download location. A former reader cannot
use a retained URL or an earlier job result as current authority.

## 11. Bounds, compatibility and acceptance

Load the existing M1 release profile and M4 immutable runtime profile. Runtime
and browser input/HTTP/crypto/allocation limits are checked before expensive
work, with shared nested accounting. Private reader-source envelopes are larger
than coverage envelopes: pack batches by both the actual class byte bound and
the response-byte ceiling, not merely the maximum alias count. Count cold
key/token acquisition, source/generation reads, up to 10 continuous-source checks,
proof issuance, every page, callbacks, bulk changes and hosted dispatch/delivery.
There is no authority-cache shortcut to fit a scalar request estimate.

M6 installs compatible origins, asset routing/security headers, secret families,
service entrypoints, App bindings and protected control/release pins. M5 cannot
claim readiness from a benchmark Worker, unsigned fixture or mutable installed
binding. Existing source/format1 history remains readable; M4's supported policy2
and exact old-reader denial apply to all M5 producers. No old current-write
compatibility path silently drops an explicit policy.

The detailed plan must resolve finite engineering before implementation:

- Exact closed bootstrap/export contexts, current authority providers and their
  source, purpose, session, time, key-eligibility and retry bindings.
- Complete API body/response/CSRF/escape contracts, isolated frame renderer and
  current public configuration/confirmation binding.
- Minimal permission/PR-view service unions and partial-status API parity,
  without new credentials, result classes, replay or full per-page coverage.
- Actual initial Connect/key/control-challenge and protected hosted-export
  adapters, compatible control schema/workflow ownership and missing-provider denial.
  M5 owns authenticated root-only/owned-operation observations, bootstrap key
  selection, absent-derived and fixed existing-engine integration; ordinary
  connected history is never relaxed to make those adapters appear present.
- Concrete M5 input/work/fanout/job limits, complete per-slice ownership,
  integration/sensitivity cases and separately grounded production/test LOC.

| Requirements | Responsibility and observable architecture acceptance |
|---|---|
| R01, R17 | Static same-origin shell plus isolated agreement branch; complete accessible legal presentation, public allowlist, hostile markup/CSRF/frame/header tests |
| R02, R03 | OAuth/session and existing form services; same-browser S256, absolute expiry, current identity, exact registry/no-op/head/digest and key rotation |
| R04, R05 | Self/action handlers plus shared writer/status adapter; canonical pending evidence, correction/revocation races, fresh re-sign and originating callback |
| R06, R07 | Agreement/policy handlers; immutable snapshots, exact accepted/retired/restore semantics, current configuration and advisory/opt-in v2 |
| R08, R14 | Current action-specific authority plus M4 coordinator; complete seven-check Connect evidence, conflict disclosure, scope/override/retry negative matrix |
| R09 | Exact bootstrap/idle-cell/fence/marker and total semantic absence for a new claim; atomic first event/config/generation, full normal materialization, actual M5 initial recovery/write-free repeat, both actual-key/live proofs and transfer/succession |
| R10 | M4 writer and M5 event-specific materialization; every crash/readback boundary, complete bulk generation, overflow and actual M3 recovery |
| R11 | Source forms and bounded automation; default frozen snapshot, explicit continuous delegation, union/withdrawal and missed-event repair |
| R12 | Current reader/proof/private-page service; all 32 source shards, exact per-page scope/generation/membership and immediate next-read denial |
| R13 | Fixed enforcer permission and PR-view interfaces plus subject-status service; every public/private tier, duplicate PR numbers, head/authority races and no private-evidence leakage |
| R15 | Exact context and existing M4 callback/sweep; no target substitution, lost reply and missed callback repair |
| R16 | Trigger/OIDC/trusted export provider and existing M3 renderer; concurrent source-bound pairs, current/historical views, expiry/reader-loss and private delivery |
| R18 | Real local Worker/browser/HTTP and Python integration, cost traces and separately authorized live drivers; full ordered slices and distinct final delivered LOC |

Requirements and architecture review do not establish implemented/live facts.
Actual GitHub policy/permission/OAuth behavior, installed bootstrap/control
readiness, hosted cold mutation/read/export limits and real containment remain
separate authorized execution gates. If a required provider cannot satisfy the
contract within accepted grants, bring back that concrete permission/trust or
behavior choice. No new owner decision is currently proposed by this draft.
