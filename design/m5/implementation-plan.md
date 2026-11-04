---
plan_key: m5
slice_convention: hierarchical-v1
slice_inventory: {"executable": false, "path": "slices.json", "sha256": "3cfe48e4669dde25a9e4888fc8d9667e895a545fda179eebfb0e5725a2a8e2f2"}
---
# M5 — Portal, Connect, signing and administration implementation plan

Status: detailed draft for review. The existing architecture/public-contract
approval applies unchanged. This plan authorizes no product implementation,
credential use, hosted acceptance, installation or publication. The canonical
ordered definitions are in [slices.json](slices.json); the [overview](overview.md)
renders their status and separate production/test line ranges. Existing M1–M3
source, IDs, history, approvals and spent budgets remain intact.

The [requirements](requirements.md) and [architecture](high-level-design.md)
govern this plan with their reviewed transitive authorities. The
[engineering basis](supporting/implementation-plan/engineering-basis.md)
records inspected prerequisites, provider evidence and estimate reasoning.
It is supporting evidence, not another normative architecture or plan.

## 1. Outcome, dependencies and ownership

Provide the complete initial portal: public agreement and same-browser login,
own status, signing/correction/revocation/re-signing, agreement/config/source
administration, Connect/lifecycle, authorized PR views, exact scope/override/
retry and authenticated hosted exports. Keep one Individual CLA identifier per
project, immutable versions, source union and independent legal-recipient
identity. No entity CLA, new store, public signer directory, general proxy,
new App grant, second replay/evaluator/writer or alternate signing path.

M1 supplies normative identities, strict codecs, forms, event/replay semantics
and keyring/envelope formats. M3 supplies history, actual append/reconciliation,
recovery and export renderer. M4 must first supply the reviewed production
Worker/HTTP/SQLite harness, typed clients, partial coverage observation,
registry/route/gate coordinator, protected control authentication and shared
`submitMutation`. These are prerequisites, not already installed M5 code.
M6 owns local provisioning, exact installed release/control/bindings and both
hosted/self-hosted deployment. M7 extends the same static asset tree for
dashboard/badges and assembles release/demo evidence. Each milestone counts
its shared foundations once. No delivery starts from this design operation.

Use `api/src/portal/` for browser/public/auth/admin/reader/Connect endpoints,
`api/src/records/` for M5 adapters to the one M4 writer and private state,
`api/src/enforce/` for narrow signed permission/PR/team/wrapping operations,
`api/src/control/` for fixed protected bootstrap/export purposes, and
`core/dracla/records/` for actual Python adapters to M3. The static source tree
is `dashboard/portal/`; M7 adds its own assets there instead of another app.

## 2. Concrete runtime interfaces

The HLD route table remains the public contract. Decode each path once and
require canonical numeric IDs or existing bounded project/owner/slug syntax.
The router is a fixed method/path table, never dynamic method dispatch. Each
handler slice owns its explicit index/router wiring; a module that is not reached
through the real Worker is not a completed endpoint. Unknown
API paths return the fixed API error, not the SPA shell. Public host routing
cannot call privileged handlers. No caller URL, ref, provider or file path can
select transport, credentials or an execution module.

Browser JSON uses UTF-8 and one bounded parser that rejects duplicate/unknown
members, invalid UTF-8, unsafe integers, non-finite values and excess nesting.
Use JCS only where the existing contract hashes/signs canonical data; reject
noncanonical signed bytes rather than normalizing a forged token into validity.
All sensitive browser POSTs require exact configured `Origin`, same-origin
content type and a live session; canonical mutations additionally require the
M1 form. Reject absent/wrong Origin on browser mutation routes. Machine routes
are separate fixed endpoints authenticated by their typed opaque context or
protected OIDC; a machine header never bypasses browser CSRF rules.

| Request | Closed body or query | Result and binding |
|---|---|---|
| `POST .../forms/<type>` | `{operation:{target,payload},presentation_source}` | Exact M1 form plus the same frozen operation and current display; the server derives actor, resource authority and canonical head. An unsupported/internal type denies. |
| `POST /sign`, `/revoke`, `/admin/<type>` | `{form,operation:{target,payload}}` | Validate the existing type/operation digest and event mapping; no hidden mutable payload, supplied actor or authorization boolean. Return the exact existing mutation result plus safe display state. |
| `GET .../me` | No subject query | Own current tuple, safe status/reason/actions and proven pending event/effect; subject comes from current session. No saved submitted fields. |
| `POST .../read-authorizations` | `{result_class,subject_scope}` exactly as HLD | Original short private-read JWS; scope/class must be the exact allowed pair. No bulk query class. |
| `GET .../index/<shard>` | Exactly one proof in authorization header | One fixed filtered index shard, no hidden cursor/ref/path selectors. |
| `GET .../subject-status` | Exactly one subject-status proof | Subject comes only from that proof. No user-ID query or own-status bypass. |
| `POST .../pr-view` | `{repository_id,pr_number,maximum_tier}` | Server selects permitted tier; exact current route/PR binding. No client-selected authority or raw provider result. |
| `GET .../teams/<team_id>/selection` | Required closed `purpose=exemption|reader` and configured numeric organization context | Current records admin; complete bounded selection. Reader uses records App only; exemption may use approved enforcer observation. |
| `POST .../exports` | Existing M3 request `{export_version,project_id,request_id,source_events_oid,view}` | Authorized fixed dispatch or exact retained pair status, never immediate plaintext. Use M3 request codec rather than a parallel schema. |
| `GET .../exports/<request_id>?format=...` | `json` or `csv` only | Current reauthorized exact snapshot pair; source/view/request identities are checked before streaming. |

Use the existing uniform private `404`; authentication failure uses `401`/
OAuth restart, insufficient authenticated action permission `403`, changed
confirmation `409`, dependency/completeness uncertainty `503`. Responses are
closed safe categories plus required public/source/event identities. Never
reflect exception bodies, tokens, private payloads or provider error text.

An operation outcome preserves the M4 union `landed|semantic_noop|conflict|
indeterminate` and its exact observed/canonical identities. The browser shows
completed only after full relevant effect/readback. Canonically recorded work
with incomplete effect is explicitly taking effect. A timeout cannot invent
success or silently create a fresh event. Retrying uses the original frozen form.

## 3. Authentication, key families and contexts

### 3.1 Browser authentication and sessions

Use the records App's existing OAuth client, exact configured callback and
expiring user tokens. `/oauth/start` generates a CSPRNG 32-byte verifier and
16-byte nonce, PKCE S256 and a ten-minute pre-auth record. Signed state binds
nonce, exact project/setup/conflict purpose, numeric PR context when present,
return path and issue/expiry. Use the dedicated OAuth-state HMAC family, strict
unpadded encodings and purpose/domain. The encrypted pre-auth cookie contains
that state identity and verifier; store neither verifier nor refresh token in KV.
Callback requires the same browser cookie, exact nonce/state/callback, then
exchanges once with GitHub and authenticates `/user`. Missing/invalid expiry
or remaining token lifetime at most five minutes creates no session.

The session cookie contains only `{v:1,jti,github_user_id,issued_at,expires_at}`
under AEAD. `jti` is fresh 32-byte randomness. The live KV value contains exactly
`{v:1,github_user_id,login_snapshot,access_token,token_expires_at,expires_at}`.
Authenticate and bind both copies; `expires_at` is exactly GitHub expiry minus
300 seconds, never sliding. TTL is an additional expiry, not authority when
payload time has expired. Reauthenticate `/user` before sensitive operations
and bind its numeric identity to both copies. A changed login updates display
only; a changed numeric user invalidates the session. Delete cookie/KV on `401`;
`403` denies the operation. Logout requests KV deletion without promising
immediate global revocation of a copied cookie.

Cookies are `__Host-`, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain. Existing
session, state, action-form and private-proof key families remain separate.
Encode AEAD cookies as a closed `{v:1,kid,nonce,ciphertext}` envelope. Nonce is
12 random bytes and plaintext is exact JCS; AES-256-GCM tag/encoding/key rules
match native existing crypto. Session and pre-auth have distinct fixed AAD
labels plus canonical portal origin/version/kid. Unknown keys, fields, purposes,
algorithms and expired overlap deny. Never reuse a nonce deliberately or an
artifact identity/key as a cookie. Predecessor eligibility ends at the original
absolute expiry; rotation never renews a session or form.

### 3.2 Transient setup and export contexts

Use the same session AEAD family with distinct fixed context-purpose AAD,
not the private-record artifact codec. All contexts have a closed payload
`{v:1,purpose,session_jti,github_user_id,project_id,request_nonce,
issued_at,expires_at,binding}`. AAD includes exact portal origin, version, key ID
and the endpoint's expected purpose. The endpoint supplies that purpose before
decryption; a payload cannot change it. Lifetime is at most 600 seconds and
no later than the parent session. A context is not a new live-session store or
permission verdict. Recheck session/identity and the operation's actual current
authority whenever used. Unknown/expired/foreign generation/context denies.

The wire context is strict unpadded base64url of the UTF-8 JCS envelope
`{v:1,kid,nonce,ciphertext}` using §3.1's AEAD sizes and fixed context AAD.
Require exact canonical bytes and re-encoding equality, not merely an equivalent
JSON object. The issuer retains this exact wire string for the request. Define
`authorization_context_sha256` as lowercase hex SHA-256 of its exact ASCII wire
bytes. Every bootstrap key MAC and signed ControlKeyProof includes that digest;
the original setup/Connect consumer recomputes it from its own original context,
not from a replacement supplied with the proof. Its session_jti/request_nonce
remain inside the authenticated context; the digest binds them without disclosing
them or creating a nonce/receipt store. Different encryption randomness also
creates a different context and requires its own proof.

The closed `binding` union is selected by a literal purpose:

- `initial-wrap`: exact proposed project/install generation, owner and three
  numeric repository IDs, release/policy/dependency provenance identities,
  capability, exact wrapper ID, data `kid`, actual-key fingerprint and retry
  nonce. Only an unclaimed initial project candidate qualifies (§7).
- `installed-key-challenge`: exact project/current canonical head, key candidate
  OID, key generation, wrapper/capability/kid/fingerprint, arrangement and exact
  current App identities, fresh challenge nonce and control-proof identity.
- `hosted-export`: exact M3 request digest, request ID, view/source OID, selected
  canonical reader source/generation and exact control repository/workflow pin.
- `bootstrap-control`: the fixed initial/installed control challenge binding
  in §11.2; it cannot authorize an export, normal repair or service wrapper.

The exact binding object keys are, respectively:
`{install_generation,owner_id,repository_ids,release,capability,wrapper_id,
data_kid,key_fingerprint,retry_nonce}`;
`{canonical_oid,candidate_oid,install_generation,owner_id,repository_ids,
app_bindings,key_commitments,capability,wrapper_id,challenge_sha256}`;
and `{request_sha256,request_id,view,source_events_oid,reader_generation,
authorizing_source,control_repository_id,workflow_ref,workflow_oid}`.
Bootstrap-control has §11.2's exact keys. `repository_ids` is the existing exact
records/coverage/control map; `release` is the existing bootstrap release object.
`key_commitments` is exactly `{records:{data_kid,key_fingerprint},
coverage:{data_kid,key_fingerprint}}`; fingerprints use M3's actual-key format.
`app_bindings` has exactly records/enforcer/trigger, each with app_id and
installation_id; current accepted grants are re-observed, not stored verdicts.
`authorizing_source` uses the exact private-read source schema. All IDs,
OIDs/digests/kids/enums obey their existing normative codecs. Unknown keys deny.

Only these fixed endpoints can consume their respective union. Enforcer
validates its context using the fixed private portal authorization call and
returns a bound result; it never receives portal session/HMAC keys. Expired
context requires a new explicit authorized request, not silent token refresh.
A lost dispatch response may recheck the same encrypted pair/run identity; it
cannot authorize another source or output location.

## 4. Current authority providers

Create trusted evidence only in the fixed server acquisition modules. No JSON
object, saved `allowed:true`, session alone or installation self-privilege can
construct it. All evidence binds live actor numeric ID, resource numeric ID,
exact operation/required authority, observed result, authenticated source and
whole-second UTC check time. Freeze it into the existing canonical event model
and validate its required set/order with M1. Read operations do not create events.

| Check | Concrete observation and capability |
|---|---|
| Live actor | Records-App user token `/user`; exact current numeric identity and accepted token/session time. |
| Records/coverage actor admin | Actor's user-to-server token against the exact bound repository; numeric repository/owner and actor permissions/role must agree. Never use the App's own repository permission as the actor's permission. |
| Control actor admin | Bound trigger installation's Metadata-read named-user permission endpoint, repeating exact numeric repository and live actor. It has no contents/secrets/provisioning permission. No enforcer credential is used on control. |
| Personal owner control | Current actor numeric ID equals the exact current repository-owner account ID. |
| Organization owner control | Accepted bound Members-read observation of the current actor's active organization membership with admin role and exact numeric organization/user IDs. Public membership or a repository role is insufficient. |
| Contributing resource | Fixed enforcer operation uses its exact current installation and named actor permission/organization endpoint. Return only the signed minimal result/evidence. |
| App binding | Relevant App's own authenticated repository-installation lookup, installation account/ID/grants/selection and exact numeric repository. Enforcer checks its own installation; portal checks records/trigger. A Setup URL parameter is not evidence. |
| Reader membership | Records App current exact team/organization/user membership, active only; never enforcer fallback. |

m5/18 owns this common current authority acquisition, the enforcer's closed
permission/owner/App-binding service and the existing project-independent
repository-conflict inspection endpoint. It lands after m5/2, before m5/6 and
all installed-Connect/administrative consumers. m5/7 extends the same service
with exemption-only complete team observations before m5/8 automation consumes
it. m5/10 extends it with PR observations; it does not first introduce authority
providers after their consumers. Each slice owns real router wiring and tests.

For named-user permission endpoints, verify returned user ID matches the freshly
resolved actor login/ID and metadata matches the expected repository before
using the result. Legacy `write` does not prove maintain: require explicit
maintain/admin role or a documented returned permission flag. Unknown custom
role, absent evidence, SSO/policy ambiguity or incomplete installation visibility
denies that operation. Test supported provider combinations with actual installed
grants before production; do not add a credential to make an ambiguous case pass.

Connect and whole transfer require exactly the parent seven owner, three admin
and three App-binding records. Key activation names every repository whose
material changes. Records-side agreement/config/sources/succession use current
records admin; scope and overrides/retry use their exact contributing resource
and minimum authority. Reader access remains independently canonical, never an
admin privilege. Check before form issuance and the state-dependent initial
write/activation; changed head/permission invalidates a write-bound confirmation.

## 5. Public presentation and actual browser implementation

Serve a small typed static shell with browser-native controls. `app.ts` owns the
one layout/router/API client, explicit loading/auth/stale/unavailable states and
bounded retry; action modules own their actual fields/confirmation. One owned build script bundles browser TypeScript/DOMPurify, emits immutable
assets and the exact viewer CSP hash manifest; generated output is excluded
from LOC. M6 installs those verified assets, not a caller-selected script/hash.
Keep browser and Worker build graphs separate so server credential/config
modules cannot enter the static bundle. No new framework, privileged server
rendering, storage of tokens/keys or hidden public
subject lookup. M7 adds dashboard/badge modules to this same app and read service.

The portal host has `frame-ancestors 'none'`, X-Frame-Options DENY, restrictive
script/connect policy and only the configured agreement origin in frame-src.
The agreement host is a public branch of the existing deployment. It rejects
OAuth/API/internal routes, ignores credentials, sets no cookie and returns no
private error/data. Fixed trusted viewer script alone runs under a pinned CSP
hash; iframe omits allow-same-origin, forms and top navigation. Sanitize bounded
markup with DOMPurify3.4.17 (delivery rechecks advisories and locks exact tested
bytes) in the isolated browser, HTML-only with no in-place, template, shadow-root,
SVG or MathML mode. Allow only `p,br,h1,h2,h3,h4,h5,h6,ul,ol,li,blockquote,pre,
code,strong,em,a,hr,table,thead,tbody,tr,th,td`; attributes only `href,title` on
links and bounded table spans. Permit fragment or HTTPS links only, with safe
noopener/noreferrer behavior. Remove tenant script/style,
event attributes, active URLs and uncontrolled network resources. Contextually
escape text outside that frame. Literal immutable agreement source stays accessible.

The fixed viewer readiness message is exactly `{v:1,type:"agreement-ready",
view_nonce,project_id,version,digest}`. Parent checks expected frame Window,
fresh nonce and displayed exact identity; opaque origin alone is not authority.
A missing/failed/different frame signal leaves assent disabled. Messages never
contain fields, submit a form or prove human reading. Fetch agreement bytes
without credentials and compare the existing exact content digest before render.

Public presentation is allowlisted. Fetch authenticated current canonical config/
active version before form issuance even when a cached public version is the
same: changed required fields/labels/privacy text must be displayed again.
Show exact recipient/version/digest, all required fields, retention/correction
text, explicit assent and revocation prior-rights wording. No agreement means no
sign action. Continuous delegation and blocking-trailer warnings require the
existing explicit confirmation, not a default toggle or saved preference.

## 6. Forms, canonical mutations and bounded private state

Use existing `FORM_ACTION_TYPES`, `encodeActionForm`, `verifyActionForm`, event
operation validation and `validateTerminalNoop`; do not create another mapping.
The common issuer reads one canonical head and exact relevant authenticated fold,
derives full operation/side artifacts, checks current authority, and returns
that frozen operation and form. Every Table 5.4-A row is wired only by its owning
handler. Internal materialization/activation/abandonment types reject through
forms. Terminal no-ops bind the original event, including exact restore/scope
semantics; administrative retry has no terminal no-op type.

Acceptance stores exact submitted evidence/field labels, current GitHub numeric
identity/login snapshot and display identity, then invokes one M4 writer.
Correction is a new acceptance with supersedes, not mutation of old evidence.
Revocation targets the exact tuple and cuts off earlier acceptances by canonical
position. A later acceptance invalidates a stale revocation form. Restore
currency or scope cannot undo that cutoff; re-sign requires fresh explicit assent.

M4's writer owns prepare/fence/marker/append/terminal/readback/release and exact
M3 recovery. M5 builders own action evidence and private derived effects:

1. Read bound canonical/derived/coverage/key/operation identities through shared
   bounded clients. Validate selected envelope/digest/generation and current
   key/profile before using any row. All readers use one immutable selected head.
2. Compute the action's affected classes/shards from validated event identity,
   source records/rules and selected frozen subjects. Fetch only needed current
   rows plus state/standing rules. Preserve all untouched encrypted-shard digests.
3. Extract shared deterministic row transformations from existing M1 full
   materializer. Full-model entrypoints remain strict. The partial adapter
   accepts only its own authenticated typed inputs and applies the same event
   rules, login observation/cursor/source union and class generation changes.
   Python/full reference parity covers every event and negative input. No fake
   `DerivedPlaintext`/complete coverage model bypasses a strict constructor.
4. Preflight complete prepared-cell, side artifact, shard, member, cursor, batch
   and work limits before preparing a bulk administrative request. A frozen
   snapshot remains one event/identity; no silent user-visible event split.
5. Execute the shared writer's ordinary bounded path. Publish a private class
   generation only with its complete effect and exact all-shard digest table.
   Reuse M3's existing guarded bulk reconciliation for a durable incomplete
   effect; its batches are at most the installed 32-shard write limit and its
   sole final state binds all 96 shards. No edge full replay or new job store.
6. Uncertain append/readback stays guarded and dispatches exact protected repair.
   Never return complete before the whole effect is independently observed.
   Acceptance/revocation evidence and coverage still complete if an unrelated
   private class overflows; that class denies reads pending existing repair or
   a larger tested profile, rather than imposing a lifetime contributor cap.

The adapter must not weaken M1 bulk publication checks or simply pass a partial
object to full validators. Its completion plan binds the same canonical source,
prepared operation, changed encrypted blobs and final state. A changed source,
concurrent head, incomplete bulk or lost conditional write retains guards and
uses existing immutable readback/recovery. Include actual Python recovery in
tests, not only mocked `submitMutation` success.

For publication, accept the parent's immutable GitHub repository blob reference
or gist revision. Public publication applies to the agreement snapshot, not a
blanket public-origin flag. Parse owner/repository/path/full commit OID or
gist/file/full revision into fixed GitHub API requests. Read public/otherwise
accessible references without credentials; an unlisted accessible gist is not
rejected because its metadata says `public:false`. For an origin already within
the acting user's accepted project-bound records-App/user reach, such as the
already-bound records repository, use that existing capability against the fixed
GitHub API only. Recheck the exact actor/resource and current reach at issuance
and submission. An out-of-reach private origin is unavailable; do not expand
installation, borrow enforcer/trigger credentials or create a file proxy.

Never fetch a caller URL, follow arbitrary `raw_url` or send credentials to an
origin/content host. Require exact immutable commit/revision/file identity,
complete nontruncated UTF-8 bytes and digest/snapshot metadata equality under
the document limit. Reject redirects/ambiguous files. The issuer computes and
shows the exact snapshot/digest and public-publication confirmation before
freezing the operation; submission refetches the same authorized immutable
bytes, never mutable branch content. Later origin deletion/access loss cannot
remove the stored public agreement snapshot. Test public repository, accessible
unlisted gist, already-authorized private origin and outside-reach denial.
No new paste/upload source, arbitrary private-source capability or grant is added.

Publish agreement snapshot/metadata atomically with `agreement_published`;
activation is separate. Ordinary/superseding activation selects exact accepted/
retired sets and restore names its exact prior ordinary target. Configuration
uses M4's compatible canonical v2 source and policy; old v1 history stays readable,
unknown/downgrading writers deny. M5 adds no schema or deployment-local policy.

## 7. Bootstrap, Connect and lifecycle

### 7.1 Initial wrapping before installation

Preserve the global initial installation order. User authorization can authenticate
an identity before App installation; it does not prove access to private setup
repositories. Initial wrapping is a bounded authenticated operation over the
installer's supplied actual candidate keys/challenges for an unclaimed proposed
project, not an administrative mutation or existing-project decryption operation.
The current setup session explicitly confirms hosted-controller trust, exact
proposed arrangement/generation/provenance and candidate key commitments.

Issue only the closed initial context in §3.2. Check current session and the
complete registry's absence of that claimed project/arrangement, validate the
supplied initial provenance structure and actual-key HMAC fingerprint, and accept
only a 32-byte key plus a fresh bounded matching challenge. It can return only
its capability/wrapper-bound new wrapped copy and candidate challenge result.
It reads no private repository, unwraps no existing stored copy, writes no
registry/project/route, asserts no seven-check verdict and cannot select rotation.
If the project is already connected/pending/claimed, require its separate installed
operation with current authority. Incomplete registry resolution denies.

Use three closed paths: portal records/portal-records, portal coverage/
portal-coverage, enforcer coverage/enforcer-coverage. Reuse the inherited roots,
keyring AAD and M3 actual-data-key fingerprint, not a new root topology. Enforcer
asks the portal to validate only its exact setup authorization, receiving no
session/HMAC/raw key from the portal. The CLI sends the exact raw candidate
coverage key separately to each approved service over the existing authenticated
channel; services never forward it. Neither raw keys nor challenge plaintext
persist in logs, KV, repo, response errors or job artifacts. CSPRNG randomness,
fixed endpoint/purpose and candidate equality prevent a generic decrypt interface.

### 7.2 Installed Connect and first private event

After M6 creates exact bootstrap material and all three Apps are installed,
Connect independently performs all seven current checks in §4. Resolve exact
numeric repositories/owner/installations and release/control pins; require private
records, coverage and control. Compare all three exact bootstrap manifests,
unique initial keyring commit K and child B/ancestry, actual-key binding proof,
generation, candidate OID and configured initial kids. `keys_ready` is invocation
local, never a persisted permission bit or registry shortcut.

Issue fresh installed-context challenges against each actual stored service
copy. Require portal-records, portal-coverage and enforcer-coverage independently,
both actual recovery proofs and the pinned protected-control proof. Initial
control execution uses the administrator's own Actions authority as the global
installer specifies, not the transport App or a shared provisioning credential.
M5 supplies the fixed protected proof transport; M6 performs the local orchestration.

Protected control bootstrap calls use the M4 authenticated GitHub OIDC verifier
with a separate literal bootstrap audience/purpose and exact project/generation/
challenge/workflow/repository/run binding. The fixed response binds only challenge,
actual-key/candidate and installed release observations, never raw keys. Verify
numeric executing repository and pinned source/release before secret/key access.
No caller can select a local Python provider or command through JSON. Read/write
configuration remains the one versioned control parser; incompatible installed
code denies and requires M6's upgrade ordering, not relaxed validation.

The first frozen `project_connected` package includes the exact project-config
and materialization-generation inputs. The single M4 writer commits the event
and encrypted config/generation side artifacts together or none. It uses
the authenticated README-only events root, exact K/B/manifest
and actual-key bindings, independent idle fence/empty marker/operation objects
and M1's existing `generations-absence` evidence. The bootstrap acquisition in
`api/src/records/bootstrap.ts` validates those objects independently; it never
calls the full coverage validator on fabricated active or unconnected state.
Require semantic source/agreement/shards/private-derived absence for a new first
operation; mismatched partial contents fail closed. An already prepared/appending
matching operation follows exact frozen-package/ancestry recovery, not a new
absence-based claim. After the genuine first event/config, the shared executor
materializes complete normal active/no-agreement coverage and private derived
state, verifies every readback and completes guards. No history bypass or
alternate genesis writer. Lost response resumes the same idempotent operation;
M5 supplies the fixed Python bootstrap acquisition adapter for M3's real recovery.
Test actual Worker acquisition and Python recovery at every interruption before
and after append/materialization, plus write-free repeat and conflict rejection.
Only its verified canonical effect can start the separate requested/activated
initial-scope protocol; it does not publish a route directly. Concurrency, partial
setup, changed keys or a failed challenge cannot take over an existing project.

#### 7.2.1 Fixed bootstrap acquisition and the actual Python engine

Current `records/history.py:open_history` reads the `derived` ref and rejects
unconnected replay; `MutationEngine.snapshot` calls it, encryption selects keys
from connected replay, and `StoredPreconditions` explicitly refuses initial
Connect. A future file named bootstrap is not sufficient integration evidence.
`m5/12` owns the following narrow extensions as well as its fixed adapters:

- Factor the existing root/K/B/manifest/actual-key authentication for reuse by
  `core/dracla/records/bootstrap.py`; keep ordinary `open_history` connected-only.
  The bootstrap acquisition returns a private typed observation of the exact
  root, keys, coverage/operations heads, optional derived head and validated
  existing objects. Missing semantic projection/derived state is allowed only
  under authenticated first-event absence, never a catch-all on reader failure.
- For an events root with zero events, require exact absent config and
  materialization-generations, authenticated independent idle guards or the
  exact owner-bound frozen first operation and its valid guard transition.
  An unrelated event, semantic artifact, changed K/B, malformed ref or foreign
  operation denies. Do not make a synthetic active ReplayState or new wire
  lifecycle. Preserve initial replay and select initial encryption keys from
  the authenticated bootstrap current_kids only in this bound path.
- A landed first event with incomplete materialization is a separate verified
  continuation: replay and validate that exact `project_connected` package,
  config/generation and its frozen parent/operation identity. Derive the active
  state from that event. Permit absent derived ref only while that same guarded
  operation initializes the derived ref through §7.2.2 and creates its first
  real projection commits through the existing conditional writer. A missing ref after completed connection is
  corruption, not bootstrap permission.
- Integrate this fixed typed acquisition/key selection with the existing
  `MutationEngine` and `reconcile_project`; default calls retain connected-only
  behavior. Do not duplicate prepare/fence/marker/append/terminal transitions
  or replay, monkey-patch runtime globals, or accept provider/module selection
  from request/repository configuration. The protected fixed bootstrap adapter
  derives its admission from authenticated installation and frozen operation
  evidence; browser/session state is not a recovery dependency after preparation.
- Once the first projections and guards complete, normal strict history/
  verification must succeed; a repeated completed Connect returns its exact
  canonical result without writes. Both the real Worker writer and Python
  repair traverse these persisted states. A normal reader/action, another
  operation or a corrupt connected history cannot enter the bootstrap path.

The engineering extends the M3 integration seam in M5's future slice; it does
not rewrite the completed M3 plan, source or historical acceptance during this
design work. Cover zero-event idle/prepared/appending, genuine append with
missing/partial projection, wrong-owner/ancestry and full-completion repeat.
Reuse existing engine/M1 vectors and deterministic transport fixtures; do not
count a replacement engine or a second common crash-test harness.

#### 7.2.2 First derived ref: initialize the authenticated root, then ordinary CAS

`m5/12` also owns `core/dracla/records/github.py` and the corresponding real
transport tests. Use a fixed initial-ref operation, not `conditional_commit`
with an invented expected head. The simplest safe seed is the already verified
mandatory records README root, after the genuine first Connect event has
landed. Creating this ref does not publish a semantic projection, create a new
genesis, or add an event; normal readers stay unavailable under the operation's
existing guards until full materialization and readback finish.

Before attempting `POST /repos/{owner}/{records}/git/refs` with exactly
`{ref:"refs/heads/derived",sha:root_oid}`, authenticate the exact numeric private
records repository and the frozen first-Connect operation, K/B/manifest, actual
keys, landed canonical event/package/head and current operation/fence/marker
ownership. The seed's immutable commit has no parents and exactly the original
mandatory README tree/bytes. Do not inherit the first event/config, accept a
caller-supplied root, or create an empty/synthetic materialization-generation
artifact. This operation is fixed to records/derived and never exposed as a
generic ref creator.

Add a typed missing-ref observation distinct from ordinary `head()` and from
authorization, policy, network or malformed-result failure. Admit absence only
after exact repository authentication and a successful bounded
`GET /repos/{owner}/{records}/git/matching-refs/heads/derived` under the bound
Contents credential. Validate the complete returned array and select only the
literal `refs/heads/derived`: prefix matches such as `derived-old` are not that
ref. Incomplete/oversized/error responses deny; a lone indistinguishable404 is
not proof.
Recheck live canonical and guard identities immediately before publication.
The REST ref-create operation supplies absence-to-OID semantics: it has no
force/update branch. A concurrent existing ref is never overwritten.

On success, lost reply or provider rejection, reobserve that exact ref and
validate its immutable ancestry/tree. Absent with uncertain outcome remains
uncertain until bounded readback or a safe rechecked attempt. Exactly `root_oid`
under the same still-owned frozen first operation is the same initial effect;
it can be reused without claiming which caller created it. This is safe effect
equivalence, not name-based installation provenance. Any other head must be an
authenticated direct descendant sequence of this root from this same ongoing
first materialization, with only the exact allowed encrypted shard additions
and final state, full plaintext/reference/generation comparison, and unchanged
canonical/guard bindings. Foreign, malformed, extra-file or unexplained heads
conflict. Never adopt a ref merely because one selected file or final value
looks right. Concurrent appearance outside that proved sequence stays closed.

After exact root ref readback, `publish_projections` uses its existing ≤32-shard
conditional batches followed by the sole complete `derived/state.enc.json`
publication and full readback. The first projection commit's single parent is
the root and its complete tree is README plus that exact bounded shard batch;
later commits preserve all prior allowed files. `verify_commit_files` already
checks the complete inherited tree. No new Git commit builder/encryption mode
or deterministic nonce scheme is needed. The Worker uses the same fixed
root-ref initialization semantics before its common materializer; the protected
Python repair path reaches the same persisted states. Completed Connect uses
normal strict verification and performs no ref creation or writes on repeat.

Exercise real scripted HTTP/transport plus Worker/Python integration for absent
ref, denied/incomplete visibility, lost create reply, concurrent identical-root
and different-head creator, interruption immediately before/after ref creation,
each partial batch/state write, malformed tree/parent, inherited extra file,
changed canonical/guard/owner identity and completed write-free repeat. Removing
absence admission, exact root validation or whole-tree comparison must make
the focused negative cases fail. No pre-Connect derived ref is created.

### 7.3 Later lifecycle

Whole-arrangement transfer checks new owner, all three moved repositories and
all App bindings before M4's bound transition; partial transfer stays unavailable.
Succession requires independently connected successor and active agreement.
Preserve the succeeded project's explicit revoke, reader/source/scope maintenance,
history and recovery allowlist while denying new signing/legal expansion.
Key activation proves each actual successor through all applicable stored service,
control and recovery paths before canonical selection; retain old history keys.
Routine wrap/root overlap is not revocation of copied historical data or all
previously issued tokens. Shared incidents use M4's actual quarantine/containment.

## 8. Exemptions, reader sources and continuous automation

Snapshot remains the default. Show a complete bounded current member set,
freeze the selected stable numeric identities in one event, and preserve it
across retries. Human exemptions include asserted basis/instrument/admin and
remain distinct from signatures; reader source changes do not change GitHub ACLs.
Withdrawal names exactly one source and returns remaining sources in the union.

Continuous configuration displays explicit future-membership delegation. Rule
and member observations reference exact numeric organization/team/installation,
rule event, current GitHub observation and retained prior materialization cursor.
Source selection/observations for readers use records App only. Exemptions may
use the bound records installation or fixed authenticated enforcer fallback.
No generic organization/team directory or caller-selected installation.

Validate raw webhook HMAC-SHA256 on the receiving route before parsing. Doorbells
trigger fresh observations only; delivery payload never replaces members or
chooses a project. The existing bounded daily portal scan observes complete team
membership. Compare with canonical materialized members and serialize one exact
join/departure mutation at a time. Freeze one observation/event with its prior
cursor; complete or reconcile that operation before advancing the scan. No
separate durable scan cursor/store or Actions membership poller. A repeated
scan observes already-completed changes and does not append duplicates.

Reject incomplete member enumeration, pending membership, binding drift and
out-of-profile sets. Do not confuse a provider error with an empty team. A
new member cannot read until canonical addition/materialization; a departed
continuous reader must fail the independent live check before withdrawal lands.
Exemption coverage changes only through committed/materialized automation,
with ordinary marker/fence behavior during recovery.

## 9. Private-reader proof and exact-status integration

Acquire one current canonical generation and immutable derived head/state. Validate
all32 reader-authority envelopes/shards with existing `derivedReadProjection`,
exact encrypted digests/profile and canonical/derived generation equality. Pack
requests by bytes as well as alias count. Missing, oversized or partially returned
shards deny; do not interpret them as empty or select an incomplete source union.

Prefer individual/snapshot source; continuous sources use stable source-ID order
and the records App's exact current active membership. A proved independent
source remains usable if another source fails. With no proved source, deny.
Issue exactly the global HLD private-read compact HS256 JWS header and payload,
including exact session/actor/project/result/scope/generation/source/team and
whole-second timestamps. Its lifetime is at most 300 seconds and parent expiry.
Use the dedicated proof ring; strict JCS/encoding/kid/algorithm/field validation
and native constant-time authentication precede scope interpretation.

Every page reauthenticates current actor/session, re-resolves canonical generation,
verifies exact proof/class/scope and repeats exact records-App membership when
continuous before disclosure. A failed source invalidates that proof; a fresh
issuance can select another valid current source. Never refresh a proof silently.
Only fixed server-derived shard identities may be decrypted. Private pages are
filtered, `private, no-store`; no raw keys/evidence/legal fields or arbitrary refs.

M5's partial exact-status adapter consumes the authenticated M4 coverage
observation containing exact source/active/inflight/fence and subject binding,
plus one validated private status row/state. Extract one shared status core
from `resolveReadStatus`; full entrypoints retain full-model checks. Partial
entrypoints check the real observation brand/source/project/scope/pair, exact
private generation/envelope and current lifecycle. Both return identical
status/reason/event/version/timestamps/scope/coverage decisions under the same
reference cases. Own-status uses session-derived subject; named reads use only
the exact subject proof. Never pass a fabricated full 37-file projection.

## 10. Signed permissions, PR views and administrative scope

The common enforcer observation service is delivered by m5/18 before the first
consumer. Accept only a service-authenticated exact closed envelope
`{v:1,purpose,mode,project_id,repository_id,github_user_id,operation,nonce,
issued_at,expires_at,binding}`. No browser supplies trusted actor/permission.
Portal first authenticates the live actor, then constructs the fixed request.
`purpose` selects only `permission`, `owner-membership`, `app-binding` or the
m5/7 `exemption-team` extension. No arbitrary method, URL or credential selector.

`mode` has three disjoint bindings:

- `active`: exact project/current route/gate digest and installation. Current
  route and gate must agree; changing either makes the observation unavailable.
- `installed-setup`: exact session-derived setup request digest, proposed
  project/install generation, numeric resource/owner and the relevant already-
  installed enforcer identity. Portal authenticates its live setup session and
  exact proposed map before constructing this service-authenticated request;
  `setup_request_sha256` commits to that map, generation, actor and fresh request
  nonce. This is only preliminary read observation, not a context asserting the
  seven checks already passed. It may prove current proposed resource facts
  for Connect but cannot require a route that Connect has not activated yet,
  mutate anything, claim a project or access canonical private records. Portal
  rechecks the same session/request before consuming the reply; only after all
  seven checks can it issue installed key-challenge/control authorization.
- `repository-inspection`: project_id is null; exact current affected repository
  and installation plus live actor. A fixed read-only operation proves current
  admin on that repository before portal reveals only its matching claims.
  Conflicted/no-active routes may be inspected; their project or gate cannot
  be substituted as permission. No mutation or records-reader authority follows.

Each binding is a distinct closed object with only those named fields; active
uses `{route_sha256,gate_generation,installation_id}`; installed-setup uses
`{setup_request_sha256,install_generation,owner_id,installation_id}`;
inspection uses `{installation_id}`. The server's exact proposed repository map
supplies only the three accepted roles; an observation cannot add a resource.
The setup digest is SHA-256 of JCS of exactly `{purpose:"setup-observation-v1",
project_id,install_generation,github_user_id,repository_ids,nonce}`. It is a
request correlation identity under trusted service authentication, not a browser
permission token, new context family or persistent approval record.
Operations are the literal approved minimum `admin`, `maintain` or `write`,
`organization-owner`, `installation-binding`, and m5/7 `exemption-team-selection`
or `exemption-team-membership`; invalid purpose/operation/mode pairs deny.
Team operations require active mode and bind the exact numeric organization,
team and optional member within the signed purpose-specific request; extend
its closed binding with `{organization_id,team_id,user_id}` where user_id is null
only for complete selection. They never return reader-source authority.

Response repeats the exact request identity/digest, mode/binding and minimum
authority with `allow|deny|unavailable`, checked_at/expires_at and a closed
purpose-specific evidence union: numeric actor/repository and permission/role;
organization/user/active-owner membership; App/installation/account/repository/
accepted-grants/selection; or complete bounded numeric team members/current
active membership. Check source identity, completeness, accepted grants and time
before signing; partial/unknown/SSO/policy/error evidence is unavailable, never
allow or a false complete empty set. Return no token, arbitrary response body or
canonical signer record. Existing fixed portal/records/trigger providers perform
their own corresponding checks; enforcer never gains control-repository access.

Expiry is at most60 seconds, request expiry and parent session/context expiry.
Sign JCS with native Ed25519 and distinct `dracla-permission-v1` domain/key role,
using M4's canonical signed-envelope encoding rules with a purpose-specific
version/header and the exact request/response payload. Pin verification-only
keys installed by M6. A route key/signature or caller URL/JWK cannot replace a
permission key. Rotate with explicit overlap. Unknown/foreign purpose, kid,
mode, actor, resource, operation, context, nonce or expiry denies. Test valid and
wrong-value cases through actual Worker/HTTP routing, including first Connect
before active routing and conflict inspection while routes are conflicted.

A separate named PR observation operation has a closed self/aggregate/named union,
exact request/route/repository/PR/head/tree identity and the same bounded lifetime.
Only portal service authentication plus prior current reader resolution can ask
for named observations. Enforcer independently rechecks current route/gate,
installation and complete PR facts; it returns GitHub IDs/logins only for that
allowed tier and never canonical signer evidence. For aggregate it independently
checks current write authority and returns counts/classes only. Self binds the
live viewer and returns only their reason. Public output remains generic.

Portal named reasons call the ordinary exact subject-proof/page service for each
subject and recheck current generation/membership before the response. Page work
is bounded; a large PR can use the same fixed per-subject pages without a bulk
permission cache. An uncompleted subject list or changed PR head/route is unavailable,
not a partial named answer. Bind numeric repository context in existing generated
PR links and signed OAuth state. Missing context may resolve only when complete
registry proves one candidate; otherwise guide reopening the exact check, without
enumerating private repositories or choosing among same-number PRs.

Conflict inspection separately requires current admin on the affected contributing
repository and reveals only its matching claims/selectors and necessary resolution
authority. Resolution writes recheck their own resources. Scope moves remove then
bind through M4 requested/activated transitions; GitHub-created overlap quarantines
only affected repositories. Overrides bind exact repository/PR/subject/tree, require
maintain and withdraw whole-grant forward. Retry requires write, targets one exact
PR/merge group and cannot clear another reservation/quarantine or grant legal assent.

## 11. Protected export adapter and delivery

Use the existing exact M3 export request codec and source observation semantics.
The portal resolves current canonical reader authorization and explicit view/source,
freezes the request digest/context and uses the existing Actions-only trigger App
to dispatch only the pinned protected workflow. No App grant grows. Dispatch input
is inert data/file content, never interpolation into shell commands or a module name.
A queue delay beyond context/session expiry requires a fresh authorized request.

Use M4's OIDC verifier with a distinct fixed hosted-export audience/purpose,
exact numeric control repository/owner, workflow path/source pin, actual run/
attempt, request digest and context. Verify installed release/control identity
before keys. The fixed Python `PortalHostedExportAuthority` constructs only from
this trusted invocation and fixed portal transport; config cannot choose a provider.
`authenticate_request(exact_request)` checks context/request/session/current actor,
source and current reader union before M3 obtains keys; `is_team_member` calls
only the exact bound records-App membership operation. Repeat authority at the
existing renderer's final gate. Missing/expired/foreign provider preserves today's
explicit hosted-authorization denial.

Extend the one M4-compatible protected control configuration/parser/workflow with
a closed export branch, not an arbitrary operation/endpoint. Keep v1 verify/local
history behavior and M4 v2 routing requirements intact; old code denies unsupported
new branch. M6 installs compatible pinned code before enabling this flow. Preserve
release-profile-v1 and all existing numeric execution-repository checks. Transport
App/credentials remain actual M3 facilities, never reader authority or a supplied PAT.

M3 owns current/historical rendering, CSV safety, encrypted request-scoped pair and
final reader gate. Reuse the same two retained encrypted objects/metadata. Before
decrypting a download, reauthenticate current reader/session and records-App live
membership, then verify project/view/source/request and both pair identities.
Poll only exact existing pair metadata, not arbitrary Actions artifacts or a new
job registry. A repeated exact request can reuse the retained original snapshot;
source/request mismatch is conflict. Concurrent request IDs never overwrite pairs.

Stream only the selected bounded verified plaintext with private/no-store headers,
format/content-disposition and source/snapshot wording. JSON preserves canonical
values; CSV formula neutralization occurs in the actual renderer before encryption.
No private values reach Git plaintext, logs, workflow outputs/artifacts, caches or
public URLs. An incomplete pair, failed current gate or limit violation cannot
return successful partial output. Offer the existing local streaming CLI for work
outside hosted bounds. Sign/admin mutations never regenerate exports automatically.

### 11.1 Fixed control inputs and provider calls

Retain M4 `control_version:2` with exactly its existing root fields and `routing`
object. No v3 configuration or separate provider registry is needed. `routing`
already pins the portal origin/domain, numeric control repository, workflow
ref/OID and runtime profile. Keep static `export_request:null` for dispatched
exports; the authenticated inert invocation supplies the one dynamic M3 request.
Legacy v1 verify/reconcile/probe keep their existing closed behavior and hosted
export denial. New hosted operations require the protected v2 installation;
release production-profile-v1 remains unchanged.

The fixed workflow keeps its command allowlist. Add bounded string inputs
`export_request`, `bootstrap_request` and `authorization_context`, empty by default. The trusted
Python dispatch adapter reads only GitHub's local `GITHUB_EVENT_PATH` JSON,
validates the expected dispatch command/input keys and writes one0600 inert
invocation file under the fixed runner temp directory. Do not interpolate these
inputs into `run:` or environment values. The `export` branch requires exactly
one M3 request and hosted-export context, with empty bootstrap_request; `probe`
may carry exactly one bootstrap request/context and empty export_request.
Ordinary scheduled reconciliation has none. The bootstrap request is exactly
`{v:1,phase,control_copies,portal_copies,challenge_sha256}`. Initial copies are
exactly the records and coverage existing wrapped-key objects with the right
wrapper IDs; installed copies are null and are selected from validated stored
bindings instead. Phase must match the authenticated context.
Unknown/nonempty inputs for another command reject before secrets or key use.
The path is platform-controlled; a dispatch input cannot name it or an executable.

A protected export call is exactly `{v:1,request,authorization_context}` to
`POST /internal/exports/authorize`; membership uses a distinct fixed
`POST /internal/exports/membership` body exactly
`{v:1,request_sha256,authorization_context,organization_id,team_id,user_id}`.
The token audience is `dracla-export-v1.<domain hex>.<body SHA256 hex>`.
OIDC issuer/JWKS/claim/time/run/source checks are the M4 implementation; request
hashes are SHA256 of JCS complete bodies. An authenticated response is exactly
`{v:1,request_sha256,github_user_id,allowed,checked_at,expires_at}` or its fixed
nonprivate error. Membership additionally echoes organization/team/user and
returns one active-membership bit. The portal computes authority now; Python
cannot submit `allowed`. A response is scoped to this exact job/request and
expires in at most60 seconds and before context/session expiry. The final
renderer gate calls again; an earlier response is not cached authority.

`PortalHostedExportAuthority` exposes the actual M3 callable signatures. Its
constructor fixes project/request/context and authenticated control invocation.
`authenticate_request(request)` rejects any changed request and returns the
current authorized numeric user; `is_team_member(org,team,user)` rejects any
source not selected by current canonical reader policy and calls the fixed
records-only membership operation. No module path, generic method, token or
principal object in a file constructs this provider. The same bounded transport
validates origin, content type, status, complete response and exact echo fields.

### 11.2 Control key-proof transport without another job store

Use the existing `probe` dispatch command for the required bootstrap key proof.
Its separate closed `bootstrap-control` context binding is
`{phase,install_generation,repository_ids,release,workflow_ref,workflow_oid,
candidate_oid,key_commitments,challenge_sha256}`. `phase` is exactly `initial`
or `installed`; initial candidate_oid is null before K, installed is the exact
K/candidate OID. Repository roles/release and key commitment members use the
existing M1/M3 closed schemas; exactly records and coverage are present. Initial
context has only initial wrapping authority (§7.1); installed context requires
the current seven-check/activation authority and current candidate. Existing
project material cannot be selected through an initial context.

The CLI dispatches only bound encrypted control key copies and bounded fresh
challenge input as inert data, never a raw key. For initial setup, this data may
precede K and therefore the protected initial probe alone permits an empty static
`keyrings` map; all normal history/export/reconcile commands retain the existing
nonempty protected-map requirement. The fixed bootstrap adapter validates joint
command/context/phase/config before control-key access, and never calls history
verification on nonexistent first-event history. Before unwrapping it calls
`POST /internal/bootstrap/authorize` with exactly
`{v:1,authorization_context,bootstrap_request}` and a body-bound bootstrap OIDC
audience. The response is exactly `{v:1,request_sha256,phase,project_id,
install_generation,allowed,expires_at}` and is current for this job/request only;
false/mismatch/expiry denies before key access. Installed proof uses exact
stored copies/ancestry. M6 owns assembling/installing the temporary and final
protected binding; this is not a new canonical field or persisted keys_ready flag.

For each capability the probe unwraps its exact control copy and computes a
native HMAC-SHA256 proof under that actual data key over JCS
`{purpose:"dracla-key-challenge-v1",project_id,install_generation,capability,
data_kid,wrapper_id:"control",candidate_oid,challenge_sha256,workflow_oid,
authorization_context_sha256,run_id,run_attempt}`. The existing M3 key fingerprint stays unchanged. No raw
key, plaintext challenge or wrapping root is emitted. Python authors parity
and substitution vectors; do not invent a custom MAC or use an App JWT as proof.

The job submits exactly
`{v:1,authorization_context,bootstrap_request,commitments,proofs}` to the
fixed `POST /internal/bootstrap/prove`. OIDC audience is
`dracla-bootstrap-v1.<domain hex>.<body SHA256 hex>`. The portal checks the exact
initial/installed context, current session/authority appropriate to that phase,
job/workflow/repository identity and each actual candidate commitment/proof
against its independent service copy. In the initial phase it uses only the
supplied context-bound portal candidate copies in bootstrap_request, never an existing project's repository key. A control
proof cannot stand in for the separate portal/enforcer service challenges.

Return one nonprivate, short-lived signed `ControlKeyProof` containing exactly
`{v:1,domain,project_id,install_generation,control_repository_id,workflow_oid,
run_id,run_attempt,candidate_oid,commitments_sha256,challenge_sha256,
authorization_context_sha256,verified_at,expires_at}`. Use the existing portal Ed25519 primitive/key family
with distinct `dracla-control-key-proof-v1` domain. The closed envelope is
`{proof_version:1,kid,payload,signature}`. Sign ASCII
`dracla-control-key-proof-v1`, one zero byte, then JCS of exactly
`{proof_version:1,kid,payload}`. Use M4's exact raw Ed25519 key/kid/64-byte
signature encodings; deny unknown fields/version/kid/domain, noncanonical JCS
and malformed/malleable signatures. `domain` is the configured installation
routing domain, not a caller string. It grants
no read/write/session permission and expires at the context expiry. The job may
emit exactly one `DRACLA_CONTROL_KEY_PROOF_V1 ` line followed by strict unpadded
base64url of the complete envelope's UTF-8 JCS bytes (at most16 KiB decoded).
The CLI reads bounded logs only from its own exact dispatched repository/run/
attempt/job, strips GitHub's known timestamp prefix, and accepts one full literal
line only. Reject missing/duplicate/oversized lines, unexpected job/run/attempt,
invalid encoding or trailing data; do not search arbitrary text for a JSON blob.
Decode and verify the envelope before passing it to original setup/Connect. No service token, context envelope,
raw key/challenge or private response goes into that log. The portal verifies
signature/purpose and exact request/session-bound context/nonce commitments,
including equality of the original wire-context digest, then independently
rechecks all required installed facts before activation. Negative vectors must
swap contexts differing only in session_jti or request_nonce, re-encrypt an
otherwise identical context, alter a digest in MAC/proof, and substitute the
job/attempt. Every substitution fails; valid original context succeeds.

Existing GitHub job results transport this bounded nonprivate evidence; no new
CLA receipt/job registry, KV approval record or polling database is introduced.
The result is not authoritative canonical state and cannot survive its bound
setup generation/session expiry as a permission. Lost result restarts the same
fresh proof sequence; it cannot create another project or retarget a candidate.

## 12. Concrete bounds and cost model

Load unchanged M1 release-profile-v1 and M4 runtime-profile-v1. A shared invocation
budget accounts for every nested call, retry and response byte. Do not multiply
allowances by calling another service, cache authority to meet a scalar estimate,
or raise a bound through an environment/request field. The stricter applicable
profile governs. Unsupported inputs fail before allocation or state publication.

| Surface | Initial bound and enforcement |
|---|---|
| M5 browser JSON | 64 KiB total, depth16, no unknown/duplicate members; canonical event/side artifact limits additionally govern. |
| Agreement content | 256 KiB uncompressed UTF-8 before sanitize/render; renderer node count4096/depth32, URLs2048 bytes, fixed allowlist. A larger document fails explicitly before assent, never truncates. |
| Cookie/state/context | 3800 bytes per cookie/envelope, OAuth code2048 bytes, nonce16/verifier32 raw bytes, state/pre-auth/context600 seconds, return path512 bytes and fixed allowlist. |
| Current session | Token expiry minus300 seconds; at most7h55m under the initial token policy, no refresh/sliding. |
| Private proof/permission | Original proof≤300 seconds/session; signed permission/PR result≤60 seconds/request. Input proof/context capped16 KiB before decoding. |
| Team/source work | M1 reader-source512 members, continuous readers10, exemptions32, cursors2048; complete API pagination100/page and existing shared49-call ceiling. |
| Private/class transport | Existing per-class ciphertext/state caps; immutable batches≤8 aliases,≤1 MiB response and≤3 MiB total invocation HTTP bytes under M4. Pack by actual encoded envelope bytes; maximum-size reader blobs need smaller batches. |
| Mutation | Complete prepared cell≤1 MiB, at most3 M1 attempts, deterministic affected paths, bulk writes≤32 shards and one complete final state. Original M4 limits and guards apply to any handoff. |
| PR | M4 complete PR≤250 commits/512 subjects; private subject page/work ceiling uses exact same ordinary proofs and shared budget, no new bulk authority. |
| Hosted export | Existing383000 plaintext bytes/output,512000 encrypted bytes/output,1024000 pair bytes,10000 records; protected context600 seconds and fixed job timeout15 minutes. Missing/expired current authority still denies within timeout. |
| Bootstrap | Exactly3 repository roles/3 service wrapper pairs,2 current data capabilities,32-byte candidate keys,12-byte AEAD nonce and16-byte fresh challenge nonce; context/payload≤64 KiB, no arbitrary wrapper or fetch URL. |

These are concrete initial implementation constraints, not measured capacity or
new canonical formats. Apply the existing supported larger-profile process rather
than relaxing a parser. Private-class/runtime overflow denies that class and stays
visible; do not convert it into a lifetime contributor cap or pretend skipped
shards are empty. Validate bulk cell/selection/fanout admission before append and
exercise all boundaries at below/equal/above values.

Record cold traces for login/form/action, all32 reader-source shards plus up to10
current memberships, each private page, named PR detail, every continuous observation,
Connect/challenges, dispatch and download. Include key/installation-token acquisition,
metadata/identity/generation reads, immutable blob batches, retries and service
fanout. Count nested calls once in shared totals and separately attribute each
provider/Worker for billing. A successful fixture is not evidence of Free CPU,
SSO/App visibility, OAuth, control execution, real token containment or account
capacity. The runnable acceptance driver must block the corresponding production
claim when those measurements/providers do not meet the approved baseline.

## 13. Completion evidence and requirement ownership

Each canonical slice lists concrete ownership and observable checks. Cross-slice
completion must traverse the actual local Workers/HTTP, browser and Python engine,
not merely mock success unions. Extend M4's existing real runtime harness; create
one browser harness in m5/2 and reuse it. Python authors semantic/parity vectors.
M5 tests include actual adapter/provider calls with scripted authenticated HTTP,
not only pure codecs. A separately authorized live driver proves real providers;
it is not run as part of design or an ordinary offline suite.

| Requirement | Owning behavior and integrated evidence |
|---|---|
| R01 | m5/2: full public presentation, rename/no-active/current-field/source and hostile markup; m5/17 full journey |
| R02 | m5/1: same-browser PKCE, absolute session expiry, identity/401/403, logout/rotation and preinstallation identity |
| R03 | m5/4 common forms; m5/6/7/12/13/14 all24 exact action rows; tamper/internal/no-op/stale-head/retry negative matrix |
| R04 | m5/3 partial exact own-status; m5/4/5 canonical pending state, no arbitrary subject and unaffected subject races |
| R05 | m5/4/5 actual assent/correction/revoke/re-sign and originating continuation, tuple cutoff and legal evidence retention |
| R06 | m5/6 immutable publish/activation/restoration; m5/17 actual lifecycle and independent revocation |
| R07 | m5/2/6 current public config/labels, immutable recipient, advisory/explicit blocking v2 and compatibility |
| R08 | m5/18 actual authority providers; m5/6 admin consumers; m5/12 all seven Connect checks; m5/13/14 exact later resource matrix |
| R09 | m5/11 initial wrapping and all three service paths; m5/12 control/recovery/K-B/Connect; m5/13 transfer/succession/keys |
| R10 | m5/4 actual bounded private adapter, m5/7 bulk generation and m5/17 real M3 crash/readback recovery; one M4 writer |
| R11 | m5/7 default frozen snapshot/source union; m5/8 explicit continuous delegation, actual observers/cursors/doorbell/daily repair |
| R12 | m5/9 all32 source validation, exact proofs/pages/records-only membership and immediate next-read denial |
| R13 | m5/18 signed minimal permissions; m5/10 bound PR facts and every tier; m5/9 exact private per-subject authority |
| R14 | m5/18 read-only repository conflict inspection; m5/14 scope/maintain override/write retry; actual M4 coordinator and no quarantine bypass |
| R15 | m5/5 exact continuation and existing M4 sweep; m5/10 unambiguous numeric PR context |
| R16 | m5/15 real protected Python export authority/renderer; m5/16 current private delivery, concurrency/source/history/CSV and limits |
| R17 | m5/1/2/4/9/11/16 input/CSRF/rendering/privacy; m5/13/17 actual controller/key/rotation/isolation and redaction sensitivity |
| R18 | m5/17 actual assembled runtime/browser/Python checks, cold cost traces, runnable authorized live drivers and complete separate LOC |

Inject failures at every persistent transition and verify deliberately broken
checks fail: remove membership/generation/head verification; expose a named
lower-tier subject; skip one wrapper; suppress final export authorization;
misroute callback; mark a partial effect completed. Preserve ordinary conformance,
full package/vector/type checks and test scope appropriateness. Nine existing live
skips are not passing evidence for these newly required production gates.

## 14. Estimates, readiness and review boundary

Current planned totals are **9,570–15,200 production lines** and
**15,810–25,340 test lines**, across18 coherent ordered slices. Preserve original
m5/1–17 IDs; m5/18 is the early observable authority/conflict-inspection
foundation, ordered after m5/2 and before m5/6, not an eighteenth late consumer. The canonical
numbers are the schema-2 inventory. The unit is incremental final delivered
nonblank physical lines excluding comment-only lines; count docstrings physically.
Production includes shipped config/packaging/Markdown instructions. Tests include
helpers/config/generators and browser/integration/live drivers. Exclude designs,
static fixtures, generated output/images, dependencies/locks and disposable probes.
These are neither fixed-base edit churn nor time/productivity estimates.

The wider test range comes from browser security and full action/resource matrix,
actual Worker/Python recovery, cross-service authorization, live-provider drivers
and crash/race/expiry sensitivity; it is not a fixed ratio. Shared M4 runtime/
writer/OIDC/HTTP/SQLite and M3 renderer/replay tests are not counted again. Per-slice
reasoning and source anchors are in linked support. Changed execution evidence
requires reviewed resizing/engineering correction, not dropping an obligation to
fit a number or hiding a new credential/store in a high estimate.

No new owner question is currently proposed. Required plan/inventory review and
its exact current dependency/approval reconciliation remain pending. A clean plan
will still not establish authentic publication, installed grants/release, live
OAuth/PKCE, hosted private-read/mutation/export CPU or real containment. Those are
explicit execution/production acceptance gates. If a provider cannot meet the
contract inside approved grants or engineering exposes a genuinely new material
behavior/trust choice, preserve the draft and bring that concrete decision back.
