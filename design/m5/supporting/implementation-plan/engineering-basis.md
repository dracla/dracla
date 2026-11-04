# M5 detailed engineering and estimate basis

This supports the [implementation plan](../../implementation-plan.md). The
[architecture basis](../high-level-design/engineering-basis.md) is the canonical
shared source inventory. Do not repeat its current-primitive counts as new
production work. Inspected Sapling head is
`ec45c63ad01c197330702bbaefb2c5935333e688`; the requirements and final HLD are the
exact clean reviewed documents. M4's planned runtime is a prerequisite, not
already shipped code. No product implementation or live test ran here.

## Source conclusions

- `actionForms.ts` has complete closed form/HMAC/head/terminal-no-op semantics.
  Add actual issuance, live session/resource checks and action handlers; do not
  create another nonce store or canonical operation registry.
- `derived.ts` has full materialization plus selected-class reads. Its full
  `DerivedPlaintext` owns all 96 private shards and its `resolveReadStatus`
  requires a full coverage projection. A bounded production mutation/read
  adapter is real missing work. Extract shared row/status transformations and
  retain strict full-model validation; compare partial results with the actual
  Python/full reference, including untouched shard digests. Do not construct
  fake complete models or fetch/decrypt 96 shards per ordinary action.
- `publishDerivedProjection` counts all changed private shard paths against
  the installed bulk bound, not merely the number of selected users. Admission
  must calculate actual fanout/bytes before append. Never silently split one
  frozen snapshot event or weaken the existing 32-shard publication check.
- `exports.py` already renders, pairs, encrypts and performs the final reader
  gate. `control_job` deliberately denies `export` with `authority=None`
  before history/key use. The real authenticated adapter, protected context,
  dispatch and delivery integration are M5 work; count the renderer once in M3.
- `github_admin.py` is a local provisioning client with broad administrator
  credential visibility rules. It cannot be reused as a portal credential or
  prove all repositories are visible through a records-App user token.
- `provisioning.py` is an explicit blocked installation description. M6 must
  implement the orchestrator. M5 supplies real wrap/challenge/Connect contracts,
  not a second installer or an assertion that the old description executes.

## Provider checks, 3 November 2026

Primary documentation was read; these are capability facts, not installed/live
acceptance. Keep links instead of embedding provider examples or private data.

- [User authorization](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user)
  is possible before App installation. Resource access remains the intersection
  of App and user access. This permits identity-only authentication for initial
  setup, not a preinstallation claim of private-repository administration.
- [Repository permission observation](https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user)
  supports App user/installation tokens with Metadata-read. Legacy `permission`
  collapses maintain to write; inspect exact role/permission evidence before
  allowing maintain. Rebind the returned numeric user and repository identity.
- [Organization membership](https://docs.github.com/en/rest/orgs/members#get-organization-membership-for-a-user)
  needs accepted Members-read; active admin membership proves organization-owner
  control. Public membership alone does not. Personal-owner control is exact
  equality of live actor and repository-owner numeric IDs.
- [Repository installation lookup](https://docs.github.com/en/rest/apps/apps#get-a-repository-installation-for-the-authenticated-app)
  requires the relevant App's own JWT. A records token cannot inspect another
  App's installation. Keep the enforcer lookup on the enforcer and observe the
  trigger binding using its already-approved portal capability.
- [Team membership](https://docs.github.com/en/rest/teams/members#get-team-membership-for-a-user)
  uses Members-read and distinguishes active from pending membership. Resolve
  stable team/organization IDs; a renamed login/slug must never select a new
  subject/team. Reader checks stay records-App-only. Enforcer fallback is for
  the approved exemption purpose only.

The [architecture basis](../high-level-design/engineering-basis.md) owns PKCE,
static assets and browser isolation references. M4's basis owns common
Worker/SQLite/OIDC/runtime limits. Delivery locks a compatible tested browser
harness and sanitizer; choosing a dependency does not prove its configuration.

## Initial setup and later Connect are different operations

Global HLD §6.10.2 explicitly wraps caller-generated keys before App installation
and repeats repository-bound live proofs after installation. Preserve that
sequence. The initial operation authenticates the current setup session and
binds the exact caller-owned proposed key fingerprints/arrangement to an
unclaimed project and install generation. It wraps/decrypts only supplied
candidate challenge material. It reads no private project state, unwraps no
existing repository key, claims no administrator permission and creates no
registry/event/route. No fabricated seven-check verdict enters this context.
Connect separately performs all seven current owner/repository/App checks and
proves the actual installed key copies before the first private event. Existing
project rotation is not initial wrapping and requires its current authority.

This is an engineering interpretation of the approved two-phase bootstrap,
not a grant for anonymous or existing-project key access. Test both phases and
negative cross-phase substitution. If actual implementation needs wider access
or cannot maintain this separation, return that specific trust decision before
changing the accepted boundary. Do not reorder installation or add a PAT flow
silently.

## Estimate method and uncertainty

Canonical per-slice numbers live in `slices.json`; the final plan states their
sum and the same counting unit. The estimates describe incremental final
shipped nonblank physical lines, excluding comment-only lines and counting
multiline docstrings physically. Shipped runtime config, packaging and Markdown
instructions are production. Test helpers/config/generators/browser and live
acceptance drivers are tests. Designs, static fixture data, generated files,
images, lockfiles, dependencies and disposable probes are excluded.

Estimate each owned handler, codec, UI and integration against the inspected
existing seam. Shared HTTP/crypto/Worker/SQLite, route/gate, canonical writer,
OIDC and their base tests stay in M4. Full replay, keyring/history, renderer and
existing Python transport stay in M1/M3. Only M5 changes/extensions count here.
The browser harness has one owner; other slices add cases to it. Do not
translate lines into hours or report added-plus-removed churn as delivered LOC.

Ranges allow validation/error/mapping/test detail and supported provider
variance. They do not hide a new credential, store, canonical format, replay
engine, scope reduction or new trust model. Actual cold CPU/bytes/subrequests,
GitHub SSO/custom-role/installation visibility and protected dispatch remain
execution acceptance. A failed gate blocks the corresponding production claim;
it cannot be replaced with documentation or a passing mock.

## Per-slice estimate composition

The inventory owns the numerical ranges. This table records why the required
work belongs in each range; it is not another delivery definition.

| Slice | Production composition | Test work and uncertainty |
|---|---|---|
| m5/1 | OAuth/callback, cookie/context codecs, live-session KV/key eligibility and safe errors over existing HTTP | Same-browser/replay/swap/expiry/rotation matrix and actual Worker/KV behavior; no second HTTP/runtime harness |
| m5/2 | One shell/client/assets, public presentation and isolated fixed viewer, CSP/routing/package wiring | One reusable real-browser harness, hostile markup/frame/readiness and complete/current public content; no dashboard duplication |
| m5/3 | Shared status-core extraction, partial validated coverage/private-row adapter and own-status acquisition/UI | Actual Python/full parity and untouched/unknown/wrong-subject/fence/generation cases; existing derived codec not reimplemented |
| m5/4 | One common form/builder service, missing bounded private-mutation adapter, actual assent/correction UI | Every form/head/no-op/idempotency branch, partial/full parity and actual Worker plus Python crash recovery; common form tests counted once |
| m5/5 | Revocation/re-sign and exact M4 callback integration | Interleaved acceptance, tuple cutoff, lost callback and complete browser journey; no callback engine or queue re-estimate |
| m5/6 | Common admin UI and immutable publication/activation/config over m5/18 authority | Public/unlisted and existing-authorized private source versus outside-reach, exact snapshot/restore and v2 default/warning/downgrade; common authority is counted once in18 |
| m5/7 | Source/member selection, exemption-only enforcer team extension, frozen snapshots, withdrawals and bounded bulk adapters | Multi-source union, actual shard fanout, full final generation and interrupted M3 bulk repair; tests extend existing materializer reference |
| m5/8 | Actual daily/doorbell team observers and cursor-bound automation producers | Missed/duplicate/reordered events, pending/departed membership, source binding and serialized recovery; no second scheduler/store |
| m5/9 | Strict existing proof/JWS and runtime all32-source/current-page service | Every source/proof/class/scope/generation/live-check case with actual ciphertext; base crypto/HTTP are not recounted |
| m5/10 | PR unions/views extending m5/18 signed observation service, numeric link context and tier UI | Every public/private tier, same-number repos, head/route races, signature substitution and per-subject proof loss; M4 PR facts are reuse |
| m5/11 | Three closed wrappers/challenges, bounded initial setup context and current installed operation separation | Cross-phase/project/wrapper/actual-key/context/expiry/rotation and no-persistence cases; native wrap/keyring crypto already exists |
| m5/12 | Seven-check Connect, exact bootstrap/K-B, first-writer inputs, fixed control-key proof adapter and authenticated root-only initial derived-ref transport | Real first append/ref creation/recovery, lost replies/concurrent creators/whole-tree denial, every missing live/recovery proof, replay/partial claim and protected control boundaries; M6 installer not counted |
| m5/13 | Transfer/succession/key activation handlers and UI | Whole/partial move, succeeded-project allowlist, every successor service/control/recovery path and retained historical access |
| m5/14 | Scope/override/retry UI and exact handlers reusing m5/18 conflict inspection | Correct independent authorities, remove-before-bind, tree/subject scope and quarantine/fence cases over actual M4 coordinator |
| m5/15 | Fixed dispatch/inert input/control schema integration, actual Python authority provider and purpose-bound portal calls | Actual renderer/provider before-key/final gates, expiry/membership/current/history/concurrent-pair reuse and protected release source; no renderer rewrite |
| m5/16 | Request/status/download client and reauthorized fixed snapshot stream | Lost/incomplete/wrong-source pair, former reader, formula cells, no-store/redaction and output boundary; no second export format implementation |
| m5/17 | Shipped portal/security/capacity guidance and package integration | Cross-service browser/HTTP/Python full journey, broken-check sensitivity, controller lifecycle and actual-resource/live drivers; individual suites/base harness are reuse |

| m5/18 | Current actor/owner/App/named-user authority, signed closed observation modes and authorized read-only repository conflict inspection | Wrong-resource/role/SSO/grants/signature/completeness matrix, setup before route and conflicted-route admin inspection; providers and their tests moved here once from6/10/14 |

Moving authority/permission/inspection work earlier does not add duplicate LOC.
The increase covers missing exemption-team provider work (150–250 production,
200–350 tests) and the existing-capability immutable-source branch (50–90
production,80–120 tests). Explicit context binding/parser negatives are within
the existing bootstrap cross-context matrix. Preserve original17 IDs and add18
in prerequisite order; no extra credential, store, corpus or approval mechanism.

The approved bootstrap-order correction exposed an actual source integration
cost in m5/12. `history.py` has380 counted source lines, `append.py`656 and
`reconcile.py`381 under this package's nonblank/non-comment-only unit. The
ordinary history path requires a derived ref and connected replay, engine
snapshot/key selection assumes that history, and default stored preconditions
refuse first Connect. The fixed bootstrap adapter therefore needs minimal
initial-observation, absent-derived and key-selection seams in those existing
modules, plus real before/after-append repair tests. Budget an incremental
150–250 production and250–450 test lines within m5/12: the bootstrap-adapter
subtotal before the transport addition below is800–1,250 production and
1,300–2,150 tests. This counts new integration only,
not existing reader/crypto/replay/engine code or M4's common executor/harness.
It refines an absent prerequisite in the approved first-Connect responsibility;
no new slice, permission, wire format, persisted store or alternate writer.
The range remains uncertain until the actual acquisition and transport tests
are implemented; the affected review must challenge it.

The actual first-ref source inspection exposes a further missing seam:
`RepositoryTransport.conditional_commit` requires an existing head, while
`publish_projections` starts from `snapshot.derived_oid`. m5/12 now owns
`github.py` and its real transport tests. Initialize the absent derived ref to
the already authenticated README-only root only after genuine Connect lands,
then reuse normal bounded conditional projection publication. This avoids a
new commit builder, projection format, writer or deterministic encryption.
Budget80–140 production and180–300 test lines for typed authenticated absence,
fixed root-ref creation/readback, exact frozen-operation retry classification
and the actual HTTP/crash/concurrent/extra-file negative matrix. This is new
incremental work, not the entire transport or existing bulk publisher again.
m5/12 therefore totals880–1,390 production and1,480–2,450 tests. Its basis remains
uncertain until real transport integration, with no obligation removed.

[GitHub's reference API](https://docs.github.com/en/rest/git/refs), checked4November2026,
documents successful array-based matching-ref observation and create-ref under
Contents-write. Prefix matches require exact-ref filtering. The repository is
already nonempty at this point; the first records branch was initialized by
Contents before genuine Connect. Documentation supports this adapter direction,
not a live policy/permission proof. The focused real HTTP and authorized live
drivers must still test its denial/ambiguity/concurrency behavior.

M5 total: **9,570–15,200 production** and **15,810–25,340 test lines** in the stated
final-delivered units. Upper ranges allow actual provider/error combinations and
browser/crypto integration detail; they do not assume a fixed test/production
ratio. New material scope/trust or unsupported baseline behavior is not an
estimate variance and must not be hidden there.

[DOMPurify's current release](https://github.com/cure53/DOMPurify/releases/tag/3.4.17)
and its [security advisories](https://github.com/cure53/DOMPurify/security/advisories)
were checked for the selected isolated HTML-only rendering approach. The design
uses no in-place/template/shadow-root mode. Delivery must still lock reviewed
bytes and exercise actual CSP/browser behavior; a version string is no isolation
proof. Browser tests extend one real Playwright harness with the M4 Worker/HTTP
harness rather than replacing actual browser execution with a DOM emulator.

The existing conformance authoring pipeline (`conformance/authoring/build.py`,
`derived-v1.json`, `transitions.py` and `core/dracla/conformance/vectors.py`)
owns the common corpus/manifest. m5/3 extends those inputs and checked cases,
not a nonexistent or parallel generator. Public publication does not require a
public-origin flag: [GitHub gist visibility](https://docs.github.com/en/enterprise-cloud%40latest/get-started/writing-on-github/editing-and-sharing-content-with-gists/creating-gists)
includes accessible unlisted gists. Authenticated repository reads stay within
the acting user's already-accepted project-bound reach.
