# M6 — End-to-end installation and deployment requirements

Status: locked-scope requirements draft. Existing product and architecture
approval applies where decisions remain unchanged. This document authorizes no
product implementation, account operation, credential use or publication.

## 1. Outcome, authorities and ownership

An unrelated adopter can provision one complete private three-repository
arrangement with the released `dracla install`, keep its own recovery material,
install the approved Apps and proceed to the separate authenticated Connect
journey. A partial operation must remain safe to rerun or explicitly refuse
unproved reuse. The same released system must support the default shared service
and a real adopter-controlled self-hosted deployment, with verified upgrade,
rollback, recovery and migration integration.

The governing documents are the [product requirements](../requirements.md),
[global architecture](../high-level-design.md),
[M1 formats and semantics](../lld/m1-conformance-kernel.md),
[M3 control, recovery and release contracts](../lld/m3-control-reconciler.md),
[M4 runtime/routing architecture](../m4/high-level-design.md) and
[M5 portal/bootstrap architecture](../m5/high-level-design.md). Their parent
prose, trust disclosures and release obligations remain in scope. This package
refines installation responsibilities; it does not replace those contracts.

M2 already supplies scoped administration operations and the pure installation
planner/resume seam. M1 owns canonical encoders, envelopes and reference
semantics. M3 owns transport authentication, external protected execution,
history, reconciliation and export rendering. M4 owns the runtime, shared
writer, registry/route/gate and sweep. M5 owns actual wrapping/challenge,
Connect, legal configuration and authenticated portal operations. Reuse those
engines and their tests. M6 owns the real installer orchestration, missing
initialization/provenance adapters, installed configuration and deployment,
upgrade/recovery integration and their acceptance drivers. M7 owns dashboard,
badges, sample presentation and final assembled release/capacity evidence.

No hosted provisioning App, records database, alternate writer/replay engine,
new agreement format or second installation truth store is required. The
owner-approved replacement-recovery extension is the sole new event contract: a
prospective authenticated append-only repository rebind, with original history
unchanged and all first-installation security standards retained. An organization dedicated to DraCLA is optional. Do not rewrite
completed M1–M3 plans, IDs, approvals or source merely to standardize this package.

## 2. Actors, authority and completion

The adopting administrator runs provisioning locally with their own current
GitHub authority. Hosting the portal never grants it repository creation,
workflow-editing, administration or secret-write permission. The transport App
is a separate integrity principal from the three service Apps and never
becomes a provisioning credential or a records reader.

GitHub owns App registration, installation and permission consent. A printed
link, callback parameter, session alone or App's own privilege cannot prove
the actor's current authority. Every executing operation binds stable numeric
account/repository/App/installation identities and the exact intended role.

Distinguish these outcomes in both UI and machine-consumable results:

- **Planned:** fresh read-only observations and release checks support the
  displayed intent; no installation effect is implied.
- **Provisioned:** the required repositories, protected control, actual key
  paths, recovery handoff and bootstrap state are verified. App installation,
  Connect, signing and routing do not follow automatically.
- **Connected/signable/routable:** independently established by the owning M5
  and M4 protocols, including agreement activation and scope activation.
- **Blocked or uncertain:** name the safe category, exact known identities and
  finite next action. Never print success for an accepted but unverified write,
  secret update, dispatch, incomplete proof or partial bootstrap.

## 3. Required behavior

### M6-R01 — Existing CLI intent and local preflight

Preserve the approved `dracla install github.owner=ACCOUNT` journey, optional
owner-scoped `project.slug`, and `dry_run`/`force` behavior. The default slug is
the exact case-folded owner login; do not strip `-cla` or infer a legal recipient.
One invocation concerns one independent arrangement named
`<slug>-cla-records`, `<slug>-cla-coverage` and `<slug>-cla-control`.

Validate inputs, exact package version, canonical bundled release policy,
dependency constraints and actual installed dependencies before authorization.
Report declared source/publisher/provenance identities honestly. Installed
package declarations alone are not independent proof of that package's origin.
Reject invalid or unexpected configuration without echoing secret input.

### M6-R02 — Nonmutating planning and meaningful confirmation

A dry run performs only bounded reads and local verification. It creates no
repository, ref, App, key, secret, workflow run, project claim or route. Show the
same exact intended resources, missing prerequisites and trust disclosures as
execution. A ready plan does not prove executable engines or live acceptance.

Before mutation, confirm the exact current intent unless `force=true` suppresses
that execution confirmation. Force cannot clear a blocker, change an anchored
identity, adopt a collision, bypass GitHub consent, suppress trust disclosures
or replace required explicit hosted-controller authorization. Preserve spent
confirmation and retry context rather than silently widening intent.

### M6-R03 — Fresh administrator and resource observations

Resolve the current personal or organization account and stable numeric owner.
Prove complete relevant private-repository visibility and administration under
the accepted local credential. Read the exact three-role scope and bind every
known numeric repository ID. An invisible repository is not a free name.

Recheck actor/account, privacy, current permissions and numeric bindings before
an administrative write and during readback. Account rename cannot select a
recycled account; changed or missing known IDs conflict. Unknown SSO, policy,
permission or incomplete inventory evidence blocks that operation. A shared
service or transport App credential cannot stand in for the administrator.

### M6-R04 — Private repository creation and exact branch genesis

Create all three repositories empty and private, using the supported GitHub
initialization sequence. Create the mandatory records README root through the
Contents API on GitHub's actual initial default branch, then rename that same
branch/head to `events` and verify it is default. Do not assume `main`, use
`auto_init` or attempt an impossible first Git-ref creation.

The root contains no configuration, agreement, event or executable workflow.
Keep canonical `events`, prepared `operations`, wrapped `keys` and derived data
on their approved separate branches. Coverage and control have their own exact
approved layouts. Initialize only through intended non-forced writes and
current readback; a conflict never authorizes rewriting another branch.

### M6-R05 — Protected control and pre-key execution verification

Seed control with the exact released pinned workflow, protected inert bindings
and provenance. Use repository Actions secrets for the private-control Free
baseline; environment secrets or paid private-repository branch protection
cannot be required. Optional hardening must not carry a correctness dependency.

Before the protected control workflow receives transport or project-key
material, verify its actual executing repository's numeric identity, pinned
workflow/source and external artifact/dependency/verification-tooling evidence
required by M3. Execute that verified artifact without resolving it again by a
mutable version. For the ordinary one-time installer, external pre-execution
verification remains optional; bundled local policy and dependency preflight
remain mandatory. Do not add a mandatory external installer wrapper. No records/coverage content,
workflow fragment, JSON module path or request can select executable behavior.
M5's initial and installed proof branches retain their distinct authority and
compatible protected configuration. Missing verification fails before keys.

### M6-R06 — Transport App provisioning, scope and custody

Support the approved dedicated or explicitly shared private transport App owned
by the data repositories' account. Its permission set remains only Contents
write and implicit Metadata read, with selected records/coverage repositories.
Verify the complete approved arrangement union, exact App/client/installation/
owner identities and exclusions before key use. No control or contributing
source repository, all-repository selection, additional grant, deploy-key or
personal-token runtime fallback qualifies.

The administrator confirms registration and selected installation through
GitHub. Handle registration conversion and private-key material locally; never
send it to hosted DraCLA. Store the App key only in assigned control secrets,
with the protected assignment binding and actual restricted transport challenge.
Operational tokens remain narrowly scoped, short lived and process local.

Show the mandatory integrity warning before authorization and in completion:
the App key can mint credentials to read encrypted and rewrite/delete/rollback/
replay repository state across all assigned arrangements, affecting checks. It
cannot decrypt records by itself or edit excluded control. Identify every
assigned arrangement/repository and secret controller. Sharing couples exposure,
rotation and suspension; different key pairs for one App do not isolate reach.

### M6-R07 — Actual project-key proof and safe recovery handoff

Generate the actual records and coverage data keys, current kids, control
wrapping material and adopter recovery wrapping key using the existing crypto
contracts. Prove both actual data keys through recovery, the exact three service
paths and protected control before enabling initialized private artifacts.
Portal-records, portal-coverage and enforcer-coverage are independent paths.
A matching kid or successful secret write alone is insufficient.

Preserve approved two-phase setup: before App installation, only authenticated
unclaimed-candidate wrapping/challenges are permitted. Installed Connect later
rechecks current repository-bound authority and actual stored copies. Use M5's
purpose/context/session/generation/key/request-bound proofs; no durable
`keys_ready` flag or replayed setup receipt grants authority.

Disclose the hosted operator's ability to obtain hosted signer PII and link the
specific controller/FAQ/self-hosting explanation before sending raw candidate
keys to that service. Deliver recovery material securely to the adopter with
prominent safe-storage instructions before private writes. Do not put keys in
argv, ordinary configuration, Git, logs, URLs, outputs or artifacts. Keep
necessary transient material bounded and private, and retain no raw key after
successful handoff. An incomplete proof or handoff never reports provisioned.

### M6-R08 — Exact bootstrap and independent idle guards

Create the unique initial keyring candidate commit `K` descending from the
mandatory records root, including both recovery metadata and actual-data-key
binding proof. Its direct child `B` adds the canonical non-secret bootstrap
manifest. Preserve exact project/install generation, release declarations,
three repository IDs, K/current kids and wrapper bindings. Store identical
manifest bytes on records, coverage and control; final control provenance pins B.

Create the encrypted schema-valid idle operation cell, independent idle
coverage fence and empty in-flight marker using existing M1 formats and verified
actual keys. These are bootstrap guards, not a complete coverage projection.
Before genuine Connect, semantic coverage source/active-agreement/shards and
private derived generations remain absent. Installer writes no
`config/project.enc.json`, agreement or private event. Do not fabricate active
replay state or introduce an unconnected coverage format. The owning M5 Connect
and single M4 writer authenticate exact root/K/B and absence/guard preconditions,
append the genuine first event/config, then build and read back complete normal
coverage and private derived state before guard completion.

No force-updated keyring, duplicate initial candidate, changed manifest,
wrong K/B ancestry or inconsistent stored copy can enable Connect. Wrapped
recovery material remains sufficient to interpret retained history independently
of the former operator.

### M6-R09 — Provenance-based rerun and immutable intent

Rerun recomputes current evidence for the exact intent. Reuse only resources
whose own genesis, branch/content/provenance and bootstrap bindings establish
the correct role and generation. Compare release/policy/constraints, numeric
owner/repositories, K/B and all available manifest copies. Never trust a prior
step flag, name, empty repository, secret name or browser callback as ownership.

Keep partial generations non-routable and explicitly distinguish a verified
resumable prefix from absent or conflicting proof. A previously known resource
that disappears does not become an unassigned name. Missing early provenance
may require explicit owner cleanup or a new plan; it cannot be hidden by a
claim that every partial failure is automatically resumable. Preserve known
identity anchors and historical data. No separate progress store becomes
installation authority or canonical project truth.

### M6-R10 — Ambiguous writes, races and bounded retry

Use existing scoped administration/transport result distinctions. An accepted
request is not verified completion. For a lost repository/ref/secret/dispatch
response, read the exact current identities/effect before any bounded repeat.
Name-only readback cannot prove uncertain creation ownership; secrets need
actual challenge, and dispatch needs a bound observed run/result.

Concurrent installer, head/default-branch change, immutable-content mismatch,
rate limiting, interrupted pagination or unavailable evidence leaves safe
blocked/uncertain state. Never automatically force a ref, overwrite unrelated
content, delete a collision, mint fresh setup authority or rerun an uncertain
write blindly. Define finite safe recovery guidance and redact provider errors.

### M6-R11 — Three service Apps and stateless installation callbacks

Present the approved records, enforcer and reconciler-trigger installation
links with their exact permission and repository roles. Records serves records
and coverage; enforcer serves coverage and contributing repositories; trigger
serves control with Actions-only capability. Keep the separately provisioned
transport App's authority and consent distinct.

GitHub consent is a human operation. Do not claim one App can install another.
Callbacks persist no supplied installation identity or project claim. Direct
GitHub installation works identically; Connect discovers and verifies actual
bindings independently, including accepted permission changes. Links contain
no credential and never imply connected/signable/routable completion.

### M6-R12 — Separate Connect and first-private-write integration

Hand the exact provisioned arrangement to the approved M5 Connect journey.
The authenticated administrator supplies recipient, agreement/policy/field/
reader/scope intent there, not through install flags. Connect independently
requires the exact seven owner/repository-admin/App-binding records, installed
release/bootstrap equality and all live/control/recovery proofs before the
first idempotent `project_connected` event and encrypted config. Their guarded
append precedes full coverage/derived materialization; the normal resulting
lifecycle is active with no active agreement yet. Use M1's existing
`generations-absence` and independently validated guard objects for the initial
acquisition. An absent semantic projection never authorizes a regular connected
mutation or a success check. A prepared/appending first operation resumes only
with exact owned frozen-package/ancestry proof and actual M3 recovery.

Installer cannot write the shared registry or publish a project route. Initial
scope follows M4 requested/activated generation and gate transitions after
connection. Agreement publication and explicit activation remain separate from
provisioning and connection. Test first append, lost result and scope activation
through the real owning services; do not replace them with a saved success bit.

### M6-R13 — Supported shared and self-hosted deployment

Shared hosting is the default. Provide a complete documented deployment of the
same released code into adopter-controlled Cloudflare/GitHub accounts with
adopter wrapping roots and its own registry, App identities and operational
credentials. The normal installer can target that accepted deployment without
source edits or former-operator assistance. No new hosted provisioning power
or canonical record conversion follows.

Preserve two Workers, disjoint secret bindings, same-origin portal shell/API,
a separate isolated cookieless agreement origin and bounded repository routing
gates containing no CLA evidence. Install exact released assets, verification
keys, service bindings, accepted configs/profiles and reconstructible registry/
operational state. Never discover trust keys or credential destinations from
untrusted repository/request data. Carry correct domain/origin and release
identity through bootstrap, control and verification. A half-installed service
or missing gate fails closed.

### M6-R14 — Explicit compatible upgrade and rollback

Upgrade is an explicit adopter operation over pinned verified artifacts and
protected workflow/config. Retain the prior verified identity. Install compatible
runtime, parsers and verification-key sets before enabling new writers, formats,
proofs or bindings. Preserve M4's v1 history/v2 writer compatibility and M5's
protected initial/bootstrap/export branches; unknown or downgrade-incompatible
execution cannot silently proceed.

Rollback restores a verified compatible prior release and repeats required
verification. It cannot rewrite canonical history, make an unsupported writer
safe or clear a guard. Preserve historical decryptability and honest key-overlap
limits. Test interrupted upgrades, stale installed code, changed assets/origins
and rollback with current canonical state.

### M6-R15 — Backup, restore, rebind and hosted migration

Integrate the approved backup of all three repositories' complete histories and
refs with a snapshot manifest recording source numeric IDs and branch-head OIDs.
Verify exact restored commits and full ref-set equality. Preserve missing
application refs, corrupt content, stale projections and pending operations
exactly; copy performs no replay, repair, synthetic ref or canonical write.
Report verified copying separately from application health. Recovery material
stays separate from repository backups. Do not claim
a checkpoint can detect an administrator who controls both records and backups.

Separate raw copy from the explicit later live-activation request. A broken copy
can remain offline and equally broken. Activation requires an already consistent
source with complete current projections and idle operation/fence/marker state;
failure leaves all imported Git refs/content unchanged and runs no protected
job. Do not finish an operation imported from the backup or treat activation as
repair. Independently requested repair/rebuild retains its own existing contract.

Allow activation with replacement of one or all storage repositories through the
owner's approved append-only canonical rebind in global §9.1.1. Authenticate the exact
backup/source refs and root/K/B/genesis/full history with adopter recovery keys;
retain original objects and signatures. Genesis IDs remain historical, while
validated rebind events determine the current repository set. Matching names,
backup possession or a registry pointer alone cannot authorize replacement.

Before importing any control ref, require verified Actions disable/readback and
unavailable inherited secrets/runners; copying alone never enables execution.
Every live replacement must meet the same applicable standard as initial installation:
private role-bound repositories; current owner/admin and exact service/transport
App permissions; protected release/workflow/dependency/executing-repository
verification before keys; actual records/coverage recovery and every live-path
proof; exact provenance, ref, guard and final readback checks. Restored control
code and secret names are not readiness proof. No initial-check bypass is allowed.

Use the existing engine under a narrowly authenticated origin-aware activation
binding to append the single exact new rebind and materialize/read back its full
coverage and private derived state. Only that activation's own newly accepted
operation can resume on retry, never an imported source operation. All six source
heads remain required OIDs; no nullable-derived exception is needed. Routes remain
unbound for new targets during copying/read-only checks, while existing source
routes stay unchanged on unhealthy denial. Only after health, current-head/
authority checks and explicit confirmation, conditionally stage the existing
registry generation and pending/quarantine every currently routable affected
gate. Recheck source/target heads and registry before secrets/protected jobs or
rebind writes. Pre-event failure uses only matching conditional gate restoration;
accepted activation stays pending until completion and never overrides a newer
quarantine. Routes remain unavailable through current M4/M5 App/registry/scope and
bounded sweep completion. A completed retry writes nothing; stale snapshots,
partial or foreign operations and newer quarantines cannot be overwritten.
Reused companion roles must match the coherent snapshot; otherwise restore a
complete verified successor set without rolling back existing repositories.

Install compatible schema2 readers/writers/control before this event is enabled;
unknown/old execution fails closed. M6 owns the prospective codecs/replay/vectors,
strict genesis/current reader distinction, recovery-only admission and service
integration extensions once, preserving completed M1–M3 plan/source bytes and
IDs. Rebind does not rewrite old event formats, create an alias truth store,
grant ordinary bootstrap bypass or guarantee against a recovery-key controller
forking a backup. State the exact restore point and inaccessible-later-history
limit; keep current source retirement and credential containment requirements.

Hosted-to-self-hosted migration works from adopter recovery material without
former-operator help or canonical conversion. Ordinary rewrap changes the live
operator but cannot revoke copied historical keys. A security cutoff also needs
both data-key rotations and current-state rebuild under the approved existing
lifecycle protocols. Clearly distinguish those outcomes.

### M6-R16 — Controller and credential lifecycle

Install and documentation identify deployment/control/transport/App/root/key
controllers and exact secret locations. Stage and prove successors before
retirement, coordinate all assigned arrangements for a shared transport App,
and retain the existing actual-token expiry/revocation containment barrier.
Removing a key or briefly suspending an installation does not prove all earlier
tokens permanently inactive. Affected routes remain closed until the required
minting and potentially exposed-token conditions are satisfied.

Reuse M3/M4/M5 rotation, quarantine, recovery and key-activation engines. M6
owns their provisioning/installed integration, not another containment registry
or a claim that old ciphertext becomes unreadable after controller removal.

### M6-R17 — Truthful results, safe diagnostics and operator instructions

Report exact declared/verified release, resource and generation identities,
which effects are actually observed, required App/Connect steps and safe
recovery categories. Preserve useful nonprivate source OIDs/correlation IDs;
never reflect raw provider errors, secret values or signer PII.

Completion repeats recovery-storage, hosted trust and transport-integrity
warnings and names the precise remaining work. Document permissions, partial
cleanup, supported deployment, rotation, backup, rollback and migration in
shipped instructions. A plan, accepted secret write, successful dispatch or
clean offline test cannot be labeled installed, connected or production-ready.

### M6-R18 — Evidence, complete engineering and credible estimates

The detailed design must assign every required behavior to real prerequisites,
concrete owned adapters and coherent ordered slices, including the assembled
end-to-end check. Inspect existing code and reuse current M2/M3/M4/M5 primitives
instead of counting them again. Distinguish shipped engines from planned ones.

Provide separate evidence-based production/test LOC per slice and totals using
incremental final-delivered nonblank physical lines, excluding comment-only
lines and counting docstrings physically. Shipped configuration/instructions
count as production; test helpers/generators/integration/live drivers are tests.
Exclude designs, static fixtures, generated output, dependencies and locks.
Count shared foundations once across M4–M7; do not convert churn into delivered
LOC or add time/productivity estimates.

Offline acceptance must exercise actual scoped HTTP, installed CLI/wheel,
crypto, bootstrap, control and owning-service integration with crash/race/error
injection and tests that fail when critical checks are deliberately removed.
Separately authorized live drivers must cover current account/provider/policy,
secret/transport/token, protected execution and deployment behavior. M7 assembles
release evidence; an unrun driver or skipped live test establishes none of it.

## 4. Acceptance ownership and scope closure

| Requirement | Observable acceptance |
|---|---|
| R01 | Installed CLI validates exact owner/slug/version/policy/dependencies before credential use; changed/invalid input fails safely. |
| R02 | Dry-run capture contains no write/key/job; force skips only permitted confirmation and preserves every disclosure/blocker. |
| R03 | Personal/org, hidden/private scope, recycled login, ID disappearance, SSO and current permission negatives preserve anchors. |
| R04 | Non-default initial branch, exact README, rename/readback, privacy and every branch-role/content negative are tested. |
| R05 | Protected control external source/artifact/repository checks precede secrets; installer external verification remains optional with mandatory local preflight; private Free control needs no environment secrets. |
| R06 | Dedicated/shared exact assignment, excess grants/repositories/control reach, secret challenge and scoped token failures deny. |
| R07 | Both actual data keys pass recovery, all3 service and control paths; missing proof/handoff or key substitution blocks. |
| R08 | Exact K/B, identical3 manifests, actual-key binding, independently valid idle guards and absent first event/config/full semantic projections are checked; fabricated active or unconnected projection is rejected. |
| R09 | Every verified partial prefix can be reobserved; conflicting/unproved prefix or identity drift is refused without takeover. |
| R10 | Lost create/ref/secret/dispatch responses, concurrent heads and rate/error bounds never produce false success or blind retry. |
| R11 | Real links/consent/roles and direct installs reach the same stateless callback/independent Connect discovery. |
| R12 | Actual installer-to-Connect/writer integration appends first event/config once before full coverage/derived publication; crash/lost-result states recover through actual M3 with write-free completed repeat; scope routing stays separate. |
| R13 | Clean shared/self-hosted deployment has exact origins, split keys/bindings/gates/assets and unrelated-project isolation. |
| R14 | Upgrade/rollback verifies pinned compatible artifacts and ordering against real retained state, including interruption. |
| R15 | Exact copying preserves healthy, missing-ref, corrupt, stale and non-idle source states without repair; unhealthy activation is write-free and blocked. Explicit healthy-source one/all-role activation enforces every first-installation privacy/authority/App/source/key proof; its own new rebind/materialization/routing operation survives crashes with write-free repeat, rejects identity/source/stale-snapshot/quarantine substitutions, and preserves ordinary/security-cutoff migration limits. |
| R16 | Actual controller/key/token lifecycle and shared assignment failures keep affected routes closed until the owning barrier passes. |
| R17 | Output/log/error capture preserves safe diagnostics and all mandatory warnings, with no secret/PII or overclaimed status. |
| R18 | Full requirement/parent-journey ownership, concrete ordered slices, nonduplicated production/test estimates and runnable integrated evidence exist. |

No requirement is deferred to make estimates smaller. Detailed fields, provider
adapters, bounded retry mechanics, deployment targeting and test/estimate work
remain engineering tasks for the HLD and plan. No new material owner decision
is proposed in this requirements round. If later evidence needs a new public
behavior, scope, permission or trust boundary, preserve this scope and bring
back that concrete decision before changing it. Clean design is not permission
to provision, deploy, merge or publish.
