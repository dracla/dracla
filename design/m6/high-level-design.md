# M6 — Installation, deployment and recovery architecture

Status: architecture draft against the current reviewed [requirements](requirements.md).
The approved bootstrap and replacement-recovery contracts apply. This is design
work, not an implementation or production-readiness claim. The owner approved
the deployment-profile selection interface in §2.2 on4November2026; the
existing deployment topology, authorities and recovery decision remain approved.

The [global architecture](../high-level-design.md),
[M1 contracts](../lld/m1-conformance-kernel.md),
[M3 records/control engine](../lld/m3-control-reconciler.md),
[M4 architecture](../m4/high-level-design.md) and
[M5 architecture](../m5/high-level-design.md) govern this package. Their complete
parent prose and trust disclosures remain applicable. The [engineering basis](supporting/high-level-design/engineering-basis.md)
distinguishes inspected existing code, planned prerequisites and feasibility gates.

## 1. Selected structure and ownership

Use one local installer coordinator over the existing pure planner and scoped
GitHub administration client. Keep one canonical records engine and the existing
M4 guarded writer. Deployment uses the same two Workers, isolated agreement
origin, Git registry and bounded routing objects. There is no hosted provisioning
App, extra service, database, installation progress authority or second replay
engine. GitHub consent and local credential custody remain separate from portal
configuration and Connect.

| Component | Responsibility |
|---|---|
| Local CLI and pure planner | Closed input composition, release/dependency preflight, exact intent and disclosures, read-only planning, safe result categories and confirmation. |
| Local installation coordinator | Fresh typed observations, non-forced ordered effects, immutable readback and classification of resumable prefixes. It calls the administration port; it does not embed provider HTTP in the planner. |
| Installation verifier | Authenticate actual role genesis/ancestry, common manifests, release, K/B and current guards before returning M2's existing `VerifiedInstallation`. No caller-supplied success flag. |
| Scoped administration adapter | Exact current personal/org authority, complete relevant private visibility, empty private creation, Contents initialization/rename, encrypted secret delivery and bound dispatch. Existing M2 operations are reused and narrowly extended. |
| Transport setup adapter | Owner-mediated dedicated/shared App registration and selected installation, complete assignment/exclusion verification, protected local key custody and real restricted-token challenge. |
| M5 bootstrap/proof services | Authenticated unclaimed-candidate wrapping before installation; independent installed current-authority and actual stored-key proofs during Connect. M6 is their local client, not another wrapper service. |
| Protected control | M3 pinned external verification before secrets; M4/M5 fixed purposes and actual Python engine. M6 installs compatible artifacts and inert exact configuration. |
| Deployment assets and runbooks | Reproducible shared/self-hosted code/config/assets, split secrets and origins, independently checked release identity, upgrade/rollback and operator procedures. |
| Local recovery coordinator | Inspect exact mirror-copy equality separately from health; activate only an already consistent source under current successor proofs, then use the existing writer/reconciler for the approved new rebind and its own retries. |

M1/M3 codecs, crypto, full replay/export, process-observed token issuance/expiry/
cleanup and Git transport already exist. That cleanup does not prove unknown
attacker-minted tokens inactive. The full App-incident all-token barrier is
planned in M4's `m4/13`, not implemented by current M3 cleanup. M4's production clients/runtime/coordinator and M5's actual
bootstrap/Connect providers are planned prerequisites, not shipped services.
M6 owns only missing installer/deployment adapters and prospective recovery
extensions. M7 owns dashboard/badges, demonstration and final assembled release
and capacity evidence. Shared foundations and their tests are counted once.

## 2. Public operation and deployment selection

### 2.1 Existing installation and recovery commands

Keep the existing input grammar and defaults:

```text
dracla install github.owner=acme
dracla install github.owner=foundation project.slug=project-x dry_run=true
dracla install github.owner=acme force=true
dracla restore --snapshot BACKUP.json --target TARGET.json
dracla restore --snapshot BACKUP.json --target TARGET.json --execute
```

One installation provisions one independent three-role arrangement. The default
slug is the exact case-folded owner login. `force=true` suppresses only ordinary
installation confirmation. It cannot adopt a collision, clear a blocker, replace
GitHub consent or suppress hosted/controller trust acceptance. `dry_run=true`
does not mutate repositories, keys, secrets, Apps, jobs, registry or routes.
Legal recipient, agreements, fields, privacy/retention and scope stay in the
portal. There is no general local legal/configuration administration command.

Restore retains the exact approved global §9.1.1 interface and bounded canonical
file schemas. It starts after documented mirror import; default operation is
read-only. Exact copying preserves broken/incomplete source state without repair.
Execution is a separate live-activation request for an already consistent source;
it repeats proof and requires explicit exact restore-point and successor-set
confirmation. There is no force/automatic-yes restore option.
Use exit0 only for a verified plan or completed result,2 for invalid/blocked/
conflicting/uncertain evidence and1 for an internal failure. An accepted write,
secret request or dispatch is never verified completion.

### 2.2 Approved trusted local deployment profile selector

Shared hosting is the default. To make the already-required self-hosted target
usable without editing source or adding separate configuration mechanisms,
use one local selector used by installation and recovery:

```text
DRACLA_DEPLOYMENT_PROFILE=/absolute/path/dracla-deployment.json dracla install github.owner=acme
DRACLA_DEPLOYMENT_PROFILE=/absolute/path/dracla-deployment.json dracla restore --snapshot BACKUP.json --target TARGET.json
```

When the variable is absent, use the exact release-bundled shared profile.
An empty value, relative path, unavailable file or invalid profile blocks; never
fall back silently. Unsetting the variable selects the bundled shared profile
for a fresh invocation. It does not migrate an existing arrangement or replace
its recorded bindings. No equivalent URL flag, repository discovery, browser
callback override or alternate environment selector is added.

The selected file is non-secret, bounded, closed canonical JSON, read locally
as a regular one-link non-symlink file. It identifies one accepted deployment:
portal/agreement HTTPS origins; three service App identities and installation
links; bootstrap/control verification identities and public verification keys;
registry identity; compatible release/profile identities. It contains no token,
private key, root-wrapping secret, executable module or provider instruction.
Detailed fields and validation belong in the plan. No referenced URL can replace
trusted local verification keys or choose executable behavior.

The administrator creates the self-hosted profile from the verified deployment
outputs through the shipped runbook and checks its exact controllers/origins/
identities locally. Before the first candidate key is submitted, display that
complete trust selection and require explicit acceptance; `force` cannot bypass
it. A profile is configuration, not independent proof of its own publisher or
endpoint. Current authenticated bootstrap proofs remain mandatory. Bind its
canonical digest to invocation intent and existing protected configuration;
do not add a second canonical registry. A changed profile on rerun conflicts
with an established deployment binding and uses the approved migration flow.

This selector is the approved public configuration choice for this package. The
alternative is separate endpoint/key/App overrides per command; that broadens
the input surface and permits mismatched trust components. Editing packaged
source or installing an unofficial custom wheel does not meet the locked
same-release self-hosting requirement. This interface changes neither App grants
nor the approved hosted/self-hosted trust model.

## 3. Installation journey and durable boundaries

### 3.1 Read, plan and confirm

Validate closed owner/slug/booleans, selected deployment, exact released package,
canonical bundled policy/constraints and actual installed dependency versions
before credential use. Local declarations are not independent package-origin
proof. External verification of the one-time installer remains optional; it is
mandatory for protected key-bearing control execution.

Resolve the current actor and personal/org account using the local provisioning
credential. Prove relevant private inventory visibility and current administrator
authority. Bind observed numeric owner/repository IDs and exact role names.
Known disappearance, recycled login, unknown SSO/policy or incomplete inventory
blocks; invisibility is not a free name. Show resources, release/deployment,
missing prerequisites, controller disclosures and whether effects are merely
planned or verified before ordinary execution confirmation.

### 3.2 Private resources, roots and protected control

Create three empty private repositories and read back exact IDs/privacy. Create
the exact mandatory records README through Contents on the actual initial
default branch. Rename that exact branch/head to `events` and verify default
and head. Do not assume `main`, use `auto_init`, create an impossible first Git
ref, or install workflow/config/event content into the canonical root.

Create the other approved layouts through exact non-forced operations. Seed
control with the released protected workflow, inert bindings and provenance.
Repository Actions secrets support private GitHub Free; environment-secret or
paid branch-protection features cannot be correctness dependencies. Before any
key-bearing job, verify numeric executing control repository, immutable workflow/
source/artifact/dependency and verifier identities. Execute the verified bytes
without mutable re-resolution. Restored or repository-supplied executable code
is not accepted as a verifier.

### 3.3 Transport authority and actual key paths

The administrator creates or selects the transport App through GitHub consent.
Keep App-manifest conversion, any returned registration code and private key on
the local machine. No general provisioning or transport credential goes to
hosted DraCLA. Support dedicated or explicitly shared assignments with the
exact owner/App/client/installation IDs, Contents-write plus implicit Metadata,
selected records/coverage union and exclusions. Control, contributing source
repos, all-repository mode or additional grants block. Different keys of one
App do not isolate assignments.

Display the full integrity reach before authorization and at completion. Store
the App key only in assigned protected control secrets and prove its actual
scoped transport capability. A secret name or accepted encrypted write is not a
proof. Dispatch uncertainty requires bound run/result observation before repeat.
Use current M3 cleanup for this process's observed tokens. App/key exposure
requires M4's planned all-token incident barrier and M6's installation/recovery
integration before final repair or route restoration; process cleanup alone
cannot satisfy it.

Generate actual records/coverage data keys and recovery/control wrapping
material under existing crypto contracts. Disclose the selected operator's PII
and integrity reach before transient service submission. Use M5's distinct
authenticated unclaimed-candidate setup context for initial wrapping/challenge;
it grants no current project read/admin/registry authority. Prove both actual
data keys through recovery, portal-records, portal-coverage, enforcer-coverage
and protected control. Deliver recovery material to an explicitly selected
private local destination using safe non-echoing interaction, before private
initialization; never argv, normal config/output/logs, URLs or Git. Refuse
unsafe handoff; erase process-held raw/recovery material when no longer needed.

### 3.4 Bootstrap without invented connected state

Create K from the original records root with actual key-binding/recovery
metadata. Its direct child B adds the canonical bootstrap manifest. Verify
identical manifest bytes across all three role repositories, exact generation,
release/IDs/K/current kids, and control provenance pinning B. Construct valid
idle operation cell, independent idle coverage fence and empty marker with
existing M1 formats. There is no semantic full coverage, private derived
generation, agreement, project config or first event before Connect.

After final immutable/readback/proof checks, report **provisioned**, print the
three exact service-App installation links and the separate Connect next step.
GitHub owns consent; one App cannot install another. Stateless setup callbacks
only direct the browser. Direct installations reach the same independent
Connect discovery. Neither install nor an App callback writes the registry.

Connect rechecks M5's seven live authority rows, bootstrap and actual stored-key
proofs. M5's initial adapter and M4's one guarded writer append the genuine first
`project_connected` event/config before building complete coverage and derived
state. M3 recovers an exactly accepted first operation after interruption. M6's
assembled tests exercise those real providers. Connected, agreement-active,
scope-active and routable remain separate verified states.

## 4. Rerun, collisions and uncertain effects

The verifier rederives authority from current role contents, genesis/ancestry,
release, common generation/manifests/K/B, key proofs and guards. Reuse M2's
typed verified-installation seam; never trust local progress, a previous CLI
message, empty names, secret names or callbacks as provenance. Distinguish
absent, exact resumable prefix, complete idle bootstrap, first-operation recovery,
connected arrangement and conflicting/unproved content. An existing connected
project is verified, not reset to installation state.

Reobserve before every effect and on lost create/Contents/rename/ref/secret/
dispatch replies. Expected numeric IDs and immutable head/content bindings
must still match. Use conditional non-forced updates and finite installed
attempt/page/byte/deadline budgets. An uncertain creation without attributable
provenance stays blocked; do not claim every partial prefix can be safely
adopted. Safe operator guidance can require explicit cleanup outside this
command or a new intent. No automatic deletion, takeover, ref force or blind
write retry follows from `force=true`.

## 5. Shared/self-hosted deployment and compatible upgrades

Ship reproducible deployment configuration for the existing portal and enforcer
Workers, their disjoint secrets, portal static assets on its API origin,
separate cookieless agreement host and routing namespace. Registry state stays
Git-backed; routing objects remain reconstructible operational projections with
no CLA evidence. Use exact released assets, known service bindings, verification
keys, App identities and numeric installed profile limits. Account/domain setup
is an explicit operator procedure, not hidden installer privilege.

Self-hosting deploys the same released code in adopter-controlled Cloudflare/
GitHub accounts with its own roots, Apps, operational keys and registry. The
normal installer then selects the accepted local profile. No source edits,
former-operator dependency or canonical conversion is required. Missing service,
wrong origin/assets/binding, mixed key capabilities or incomplete gate setup
fails closed. Current bench-only `api/wrangler.toml` is not a production template.

Upgrade and rollback are explicit shipped operator procedures over immutable
verified release/config artifacts, not new general administration CLI commands.
Retain prior verified identity and compatibility evidence. Install compatible
readers, verification-key overlap and protected control before enabling new
writers/formats. Activate through existing guarded service/config transitions;
never clear a guard or revert canonical history as part of deployment rollback.
A prior release incapable of reading schema2 history cannot be selected after a
rebind. Interrupted deployment remains closed until the compatible same-release
set and actual readback/proofs pass. Actual account, policy and cold-resource
acceptance remain production gates.

## 6. Backup, new-repository restore and recovery admission

Document a full-history mirror backup/import of all three repositories and the
approved canonical BACKUP manifest of exact IDs/default branches/full refs.
Recovery material stays separately held. Verify new targets are private and
empty before import, or exact matching companion roles, and read back imported
objects/refs. No new Git object-copy engine or source overwrite is introduced.
Restore does not restore GitHub settings, secrets or App consent from Git data.
Missing application branches, corrupt content, stale projections and non-idle
operation/fence/marker state are copied exactly, with defects reported separately
from ref/object equality. Raw copy performs no repair, ref synthesis, accepted-
operation continuation or event append. Source application health does not gate
that copy. The copied system may remain offline and equally broken.

The documented mirror procedure has a mandatory **pre-import execution gate**.
The current adopting administrator first disables Actions for the exact target
control repository and reads back that effective policy before any imported
ref is pushed. Use the existing local administrator authority against GitHub's
repository Actions-permissions setting, not a service or transport App. Missing
permission, an organization policy that prevents a verified deny, a lost reply
without confirmed readback or any uncertain state blocks import. No new ref or
workflow is written while that gate is unproved. Do not assume an empty private
repository has Actions disabled.

Keep organization/self-hosted runner access and inherited organization secrets
unavailable to imported control code. For a reused target, disable new runs,
cancel/drain existing or queued runs and apply the owning credential-containment
barrier where exposure is possible before treating execution as unavailable.
If those conditions cannot be proved, use no execution resources and remain
blocked. Disabling future Actions is not proof that an already running job or
minted token stopped. This is local administrator/operator preparation, not
hosted provisioning authority.

While Actions remains disabled, import and verify exact snapshot objects/refs.
Stop there for raw copy. Only after separate explicit activation verifies an
already consistent source, install the independently verified current protected workflow and inert
successor bindings, and verify the complete executable workflow/ref surface.
An old branch/tag with another eligible workflow cannot inherit fresh secrets
or runner access. Leave unapproved workflows disabled; if the platform cannot
isolate the intended verified workflow/ref while retaining required history,
keep Actions disabled and report blocked rather than discarding history or
silently widening execution. Mere action/reusable-workflow allowlisting does
not authenticate inline `run` code. Only the intended protected release/ref
and triggers may be enabled. Recheck that code/repository/policy boundary before
secrets, then run only its fixed bound proof jobs; enable normal scheduled repair
only after actual key, permission and transport proofs pass. A failed proof
keeps routes closed and removes that temporary execution permission.

The restore command's read-only planning does not perform this preparation or
import. The shipped operator procedure and assembled driver must exercise the
disable/readback-before-push order; later observation of `enabled:false` cannot
prove that an earlier unsafe push did not execute. An import made outside that
verified order requires incident assessment/containment, not retrospective
success. No local receipt becomes independent authority for GitHub policy.

Use the exact global §9.1.1 schema2 `project_repositories_rebound` contract,
authorization tokens, authenticated event schema/path dispatch, unchanged
origin root/K/B/manifest and snapshot/source-head bindings. The new event's parent
is the exact source events head. All six source heads are OIDs; there is no
nullable-derived exception or imported-operation continuation field.
The event updates replay's current set; genesis remains historical. All private
class generations advance in the same canonical package, followed by complete
materialization/readback. Legacy event and envelope contracts are not rewritten;
unknown/old readers deny before disclosure or mutation.

The local coordinator first establishes current private owner/admin/service/
transport/release/control authority, then prompts safely for recovery keys and
authenticates full origin history. The same checks as first installation apply
before key-bearing execution/output, including all independent recovery and
service/control live proofs. Old control history is inert until current verified
protected code and exact successor bindings are installed before secrets.

The required engine extension is narrow typed **recovery admission**. Its
constructor is local authenticated source/proof verification, never a supplied
boolean or generic callback. It carries the exact origin snapshot, actual
successor transport binding, current actor/release/proofs, one frozen registry
transition and only this explicit activation's own operation digest. Ordinary history acquisition keeps
manifest-to-genesis and final-replay-to-live checks; do not globally substitute
new IDs into old manifests, weaken transport authorization, or accept an alias
table. The common reader gains explicit origin/current validation and the
existing engine accepts only the fixed admitted recovery operations.

Before any activation write or protected execution, authenticate full source
history, keys and current projections and require idle cell/fence/marker state.
An unfinished Connect, absent derived ref, pending imported operation, stale
projection or unverifiable application state blocks activation without changing
any imported ref/content, replaying work or clearing guards. Separate requested
repair retains its existing authority; restore does not make broken copies
activatable. For a healthy source, acquire the existing fence/marker and append
one new rebind using the shared writer. After its acceptance, retry may resume
only this exact activation package, reconstructing prior health from its frozen
source heads and guarded effects. It never adopts an operation in the backup.

During copy and read-only health checks, new targets remain unbound/unroutable;
do not change source routes or registry on unhealthy denial. After healthy source,
current heads/authority and explicit confirmation, use the existing M4 coordinator
to conditionally stage the exact registry generation and set all current affected
gates pending/quarantined. Revalidate source/target refs and registry after staging
and before secrets, protected jobs or rebind writes. Changed evidence blocks.
Pre-event failure restores only the matching staged gates conditionally; after
acceptance keep gates pending through completion. Newer quarantine always wins.

Keep both affected route sets unavailable through activation, rebind, full
rebuild/readback and bounded sweep. Bind the staged registry OID/
generation into the event and frozen operation. Preserve M4's landed order:
projection readback, marker close/readback, terminal CAS/readback, fence release/
readback, then cell clear/readback. Restore only conditionally matching gates;
newer quarantine wins. A lost reply reuses exact accepted intent/fingerprint;
completed repeat writes nothing and allocates no new nonce.

Refuse live activation from an older snapshot when the observable original has
unaccounted later history; exact copying into fresh isolated targets may still
preserve that snapshot. Never roll back an advanced companion. If originals are inaccessible,
show the exact recoverable point and unavailable-later-history limit before
confirmation. Backups cannot prove the absence of inaccessible later events or
prevent a controller of all keys from forking across independent deployments.
Rebind does not cryptographically revoke copied keys or earlier tokens.

For any potentially exposed transport credential, M6 composes M4's `m4/13`
quarantine, minting-cutoff and all-token barrier with local administrator proof
and installed successor bindings. Prevent future minting, including outstanding
signed requests, and establish permanent installation-wide invalidation or wait
the documented maximum token lifetime after the last possible issuance plus
the live-tested clock/propagation margin. Unknown tokens count. Current M3
`InstallationCredentials.close()` handles only this process's observed tokens;
it cannot produce this incident evidence. Unknown cutoff, expiry margin,
permanent invalidation or current binding leaves routes closed. Temporary
suspension does not prove permanent invalidation after resumption. M6 owns
installer/restore/lifecycle wiring and its real acceptance driver, reusing the
planned M4 barrier rather than another containment engine/store. Its actual
unknown-token proof remains an unperformed live acceptance gate.

Hosted-to-self-hosted migration ordinarily preserves repository IDs and rewraps
under adopter roots through the existing key lifecycle. Replacement additionally
uses this rebind. Security cutoff needs the approved data-key rotations/current
rebuild and token containment; rewrap alone is not historical erasure. Identify
all shared transport assignments before successor staging and retirement.

## 7. Requirements, evidence and remaining engineering

| Requirements | Owning architecture and observable check |
|---|---|
| R01–R03 | §§2–3.1: installed closed CLI, dry-run write capture, force limits, exact numeric authority/visibility and selected release/deployment. |
| R04–R05 | §3.2: actual scoped HTTP/Contents/rename/default readback and protected artifact/repository-before-key ordering, including private Free. |
| R06–R07 | §3.3: GitHub consent, complete assignment/exclusion checks, actual token and all independent key paths, safe handoff/redaction. |
| R08 | §3.4: exact K/B/manifests and independent idle guards, no fabricated connected projection. |
| R09–R10 | §4: provenance classification and every uncertain-effect/concurrent-head branch without takeover/force. |
| R11–R12 | §3.4: all service App roles, stateless callback and actual installer→Connect→first append/recovery→scope route journey. |
| R13–R14 | §5: complete same-release shared/self-hosted deploy and compatible interrupted upgrade/rollback against real retained state. |
| R15 | §6: Actions disable/readback before imported refs, no inherited execution resources; exact copy preserves broken/incomplete state. Explicit healthy-source one/all-role activation alone permits protected reenabling, new rebind/materialization/sweep and its own retries; unhealthy denial is write-free and completed repeat writes nothing. |
| R16–R17 | §§2–6: controller/key/token lifecycle, honest categories/OIDs, finite safe next action and all mandatory trust/recovery warnings. |
| R18 | This package and detailed plan: source-grounded ownership, all integration/failure cases, distinct production/test estimates and shared work counted once. |

The plan must close actual adapter signatures and bounded formats, provider
budgets, profile fields, secret-handoff mechanics, initialization/verifier states,
protected proof/config compatibility and common reader/engine recovery seams.
It must assign both Python/TypeScript schema2/replay/envelope/vector extensions
and the writer/control/portal integrations to prospective M6 slices once.
These are missing engineering, not implemented primitives.

Offline acceptance uses installed wheel/CLI, actual scoped HTTP, crypto and
owning M3/M4/M5 engines with lost reply/crash/race/sensitivity cases. Extend
existing harnesses rather than introducing mock success authorities. Separately
authorized live drivers cover GitHub registration/policy/visibility, private
Free Actions/secrets, actual restricted token containment, protected execution,
Cloudflare origins/bindings/deployment and unrelated-adopter end-to-end behavior.
Skipped live tests and reviewed designs establish none of those live claims.
M7 assembles the complete release traceability and capacity evidence.
