---
plan_key: m6
slice_convention: hierarchical-v1
slice_inventory: {"executable": false, "path": "slices.json", "sha256": "4ff9e16c0f6a61144c0313418bbb308643f09c4a694dd72c417772dec4b11035"}
---
# M6 — Installation, deployment and exact recovery implementation plan

Status: detailed draft for review. The existing architecture, the approved local
profile selector and the owner's exact-copy correction govern this plan. This
document authorizes no product implementation, account operation, publication or
live credential use. The sole ordered slice definitions are in
[slices.json](slices.json). The [overview](overview.md) renders them. Completed
M1–M3 source, IDs, approvals and consumed delivery/review history remain intact.

The [requirements](requirements.md), [architecture](high-level-design.md) and
their current transitive authorities govern. The
[engineering basis](supporting/implementation-plan/engineering-basis.md) records
actual source reuse, platform evidence, alternatives and separate estimate
composition. It is supporting evidence, not another specification or inventory.

## 1. Complete result and prerequisite ownership

An unrelated adopter uses the released `dracla install` to provision one private
records/coverage/control arrangement, retain tested recovery material, install
the three service Apps and enter the separate M5 Connect journey. The same code
supports shared hosting and a real self-hosted deployment, compatible upgrades,
controller lifecycle, exact backup copying and separately requested activation.

M2 supplies the pure planner, typed local administration and ambiguity categories.
M1/M3 supply codecs, native crypto, immutable history, transport, guarded append,
reconciliation and exports. M4 must first deliver its production HTTP/Worker/
SQLite harness, routing signatures/registry/gates, shared mutation executor,
protected control bridge and `m4/13` all-token incident barrier. M5 must first
deliver real setup/installed wrapping contexts and challenges, current authority,
Connect's initial acquisition/derived-root adapter, actual Python integration
and ordinary lifecycle services. These are reviewed planned prerequisites, not
installed services in the current checkout.

M6 counts only its missing local adapters/coordinator, initial no-history probe,
verified installed/deployment configuration, prospective schema 2 recovery
extensions and assembled installer/activation drivers. M7 reuses those drivers
for dashboard, badges, independent sample and final release/capacity acceptance.
Do not count M4/M5 runtime/test foundations, M3 engines or M1 crypto again.

Use `core/dracla/installation/` for local installation/deployment composition,
`core/dracla/recovery/` for exact snapshot and fixed activation composition, and
extend the existing `records/`, administration and CLI ports. New fixed Worker
recovery adapters stay in the existing portal/enforce/control/records trees.
No second replay/writer, Git-copy engine, database, job authority store, per-project
Worker, hosted provisioning credential or general provider configuration follows.

## 2. Local input, profile and result contracts

### 2.1 Existing commands

Keep the existing four install overrides and their current validation:

```text
dracla install github.owner=acme
dracla install github.owner=foundation project.slug=project-x dry_run=true
dracla install github.owner=acme force=true
dracla restore --snapshot BACKUP.json --target TARGET.json
dracla restore --snapshot BACKUP.json --target TARGET.json --execute
```

Default slug is the exact case-folded owner login. One install concerns its
three `<slug>-cla-<role>` repositories. Recipient, agreements, policy/fields,
reader and contributing scope remain portal operations. No local legal mutation
or new deploy/upgrade/backup command is introduced. Operator procedures use the
released assets and official tools; their values are configuration, not source
edits. Restore begins after the documented mirror import, not by running install
against empty replacement repositories and creating a new genesis.

Local preflight validates exact package version, bundled canonical release
policy/constraints and actual installed dependencies before authorization.
One-time external installer verification remains optional and its absence is
disclosed honestly. External verification of protected key-bearing control is
mandatory. A package's own declarations cannot authenticate that same package.

Dry-run is bounded read-only discovery/planning: no key generation, repository/
ref/secret/App creation, workflow dispatch, claim, registry or route write.
`force=true` suppresses only ordinary install execution confirmation, never
controller trust consent, GitHub consent, current proof or a blocker. Restore
has no force/automatic-yes option. `--execute` is neither authority nor confirmation.

Use existing CLI JSON printing/exit conventions and safe fixed categories.
Distinguish planned, provisioned, already provisioned/connected, activation in
progress, complete and blocked/uncertain outcomes. Include exact known resource,
release/source/generation identities and a finite next action; never raw provider
errors or private plaintext. Restore reports copy state separately: exact,
advanced by this same accepted activation, or unverified. After activation
advances refs, never report that current refs still equal the original backup.
Exit0 means a verified read-only plan or fully verified completion; exit2 means
invalid/blocked/conflicting/uncertain evidence and exit1 an internal failure.
An accepted write, secret update or dispatch is not completion.

### 2.2 One trusted local deployment profile

The only selector is the approved
`DRACLA_DEPLOYMENT_PROFILE=/absolute/path/profile.json`. Unset selects the
bundled shared profile for this fresh invocation. Empty, relative, unavailable
or invalid selection blocks without shared-service fallback. Changing/unsetting
it does not migrate an already bound installation.

Load exactly one bounded canonical UTF-8 JSON regular one-link non-symlink file,
using an opened descriptor and complete bounded read, before credentials. Reject
unknown/duplicate fields, invalid Unicode/numbers, noncanonical encoding,
private keys/tokens, executable instructions and more than 1 MiB. The closed
local schema is:

```text
{deployment_profile_version:1,portal_origin,agreement_origin,apps,registry,
 verification_keys,release,profiles,assets_sha256}
apps = {records:{app_id,client_id,slug},enforcer:{app_id,client_id,slug},
        trigger:{app_id,client_id,slug}}
registry = {owner,name,repository_id,branch}
verification_keys = {routing:[{kid,public_key}],control_key_proof:[{kid,public_key}]}
profiles = {release_profile_sha256,runtime_profile_sha256}
```

`release` is the unchanged bootstrap release object: package_version,
release_policy_sha256, source_commit_oid, provenance_identity and
dependency_constraints_sha256. Use its existing codecs and require congruence
with the verified executing release. The two origins are distinct canonical
HTTPS origins with no path/query/fragment/credentials. App/registry identities,
slug/name/ref syntax and digests reuse existing M2/M4/M5 codecs. Key arrays are
bounded, nonempty, duplicate-free accepted sets using M4's exact 32-byte Ed25519
public-key encoding and derived `ed25519.` kid. Purpose separation remains fixed.
Profile public keys verify deployment routing/control proofs; they cannot replace
the release publisher, external verifier, bootstrap image or executable trust.
There is no arbitrary verification URL, module, callback or provider field.

Derive M4's domain from its existing exact JCS object
`{portal_origin,registry_repository_id,gate_namespace:"repository-routing-v1"}`;
do not configure an independent competing domain value. Derive GitHub App links
from verified App metadata/slug and check numeric IDs. A metadata mismatch blocks,
not redirects credentials. Pin profile canonical SHA256 in invocation intent and
the existing intended final control installation provenance. Match actual protected
v2 routing fields, release, App observations and live proofs to it. Do not add a
v3 control root or change the M1 bootstrap manifest just to store this digest.

Before sending a candidate key, display both origins, exact Apps/registry,
public proof-key identities, release and all selected controllers and require
explicit consent. Hosted PII/integrity reach and self-hosting alternatives stay
visible. Force cannot suppress it. A local file records the administrator's trust
selection; it is not independent proof of its publisher or endpoint.

## 3. Typed composition and effects

The planner stays pure. Implement an I/O-owning coordinator consuming typed
fresh observations and the M2 `InstallationVerifier` result; do not make
`plan_install` call providers. Retain `InstallInput` and its grammar. Remove its
unconditional execution blocker only when the actual composed M3/M5/M6 engines
are installed and validated, not because configuration claims they exist.

| Port/result | Concrete responsibility |
|---|---|
| `DeploymentProfile` | Closed immutable local profile and canonical digest; fixed client origins/purpose-key sets. |
| `InstallationResources` | M2 scoped creation/Contents/rename/ref and actual immutable readback; no broad URL/method port. |
| `ControlInstaller` | Released protected workflow/current numeric repository and v2 binding verification before secrets. |
| `TransportSetup` | Current complete App assignment/grants and local key custody; actual challenge uses M3. |
| `CandidateKeySetup` | Existing purpose-bound M5 authorization and three direct service proofs plus control/recovery. |
| `BootstrapInstaller` | Unique K/B/copies/idle guards and final control provenance; no canonical event or semantic projection. |
| `InstallationVerifier` | One rich typed read-only inspection (§4.2.1), projected to existing `VerifiedInstallation` only for the exact complete arrangement. |
| `ActivationAdmission` | Trusted factory verifies exact healthy frozen source/current target and only the new rebind intent/retry. |
| `RecoveryCoordinator` | Existing registry/gates, fixed control/service proof adapters and one guarded rebind/materialization path. |

Ports are selected by released composition, not JSON or repository content.
All observation values distinguish missing from unknown/denied/incomplete.
Bind numeric IDs, expected immutable heads and intent before every effect and
readback. Use bounded provider budgets and existing retry/result distinctions.
Names locate resources; they do not prove identity. No credential-bearing redirect,
partial pagination or ambiguous response becomes absence or success.

M6's test fixture extensions reuse actual M4/M5 HTTP/runtime/engine harnesses.
Never replace a required cryptographic/authorization readback with a caller
boolean, saved step status or mock that merely returns provisioned.

## 4. Installation protocol and exact ordering

1. Validate CLI/profile/release/dependencies; discover current actor, numeric
   personal/org owner, complete relevant private visibility and exact intended
   three-role names. Block collisions without proven provenance.
2. Show resources, complete trust/integrity disclosures and finite prerequisites;
   obtain ordinary execution and explicit selected-controller consent as required.
3. Create empty private roles with local administrator authority. Read back IDs,
   owner, privacy and permissions. Create the mandatory records README via Contents
   on the actual initial branch, rename that exact head to default `events` and
   verify. Do not use auto_init or first Git-ref creation on an empty repo.
4. Seed exact released control code, externally verified source/tool/artifact
   identities and inert current v2 binding. Keep repository Actions secrets for
   the private Free baseline. Validate control scope/source before any key access.
5. Guide GitHub App registration/selection and human installation. Verify the
   complete transport union, only Contents-write/Metadata, current exact IDs and
   exclusions. Store its private key only in the assigned control secrets.
6. Generate actual project/control/recovery keys once. Construct existing native
   wrapped copies/fingerprints. Prove both recovery paths and separately portal-
   records, portal-coverage and enforcer-coverage through M5's initial authorized
   unclaimed-candidate path. Dispatch/verify the bound initial control key proof.
7. Deliver recovery material to the adopter through safe local non-echoing
   interaction and exclusive private destination; require safe-storage receipt.
   No raw key enters browser JS, normal output, argv, URLs, Git or job artifacts.
8. Create the nonsecret coverage root/layout needed by the initial transport
   probe. Run its fixed no-history protected phase using M3's actual generation-
   specific temporary challenge branches, exact readback and conditional cleanup.
   Full history/coverage does not exist yet. Scope verification precedes keys;
   this actual write challenge precedes K/B/encrypted guard completion.
9. Create unique initial keyring candidate K from the authenticated records root,
   with actual-data-key binding/recovery metadata; its direct child B adds the
   existing bootstrap manifest. Store identical bytes in all three roles. Write
   schema-valid encrypted idle operation cell, independent idle fence and empty
   marker with the proven keys. No first event/config, full semantic coverage,
   agreement or private materialization generation exists yet.
10. Finalize/read back protected installation provenance and all actual stored
    copies/guards/proofs. Report provisioned, repeat mandatory recovery/controller/
    transport warnings, print exact three service-App links and separate Connect
    next step. Do not claim connected, signable, scope-active or routable.

Do not manufacture replay state or a new unconnected coverage format. M5's
`m5/12` authenticates root/K/B and independently valid idle guards, accepts the
first genuine event/config through M4's shared writer, creates the first derived
root via its specified non-forced protocol, then builds/readbacks full normal
coverage and private state. Interrupted Connect resumes its own exact accepted
package through actual M3. Installer cannot use a callback or a past proof to
write registry or publish a project route. Agreement and scope activation follow
separately through their existing protocols.

### 4.1 Setup context and local secret handling

Reuse M5 HLD §7's approved browser-authorized opaque setup context. The CLI gives
the existing setup screen only nonsecret exact proposed identities/generation/
release/capability/kid/key commitments and a fresh retry nonce. The same-browser
GitHub session authorizes that exact request. Read the returned purpose-bound
opaque context through safe non-echoing local input; never copy the browser's
session cookie or local GitHub credential, start a loopback authentication server
or introduce device OAuth/another grant/store. If a metadata exchange file is
used, it contains no key/context and is bounded/private/locally cleaned.

Every use rechecks original session/actor, purpose, exact source/request nonce,
capability/wrapper, key commitment, release and expiry through M5. CLI sends each
raw key directly only to its selected service; services never forward keys.
Initial contexts cannot unwrap existing claimed-project material. Installed
Connect repeats its independent current seven checks and actual stored-key proofs.
Use M5's exact original-wire context digest in every MAC/control proof; do not
replace the context supplied by the original consumer.

Reuse `DRACLA_TRANSPORT_APP_KEY` and `DRACLA_CONTROL_KEYS` with the existing M3
secret formats. Initial controlled dispatch may use M5's explicit empty keyrings
map only for its approved pre-K probe. Ordinary history/reconcile/export retain
their existing nonempty map requirements. Secrets are input only to independently
verified fixed steps. Zero process-held key references after use; acknowledge
Python cannot promise physical erasure of every runtime copy. Do not persist raw
material to make a crash resumable.

### 4.1.1 One local recovery bundle and durable handoff

Use one canonical UTF-8 JSON bundle, at most64 KiB, with exactly
`{recovery_bundle_version:1,project_id,install_generation,intent,keys}`.
`intent` is exactly `{repository_ids,records_root_oid,release,profile_sha256}`;
IDs/release use the existing bootstrap codecs. `keys` is a nonempty map from
existing recovery wrapper-generation strings to lowercase64-hex-character
32-byte wrapping roots. Reject duplicate/unknown fields, noncanonical bytes,
invalid generations/keys and cross-project/intent mismatch. Initial installation
has exactly its one new generation. Later authorized recovery-root succession
may deliver a bundle containing every still-required recovery generation; no
raw data key, transport App key, user token or controller wrapping root belongs
in it. The bundle is secret recovery material, not another progress ledger or
independent installation authority.

After current resource authorization, acquire the destination through the local
interactive handoff, without a new CLI flag or ordinary secret output. Open each
directory component relative to an already opened directory descriptor with
no-symlink traversal; reject mutable/untrusted ancestors. Ancestors must be
owned by the current user or root and not group/world writable. The final
user-owned directory must be mode0700. Do not create directories implicitly or
use a shared temporary directory. Capture and recheck directory identity.

Create the final basename through that descriptor with
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, mode0600; never open/truncate/replace an
existing path. Check its opened descriptor is a regular file, current-user
owned, link count1 and mode0600. Write all canonical bytes with a short-write
loop, fsync the file, recheck its identity/type/link/mode and path-to-descriptor
match, then fsync the parent directory. A filesystem lacking the required
operations or durable-sync result blocks handoff. Keep the path/content out of
provider requests; only the safe destination location may be displayed locally.

After full durable write, require the administrator's explicit storage receipt.
No private guard/bootstrap write occurs before that receipt. On a handled write
failure, close and remove only the still-matching inode created by this attempt,
then fsync the parent; a replaced path is never removed. Report uncertain cleanup
without secret bytes. An interrupted process can leave an incomplete file; the
next invocation refuses to overwrite/adopt it. Explicit operator inspection/
cleanup or selection of a different private destination is required. Never
regenerate a new root under an existing attributed K to make a file error pass.
An unreadable path, unsafe mode, short write, failed fsync or missing receipt
cannot become a successful recovery handoff.

The ingestion adapter uses the same bounded no-symlink regular-file/owner/link/
private-mode checks and validates project/intent after current repository
permission checks. It returns only `Mapping[str,bytes]` from `keys` to the
existing `WrappedKeys("recovery", provider)` callback; the existing keyring
consumer continues authenticating every project/capability/generation/wrapped
copy and actual data-key binding. Existing bare generation-map non-echoing
input remains valid for completed M3 commands; the new M6 handoff uses the
versioned bundle, not a second key codec or file-derived authority. The restore
interactive recovery prompt may select this bundle locally; no secret path or
key is added to argv or BACKUP/TARGET/profile. Clear transient byte/key references
after the immediate installation/recovery uses and on every exit; no persistent
working copy or debug dump is allowed. The pre-private-write storage receipt is
not a promise that Python can erase all physical memory copies.

Round-trip acceptance writes a real bundle with the secure filesystem adapter,
opens actual native recovery copies through `WrappedKeys`, then restores both
capabilities. Test existing files, symlinked ancestors/basename, hardlinks,
wrong owner/mode, short write, file/directory fsync failure, destination swap,
crash residue, denied receipt and incompatible project/generation; every failure
preserves unrelated files and blocks private initialization.

### 4.2 Final provenance and rerun

The intended final nonsecret control installation provenance has closed fields
`{provenance_version:1,project_id,install_generation,release,repository_ids,
records_root_oid,records_keyring_candidate_oid,bootstrap_commit_oid,
bootstrap_sha256,deployment_profile_sha256,control_binding_sha256,workflow_sha256}`.
Store it at `.dracla/install-provenance.json` in control after B is known. It is
the existing planned installation-provenance role, not another canonical record
or independent installation truth store. The released execution-verification
profile stays separate/version 1; do not ship an adopter-generated production-
profile.json in the product inventory. Earlier release seeding/proofs do not
invent null K/B values in this final provenance format.

Verifier reconstructs actual Git ancestry/content, K/B/all manifest copies,
current release/profile/protected configuration, actual keys/proofs and valid
idle guards before using this provenance. A matching file alone grants nothing.
On a fresh rerun, reuse original generation/keys only with their actual recovery/
control proof and exact intent. Missing recovery material or unproved source
blocks; do not generate replacement K/data keys under the same arrangement.

Distinguish absent, verified resumable prefix, complete bootstrap, own first-
Connect pending, connected and conflicting/unknown states. Empty/name-only or
README-only prefixes after a lost creation can lack attributable ownership;
refuse adoption and explain explicit owner cleanup/new intent rather than claim
every partial failure is automatically resumable. Never delete a collision,
force a ref or reset a connected project. Previous local plan/output is evidence
of intent only, not permission. Known disappearance cannot become a free name.

### 4.2.1 One observation result and explicit effect admission

Add immutable types in the owning installation module; do not put I/O into M2:

```text
InstallationIntent = {owner_id,slug,project_id,install_generation,
                      repository_ids,release,profile_sha256}
InstallationInspection = {state,intent,observed,anchors,next_effect,category}
state = absent | resumable_prefix | provisioned | connect_pending |
        connected | blocked
observed = {repositories,heads,control_source,proofs,guards,history}
anchors = {records_root_oid,keyring_candidate_oid,bootstrap_commit_oid,
           bootstrap_sha256,control_binding_sha256,workflow_sha256}
```

`repository_ids` is exactly `{records,coverage,control}`, each value a positive
integer or explicit null. Allocate the first intent with all three null. Keep
owner/slug/project/install generation/release/profile fields fixed. Incorporating
an independently verified create/readback produces one immutable successor
intent by filling only the corresponding null; every already non-null member
must stay identical. Never clear or reassign an observed ID. A disappeared known
resource blocks; a matching name cannot refill it with another numeric ID.
An uncertain create response cannot fill a null from name-only discovery.

`InstallationAttempt` carries the latest monotonic intent and the exact matching
in-process effect receipts; inspections compare every retained non-null ID with
current discovery. No placeholder0, omitted role or mutable shared map is valid.
Require all three positive IDs before recovery-bundle intent, K/B or later
anchors, restarted-prefix recovery, the M2 VerifiedInstallation projection,
provisioned/connect_pending/connected results or final provenance. These complete
objects keep their existing non-null ID codecs; the nullable shape exists only
inside pre-creation installer intent and observations. Fault between every role
creation/readback and verify previous IDs survive, fresh unknown IDs cannot be
adopted, and bundle/bootstrap/completion remain denied until complete.

Each anchor is an existing validated OID/digest or explicit null before it is
created. `repositories` is exactly the current complete three-role M2 discovery;
`heads` is the exact observed approved branch/OID map. Each of control_source,
proofs, guards and history is an owning validated typed result or the explicit
observation enum `absent|unavailable|not_applicable`; never a caller boolean.
`intent` may be null only for truly absent, unallocated planning. `next_effect`
is one fixed effect enum below or `none`; category uses the existing finite safe
result categories. An unavailable required observation yields blocked, not absent.
Construct these values only inside the released read-only inspector.

The concrete internal call is
`inspect_install(config:InstallInput, release:PlannedRelease,
profile:DeploymentProfile, discovery:Discovery,
recovery:RecoveryKeys|None, attempt:InstallationAttempt|None)
 -> InstallationInspection`.
RecoveryKeys is the validated in-memory provider, not a raw serialized argument.
InstallationAttempt contains only this process's latest monotonic intent and
its matching independently read-back numeric creation/effect identities; it is not persisted
or accepted from a request. A process restart has no such attempt authority.

Implement one inspector. Existing `InstallationVerifier.verify(config,release,
discovery)` is a compatibility projection over that inspector with its released
profile/provider composition fixed at construction. It returns the current M2
`VerifiedInstallation` only for a fully verified same-intent provisioned or
connected arrangement; otherwise None. Its owner/slug/release/repository members
remain unchanged and confer no new partial-state authority. The coordinator
consumes the richer inspection, then supplies only that complete projection to
M2 `FreshObservations`/`plan_install`. It never treats M2's None as permission to
create a resource or strips a blocker merely because a prefix exists.

| State and actual evidence | Allowed next effect/result |
|---|---|
| absent: complete visibility, all3 intended names truly absent, no disappeared known ID | Read-only plan; after consent allocate the all-null intent and enter the same-process prefix; execute only its fixed create_next_role effect. |
| resumable_prefix, same process: exact intent, every existing numeric role from an independently verified effect and current observations; no conflicting head/code | Only the next missing fixed effect: create_next_role, seed_roots, install_control, install_transport, prove_keys, handoff, bootstrap or finalize_provenance. Recheck its prerequisites/readback; no key/genesis replacement. |
| resumable_prefix, restart: exact actual K and original root, native actual-key/recovery proof, matching bundle intent/current numeric roles, verified original released control binding, and no B/event/foreign guard conflict | With explicit current authority/consent, reconstruct only the original K→B/bootstrap/guard/final-provenance suffix. K is never recreated; deterministic existing B/objects are read back before an absent write. |
| provisioned: exact root/K/B/all copies/final provenance, valid independent idle guards, all actual proofs and no first canonical event/config/full projection | Return provisioned; install rerun creates nothing. Direct to separate App installation/Connect. |
| connect_pending: authenticated original Connect package/cell or landed event with incomplete effects and exact intent | No installer write or reset; report pending with source OIDs and direct the existing M5/M3 owned operation recovery. |
| connected: full normal authenticated history/current bindings and provenance match, including valid lifecycle | Return already connected and finite normal action; no installer bootstrap/key/guard write. |
| blocked: unknown/denied observation, identity disappearance/drift, unproved early prefix, missing recovery proof, mismatch or foreign operation | No write. Report exact safe category/known identities and explicit operator cleanup/new-intent or separately authorized repair guidance. |

The same-process prefix also covers an allocated intent with zero created roles.
`create_next_role` selects only the first null in the fixed records, coverage,
control order. Require fresh complete authorized discovery proving that exact
name absent, every previous positive ID current and private, and each prior
creation/readback receipt matching the latest attempt. Create/read back only
that role, then produce its one monotonic intent successor and reinspect. An
uncertain creation blocks this effect; it cannot try the next role, blindly
repeat or enroll an ID from name-only discovery. A disappeared known ID,
conflicting name or inconsistent receipt also blocks. No other effect creates
a role, and seed_roots is unavailable until all three IDs are positive.

Derive `next_effect` from actual current verified evidence in this fixed order,
not a saved step number. A completed postcondition advances to the next row;
a missing prerequisite blocks instead of skipping a row. Detect actual Connect
history/guards first and classify connect_pending/connected rather than prefix.

| Fixed effect | Required evidence before it; observed completion |
|---|---|
| create_next_role | Matching same-process intent/receipts, next exact name truly absent; actual private role ID read back and monotonically filled. Repeat this same effect only for the next still-null role after reinspection. |
| seed_roots | All3 current IDs positive; exact records README/default-events root created/read back. No semantic coverage; the coverage probe root stays in bootstrap. |
| install_control | All resources/root current; exact released inert protected code/config verified independently before secrets. |
| install_transport | Current verified protected control; human consent and complete exact transport assignment, then actual bound secret delivery. |
| prove_keys | Current controlled secret/code/context intent; actual candidate/recovery/three service/control proofs for the original keys. |
| handoff | Those actual proofs and safe local destination; section4.1.1 durable bundle and explicit storage receipt. |
| bootstrap | Complete IDs, roots/code/assignment, proofs and handoff; create the nonsemantic coverage probe root, run/read back initial transport/cleanup, then exact original K/B/all copies and idle guards. |
| finalize_provenance | Exact K/B/copies/guards/current proofs; final closed provenance written/read back and full verifier confirms provisioned. |

Each row retains §4's fresh authority, current-source, expiry, uncertainty and
readback checks. Already completed exact effects are observed, never rerun merely
to advance a local phase. These are guards on existing installer operations,
not a new state store, writer or independent authorization path. Test every
adjacent transition and a fault between each role creation, including all-null,
one-ID and two-ID prefixes, uncertain response, disappearance and name conflict.

Before K exists, a restart cannot derive attribution from a name, bundle, empty/
README-only repository, released code alone or prior CLI output. It is blocked;
no promise of arbitrary early crash resumption is made. A bundle's original
intent is context, and even the restart suffix requires its actual root/K/key/
current resource evidence together. Do not manufacture a new local anchor store.
Every allowed effect has the ordering in §4 plus fresh before/after identity and
head checks; another state cannot skip to that effect. At each effect boundary,
fault lost replies and process restart separately. Test the compatibility
projection, all state/effect combinations and denial of invented observations.

### 4.3 Exact dispatch, job observation and proof retrieval

Extend the existing administrator Actions port with bounded run/attempt/job
observation and per-job text-log retrieval. Use a returned dispatch run ID when
the pinned GitHub API supplies one, then independently verify its repository,
workflow/ref/source SHA, event, actor and attempt. A legacy empty response or lost
reply remains effect-unverified. A fixed nonprivate `request_id` dispatch input
and run-name metadata bind bounded lookup to that exact request; never put an
opaque context, key or registration code in a run name. Missing/multiple/unknown
matches do not authorize blind redispatch or choosing an arbitrary successful job.

Read only the expected job in the exact verified run/attempt. Use GitHub's
per-job plain-text log endpoint, not a whole-run archive. Its authenticated
temporary download location is consumed privately once over HTTPS without
forwarding GitHub credentials, logging the signed URL or accepting a caller URL.
Reject local/private-network or malformed locations and further redirects;
bound the text bytes and deadline. Reuse M5's exact single ControlKeyProof line,
timestamp stripping, strict encoding,16KiB decoded bound, signature and original
context/request/run bindings. Do not parse arbitrary log text as a success receipt.
The initial transport result is accepted only from this same independently
verified fixed job and the actual M3 challenge/readback/cleanup report.

Queue/runtime delay cannot extend a context or parent session. Expiry blocks
before key access/new effects; an explicit fresh authorization can continue only
the exact retained intent/accepted operation. Installed proof, transport challenge
and canonical event nonces retain their distinct existing purposes.

### 4.4 Concrete provider and local traversal budgets

Use one released immutable `InstallationLimits` value in the owning local
composition; these are execution ceilings, not another configuration surface or
permission source. Reuse stricter existing release/M4/M5 limits for their calls.
All byte counts are raw delivered bytes unless separately stated. A new request
must fit both its own ceiling and the remaining aggregate budget before sending.

| Operation | Complete bound |
|---|---|
| JSON profile/BACKUP/TARGET | 1 MiB each; recovery bundle64 KiB; nesting32; duplicate/unknown fields reject; no partial parsing. |
| GitHub ordinary HTTP | 15s per attempt including body; at most4 attempts; retry only existing retryable read/conditional semantics, never uncertain blind writes; total retry sleep at most30s per operation. |
| Current actor/repository/App/install/assignment observations | 100 entries/page, at most10 pages/1000 entries per collection, at most1 MiB/page and10 MiB/collection; every relevant next-page link must terminate inside these bounds. |
| Actions run lookup | At most10 pages of100 runs for the exact workflow; verify at most10 matching candidate runs and5 attempts/run,100 jobs/attempt; one exact request/run/attempt/job result or blocked. |
| Run completion observation | At most60 reads across at most15 minutes monotonic, with at most15s between observations; context/session expiry can stop earlier. No expiry extension or new dispatch on timeout. |
| Exact proof log | At most2 MiB text/job, one documented302 location, one15s download, no further redirect, no credential forwarding; decoded ControlKeyProof at most16 KiB. |
| Actions policy/code and fixed blob | At most1 MiB complete response/body each; fixed self-control raw blob at most1 MiB; write result needs exact readback, not repeated side effects. |
| Source/target ref equality | At most100 pages of100 refs/10,000 refs per role, at most16 MiB complete ref metadata per role; exact map must fit BACKUP's1 MiB first. A recorded/present ref outside the complete set is not ignored. |
| Local mirror/object verification | Existing official Git commands, no new copy engine: complete reachable-object traversal at most1,000,000 objects and10 GiB streamed decoded content across all3 roles;600s monotonic/process deadline;32 MiB bounded diagnostic output. Object hashing streams; no full-history in-memory buffer. |
| Recovery service calls/proof maps | Existing64 KiB complete request/response ceiling, including context and all required commitments/proofs; at most512 capability-key entries across retained maps, then encoded-byte bound may reject sooner. No truncation/current-key-only substitute; each single-key wrap/challenge also obeys the64 KiB bound. |
| Complete local invocation | At most4000 provider requests including retries/observation,128 MiB aggregate HTTP response bytes and30 minutes monotonic including sleeps; proof/session deadlines remain stricter. Mirror verification has its own local10 GiB bound and no secret-bearing provider request. |

A new collection, run attempt or per-key operation consumes the same aggregate
counters; nested clients cannot reset them. Complete external response reads
must stop at ceiling+1; local child processes are terminated/reaped at deadline,
and diagnostic output is bounded/redacted without asserting success. Honor
Retry-After only within the remaining sleep/deadline budget. Cancelled/expired
caller work cannot continue silently with held secret references.

Exhaustion returns existing incomplete/blocked or uncertain-after-effect with
nonprivate current identities and a finite explicit next step. Never infer
absence, equality, unique match, permission or success from a truncated page,
log, ref/object list or proof map. Raw operator copying remains separate and can
succeed even when bounded inspection cannot verify equality; report equality
unverified and do not activate. No limit relaxes actual full-history/key proof.
Test each at-limit/over-limit boundary, aggregate exhaustion, slow body/deadline,
retry ceiling and encoded-versus-decoded size before private effects. Live
suitability and provider policy remain future acceptance, not demonstrated here.

## 5. Protected initial transport and deployment

Extend the existing fixed probe adapter with literal phase `initial-transport`.
It verifies actual numeric executing control repository, pinned source/release,
current transport assignment and exact initial root/layout before App-key use.
It does not read absent normal history/semantic coverage or construct fake state.
Reuse M3 minting, temporary nonprivate branch challenge/readback and conditional
cleanup. Lost cleanup reply needs exact observation; unknown ownership blocks.
Do not add commits to events or mutate live coverage for the challenge.

The transport App baseline is guided manual GitHub create/select, explicit human
consent and local PEM generation/download. No loopback registration callback or
automatic manifest-conversion path is needed to deliver the approved outcome.
Do not add a second mandatory registration mechanism; any later optional
conversion must remain entirely local under the existing architecture.

The two production Worker configurations and release assets come from M4/M5.
M6 supplies reproducible operator templates and checks: disjoint secret roots,
exact service bindings/registry/gate namespace, relative portal assets on the API
origin, separately configured cookieless agreement origin and current public
verification keys. The same released code/assets instantiate selfhosted accounts
without editing source or hardcoded origins. Config is inert operator data.
Current bench-only wrangler.toml is not a production template.

The shipped runbook covers GitHub App ownership/consent, Cloudflare bindings and
secret entry through official tooling, independent code/asset/release validation,
profile generation/inspection, registry initialization and actual installed
challenge. It creates no new hosted admin API or general local deployment CLI.
No secret occurs in profile/templates, source, ordinary output or deployment
artifacts. A missing gate, wrong origin/asset pin, mixed service capability or
half-installed deployment stays unavailable.

Upgrade is explicit: verify target release and prior immutable identity; install
accepted public keys and compatible readers before writers; install verified
control/config/source pins before enabling their new fixed purpose; then perform
actual readbacks/proofs and existing guarded transitions. Public-key retirement
uses M4's full active-route successor/overlap rules, not a local TTL shortcut.
Rollback selects only verified code compatible with current history/capabilities.
It cannot downgrade schema 2 history, clear guards, restore old canonical refs or
silently turn a profile change into migration.

## 6. Snapshot capture and exact mirror copying

Use global §9.1.1's exact BACKUP/TARGET schemas and existing canonical codecs;
complete read/parse is at most 1 MiB per regular file, without symlink traversal,
duplicate/unknown keys or partial results. Capture a complete backed-up ref map
and all retained objects from the actual mirror snapshots, then atomically write
the one canonical manifest. Do not claim atomic capture across three live remote
repositories; source consistency is a later activation check. Keep recovery
material separate. This manifest is not a checkpoint against an administrator
controlling both history and backups.

The operator creates fresh empty private targets, records current numeric TARGET
identities and uses GitHub's documented full-history mirror transport. Do not run
normal installation to invent new roots before import. Reused companion roles
must already match the exact recorded snapshot; advanced/unproved repositories
are never overwritten. Follow the recorded default branches and compare full
backed-up ref sets, OIDs and reachable history/object availability after import.
A missing recorded Git object cannot be called a complete verified copy. Missing
application refs and semantically invalid application files are preserved exactly.

Before any imported control ref, current administrator disables Actions and
reads back effective denial. Keep inherited organization secrets/runner resources
unavailable; reused targets also require cancel/drain and relevant containment.
Policy denial/uncertainty blocks import. An empty private repository is not proof
of disabled execution. Do not write imported refs first and later infer safety
from enabled:false or an unsigned local receipt.

Raw copying stops after exact object/ref readback. It performs no replay/repair,
new workflow/config installation, secret write, guard clearing, pending-operation
continuation or rebind. Unfinished Connect, missing derived, stale projection,
non-idle guards and corrupt application contents remain exactly as backed up.
Keep new targets unbound and all imported code disabled. Report copy equality
and defects/readiness separately. Original source routes/registry are unchanged.
Copying an older snapshot to fresh isolated targets remains allowed; live
activation rejects an observable newer unaccounted source history.

## 7. Explicit activation and frozen source health

Default restore is read-only planning/inspection. Obtain current private target
owner/admin and exact release/profile authorization before safe recovery-key
prompting. Locally authenticate old root/K/B/manifests, retained keys, full
canonical history and all required source branches. Reuse full read-only
`verify_project` comparisons through the narrowly typed origin/current source
view: complete coverage/private projections, configuration, current data keys,
operation cell, idle fence and empty marker must agree at frozen source heads.
Healthy closed/succeeded projects retain that lifecycle; recovery cannot reopen
legal state, agreements, signatures, revocations or contributing scope.

Unconnected or missing-derived, malformed/stale/partial/non-idle source is not
activated. Return copy result plus blocked activation with no Git/secret/job/
registry/source-route write. Never complete an operation imported from BACKUP,
including an accepted first Connect. Separately invoked repair keeps its own
existing authority; restore makes no promise that an arbitrary broken new-ID
copy can later be activated without restoring a healthy source snapshot.

For new activation, show exact old/new IDs, source point/heads and known later
history limits, selected controllers/release and remaining GitHub consent.
Require explicit confirmation. Fresh GitHub-backed actor/target authority and
adopter recovery possession are separate proofs. A current administrator of
unrelated targets cannot claim a project merely by naming its snapshot.

After health/current-head/authority/confirmation, use M4's existing conditional
registry generation staging and set every currently routable affected gate
pending/quarantined against the observed generation. New targets remain unbound.
Revalidate original observable source heads, imported target refs and registry
state after staging and before secrets, protected jobs, key-bearing writes or
rebind. Changed/unaccounted later source history blocks, never rolls back source.
On pre-event failure, only matching conditional restoration is allowed; newer
quarantine wins. Once event acceptance begins, finish that exact operation with
gates pending through materialization/readback/sweep.

Only then, with Actions still disabled, install independently verified current
protected code and inert successor bindings. Audit all eligible workflow/ref
surfaces, not just action allowlists; inline run code must be verified. Keep old
unapproved workflows disabled. If required history prevents safe isolation,
activation blocks without deleting it. Recheck code/repository/policy before
secrets; allow only bound proof jobs initially and normal scheduled repair only
after actual independent key/permission/transport proofs pass.

## 8. Fixed activation inputs and service proofs

Reuse the existing protected v2 root and its fixed routing binding. Add literal
workflow command `restore` and bounded inert `recovery_request`, empty for every
other command. The existing `authorization_context` carries a fixed recovery-only
purpose. This is internal activation, not a new general public CLI command or
browser mutation form. Decode only GitHub's bounded local event input through
the existing trusted adapter; no request interpolation into run/env/module paths.
Ordinary scheduled commands have no recovery input and cannot adopt old source.

### 8.1 Exact large manifest without a dispatch-size shortcut

After healthy confirmation/staging, local administrator creates the exact
canonical nonsecret BACKUP bytes as a Git blob in the current target control
repository, without changing a ref/tree/commit or executable code. Read back raw
blob bytes through the fixed GitHub endpoint and verify exact size/canonical
schema/SHA256. For lost upload replies, derive/verify the ordinary Git blob OID
from its standard object bytes and observe that exact object before bounded
idempotent repeat; unavailable/denied readback is not absence. SHA256 of the
original manifest, not Git SHA1 alone, authenticates input equality.

The closed dispatch request is
`{v:1,snapshot_blob_oid,snapshot_sha256,target,source_heads,registry_commit_oid,
registry_generation,challenge_sha256}`. Target uses the existing closed TARGET binding. Source
heads are the six global event fields. No raw key, recovery key, context, provider,
URL, arbitrary path or executable instruction enters that blob. The context is
transient dispatch data, never Git/log output. Aggregate dispatch fields obey
both unchanged M4 control-message limits and GitHub's stricter 65,535-character
limit; count serialized UTF-8 bytes conservatively. Never inline/truncate a 1 MiB
manifest or raise the Worker body/profile limits.

Before key access, the verified job checks its numeric control repository and
fixed purpose/context, reads only that exact self-repository blob with its
contents-read GitHub token, bounds raw response to 1 MiB, checks exact SHA256/schema
and reconstructs the admitted source/target intent. Use fixed raw media type,
not an unbounded base64 JSON response. No cross-repository blob/URL lookup.

An unreferenced Git blob has no promised indefinite retention. Missing/uncertain
input blocks safely; an explicit retry with the same required BACKUP file can
recreate the same content-addressed bytes and reauthorize only the same accepted
operation. Do not turn blob presence into source-health/administrator proof or a
second durable job authority. Before canonical acceptance, missing fresh context
or original manifest leaves the operation pending rather than erasing/replacing
it. Ordinary completed reading does not need a permanent backup lookup store.

### 8.2 Recovery-only proof authority

M5 initial-wrap authorizes only unclaimed candidate material; ordinary installed
proof requires current normal repository bindings. Neither is broadened to
accept new IDs silently. M6 adds one fixed recovery-only authorization/proof
purpose in the existing opaque-context and protected OIDC machinery, with typed
verified origin/current source. Bind project, actor/current seven target rows,
exact snapshot/source heads, complete successor set, current profile/release/
workflow, key commitments, nonce/expiry, registry generation and permitted new
rebind fingerprint. Recheck actual current facts and code before key use.

Reuse M5 actual-key fingerprints/MACs and exact ControlKeyProof signature/wire
verification, three direct capability-specific service paths and independent
records/coverage recovery checks. Authority only permits those exact recovery
proofs and this rebind; it grants no ordinary record view, old-ID transport,
initial unclaimed shortcut, general key unwrap or arbitrary provider. Source
root/K/B/key authentication is mandatory in addition to current target admin.

Static code/current authorization checks precede the limited key-proof job;
all independent actual proofs complete before canonical rebind/materialization
or normal routing. Do not require a job to have already produced its own proof,
and do not persist a keys_ready bit to bypass these phases. Updated control/
wrapping copies are verified successors of retained origin, never a new genesis.

### 8.3 Concrete recovery context and fixed service calls

The existing Connect/setup screen issues a new fixed context purpose through
`POST /bootstrap/recovery-context`, authenticated by its live browser session
and exact Origin. It displays only nonsecret source/target/release/key-commitment
metadata. Its closed body is
`{snapshot_sha256,source_heads,source_repository_ids,source_repository_owner,
target,release,profile_sha256,key_commitments_sha256,challenge_sha256}`. Target is the existing
TARGET object; source IDs/owner are the current source epoch at the snapshot,
not a replacement for historical genesis. The server resolves the actual actor,
current seven target facts and current registry base; it never accepts supplied
authorization rows or a health boolean.

Reuse M5's existing closed opaque outer context and AEAD/key family, with literal
purpose `repository-recovery-source` and at most 600-second/parent-session expiry.
Its binding is exactly the body above plus `registry_base_oid` and
`registry_base_generation`. The original-wire digest remains the binding used
by later proofs. Profile identity must match independently configured deployed
origins/Apps/registry/public-key/release fields, not configure them from a caller.

After local full source-health/recovery verification and explicit confirmation,
the CLI calls fixed `POST /bootstrap/recovery-authorize` with
`{v:1,authorization_context,key_commitments,records_keys}`. Commitments are
canonical kid-sorted records/coverage lists of existing `{data_kid,key_fingerprint}`
values, in exactly `{records:[...],coverage:[...]}` with each list kid-sorted.
Fingerprints use existing `sha256:` plus64 lowercase hex; hash exact JCS of
this complete object. Its SHA256 must equal the context. `records_keys` is the supplied
records capability's kid-to-lowercase64-hex32-byte-key map, transient only at the already
consented portal, never a GitHub credential or recovery wrapping root. No key
goes through browser JS or to the enforcer as records capability.

The portal rechecks the live actor/current target facts and authenticates source
possession against actual immutable key-binding material and, for an existing
claim in this domain, a canonical object already referenced by its trusted
registry history. Authenticate that exact object's project/path/AAD with the
supplied key; do not accept a caller-chosen anchor, synthetic copy or unrelated
new repository as existing-project authority. Existing-domain authority must
match the authenticated current ownership and data-key epoch; possession of an
older valid key/object cannot replace that proof or reopen a newer generation.
If current-epoch continuity cannot be proved, block without a checkpoint bypass
or an older-anchor fallback. Unavailable or unauthenticated
source possession blocks without staging. A new independent domain has no old
claim to take over; it retains the explicit independent-controller/fork limits.
No raw key or plaintext result persists or is returned.

This is bounded source-possession/current-authority validation, not another
TypeScript full replay. The released local Python coordinator performs complete
read-only health before calling it, and the protected Python job repeats complete
source validation before canonical effects. The service never treats a local
`healthy:true` or receipt as authority. An authorized source controller can request
only this exact pending transition; ordinary reads/mutations are not granted.

Only then invoke the existing M4 coordinator to stage the exact generation and
pending gates, recheck current heads/registry, and return
`{v:1,authorization_context,registry_commit_oid,registry_generation}`. The returned
opaque purpose is `repository-recovery-activation`; its binding is the original
source binding plus exactly `control_repository_id`, `workflow_ref`, `workflow_oid`,
`registry_commit_oid`, `registry_generation`, `operation_nonce` and
`operation_sha256`. Derive that last fingerprint with the unchanged M1 algorithm
over the now-known S2 payload and stable actor. An identical
lost-response retry reuses the matching stage; another intent conflicts.

Use the existing registry's pending-generation artifact for a closed
preparation with exactly
`{kind:"repository-recovery",project_id,operation_nonce,actor_identity,
snapshot_sha256,source_heads,source_repository_ids,source_repository_owner,
target,release,profile_sha256,key_commitments_sha256,challenge_sha256}`. Actor identity uses the
existing stable M1 codec and the shared writer issues the one CSPRNG nonce only
after checking for an accepted/staged match. No canonical event or new
progress store is introduced. Read a matching accepted cell/event/staged intent
before issuing another nonce. The nonce is independent of the resulting registry
OID; derive the existing operation fingerprint only after that OID/generation is
known. Do not put the future activation commit OID back into its own input or
create a circular hash. Pending metadata alone never activates a route.

On a retry, distinguish the current authorized caller from a frozen accepted
event's actor. A newly authorized caller can only complete an already accepted
exact package through the existing repair rules, not change its actor, rows or
payload. A different not-yet-accepted intent conflicts rather than silently
retargeting the staged request.

Fixed recovery wrapping/challenge cases in the existing service handlers accept
`{v:1,authorization_context,capability,wrapper_id,key_commitments,data_kid,key,
challenge}`. Only portal-records, portal-coverage and enforcer-coverage tuples are
allowed. Validate map digest/member, actual fingerprint, request nonce/expiry and
current staged identity for each provided key; return the existing bound wrapped
copy/challenge result only. Rewrap all retained keys needed for history under
the new selected controllers, not just current kids. Never unwrap an arbitrary
existing project key through this supplied-key operation or forward raw keys.

### 8.4 Closed recovery control proof wire

Recovery uses its own fixed wire, not M5's closed initial/installed
`bootstrap_request`. Do not add a recovery phase to that existing union.
`POST /internal/recovery/authorize` accepts exactly
`{v:1,authorization_context,recovery_request}`; recovery_request is §8.1's exact
short descriptor, including the fresh32-byte challenge's SHA256. Its complete
canonical body SHA256 binds the fixed OIDC audience
`dracla-recovery-v1.<domain hex>.<body SHA256 hex>`. Validate actual private
control repository/owner, approved immutable workflow/ref, run and attempt plus
the exact recovery-activation context/staged generation before key access.
The challenge digest must match the source context and staged preparation; a
fresh proof authorization may not change an already staged activation intent.

Success response is exactly
`{v:1,request_sha256,project_id,install_generation,allowed,source_candidate_oid,
key_commitments_sha256,challenge_sha256,registry_commit_oid,registry_generation,
expires_at}`. `source_candidate_oid` is exactly frozen source_heads.keys,
not bootstrap K, a new wrapper commit or a caller-chosen candidate. Install
generation is original authenticated bootstrap generation. Digests/registry/
project values must equal the frozen context and local admitted source;
allowed must be true. Expiry is no later than60 seconds or context/session
expiry. Read all values as assertions to compare, never new source selectors.
Denial/expiry/mismatch uses fixed nonprivate401/403/409/503 categories.

Only after authorization may the verified job open its current protected
control copies, authenticate original activated candidate bindings for every
retained key and select the complete committed records/coverage maps. The
independent service copies are read back from the actual successor keys branch
through the fixed recovery-only source view; a submitted copy cannot substitute
for stored readback. Rewrapping may advance keys after source_heads.keys, but
source authentication remains frozen there and every successor must be proven
wrapper-only. Portal verifies its own records/coverage copies; enforcer verifies
its coverage copy through M5's authenticated request-bound observation path.
The source context's complete map digest and actual supplied-key fingerprints
must agree throughout; no unverified fingerprint enrolls a key.

For each retained `(capability,data_kid)`, use M5's unchanged HMAC-SHA256 object
and domain, with `wrapper_id:"control"`, `candidate_oid:source_heads.keys`,
the original bootstrap install generation, current workflow/run/attempt, exact
challenge_sha256 and original recovery-activation wire-context SHA256. The
existing context binds the full retained-map digest. This is the existing key
challenge, not a new MAC or a bootstrap phase substitution.

`POST /internal/recovery/prove` accepts exactly
`{v:1,authorization_context,recovery_request,commitments,proofs}`. Commitments is
exactly the canonical complete records/coverage lists from §8.3. Proofs is the
same capability-then-kid sorted unique list, each exactly
`{capability,data_kid,proof}`; proof is strict unpadded base64url of the32 native
HMAC bytes using the existing M1 codec. Missing, extra,
duplicate or cross-generation members deny. Its distinct complete-body SHA256
binds a fresh recovery OIDC token; never reuse the authorize body digest.
The portal rechecks live current authority/context/stage/source/code and every
control MAC against its independent actual service copies and enforcer proof.
No control proof replaces either recovery possession or a direct service proof.

Return exactly M5's existing signed ControlKeyProof envelope and payload. Set
candidate_oid to source_heads.keys; commitments_sha256 to the complete retained
map digest; challenge_sha256 and authorization_context_sha256 to the original
values above; install generation to the authenticated origin. Domain, numeric
control ID/workflow/run/attempt remain actual. verified_at is current and
expires_at is at most60 seconds and before context/session expiry. All unchanged
Ed25519 encodings, domain and16 KiB single-line log rules apply. The CLI checks
every payload field against its original frozen request before acceptance.
Neither endpoint grants general dispatch/registry/records/enforcer credentials.

Parity and substitution vectors cover exact valid multi-generation maps,
bootstrap-versus-recovery confusion, old-K-versus-source-keys substitution,
post-rewrap source/candidate mismatch, omitted retained member, context
reencryption/digest change, different challenge, authorize/prove body swap,
run/attempt and actual stored-copy substitution. Oversized complete proof input
blocks; it cannot drop historic keys or weaken unchanged body limits.

Use only the existing wrapper-only keyring descendant protocol for new wrapping
paths: verify every retained raw key against its original activated candidate
binding, preserve all canonical/data-key generations and K/B, then CAS/read back
the fixed keys branch and inert current control copies. The recovery provider
authenticates frozen old source heads using these same proven raw keys while
transport always names the actual successors. After rebind, ordinary readers
must open the real current wrapped copies without a recovery bypass. A changed
data key instead needs its separately authorized normal activation; it cannot
be hidden inside repository rebind.

## 9. One canonical transition and existing engine

Use exactly global §9.1.1's `project_repositories_rebound`, schema 2, closed target
`{prior_repository_ids,prior_repository_owner}` and payload
`{repository_ids,repository_owner,project_slug,snapshot_sha256,source_heads,
registry_commit_oid,registry_generation}`. No recovered_events_oid or prior-
operation digest, no nullable source derived head. The event's single parent is
exactly source_heads.events. Prior owner/set match replay there, slug/recipient/
legal state stay unchanged and at least one role ID changes. Same-ID activation
uses existing strict bindings and needs no fake rebind event.

Require exactly the global seven project_rebind owner/repository/App rows at
the existing Connect minimum authority, actual current target resources and
GitHub actor. Preserve M1 nonce/idempotency/event-ID/operation digest algorithms
and existing domain strings. Schema2 admits only this event; every old event
keeps its closed v1 contract, including normal action forms and confirmations.
No ordinary browser/append form exposes the internal transition.

Envelope version stays unchanged. For events only, select supported semantic
schema 1/2 from the bounded untrusted identity header, recompute the expected
project/role/path identity, authenticate AAD/ciphertext under the correct epoch
key, then require plaintext schema/type/path/event identity to match. Reject
unknown versions before allocation/decryption. Non-event artifact identities
remain schema 1. Never add repository IDs to old ciphertext AAD or rewrite
historical events to make the copy decryptable.

Extend Python/TS closed validators, authorization/precondition tables, package
requirements and replay using the same Python-authored shared corpus. The S2
transition changes repository binding only, retains lifecycle (including closed/
succeeded), and uses a project-wide fence. The existing generation side artifact
remains version 1 and advances all three private classes to this event ID in the
same canonical event package. No extra legal config event, copied old generation
or partially committed generation artifact is acceptable.

The existing writer uses exact-head prepare/fence/marker/claim/non-forced append,
then complete coverage and all 96 private shards as required by current profiles.
Read back every actual encrypted object and sole publication marker. Preserve
M4's landed order: projection verification, marker close/readback, terminal CAS/
readback, fence release/readback, then cell clear/readback. Preserve its distinct
prepared-but-not-landed failure completion order; do not erase accepted work.
Only exact staged registry/App/scope generation and bounded open-PR sweep can
complete gates. A newer incident/quarantine always defeats old restoration.

## 10. Origin/current readers and own-operation retry

Before the transition, a trusted factory constructs invocation-local admission
only after exact snapshot/object/key/current-target proof. Historical manifest
IDs validate against original genesis and each later rebind, never against a
forged old-ID transport. Every transport authorizes actual successor numeric IDs.
The admitted read-only source view cannot become an ordinary private reader or
permit arbitrary refs/actions. No boolean, JSON alias table or generic callback
is accepted as this authority.

After rebind, normal readers need no recovery bypass: authenticate original
manifest/root/K/B, complete key and canonical history with each valid binding
epoch, and require final replay owner/IDs to match actual authorized current
resources. Historical authorizations retain their event epoch. Update actual
M4/M5 reader/admin/sign/revoke/export call sites, not only a detached local helper.
Unknown schema/type/capability or missing history fails closed.

Before preparing another operation, read matching accepted activation cell/event.
Only exact snapshot digest/source heads/target/staged registry and the original
frozen package can resume. Reconstruct pre-activation health at immutable source
heads; partial effects of this new operation do not turn into an imported broken
backup. Imported original non-idle state is never this operation. Retry current
authority/proof context cannot change frozen actor/event/nonce/artifacts or
retarget the intent; authorized repair completes only the existing accepted act.

If the event already landed, use actual ancestry/package/readback evidence and
normal current binding to finish its exact projections/gates. A completed repeat
reads and validates the original completion/current binding/generation without
creating a new event, nonce, proof dispatch or Git write. It reports that same
activation's completion and what was checked now; it does not claim every
external secret was freshly challenged. Changed/expired required evidence for a
new write blocks instead of treating a past receipt as fresh permission.
A later unrelated canonical event in this project, changed project claim or
changed affected gate/registry generation conflicts and is reported with its
actual source identities; restore never rolls it back. Unrelated tenants' registry
updates use M4's authenticated continuity/unchanged-derivation rules and cannot
retarget this activation. Test a completed repeat before ordinary new mutations,
then verify a repeat after such a mutation reports conflict without writes.

## 11. Controller lifecycle, limits and operator results

Reuse M3 observed-token cleanup for this process only. For potential App/root
exposure, compose M4 m4/13's full affected scope, minting cutoff (including
outstanding signed requests), permanent installation-wide invalidation or full
maximum lifetime after last possible issuance plus live-tested clock/propagation
margin, then M5 actual successor-key/full current-state activation. Unknown
attacker tokens count; removing a key or temporary suspension is not permanent
containment. Missing evidence leaves affected routes unavailable.

Shared transport App changes coordinate every assigned arrangement/control
secret and exact union; different App key pairs do not isolate reach. Operator
and profile migration uses explicit current authority/consent, compatible code,
actual new wrapping/live paths and conditional registry changes. Rewrap alone
keeps old data keys and cannot revoke copied old material. A security cutoff
rotates both data keys and rebuilds current coverage/private state; canonical
history stays unchanged and may remain readable with old copied keys.

An inaccessible original cannot prove no later event existed. Show exact
recoverable point and that limit before confirmation. Refuse observable later
unaccounted history, never force source or advanced companions, and quarantine
conflicting claims in the same coordination domain. Backup/rebind cannot prevent
a controller of all keys from forking independent deployments. It grants no
hidden cross-domain precedence or retroactive revocation.

Shipped guidance covers safe cleanup of unproved prefixes, permissions/consent,
private recovery storage, controller/integrity reach, actual source/generation
results, missing proof categories, compatible rollback, mirror isolation,
activation and migration. No key/token/context/signer PII enters logs, error
reflection, Git plaintext, ordinary artifacts or URLs. Preserve useful nonprivate
source OIDs and exact correlation IDs. Never label offline/fake/skipped evidence
as installed, connected, routable or production-ready.

## 12. Requirement ownership and acceptance

The inventory owns paths, dependencies, full intents and completion checks.
This map closes parent requirements and integrated journeys without a second
embedded inventory:

| Requirement | Owning delivered result and joined check |
|---|---|
| R01 | m6/1 exact CLI/profile/preflight; m6/7 actual installed execution. |
| R02 | m6/1 read-only/no-key capture; m6/7 force/confirmation; m6/15 restore consent. |
| R03 | m6/2 current numeric/private scope and m6/7 fresh rerun/known disappearance. |
| R04 | m6/2 actual first Contents/default rename/roots; m6/6 exact branches/guards. |
| R05 | m6/3 external protected source/ID before keys; m6/6 and15 fixed initial/activation phases; m6/11 pre-import deny. |
| R06 | m6/4 dedicated/shared union/local custody; m6/6 actual restricted transport; m6/16 successor reach. |
| R07 | m6/5 actual independent key paths/private recovery handoff; m6/6 stored bootstrap and15 recovery proof. |
| R08 | m6/6 unique K/B/all copies and independent idle guards with absent semantic projection. |
| R09 | m6/7 actual provenance verifier and finite prefix classification; m6/10 changed release/profile handling. |
| R10 | m6/2–7 exact ambiguous-effect readbacks and faulted coordinator; m6/15 activation retry. |
| R11 | m6/4 human GitHub consent and m6/8 actual linked/direct service-App handoff. |
| R12 | m6/8 installed-wheel/real M5 first-Connect/M4/M3 integration and separate scope state. |
| R13 | m6/9 same-release shared/selfhost assets/bindings/profile; m6/18 actual independent deployment driver. |
| R14 | m6/10 actual reader/key/control-before-writer upgrade/compatible rollback; m6/18 live identities. |
| R15 | m6/11 exact raw copy/isolation,12 closed S2,13 strict normal readers,14 healthy admission/own retry,15 actual full activation;16 migration. |
| R16 | m6/16 installed controller/all-token lifecycle over existing M4/M5 engines; m6/18 actual provider behavior. |
| R17 | m6/1/4/5 safe disclosures, m6/7/15 real result categories, m6/17 complete joined operator guidance/warning sensitivity. |
| R18 | Every owning slice's concrete checks/basis; m6/17 real assembled offline/sensitivity and m6/18 separately authorized real adopter driver. |

The joined driver uses actual installed CLI/wheel, crypto, scoped HTTP clients,
Workers/browser, control adapter and M3 engine. It covers lost replies/crashes
at every durable boundary, current authority/privacy/profile/source/key changes,
foreign guards and own-operation retry, same/new-ID restore and normal
read/admin/sign/revoke/export afterward. Deliberately bypass critical checks in
disposable sensitivity runs and prove assertions fail. A fixture returning true
or a suite duplicating implementation branches is insufficient.

Run the appropriate actual Python/TS/vector/type/package and overview checks
for the delivered code. Existing741 Python/67 TypeScript results and nine live
skips describe old source, not these future features. New live driver needs
separate account/credential authorization and authentic published release/pins.
It records exact resources, executed assertions and residual cleanup. No skipped
provider case counts as passing. M7's release matrix joins this evidence with
its own UI/sample/capacity and all-MUST traceability; unrun acceptance stays open.

## 13. Estimate units and delivery boundary

The 18 planned slices total **10,210–16,100 production lines** and
**19,930–31,800 test lines**. These are incremental final-delivered nonblank
physical lines, excluding comment-only lines and counting docstrings/multiline
statements physically. Shipped configuration, packaging and operator instructions
are production. Test helpers/configuration/generators/integration/live drivers
are tests. Designs, static fixtures/data/images, generated output, lockfiles,
dependencies and disposable probes are excluded. Not added-plus-removed churn,
not whole existing modules, and no time/productivity conversion.

The engineering basis separates actual new responsibilities from current
M1/M2/M3 reuse and planned M4/M5 prerequisites and shows per-slice composition.
One shared file may have several later owners' incremental contributions; each
new delivered responsibility/line is attributed once. Reuse common fixtures and
engines. Ranges include installed/server integration and real negative/live-driver
code; they do not assume named future components already exist or omit tests to
fit a cap. Actual platform/policy/cold behavior and implementation discoveries
can require evidence-backed replanning, never silent scope reduction.

Architecture/profile/exact-copy decisions remain the owner's recorded approvals.
This draft still needs actual plan/inventory review. A clean design does not
publish a release, provision accounts, pass live/production gates or start product
delivery. Preserve original M1–M3 history and all consumed budgets.
