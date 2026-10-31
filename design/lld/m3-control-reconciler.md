---
plan_key: m3
slice_convention: hierarchical-v1
---
# M3 low-level design — control reconciler

Status: Locked
Owner approval: 25 October 2026 — design and six delivery slices;
28 October 2026 — actual-data-key binding and published-slice scope amendment;
31 October 2026 — §6.1 export contract and M3/4.1 ownership successor
Date: 25 October 2026
The owner accepted the export contract and replacement of unstarted `m3/4`
with `m3/4.1`. Exact current design review and campaign admission remain
required before implementation; earlier approvals remain preserved history.
Requirements: `design/requirements.md`, locked revision 14
Architecture: `design/high-level-design.md`, including the owner-approved
25 October adopter-owned transport App amendment
Prerequisite: M1 and M2 merged; inspected main revision
`11e8d0f07ef3406451dc954ecda504c3f3854877`

## 1. Outcome and boundaries

M3 makes encrypted repository history readable, verifiable and repairable by
the Python CLI and a pinned private control workflow. It delivers operational
`verify`, `reconcile` and explicit `export` commands using the same replay.
It does not implement a second event model or fold in TypeScript.

The requirements and HLD govern all serialized values and transitions. This
document chooses module ownership, interfaces, ordering and delivery boundaries
under HLD §§4–5, 6.6, 6.9, 6.10.2, 8.1.2 and 9. M1/M2 code is interface
context. A missing or contradictory normative contract returns to design
review; an implementation must not invent a wire field or recovery transition.

M4 owns webhook enforcement, GitHub checks, routing and publication-reservation
confirmation. M5 owns portal authentication, key-wrap services, reader-proof
checks and hosted-export authorization/download. M6 owns App creation assistance,
repository provisioning, secret installation, Connect and end-to-end install
resume. M7 owns product polish and assembled release evidence. M3 supplies real
engines and explicit integration contracts; it does not advertise those later
systems as operational.

## 2. Ownership and interfaces

Use one new Python package, `core/dracla/records/`. Domain orchestration consumes
plain immutable values, never Hydra/OmegaConf, dynamic commands or modules.

| Surface | Responsibility and principal interfaces |
|---|---|
| `records/credentials.py` | Verify protected App/installation assignments through `InstallationCredentials`; accept explicit local operator credentials through `OperatorCredentials`; redact secret-bearing values |
| `records/github.py` | `RepositoryTransport`: immutable-head/blob/tree reads, canonical non-forced append, branch-wide exact-head commit, bounded inventory and temporary-branch challenge operations |
| `records/key_bindings.py` | Encode, validate and check HLD §6.10.2 actual-data-key commitments; one shared producer/reader primitive |
| `records/history.py` | `open_history(binding, key_provider, transport)` validates bootstrap and yields authenticated `CanonicalEventRecord` values; `replay_history` returns the existing M1 `ReplayResult`; `verify_project` reports divergence without writes |
| `records/append.py` | Execute the validated frozen package with existing M1 operation-state transitions; distinguish landed, semantic no-op, conflict and indeterminate results |
| `records/reconcile.py` | `reconcile_project` repairs only authenticated, conditional transitions |
| `records/exports.py` | Stream canonical JSON/CSV locally; produce an explicitly requested encrypted hosted snapshot with its exact source OID |
| `cli/app.py` and client configuration | Register real handlers, acquire operator credentials/recovery input, render non-private results and stable exit codes |
| `control/` | Versioned workflow template, external release-verification bootstrap and upgrade/rollback instructions |
| `docs/github-apps.md` | Administrator setup, dedicated/shared choice, contributor boundary and credential incident guide |

Reuse the public `dracla.conformance` envelope, keyring, event-package, replay,
coverage, derived-state and operation APIs. Examples include
`decode_keyring`, `unwrap_key_copy`, `CanonicalEventRecord`,
`materialize_coverage`, `assemble_derived_projection`, `claim_append` and
`release_mutation_fence`. Do not read private attributes to bridge modules.
The legacy plaintext `githost.py`, `github.py`, `append.py`, `events.py` and
`projection.py` remain historical experiments, never default transports.

M2's `GitHubAdministration` deliberately requires administrator authority for
provisioning. Do not weaken that adapter or grant the transport App admin
permission to reuse it. The new contents-scoped transport owns records I/O;
the existing administration protocol remains the M6 provisioning seam. Inject
the HTTP sender, credential provider, clock and bounded retry/sleep policy.
There is no generic transport framework, daemon, database or new progress log.

## 3. Credential and execution boundary

The adopter owns a private App in the account holding the data repositories.
It has Contents write and implicit Metadata read only. The installation selects
the exact union of records/coverage IDs assigned to it, excluding all control
and contributing repositories. One App may serve one or several arrangements.
Each arrangement retains independent history, data keys and recovery material.
The App private key reaches every assigned arrangement even when the normal
job token is restricted to one. Different keys of the same App do not isolate
arrangements. The guide and completion output disclose this explicitly.

Control-owned configuration binds numeric owner, App and installation IDs and
the approved arrangement-to-repository assignment. Verify the installation's
complete grant and selected set before data-key access. Reject all-repository
selection, unexpected grants, missing/extra IDs, wrong owner, public data repo,
or control access. An inventory credential may read the approved union; every
data-operation token requests only the current arrangement and required rights.
Never derive the permitted set from App-writable business data.

Tokens and signing material stay in process memory and secret inputs. Do not
put them in argv, URLs, reprs, exceptions, outputs or artifacts. Treat token
syntax as opaque. Refresh using the returned expiry with a tested clock margin;
after authorization failure, recheck identity and scope. Reconcile an uncertain
write before refreshing and retrying. No PAT/SSH fallback or permission widening.

These App rules govern the control job. The local CLI's separate, explicit
operator mode uses the operator's own repository access plus recovery material,
as HLD §6.9 requires. It verifies repository IDs, privacy and authenticated
bootstrap/history without requiring the operator to possess an App private key.
Select that mode before I/O; it cannot replace a failed control-job App check.
Both modes use the same repository transport and replay, with distinct
credential providers. Local access grants no hosted reader or administrator
authority. The production control execution gate below is mandatory; the
one-time local command retains HLD §6.9's optional external verification path.

Production verification happens **outside the DraCLA package before executing
it**, before supplying the transport App secret or any wrapping/recovery key.
The pinned bootstrap obtains the exact distribution, its dependency closure
and standard PyPI/Sigstore evidence; verifies artifact hashes, expected publisher,
source commit, release workflow and declared build inputs; installs only those
verified bytes offline; then starts that same artifact. No unconstrained
resolver runs after verification. A package checking its own policy is a
declaration check, not this gate. Use standard tooling, no separate downloaded
allowed-file manifest or DraCLA signing key.

The release workflow must produce the source/build claims required by
`REQ-SEC-10`; a PyPI publish attestation alone does not establish all build
inputs. Implementation must test the actual producer/verifier combination and
pin its actions, tools, dependencies and builder identity. Missing claims,
unsupported evidence, absent release artifacts or failed verification block
production use. Deterministic fixtures do not substitute for that release gate.

Only protected control configuration selects executable inputs. Records and
coverage bytes are inert, closed-schema data. They cannot choose an executable,
workflow, module, dependency, filesystem destination or shell expression.

### 3.1 Concrete production verification protocol

Use GitHub Actions/Sigstore build attestations and PyPI Trusted Publishing,
with one pinned bootstrap environment. No new signing key or attestation type
is introduced. The bootstrap is outside the downloaded DraCLA package.

The adopter's protected `control/production-profile.json` has a closed version-1
schema. It contains the exact package version; source repository URL and numeric
ID; reviewed source commit; release ref; expected publisher workflow/commit;
expected reusable builder workflow/commit; bootstrap OCI image digest;
Sigstore trusted-root snapshot digest; and a selected runtime profile. The
runtime profile contains exact Python version/ABI/platform tags, one DraCLA
wheel filename and SHA-256, and the SHA-256 identities of the runtime wheel lock
and declared build-input lock. Every identity is required and non-secret.
Reject unknown fields, mutable selectors, unsupported profiles and placeholders.
These pins live in adopter-controlled code, never records/coverage or metadata
downloaded beside the wheel. M6 binds them only after verification. They are
created after wheel assembly, so no artifact contains its own digest. This is
the protected execution lock, not a downloaded release-file list.

The schema's exact top-level keys are `profile_version`, `package_version`,
`source`, `publisher`, `builder`, `bootstrap` and `runtime`. Nested keys are:
`source={repository_url,repository_id,commit_oid,ref}`;
`publisher={workflow,commit_oid,certificate_identity}`;
`builder={workflow,commit_oid,certificate_identity}`;
`bootstrap={image,trust_root_sha256}`;
`runtime={python_version,abi,platform,wheel,runtime_lock_sha256,build_lock_sha256}`;
and `wheel={filename,sha256}`. The version is integer `1`, repository ID is a
positive integer, commits are full Git OIDs and digests are lowercase
`sha256:<64 hex>` values. Every nested object is closed. URLs and filenames are
validated literal identities, not redirects, commands or path expressions.

`release/runtime-wheels.lock` declares each transitive runtime dependency by
normalized name, exact version, wheel filename, supported tags, URL and SHA-256.
It excludes the DraCLA wheel itself. `release/build-inputs.lock.json` declares
the build container digest, build-tool wheels and action commits used by the
builder. The source identity is added to the emitted provenance from the
verified build context; no source file contains its own commit hash. Lock-file content hashes
are separate from M2's unchanged version-only constraints. The protected
profile binds the locks for the selected tested runtime; do not infer support
for another Python/platform combination or re-resolve conditional dependencies.

Producer: `.github/workflows/release.yml` calls the same repository's
`.github/workflows/build-release.yml` at an immutable reviewed commit. The
builder accepts an exact source commit, not commands, paths or executable
caller options. It checks out that source, validates the locked inputs,
downloads and hashes the complete wheel set, and builds only a wheel in the
pinned build container with network disabled and build isolation disabled after
installing the locked build tools. It runs the release tests against that same
wheel set. It records the inputs actually consumed, not a caller-supplied claim.

The builder uses pinned `actions/attest` with a standard SLSA v1 predicate and
the exact wheel as subject. Require `predicateType:
https://slsa.dev/provenance/v1`, the GitHub workflow build type
`https://actions.github.io/buildtypes/workflow/v1`, and the expected workflow
repository/path/ref in `buildDefinition.externalParameters.workflow`.
`resolvedDependencies` includes the reviewed Git source commit, both lock-file
hashes, the build-container digest and every consumed build/runtime wheel
digest. The builder creates those entries from verified files and rejects an
undeclared executable input. `runDetails.builder.id` identifies the immutable
reusable workflow; its identity must agree with the verified signing certificate.
The standard predicate is generated by that trusted reviewed builder; a signed
predicate from an arbitrary workflow is insufficient. Do not claim an additional
SLSA assurance level or reproducible builds from this procedure.

Publish the exact built wheel through pinned `pypa/gh-action-pypi-publish` and
retain its standard PyPI publish attestation. Require both publish evidence
(`https://docs.pypi.org/attestations/publish/v1`) and the build evidence above.
The publish predicate establishes the publishing identity; it does not replace
the required source/build predicate. Public build attestations reside with the
public DraCLA source; this adds no private-repository paid-plan prerequisite.

Consumer: the protected workflow pins a bootstrap OCI image by digest. That
image contains the exact Python runtime, `gh`, `pypi-attestations` format reader,
Sigstore root snapshot and external `control/verify_release.py` checker. The
image digest is an explicit adopter-approved bootstrap trust anchor; it cannot
authenticate itself by reporting its version. M6/upgrade verification checks its
published provenance before installing that pin. No live tool installation or
automatic trust-root update occurs in a key-bearing run.

Before any App or project secret is supplied, the checker downloads the named
wheel, locks, dependencies and standard evidence into a private wheelhouse. It
verifies the live source repository's numeric identity before using its current
name to retrieve build attestations. `gh attestation verify` checks the exact
wheel, expected repository, signer workflow and signer commit, source commit,
SLSA predicate type and GitHub-hosted runner, using the pinned trusted roots.
Require verified transparency-log inclusion and a valid witnessed signing time.
Parse its verified JSON result; compare subject filename/digest, build type,
workflow identity, builder identity and the complete declared dependency set
against the protected profile and hash-bound locks. Missing claims, extra inputs
or a different same-version wheel fail. An offline bundle's repository name
alone cannot establish a current repository identity.

For PyPI evidence, use the pinned `pypi-attestations` public format API to parse
and convert the selected publish attestation to a Sigstore bundle. Run the same
pinned `gh` verifier with the publish predicate and exact expected GitHub OIDC
issuer/certificate publisher workflow identity. Conversion/inspection is not
verification. Require subject digest equality with the already checked wheel.
The expected issuer is `https://token.actions.githubusercontent.com`; trusted
Fulcio/Rekor material comes only from the pinned public Sigstore root snapshot.
The actual pinned producer/verifier combination must pass an authentic fixture
and real release test before production; an unsupported claim or conversion
must block use, never fall back to a weaker check.

The wheelhouse contains exactly the DraCLA wheel and selected dependency wheels,
all ordinary non-symlink files with verified hashes. Reject sdists, editable/VCS
requirements, extras outside the lock, unlisted files and unresolved tags.
Install into a fresh private environment using pinned pip with
`--no-index --no-deps --only-binary=:all: --require-hashes --no-compile` and explicit local
wheel paths in a hash-requirements file generated from the protected profile
and verified locks. Validate active wheel metadata dependencies against that
closure and the unchanged bundled M2 version constraints. No build or resolver
runs. Keep the environment and wheelhouse in
the same protected runner workspace; no workflow artifact is the trust handoff.
Only successful verification unblocks the secret-bearing workflow step. Its
fixed external launcher independently rechecks the wheel set, installed files
and environment before importing DraCLA or reading a key input. It derives the
expected file map from the verified wheel bytes and pinned pip's known generated
files; an installed `RECORD` file alone is not authority. Reject unexpected files,
links or executable paths. A workflow output flag is only a scheduling hint,
never the verification authority. No downloaded code receives a secret until
these checks pass. The launcher uses only that environment,
disables user-site/PYTHONPATH injection and never imports from the working or
data repositories. A changed file or environment aborts; it never reruns `uvx`
or another package resolution. Build, verifier and launcher dependencies are
part of the locked bootstrap image or wheel closure.

Required rejection cases include publish-only evidence, wrong source/workflow/
builder, missing build inputs, invalid transparency proof, extra or changed
wheels, sdists, network resolution and a swapped environment after verification.
This specifies the gate; it does not claim that a current release or live probe
has already passed it.

Platform references: [GitHub's workflow build type](https://github.com/actions/buildtypes/tree/main/workflow/v1),
[standard attestation producer](https://github.com/actions/attest),
[GitHub CLI verification and policy output](https://cli.github.com/manual/gh_attestation_verify),
[PyPI publish predicate](https://docs.pypi.org/attestations/publish/v1/),
[PyPI format API](https://pypi.org/project/pypi-attestations/), and
[pip hash-checked offline installation](https://pip.pypa.io/en/stable/topics/secure-installs/).
These support the proposed protocol; live implementation evidence is separate.

## 4. Repository reader and verification

Resolve numeric repository identities and immutable branch heads before reads.
Read trees/blobs by those OIDs; paginate completely with explicit resource
bounds. A truncated tree, missing page, inaccessible blob, unsupported shape,
or exceeded budget yields unavailable/corrupt, never partial success.

Follow HLD §6.10.2's exact bootstrap: mandatory README root, first keyring
commit `K`, its manifest child `B`, matching project/generation/repository IDs
and pinned wrapped-key metadata. Obtain provisional raw keys from the latest
keyring descendant through the available authorized current wrapper. Check both
initial keys against the proof in `K`; use the records key only to decrypt the
first event. Accept its authority only when `project_connected` authenticates
the exact manifest digest, `K`, `B`, generation, IDs and current kids. Do not
require the retired installation wrapping secret. Replay later key
activations for current selection and retain predecessors for old history.
Missing, duplicate, mismatched or undecryptable candidates fail closed.

Use HLD §6.10.2's exact `.dracla/key-bindings.json` contract. Keep its encoder,
closed-schema validator and constant-time actual-key check in
`records/key_bindings.py`; do not extend the existing M1 wrapped-copy/event
schemas or create a second selector inside reconciliation. `open_history`
checks both bootstrap keys at K and both selected capabilities at every pinned
activation before returning any snapshot. Check unchanged capabilities too.
Retained keys keep their original authorization. Latest wrapper-only descendants
supply candidate bytes, never new authorization. Same-key rewrap and complete
replay with only successor wrapping secrets must continue to work.

Missing historical proof and same-ID substituted bytes return `invalid-key`
before any reconciliation write. Do not infer proof from the latest keyring or
silently migrate old histories. M5's actual rotation/Connect producers must
consume the same byte contract and Python vectors before live activation; M6
must write proof in initial K before B and complete the existing key challenges.
These remain later producer responsibilities, not a completed M3 installer.

Walk the complete single-parent events ancestry in commit order from the root.
Every later commit has exactly one event and its exact event-specific artifact
set. Authenticate envelopes, path identities, canonical bytes and semantic
preconditions before folding. No timestamp ordering, merge commit, skipped bad
event or partial replay result is accepted. Reuse M1 package/replay validation
for prior-source membership and every historical relation.

`verify` uses a frozen events OID and consistent coverage/derived snapshots.
Compare M1 reference materializations with authenticated stored state, including
all 32 coverage shards, all derived classes, generations, envelope digests,
markers, operation cell and fence cross-bindings. Report the source OIDs and
generic discrepancy categories; never emit signer values in diagnostics.
This command makes no repository writes and acquires no mutation fence.

## 5. Writes, races and crash recovery

Canonical append follows HLD §5.2: validate the whole frozen package, build one
event commit whose parent is the observed events head, then non-force update
the ref. If the head moved, reread/revalidate and apply the existing conflict
rules. If the response is lost, find the exact operation/event/package before
retrying. Never merge, force-update, repair or delete canonical evidence.

Operations and coverage use GraphQL `createCommitOnBranch` with
`expectedHeadOid` and the complete transition file set. Validate every input
at that same head. A blob SHA alone does not supply branch-wide CAS. A stale
head performs no write; reread before recomputing the transition. Generic
HTTP retry must never replay an indeterminate mutation blindly.

The engine drives M1's existing prepared/appending/terminal cell, coverage
mutation fence and in-flight marker. The durable cell contains the entire
authorized package. Recovery needs no browser, session or original request.

| Observed state | Permitted recovery |
|---|---|
| Prepared cell; fence idle | Conditionally acquire the matching fence when available |
| Matching mutation fence | Open/repair its marker, validate the exact operation binding |
| Exact event already landed | Verify its complete frozen package, finish projection and terminal state |
| Event absent; append right available | Revalidate against current history and acquire the exact append claim before append or terminal no-op/conflict |
| Appending cell or ambiguous write | Finish or idempotently discover the exact event; on a non-fast-forward race revalidate and CAS-update its append claim before retrying; never abandon it |
| Terminal cell and completed matching projection | Close the exact marker/fence and then clear the exact terminal cell with existing generation checks |
| Success reservation | Require M4's independent exact check/publication confirmation; M3 has no Checks permission and cannot clear it from a local assertion or timeout |
| Malformed/mismatched operational state | Fail closed; use HLD's route-unavailable repair protocol and complete operation enumeration, otherwise require later M4 recovery integration |

Reconciliation cannot overwrite a newer authenticated source with an older
snapshot. Read the latest events head again before publication and restart when
needed; validate same-head ownership at every CAS. Rebuild private derivatives
in the existing 32-shard layout, carrying encrypted-envelope digests and class
generations. Bounded bulk work publishes its class generation only in the final
state commit. An overflowing derived class remains unavailable; it never caps
canonical acceptance/revocation or silently truncates evidence.

No local lock or Actions concurrency group is the correctness boundary. Test
concurrent hosted writes and control jobs against the actual CAS/append rules.
Only a winner of the still-prepared append-right CAS may terminalize an absent
event as a no-op/conflict. A terminal fence transition requires projection
completion, marker close and readback; clearing the cell also requires fence
readback. Recovery from appending opens or confirms its own matching marker.
M4 must complete check-publication confirmation and route-unavailable repair
integration before production recovery can claim those states recoverable.

## 6. Exports and control workflow

Local export reads authenticated canonical history with operator repository
access and recovery material from a prompt or explicit local secret provider,
never a CLI key value. It streams JSON/CSV to an explicitly requested local
destination without requiring the hosted service. JSON preserves canonical
values; CSV neutralizes spreadsheet formula prefixes before output. Use one
export renderer for local and hosted output, with deterministic snapshot OID.

Repository/key access is not permission to release plaintext. Before creating
an export sink, authenticate the operator through GitHub `/user` and bind the
stable numeric ID, replay the latest canonical reader-source union, and require
a currently authorizing individual, snapshot or continuous source. Historical
export selection never selects historical authorization. A continuous source
also requires fresh membership in the exact stable organization/team before
output; absence or provider uncertainty denies output. Recheck the canonical
head after the authorization read and retry on change before opening any sink.
Every new export/retry repeats authorization, so withdrawing the last source or
leaving a delegated team denies the next read. The local operator credential
must itself support the necessary live membership read; do not add Members
permission to the transport App. Maintenance verify/reconcile returns only
non-private diagnostics. Recovery-key possession is a key-control capability,
not an implicit reader source or a new break-glass export operation.

The local interface requires an explicit destination per requested format:
`dracla export --json /private/export.json --csv /private/export.csv`. Validate
the complete replay and current authorization before creating any plaintext.
Use a private owner-controlled parent directory and descriptor-relative file
operations. Reject symlinks in the destination chain, non-regular files,
pre-existing destinations, unsafe hard links and identical/aliasing JSON/CSV
paths. Create staging files exclusively with mode `0600` independent of umask
inside that private directory; require equivalent verified owner-only ACLs on
other platforms or refuse before writing. The format renderer prefixes every
untrusted textual CSV cell with an apostrophe before CSV encoding; JSON keeps
the original value. Numeric schema fields remain numeric.

Stream to those files without retaining a whole plaintext export in memory.
After both requested formats finish, flush/fsync and publish without replacing
an existing destination. A renderer, disk or publication error is non-success
and removes every created staging/partial output by its held file identity.
A process killed before cleanup can leave a private staging file; it is never
a completed/reusable export. The operator may explicitly remove it after the
run stops; there is no automatic path-based cleanup of unrelated files.
File deletion is not a secure-erasure claim. Stdout, logs and workflow artifacts
are not local export destinations in M3. Hosted jobs accept no filesystem path.

Hosted export is an explicit validated workflow request, not a side effect of
ordinary mutations. Write only its encrypted JSON/CSV pair under the existing
`derived/exports/<request_id>` identity with source events OID. Reject path
injection, conflicting request reuse and blob/job-limit overflow; direct the
operator to streaming local export. No plaintext Actions artifact, log or
temporary retained file. M5 authenticates the request and rechecks reader
authority before every download; M3 does not expose a download endpoint.

### 6.1 M3/4.1 export payload and job contract

This section fills the export-schema responsibility explicitly left to M3 by
the M1 LLD's M1-11 non-goals. It defines generated export data, not another
canonical event or replay model. It does not change the encryption envelope,
reader-source union, source events, legal effect of a record, or M5's
request/download authorization. The existing six functional delivery boundaries
remain; exact current review and admission of these design bytes are separate
gates from the recorded owner acceptance.

#### Selection and source

The local command adds `--view current|history`, default `current`, and optional
`--at <full-events-commit-oid>` for `history` only. The existing explicit
`--json PATH` and/or `--csv PATH` remain mandatory. Unknown, repeated,
contradictory or incomplete options fail before recovery-key access or file
creation. A path is never read from repository content. `--at` accepts only
a full supported Git OID, never a ref, timestamp or event ID.

Authenticate and completely replay the latest canonical head C and perform
the current numeric reader-source check from §6. Resolve source S to C unless
an explicit history OID is supplied. S must be a connected, completely
authenticated canonical prefix of C, ending at an event commit. A foreign,
unreachable, bootstrap-only or corrupt prefix fails; no timestamp sorting,
omission of a bad event or partial output is allowed. Use the same central
reader and actual-data-key proofs for both C and S. Historical selection does
not restore a withdrawn reader source or a departed member's access.

`current` describes the current subject/agreement records at the selected
snapshot S. For a new snapshot, S is the latest authorized C. It does not
include the full event log. `history` contains every `CanonicalEventRecord`
in the authenticated prefix ending at S, in commit ancestry order, including
earlier acceptances, corrections, revocations, exemptions and their withdrawal
or materialization evidence. Its records are the existing public `to_dict()`
values, with exactly `event`, `commit_oid` and `parent_oid`. Administrative
events remain in this explicitly requested history so the evidence retains its
canonical context. Their existing closed schemas govern their contents.

Perform current reader authorization before rendering export output. At the
final gate immediately before opening any local sink or publishing/reusing a
hosted pair, repeat the current reader-source decision at C. For a continuous
source, repeat the exact live team-membership read even when C is unchanged;
absence or provider uncertainty cannot authorize that source. A separately
authorizing individual/snapshot source retains the existing union semantics.
Recheck C around that final authorization. For a new current snapshot, also
recheck the live O and V used for status. Reuse instead validates its original
immutable O and V as specified below; newer operation heads do not replace or
invalidate that observation. Drift restarts the whole attempt, including
authorization, within `max_mutation_retries`. No local sink opens until the
gate passes. Hosted rendering uses only bounded in-process plaintext after
initial authorization; discard it on a failed final gate and publish nothing.
This is a point-in-time authorization and snapshot observation, not a lock
preventing a later departure or mutation. Each invocation/retry repeats it.
An explicit S stays fixed across retries;
an implicit local S is reselected from the newly authorized C. Hosted S is
always explicit. An exhausted observation returns non-success.

#### JSON version 1

The complete UTF-8 file is the RFC 8785 encoding of one closed object with
exactly these members. No BOM, trailing newline or compression is added.
Emit it incrementally in RFC 8785 key order; do not build a second complete
plaintext byte string to canonicalize at the end.

| Member | Value |
|---|---|
| `export_version` | Integer `1` |
| `project_id` | Exact authenticated project ID |
| `request_id` | Null locally; the canonical hosted request ID for a hosted job |
| `source_events_oid` | Full immutable S; never the later authorization head substituted for a historical S |
| `view` | Exactly `current` or `history` |
| `context` | The closed context object below, derived by replay at S |
| `records` | Array in the view's specified order; empty is valid |

Context has exactly `project_state`, `successor_project_id`, `recipient`,
`active_agreement`, `enforcement_scope` and `operational_observation`.
The first five are the existing replay lifecycle, nullable successor, recipient,
nullable `ActiveAgreement.to_dict()` and effective scope selectors at S.
`operational_observation` is null for history. For current it is exactly
`{"coverage_oid": V, "operations_oid": O}`, identifying the authenticated
live marker/fence observation used for status. It is not a verification report
or a claim that stored projections are current. No keys, wrapped copies,
tokens or executable configuration enter an export.

Current records contain exactly the following members:

| Member | Value and source |
|---|---|
| `github_user_id` | Stable positive numeric subject ID |
| `login_snapshot`, `login_as_of` | Nullable canonical login observation and its timestamp, using the M1 reference status-detail observation rule; never a live login lookup |
| `agreement_id` | Selected project's agreement ID, or null before any agreement has been published |
| `recipient_id` | Immutable recipient ID from the connected project |
| `status`, `reason_code` | Existing M1 resolved status and reason, with the pre-agreement case below |
| `basis_event_id` | Existing resolved basis ID, or null for no basis/in-flight uncertainty |
| `acceptance` | Latest acceptance `CanonicalEventRecord.to_dict()` for this tuple, or null |
| `revocation` | Current cutoff revocation record for this tuple, or null after a later acceptance |
| `exemption_sources` | Active `ExemptionSource.to_dict()` values for this subject, ascending `sequence` |

The current subject set is the union of contributor-tuple subjects, subjects
with an active exemption source and subjects explicitly unresolved by replay.
Do not include cursor-only former members with no remaining record. Emit one
row per subject and selected agreement/recipient tuple, in increasing numeric
subject ID, then RFC 8785 string order for agreement/recipient IDs. A project
has one immutable agreement/recipient identity under the existing model; do
not synthesize other projects, agreements or Entity CLA support.

Use public replay decisions and sources; the new export module must not read
private kernel attributes. The latest acceptance includes its original fields,
confirmation labels/booleans, digest, version, recipient and correction link.
If the current decision is a revocation, retain the most recent preceding
acceptance as evidence and the revocation as its cutoff. Do not resurrect it as
a signature. History preserves all earlier acceptances and corrections;
current does not bundle those superseded private values.

Authenticate the actual operation cell, marker and fence at O and V, including
their existing cross-bindings. Derive reference status facts from replay at S,
and use the public M1 status resolution semantics with that real operation pair:
covering mutation or unresolved replay yields `indeterminate`; a currently
accepted signature yields `current`; otherwise an active exemption yields
`exempt`; otherwise the existing version-cutoff/revocation/no-acceptance rules
yield `superseded` or `revoked`. Retain the matching existing reason code.
`success_reserved` alone must not blank a signed row. Never infer an idle pair
from absence, invent historical operation state, or treat exemption as a
signature. A malformed or unprovable pair makes current output unavailable.
History remains available from authenticated canonical data without that pair.

Before an agreement exists, only active exemption subjects can appear: agreement
ID and acceptance/revocation are null; status/reason are
`exempt`/`exempt_source_active` unless covered by a mutation, which yields
`indeterminate`/`operation_in_flight`. These are recorded exemptions, not a
claim of agreement coverage. A succeeded project follows the existing M1
current-read rejection and directs the caller to an explicit history export;
its retained canonical evidence must remain exportable.

Rebuild the semantic rows directly from public replay facts, one at a time,
with the same results as the M1 reference row/status rules. Do not require all
private derived shards to be present or under their shard-size limits merely
to export canonical evidence. Canonical input authentication, ordinary reader
resource bounds and live status-pair validation still apply. This does not
remove any installed input limit or claim unlimited history capacity.

#### CSV version 1

CSV uses UTF-8 without BOM, comma separators, doubled double quotes inside
quoted cells, and CRLF record terminators, including the final record. Quote
a cell exactly when it contains comma, quote, CR or LF. Preserve embedded
Unicode, whitespace and line endings. Every row has the same fixed columns,
in this exact order:

```text
row_kind,export_version,project_id,request_id,source_events_oid,view,context_json,github_user_id,login_snapshot,login_as_of,agreement_id,recipient_id,status,reason_code,basis_event_id,acceptance_json,revocation_json,exemption_sources_json,canonical_event_json
```

The first data row is always `metadata`. It contains all seven root members
except `records`: context is in `context_json`; all subject/evidence columns
are empty. It exists even for zero records. Subsequent rows repeat the five
scalar export metadata values. In current view, `row_kind` is `current`, the
current-record columns correspond exactly to the JSON record, and
`context_json` and `canonical_event_json` are empty. In history view,
`row_kind` is `event`, only `canonical_event_json` is filled after the repeated
metadata, and subject/current-record columns are empty. Row order equals JSON
array order. An empty record set is metadata only, never an ambiguous empty file.

Integers are plain decimal. Nullable scalar values and inapplicable cells are
empty. Every non-null textual data cell, including a non-null empty string,
is prefixed with exactly one apostrophe before CSV quoting. Fixed header cells
are not prefixed. Consumers remove exactly that one prefix from schema-text
cells, never trim or interpret them as formulas. Thus null is empty, the empty
string is `'`, `=1+1` becomes `'=1+1`, and an original leading apostrophe is
preserved after removal of the added one. Numeric subject IDs stay numeric.

The five `*_json` evidence/context columns contain exact RFC 8785 text, with
the same apostrophe rule: objects and arrays are not Python reprs, pretty JSON
or a lossy delimiter-joined list. Applicable nullable acceptance/revocation
columns contain textual `null` when absent, not an empty cell. Complete
canonical event/field/confirmation values remain recoverable from these cells.
This fixed layout supports arbitrary adopter-configured signer field names and
ordered confirmation labels without a changing header or guessed universal
`name`/`email` fields. It trades spreadsheet convenience for exact evidence;
the stable subject/status columns remain directly usable in current view.
No canonical event schema is duplicated in CSV.

#### Explicit hosted job, idempotence and bounds

The M3 caller API takes one closed request with exactly `export_version: 1`,
`project_id`, `request_id`, `source_events_oid` and `view`. Request IDs retain
HLD §4's canonical unpadded base64url encoding of 16 random bytes. Project,
source and view obey the rules above; creating a new `current` pair requires
S=C for that attempt. Reuse retains the original snapshot, as specified below.
It accepts neither a filesystem destination nor an output/artifact selector.
The caller also supplies a protected-code authority adapter, separate from the
closed request data, with these two required operations:

- `authenticate_request(request) -> github_user_id` authenticates the human
  request and binds its exact project, request ID, S, view and version. Return
  the stable positive numeric human ID; invalid, unavailable or uncertain
  evidence raises a denial. A transport-App identity is not this principal.
- `is_team_member(organization_id, team_id, github_user_id) -> bool` makes the
  fresh exact membership decision using that human's authorized membership
  context. Only literal true authorizes this source; false, error or unknown
  does not. Do not broaden the transport App with Members permission.

M3 calls `authenticate_request` before data-key access, then repeats it at the
final output gate and requires the same numeric principal and exact request.
It evaluates the existing reader-source union from the latest canonical C,
using `is_team_member` for continuous sources, with the final timing above.
The actual adapter is an M5 implementation gate; M3 tests use explicit trusted
fixture adapters. Missing either operation yields `hosted-authorization-required`
with no output or repository write. A caller-supplied boolean, numeric ID or
business-data flag is never an authority adapter. Protected executable
configuration chooses it; request/repository content cannot choose a module,
callback, credential or membership result. Local mode instead authenticates
the operator through `/user` and performs live membership reads with that
operator's credential, without the hosted service. No download endpoint,
proof issuance or workflow dispatch is added
by this schema. M5 owns authenticating each request and reauthorizing every
download; M3/5 owns the protected executing workflow.

Produce both formats from the same request, replay and context. Encrypt only
the complete bounded bytes using the existing export identities under
`derived/exports/<request_id>.enc.json` and `.enc.csv`. JSON uses the existing
JSON-envelope API; CSV uses its exact-byte API after neutralization. JSON
payload and CSV metadata both bind request ID, project, view and S in addition
to the envelope's authenticated path/purpose. Use existing records-key selection
and fresh nonces; do not add a manifest file or write to events/coverage.

At the frozen derived head D, neither path present permits one branch-wide
conditional commit containing the pair and preserving all other tree entries.
Both present permits reuse only after authenticated decryption, closed-schema
validation and exact plaintext comparison with this same request's original
snapshot rendering. For current view, the pair's authenticated context retains
the original O and V: reread those immutable objects and verify their original
cell/marker/fence cross-bindings against replay at S before rendering. Do not
replace them with newer live operation heads or claim the result is current
at download time. Current reader authorization still uses the latest C, and
S must still be its authenticated prefix. This preserves an explicit snapshot
when later records or operations change. Return
the retained pair without re-encryption or a new commit. A lone path, malformed
envelope, wrong binding or different payload is a conflict; never overwrite it.
A lost write response is reconciled through the existing conditional writer's
exact transition evidence; uncertain results remain non-success. On a CAS
conflict, reread D and the pair, repeat authorization and source/status checks,
and retry within the existing `max_mutation_retries`. Never make a different
request or silently choose a newer S to turn a conflict into success. A request
for a new snapshot uses a fresh request ID; changing S or view under an existing
ID is a conflict. A newer authorization head alone does not invalidate an
otherwise valid retained snapshot or authorize an older reader.

The initial M3 hosted job uses the existing transport's 512,000-byte per-blob
ceiling: each complete serialized encrypted envelope must be at most 512,000
bytes, and the pair at most 1,024,000 bytes. Bound each plaintext renderer to
383,000 UTF-8 bytes before encryption, then independently check the actual
serialized envelope and pair. Equality passes; the next byte fails. Header,
metadata, CSV quoting, UTF-8 expansion, nonce/tag and base64/envelope overhead
count at their respective boundaries. Stop a bounded in-memory sink as soon
as its plaintext ceiling would be exceeded. A pair has at most 10,000 records
per view (excluding the CSV metadata/header); source replay retains the
transport's existing input bounds. Exceeding any bound creates no pair and
directs the caller to local streaming. These constants are M3 export-job
limits, not new fields in M1's closed release-profile schema. They must pass
boundary and concrete transport-mapping tests in M3/4.1; production job capacity
and workflow execution remain M3/5–6 evidence gates. This design is not a live
capacity measurement. Local rendering has no hosted-output byte/record ceiling
and retains existing input and disk-failure limits.

#### Examples, acceptance and delivery

An empty current export has `records: []` and still carries its exact project,
source and context; CSV contains its header and metadata row. A latest
acceptance with `fields={"legal_name":"=Ada","email":"a@example.test"}`
keeps those exact strings in JSON. Its `acceptance_json` CSV cell begins with
the added apostrophe, contains the complete canonical record, and uses doubled
quotes as required by CSV. A correction changes the current acceptance record;
history contains the original acceptance and correction, in ancestry order,
with the original `supersedes` ID intact. A subsequent cutoff keeps the latest
acceptance as evidence alongside the revocation and resolves status by the
rules above, including a distinct exemption if one still applies.

For example, a connected project with no agreement or subject records emits
the object below. This is readable example formatting; the actual JSON bytes
use RFC 8785. The repeated-letter OIDs are synthetic fixture identities, not
evidence of a real repository observation.

```json
{
  "export_version": 1,
  "project_id": "project-1",
  "request_id": null,
  "source_events_oid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "view": "current",
  "context": {
    "project_state": "active",
    "successor_project_id": null,
    "recipient": {"recipient_id": "acme", "legal_name": "Acme"},
    "active_agreement": null,
    "enforcement_scope": [],
    "operational_observation": {
      "coverage_oid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "operations_oid": "cccccccccccccccccccccccccccccccccccccccc"
    }
  },
  "records": []
}
```

CSV text-cell examples, before CSV quoting, are: null → empty cell;
empty string → `'`; `=1+1` → `'=1+1`; `'Ada` → `''Ada`;
`a,b` → `'a,b` (then quoted as `"'a,b"`). Schema integer `123` stays `123`.
Nested evidence `{"checked":true,"label":"=Agree"}` stays that exact JSON
value and becomes one apostrophe-prefixed, CSV-quoted text cell. Readers
recover its original boolean and string after CSV parsing, removing one added
prefix, then parsing RFC 8785 JSON.

Success is reported only after every requested local file is fully published
or a complete hosted pair is created/reused. The CLI returns 0 on success,
2 for invalid configuration, denied authorization, conflict or exhausted
resource/snapshot bounds, and 1 for renderer or filesystem failures. Handled
local failures perform §6's held-identity cleanup before returning. Diagnostics
contain only fixed categories and source OIDs, never private values, request
evidence, credentials or rendered output. No machine-readable success flag
can substitute for the actual publication result.

M3/4.1 owns deterministic schema/byte vectors in `core/tests/test_records_4.py`
and installed-command evidence, with the existing full package gate. Required
cases, in addition to §7's sink/authentication tests, are:

| Check | Required observation |
|---|---|
| Both views at C; history at a prior S | Exact source, canonical values/order and current authorization; no historical source restores authority |
| Team membership changes from true to false/error between first and final checks while C/S stay fixed | No local sink creation, hosted commit or snapshot reuse; a separate current individual/snapshot source still follows union semantics |
| Current acceptance, correction, activation retirement, cutoff, exemption union/withdrawal | Public M1 status/evidence agreement; current excludes old corrected private fields, history preserves them |
| Real covering/unrelated mutation, success reservation, malformed pair, unresolved replay | Matching status precedence or explicit current-output failure; never a fabricated idle pair |
| Pre-agreement and succeeded project | Explicit semantics above; retained history remains readable |
| Unicode, empty/null text, quotes, commas, CR/LF, apostrophe and `= + - @ TAB CR LF` prefixes | Exact JSON preservation, deterministic CSV bytes and removal of only the added text prefix |
| Empty arrays; nested event payloads; arbitrary signer fields and confirmation order | Reversible CSV JSON cells; metadata exists for an empty export |
| Same hosted request; concurrent identical/different request; CAS conflict and lost response | One immutable atomic pair or explicit conflict/indeterminate; no overwrite/duplicate side effect |
| All plaintext, envelope, pair and record bounds at limit−1/limit/limit+1 | Inclusive finite bounds, accounting for actual encoding expansion; zero writes on overflow |
| Derived private class exceeds its profile while canonical input remains valid | Local canonical export is not capped by that class; original authentication and live-state checks still apply |

The export contract and M3/4.1 ownership have owner acceptance. Before
implementation resumes, verify the current general and DBB design reviews and reconcile
the reviewed governing-plan bytes and any required documentation-path ownership
through the existing campaign admission/replan helpers. Preserve the issued
slice history, accepted prefix, reservation and consumed allowances. Do not
amend PR #58, relabel this draft as a previously approved plan, or bypass the
M3/4.1 pre-work assessment by treating design authoring as completed delivery.

### Control workflow

The private control repository has one pinned workflow with `workflow_dispatch`
and the daily scheduled backstop. HLD §9 pins its bootstrap, action commits,
release identity and dependency inputs. Default `GITHUB_TOKEN` permission is
read-only on control. App credentials cannot write control. Dispatch input
selects only a closed supported operation and validated opaque identities;
pass parsed data to Python without shell interpolation. Do not fetch source
or executable configuration from records/coverage or pull-request heads.

Transport challenges write fixed non-private data to generation-specific
temporary branches, validate exact readback and conditionally clean up. They
never add a non-event to events ancestry or mutate live coverage for a probe.
Challenge receipts bind the protected identities and actual release/workflow;
secret names and previous completion flags are not proof.

Upgrades are explicit adopter changes to the protected pins with verification
before keys are available. Retain the previously verified pins and artifacts
for rollback; rollback passes the same verification and never rewrites events.
Backup recovery verifies all saved ref/head identities before bootstrap/replay;
replacement repository IDs require administrator-authorized rebind, not an
automatic trust transfer.

App-key incident recovery follows HLD §8.1.2, including the all-token
containment barrier before final repair/restoration. A successful successor key
does not prove attacker tokens inactive. Shared-App incidents cover every
assignment; compromise of a key-bearing job also invokes the appropriate
data-key incident procedure. M3 provides transport/probe evidence; hosted route
shutdown and open-PR sweeps require M4/M5 integration, not more App permissions.

## 7. Delivery slices

Each slice includes its engine-to-command or caller integration and focused
tests. Boundaries are behaviors, not scaffolding. Titles use the full issued
ID, for example `[m3/1.1] ...`. Review and approve each slice before admitting the
next; no merges are part of this design task.

### m3/1.1 — Authenticated encrypted history and read-only verify

Deliver the scoped App transport, bootstrap/key selection and canonical reader
through a real `verify` command. Consume existing operator-provided keys and
approved control binding; do not provision resources. Dependencies: landed M2.
Acceptance: fixture GitHub reads plus installed-command read-only proof; full
replay; wrong IDs/scope/key/history rejection; no sensitive diagnostics;
deterministic expiry/renewal; stable local user identity and current reader-union
decision support for later plaintext export. Restricted live App REST/GraphQL capabilities and
control exclusion are acceptance evidence required before production use.

### m3/2 — Durable canonical mutation and conditional projection writes

Deliver the frozen-package append driver, operation-cell and coverage CAS
integration through the public engine API used by reconciliation. Dependency:
`m3/1.1`. Acceptance: exact package commit, conflict/no-op outcomes, competing
appenders, stale-head rejection, lost responses and same-head fence checks;
cross-runtime M1 vectors unchanged. No placeholder hosted endpoint.

### m3/3.1 — Reconcile and recover persisted operations

Deliver real `reconcile`, projection repair and every M3-owned crash transition
using `m3/2`. Acceptance: fault injection before/after each persisted write,
stale delayed writer, newer canonical source, terminal clearing, corrupt state,
all derived classes and overflow. Unconfirmed success reservations and missing
M4 route-unavailable proof stay blocked with an explicit integration result.
The owner-approved correction also binds actual records/coverage key bytes in
the central reader. Acceptance includes bootstrap and activation proofs,
records-only/coverage-only/combined same-ID substitution through recovery and
control providers with zero writes, same-key rewrap, successor-only wrapping
secrets, malformed/missing/cross-context proof rejection, exact known-answer
bytes and pending-activation crash recovery. The existing m3/3.1 title and
published PR are retained; this is the same vertical correction, not another
functional slice. Incremental estimate: 80–140 production lines and 200–350
fixture/test lines, plus the existing full conformance and package gate. These
are estimates for the inspected correction, not a universal line limit.

### m3/4 — Portable and explicit encrypted exports

Retain this unstarted ID and its original intent as replaced by `m3/4.1`.
The owner approved the successor on 31 October 2026 so the same export behavior
also owns its contract and three reviewed authority sidecars. The original
work-item reservation remains spent; it is not another export implementation.

### m3/4.1 — Portable and explicit encrypted exports

Deliver local streaming JSON/CSV and the request-scoped hosted job writer using
the authenticated reader from `m3/1.1`; stack delivery follows `m3/3.1`.
Acceptance: service-independent export, preserved JSON values, CSV injection
cases, source OID, idempotent request identity, bounded hosted pair, no hosted
plaintext or workflow artifacts. Deny an administrator/recovery custodian without a reader
source; test individual/snapshot authorization, continuous departure/uncertainty,
withdrawal between attempts and historical exports under current authority.
Test umask `022`, symlinks, hard links, non-regular/existing/aliased destinations,
render/disk failures, private cleanup and hosted path/stdout rejection.
M5 request/download authorization stays an explicit gate.

### m3/5 — Verified production workflow and transport lifecycle

Deliver the actual external artifact/dependency/provenance gate, pinned workflow
template and transport challenges invoking the real engines from `m3/3.1` and `m3/4.1`.
Acceptance: failed verification cannot access either App secret or data keys;
same verified artifact executes; no unconstrained resolution; malformed dispatch
and App-writable executable input rejected; scoped live write/CAS, expiry,
rotation and all-token containment probes. No installer secret provisioning.
The owned production-profile schema, lock files, reusable builder, bootstrap
image and external checker implement §3.1. Negative provenance and handoff
fixtures listed there are mandatory; an authentic publish-only result fails.

### m3/6 — Recovery integration and M3 evidence closure

Deliver backup/restore and upgrade/rollback exercises across the installed
package and workflow from `m3/5`, current App warning/planner integration, and
traceability for every M3-owned requirement. Acceptance: exact-head reviewed
implementation, full validation and packaged command seams; every required live
probe either passed or explicitly blocks the production claim. M4/M5/M6
integration gates remain visible and cannot be reported as completed M3 work.

## 8. Validation and approval

Each implementation slice updates `design/verification-matrix.md` with exact
automated tests, observed results and remaining live gates. Run the complete
existing Python and M1 cross-runtime/vector gate plus focused tests and an
isolated installed-wheel invocation appropriate to that behavior. HTTP fixtures
must exercise concrete request/response mapping, not merely mock domain methods.

Required live transport evidence uses separately authorized disposable private
repositories and the least-privilege App. It covers both dedicated/shared
assignments, denial on excluded control, complete installation inventory,
canonical non-force update, GraphQL CAS conflict, timeout reconciliation,
token renewal/revocation, old-key retirement and untracked-token containment.
The earlier rejected deploy-key probe proves none of this. No new resources or
credential installation are authorized by this LLD alone.

Release/provenance acceptance verifies the actual published artifact and its
declared source/build/dependency claims; fixtures alone cannot close it. M3
implementation completion and production readiness are recorded separately if
later hosted/installer integration or release evidence is unavailable.

The final reviewed design and this slice map require owner presentation and
approval before locking/checkpointing. Approval of the App direction does not
substitute for that gate. This task stops before implementation or merges.

## 9. Machine-readable delivery inventory

This inventory records the same six approved boundaries as §7.
On 26 October 2026, unaccepted `m3/1` was retained as replaced by
`m3/1.1` to include `core/tests/test_cli_integration.py`, whose existing
installed-command assertions must change when `verify` is registered. The
responsibility and acceptance remain unchanged; this adds no functional slice.
The original issued intent remains immutable in the inventory. It grants no
implementation or infrastructure authorization before owner approval.
On 27 October 2026, the owner approved replacing unaccepted `m3/3` with
`m3/3.1` to add `records/github.py` for the existing public derived-branch CAS.
The original intent remains unchanged in issued history. This changes file
ownership only; the same responsibility and acceptance still form one deliverable.
On 28 October 2026 the owner approved the actual-data-key binding correction.
The reviewed pre-approval published-slice admission retains `m3/3.1`, its title,
role, parent and external dependency, and adds the central reader/proof paths.
The exact original issued intent and plan preimage remain in the existing native
admission and preserved-stop history. Accepted slices and other issued intents
do not change. Admission remains required before production edits.
The same correction owns the reviewed HLD/LLD/index/roadmap and their exact
helper-generated sidecars so they land with PR #58; it does not rewrite an
accepted ancestor or introduce a separate functional slice.

```swe-slice-inventory
{
  "schema_version": 1,
  "slices": [
    {
      "id": "m3/1",
      "parent": null,
      "state": "replaced",
      "role": "implementation",
      "intent": {
        "title": "[m3/1] Authenticated encrypted history and read-only verify",
        "responsibility": "Read and authenticate complete encrypted history through a real no-write verify command.",
        "paths": [
          "core/dracla/records/credentials.py",
          "core/dracla/records/github.py",
          "core/dracla/records/history.py",
          "core/tests/test_records_1.py",
          "design/verification-matrix.md",
          "core/dracla/records/__init__.py",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md"
        ],
        "dependencies": [],
        "acceptance": [
          "Installed verify consumes real transport mapping and M1 replay without writes.",
          "Reject identity, scope, bootstrap, key, ancestry and snapshot mismatches; redact secrets.",
          "Exercise token expiry and renewal; retain required least-privilege live gates.",
          "Local operator identity and canonical reader-source decision support does not treat recovery material as reader authorization."
        ]
      }
    },
    {
      "id": "m3/1.1",
      "parent": "m3/1",
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/1.1] Authenticated encrypted history and read-only verify",
        "responsibility": "Read and authenticate complete encrypted history through a real no-write verify command.",
        "paths": [
          "core/dracla/records/credentials.py",
          "core/dracla/records/github.py",
          "core/dracla/records/history.py",
          "core/tests/test_records_1.py",
          "design/verification-matrix.md",
          "core/dracla/records/__init__.py",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md",
          "core/tests/test_cli_integration.py"
        ],
        "dependencies": [],
        "acceptance": [
          "Installed verify consumes real transport mapping and M1 replay without writes.",
          "Reject identity, scope, bootstrap, key, ancestry and snapshot mismatches; redact secrets.",
          "Exercise token expiry and renewal; retain required least-privilege live gates.",
          "Local operator identity and canonical reader-source decision support does not treat recovery material as reader authorization."
        ]
      }
    },
    {
      "id": "m3/2",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/2] Durable canonical mutation and conditional projection writes",
        "responsibility": "Execute validated frozen packages with non-forced canonical append and exact-head operation/coverage CAS.",
        "paths": [
          "core/dracla/records/append.py",
          "core/dracla/records/github.py",
          "core/tests/test_records_2.py",
          "design/verification-matrix.md"
        ],
        "dependencies": [
          "m3/1.1"
        ],
        "acceptance": [
          "One event and exact artifacts per canonical commit; deterministic no-op/conflict results.",
          "Racing appenders, stale expected heads and lost responses cannot duplicate or overwrite state.",
          "Existing M1 operation and cross-runtime contracts remain unchanged."
        ]
      }
    },
    {
      "id": "m3/3",
      "intent": {
        "acceptance": [
          "Recover every M3-owned persisted crash point with delayed-writer and newer-head races.",
          "Verify all shards/generations; derived overflow fails closed without capping canonical evidence.",
          "Missing M4 check or route-unavailable proof remains explicitly blocked."
        ],
        "dependencies": [
          "m3/2"
        ],
        "paths": [
          "core/dracla/records/reconcile.py",
          "core/dracla/records/append.py",
          "core/tests/test_records_3.py",
          "design/verification-matrix.md",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md"
        ],
        "responsibility": "Implement the reconcile command and authenticated conditional projection/crash repair.",
        "title": "[m3/3] Reconcile and recover persisted operations"
      },
      "parent": null,
      "role": "implementation",
      "state": "replaced"
    },
    {
      "id": "m3/3.1",
      "parent": "m3/3",
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/3.1] Reconcile and recover persisted operations",
        "responsibility": "Implement the reconcile command and authenticated conditional projection/crash repair.",
        "paths": [
          "core/dracla/records/reconcile.py",
          "core/dracla/records/append.py",
          "core/dracla/records/github.py",
          "core/tests/test_records_3.py",
          "design/verification-matrix.md",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md",
          "core/dracla/records/key_bindings.py",
          "core/dracla/records/history.py",
          "core/tests/test_records_1.py",
          "design/high-level-design.md",
          "design/.review/high-level-design.md",
          "design/lld/m3-control-reconciler.md",
          "design/lld/.review/m3-control-reconciler.md",
          "design/low-level-design.md",
          "design/.review/low-level-design.md",
          "docs/roadmap.md",
          "docs/.review/roadmap.md"
        ],
        "dependencies": [
          "m3/2"
        ],
        "acceptance": [
          "Recover every M3-owned persisted crash point with delayed-writer and newer-head races.",
          "Verify all shards/generations; derived overflow fails closed without capping canonical evidence.",
          "Missing M4 check or route-unavailable proof remains explicitly blocked.",
          "Bind actual bootstrap/activated data-key bytes to the pinned candidate; reject same-ID substitution with zero writes while preserving successor-only recovery and control wrapping secrets."
        ]
      }
    },
    {
      "id": "m3/4",
      "parent": null,
      "state": "replaced",
      "role": "implementation",
      "intent": {
        "title": "[m3/4] Portable and explicit encrypted exports",
        "responsibility": "Stream local canonical JSON/CSV and write only explicit encrypted hosted export snapshots.",
        "paths": [
          "core/dracla/records/exports.py",
          "core/tests/test_records_4.py",
          "design/verification-matrix.md",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md"
        ],
        "dependencies": [
          "m3/3.1"
        ],
        "acceptance": [
          "Service-independent installed export preserves JSON and neutralizes CSV formulas.",
          "Hosted pair binds request and source OID; conflicting reuse or resource overflow fails.",
          "No plaintext workflow artifact or logs; M5 download authorization remains its gate.",
          "Authenticate current numeric reader identity and continuous membership before any sink; historical exports use current authorization.",
          "Create owner-private exclusive files, reject unsafe/existing/aliased paths and remove handled-failure partial outputs; no stdout/hosted filesystem sink."
        ]
      }
    },
    {
      "id": "m3/4.1",
      "parent": "m3/4",
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/4.1] Portable and explicit encrypted exports",
        "responsibility": "Stream local canonical JSON/CSV and write only explicit encrypted hosted export snapshots.",
        "paths": [
          "core/dracla/records/exports.py",
          "core/tests/test_records_4.py",
          "design/verification-matrix.md",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md",
          "design/.review/high-level-design.md",
          "design/lld/.review/m1-conformance-kernel.md",
          "design/lld/.review/m3-control-reconciler.md",
          "design/lld/m3-control-reconciler.md"
        ],
        "dependencies": [
          "m3/3.1"
        ],
        "acceptance": [
          "Service-independent installed export preserves JSON and neutralizes CSV formulas.",
          "Hosted pair binds request and source OID; conflicting reuse or resource overflow fails.",
          "No plaintext workflow artifact or logs; M5 download authorization remains its gate.",
          "Authenticate current numeric reader identity and continuous membership before any sink; historical exports use current authorization.",
          "Create owner-private exclusive files, reject unsafe/existing/aliased paths and remove handled-failure partial outputs; no stdout/hosted filesystem sink."
        ]
      }
    },
    {
      "id": "m3/5",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/5] Verified production workflow and transport lifecycle",
        "responsibility": "Verify exact release inputs before credentials and execute real engines in a pinned control workflow.",
        "paths": [
          "core/dracla/records/credentials.py",
          "core/dracla/records/github.py",
          "core/tests/test_records_5.py",
          "design/verification-matrix.md",
          "control/reconcile.yml",
          "control/verify-release.sh",
          "docs/github-apps.md",
          "pyproject.toml",
          ".github/workflows/release.yml",
          ".github/workflows/build-release.yml",
          ".github/workflows/bootstrap-image.yml",
          "control/bootstrap.Dockerfile",
          "control/verify_release.py",
          "control/production-profile.schema.json",
          "release/runtime-wheels.lock",
          "release/build-inputs.lock.json"
        ],
        "dependencies": [
          "m3/3.1",
          "m3/4.1"
        ],
        "acceptance": [
          "Bad or missing artifact, dependency, publisher, source or build evidence prevents secret access.",
          "Only verified bytes execute; pinned workflow rejects executable business data and dispatch injection.",
          "Live scoped writes, CAS conflicts, token lifecycle, rotation and untracked-token containment gate production use.",
          "Standard publish plus SLSA build evidence binds source, immutable builder and complete declared input locks; publish-only fails.",
          "Pinned external verifier and launcher reject wrong identities, missing inputs, extra/changed wheels, sdists, resolver use and an environment swap before import/key access."
        ]
      }
    },
    {
      "id": "m3/6",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/6] Recovery integration and M3 evidence closure",
        "responsibility": "Verify backup recovery and upgrade/rollback across installed engines, pins and evidence.",
        "paths": [
          "core/dracla/records/history.py",
          "core/dracla/records/reconcile.py",
          "core/tests/test_records_6.py",
          "design/verification-matrix.md",
          "core/dracla/provisioning.py",
          "docs/cli.md",
          "docs/github-apps.md",
          "control/README.md"
        ],
        "dependencies": [
          "m3/5"
        ],
        "acceptance": [
          "Restore exact backup refs and authenticated history; unauthorized replacement identities fail.",
          "Upgrade and rollback repeat verification and preserve canonical evidence.",
          "Full Python, M1 cross-runtime and installed-command gates pass; pending live/hosted integration remains explicit."
        ]
      }
    }
  ]
}
```
