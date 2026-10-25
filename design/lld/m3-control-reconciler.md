---
plan_key: m3
slice_convention: hierarchical-v1
---
# M3 low-level design — control reconciler

Status: Locked
Owner approval: 25 October 2026 — design and six delivery slices
Date: 25 October 2026
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
| `records/history.py` | `open_history(binding, key_provider, transport)` validates bootstrap and yields authenticated `CanonicalEventRecord` values; `replay_history` returns the existing M1 `ReplayResult` |
| `records/append.py` | Execute the validated frozen package with existing M1 operation-state transitions; distinguish landed, semantic no-op, conflict and indeterminate results |
| `records/reconcile.py` | `verify_project` reports divergence without writes; `reconcile_project` repairs only authenticated, conditional transitions |
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
and wrapped-key candidate. Use the candidate only to decrypt the first event;
accept its key authority only when `project_connected` authenticates the exact
manifest digest, `K`, `B`, generation, IDs and current kids. Replay later key
activations for current selection and retain predecessors for old history.
Missing, duplicate, mismatched or undecryptable candidates fail closed.

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

### m3/3 — Reconcile and recover persisted operations

Deliver real `reconcile`, projection repair and every M3-owned crash transition
using `m3/2`. Acceptance: fault injection before/after each persisted write,
stale delayed writer, newer canonical source, terminal clearing, corrupt state,
all derived classes and overflow. Unconfirmed success reservations and missing
M4 route-unavailable proof stay blocked with an explicit integration result.

### m3/4 — Portable and explicit encrypted exports

Deliver local streaming JSON/CSV and the request-scoped hosted job writer using
the authenticated reader from `m3/1.1`; stack delivery follows `m3/3`.
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
template and transport challenges invoking the real engines from `m3/3–4`.
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
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m3/3] Reconcile and recover persisted operations",
        "responsibility": "Implement the reconcile command and authenticated conditional projection/crash repair.",
        "paths": [
          "core/dracla/records/reconcile.py",
          "core/dracla/records/append.py",
          "core/tests/test_records_3.py",
          "design/verification-matrix.md",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "docs/cli.md"
        ],
        "dependencies": [
          "m3/2"
        ],
        "acceptance": [
          "Recover every M3-owned persisted crash point with delayed-writer and newer-head races.",
          "Verify all shards/generations; derived overflow fails closed without capping canonical evidence.",
          "Missing M4 check or route-unavailable proof remains explicitly blocked."
        ]
      }
    },
    {
      "id": "m3/4",
      "parent": null,
      "state": "planned",
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
          "m3/3"
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
          "m3/3",
          "m3/4"
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
