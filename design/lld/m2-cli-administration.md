---
plan_key: m2
slice_convention: hierarchical-v1
---
# M2 low-level design — CLI and administration seams

Status: Locked
Date: 23 October 2026
Requirements: `design/requirements.md`, locked revision 14
Architecture: `design/high-level-design.md`, locked 31 August 2026,
release-manifest amendment reviewed 23 October 2026
Prerequisite: M1 landed through `41baf0cc796213947ab6a5ae3ee9544b15564c55`
Roadmap: `docs/roadmap.md`, M2

## 1. Outcome and authority

M2 supplies a packaged CLI, an executable read-only provisioning planner, and
an independently testable GitHub administration adapter. It does not install a
working project. The actual reconciler is M3; hosted challenges are M5; the
complete installer is M6. An unavailable prerequisite is a reported blocker,
never a successful placeholder command.

Requirements and HLD govern behavior. This LLD chooses interfaces and delivery
boundaries under HLD §6.9, §6.10.3, §6.10.5 and §6.10.6, and realizes the M2
parts of `REQ-OPS-4`, `REQ-SEC-9`, `REQ-SEC-10` and `REQ-VERIFY-1..2`.
The M1 LLD and landed modules supply interface context; the HLD remains the
authority for unchanged shared artifact contracts. Existing legacy
`githost.py`, `github.py`, `append.py`, `events.py` and `projection.py` are
experiments, not revision-14 defaults. No administration method reaches into
their private attributes. No canonical event, projection or keyring is changed.

### B1 — approved release-manifest correction

On 23 October 2026 the baseline owner approved correcting HLD §6.9's circular
requirement to embed the final distribution-digest manifest inside those same
distributions. The package now bundles release policy and an exact-version
canonical manifest locator. Publication finalizes distributions first, then
publishes their digest manifest externally. Before authorization, the installer
validates that manifest's bindings and displays its computed digest. M6 records
that digest in bootstrap manifests. This remains release-declared metadata,
not a receipt for the artifact selected by the parent `uvx` process.
The HLD amendment has passed its current design review. Implementation requires
this LLD's current clean design attestation. The owner decision is retained in AWD run
`run_3p0gzah8632hxdt9q4aqmv9rqh`.

## 2. Boundaries and existing interfaces

Python owns this milestone. Hydra composes only client configuration. Resolved
plain values cross into the core; OmegaConf, Hydra objects, callbacks and
interpolation expressions do not cross that boundary. The existing
`dracla.conformance` public surface remains unchanged.

| Surface | Owner and responsibility |
|---|---|
| `core/dracla/cli/` | Command parsing, client composition, credential acquisition, release preflight, rendering and exit codes |
| `core/dracla/provisioning.py` | Plain immutable inputs, exact naming, deterministic plan and resume classification; no I/O |
| `core/dracla/administration.py` | Typed account/repository observations and a small administration protocol; no records transport |
| `core/dracla/github_admin.py` | Concrete GitHub adapter, bounded HTTP, response validation and mutation-specific reconciliation |
| `core/dracla/conformance/` | Existing M1 artifact and semantic authority; consumed without changes |

One adapter owns HTTP for administration; do not add a transport framework or
subclass the legacy GitHub records host. Inject the HTTP sender, credential
provider, clock and sleep where tests need them. Domain functions depend on
the protocol, never on raw HTTP JSON. No new database, local progress journal,
plugin loader, daemon, command bus or generic migration framework is required.

## 3. CLI and configuration

M2 registers `dracla install` and `python -m dracla.cli install` through the same
`main(argv)` dispatcher. `pyproject.toml` declares `dracla = dracla.cli:main`.
Only implemented handlers enter the registry. Operational `verify`, `reconcile`,
`export`, signing, agreement administration and rotation commands wait for
their owning engines; M2 generates no workflow that invokes them.

The resolved install input contains exactly:

| Field | Rule |
|---|---|
| `github.owner` | Required nonempty ASCII GitHub account login; reject whitespace, URL/path syntax and control characters; resolve its actual account type and numeric ID before an actionable remote plan |
| `project.slug` | Defaults to the case-folded owner login; explicit input is only ASCII-case-folded, never trimmed or stripped of `-cla` |
| `dry_run` | Boolean, default `false`; `true` enables planning without writes |
| `force` | Boolean, default `false`; suppresses only an execution confirmation, never a warning or prerequisite check |

Use the exact revision-14 project-slug grammar from HLD §5.1 and M1:
`[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`. Reject Unicode before folding.
An owner whose normalized login does not satisfy that slug grammar needs an
explicit valid slug; do not invent a different default. Names are exactly
`<slug>-cla-records`, `<slug>-cla-coverage`, `<slug>-cla-control` under the
resolved owner. `acme-cla` therefore gives `acme-cla-cla-records`.
Repository IDs remain distinct from names, the later stable project ID, and
the first keyring candidate commit `K`.

Use Hydra's Compose API in a scoped initialization context with packaged
configuration. It accepts the documented `key=value` overrides without the
`@hydra.main` run-directory and logging side effects. The only packaged interpolation is `project.slug: ${github.owner}`. Reject
interpolation/resolver syntax in user override values before composition,
including `${oc.env:...}`; do not register custom resolvers or load external
config paths. This prevents a secret from being expanded into an apparently
non-secret owner or slug. Resolve the supported configuration completely, reject unknown business
keys, missing values, non-boolean switches and unresolved interpolations, and
convert to plain values before core entry. No object instantiation from config,
multirun, dynamic Python targets, working-directory changes or `sys.path` edits.
The declared Hydra dependency follows the HLD's 1.4 line and is pinned to the
exact release-tested distribution during implementation; its Python support
must match the declared package range, or the discrepancy returns to review.

Credentials come from an injected provider; the default reads `GH_TOKEN` then
`GITHUB_TOKEN`. Values never enter Hydra configuration, plan objects, argv,
exceptions, reprs, logs or resume output. No permission-expanding GitHub App or
provisioning App is introduced. A token's actual GitHub permissions decide
whether an operation is possible; an adapter result does not grant authority.

### Execution order and observable behavior

1. Parse/compose and validate local configuration.
2. Validate release policy and resolved dependencies before requesting GitHub
   credentials or authorization. Retrieve the external manifest by the bundled
   exact-version locator, never by an arbitrary user-supplied URL.
3. Resolve account identity, read the three exact repository locations and
   produce the current plan. Permission or transport uncertainty stays unknown.
4. Display release identities, exact owner/slug/repository plan, blockers and
   applicable HLD trust/integrity warnings without secrets.
5. For `dry_run=true`, return the report without confirmation or any writes.
   This includes local files, Hydra logs, caches, secret stores and GitHub.
6. For `dry_run=false`, M2 reports that full installation requires the M3/M5/M6
   engines and exits before a mutation. `force=true` cannot enable a missing
   engine. M6 later adds the actual confirmation and execution path here.

Success exit `0` means a complete read-only plan with no observed collision;
it never means installed, connected, signable or routable. Exit `2` reports
invalid input, invalid release evidence, unavailable permissions, collisions
or missing prerequisites. Exit `1` reports an unexpected internal failure with
a redacted diagnostic. Non-dry execution in M2 always fails closed with exit 2.
A blocked plan may still be printed, clearly marked blocked; it cannot yield
exit 0. No local writes occur on these failure paths either.

## 4. Release preflight and packaging

`load_release_policy()` obtains package resources from the installed
`dracla` distribution, never the working directory. It validates a versioned,
closed policy containing exact package version, source commit, release workflow
identity, dependency constraints and their digest, and the exact-version
external manifest locator. Development or incomplete metadata is not production release evidence.
No successful test fixture is checked in as a released DraCLA provenance claim.

The bundled `release-policy.json` is RFC 8785 canonical UTF-8 JSON with exactly
`release_policy_version` (integer `1`), `package_version`, `source_commit_oid`,
`provenance_identity`, `dependency_constraints_sha256`, and
`allowed_artifacts_url`. These five string fields are nonempty;
`package_version` is the normalized exact installed distribution version,
`source_commit_oid` is the full release Git object ID, and
`provenance_identity` is the release workflow/subject identity. The URL is an
absolute public HTTPS locator for that exact version, with no user info,
query or fragment. It comes only from packaged policy, never config overrides.
All release identity digests use `sha256:` followed by 64 lowercase hex digits.
The policy identity hashes its exact canonical bytes. It has no final-manifest
digest, so its bytes can be fixed before distribution assembly.

Bundled `dependency-constraints.txt` uses UTF-8 LF lines, each
`<normalized-distribution-name>==<normalized-exact-version>`, sorted by name,
with a final LF, no duplicate names, markers, ranges, comments or URLs. It
contains the release-tested runtime dependency closure, including transitives;
its exact bytes must match the policy's dependency-constraint digest. This
resource describes dependencies, not the DraCLA distribution itself.

The external manifest is RFC 8785 canonical UTF-8 JSON with exactly
`allowed_artifacts_version` (integer `1`), `package_version`,
`release_policy_sha256`, `source_commit_oid`, `provenance_identity`,
`dependency_constraints_sha256`, and `artifacts`. Identity fields must equal
the bundled policy and its computed digest. `artifacts` is a nonempty list,
sorted by filename, of closed objects with nonempty ASCII basename `filename`
and `sha256`; reject duplicate names, path separators, invalid digest strings
and filenames whose parsed distribution name/version are not DraCLA and the
exact policy version. No self-digest field is embedded in the manifest.
Every distribution for that release contains the same policy and constraints.
M3's publisher generates the final list only after all distribution bytes are
fixed. The manifest's identity hashes its actual canonical bytes.

Fetch this public resource without credentials, cookies, disk cache or local
output. Require HTTPS, reject redirects away from the packaged origin, bound
response bytes and request time, and use at most the same four read attempts
as the administration adapter. Reject noncanonical JSON, extra/missing fields,
wrong types (including booleans where an integer is required), unsupported
versions, duplicate keys, unavailable resources and every binding mismatch
before credential acquisition. Do not infer which artifact the parent `uvx`
selected, or treat this self-reported policy as independent proof against a
compromised executing package. HLD §6.9's optional external provenance check
and mandatory recurring control-workflow pins retain their existing scope.

Use `importlib.metadata` and distribution-name normalization to check every
resolved runtime dependency, including transitives, against the release-tested
constraint set. Missing, extra unconstrained runtime dependencies and mismatched
versions reject before credential acquisition. Build tools are not runtime
requirements. Keep M1's existing exact cryptography and JCS constraints unless
separately authorized. Hydra belongs to the client import path; importing core
conformance or administration must not import or initialize Hydra.

The policy is not a secret. Plans can display its package/source/workflow,
constraint and final allowed-artifact-manifest identities. Do not claim to
identify a selected wheel, an sdist build or a cached parent `uvx` environment.
The full production publication pipeline and pinned reconciler provenance are
M3; M2 implements and negatively tests this consumer and its package boundary.
An ordinary current development build without valid release inputs must show
the honest unavailable-release result, not silently synthesize provenance.

## 5. Administration protocol and adapter

The protocol exposes named operations, not a caller-controlled REST escape
hatch. One `AdminScope` binds the intended owner and the three exact role/name
pairs from the plan; it is a local scope restriction, not GitHub authority.
All repository operations take a validated `RepositoryRef(role, owner, name,
id)` after discovery; reads before ID discovery use the exact validated
owner/name pair. Responses bind observed owner, name and numeric ID. A moved,
renamed, wrong-owner or wrong-ID repository stops the operation. Secret writes
and workflow dispatch target only the control role; deploy keys target only
records or coverage. The adapter rejects another role or a repository outside
the frozen scope before HTTP. Creation binds an initially unknown ID only from
the exact successful create response and subsequent readback.

| Operation | Exact responsibility and postcondition |
|---|---|
| `resolve_account(login)` | Read a User or Organization, preserve stable numeric ID and normalized login, reject unsupported account types |
| `get_repository(owner, name)` | Return metadata and permissions, explicit missing or explicit inaccessible/unknown; never treat an arbitrary 404 as proof of authenticated absence |
| `list_repositories(account, cursor)` | Read discovery with bounded pagination, repeated-page protection and no silent truncation |
| `create_private_repository(account, name)` | Correct personal/org create endpoint, `private=true`, `auto_init=false`; verify exact name, owner, ID, privacy and empty state; no name takeover |
| `read_visibility` / `set_private` | Read privacy; permitted change is only toward private, never public; verify exact ID and resulting privacy |
| `read_branch` / `rename_branch` | Observe exact branch/default head; rename the observed initial default branch to the HLD-required name and verify same head and new default; no force ref update |
| `list_deploy_keys` / `add_deploy_key` | Read key metadata; add only an explicit public key with explicit `read_only`; compare normalized key bytes and returned ID; never generate private keys here |
| `get_actions_public_key` / `put_actions_secret` | Bind key ID to exact repository; use libsodium sealed-box encryption with PyNaCl, never a handwritten crypto substitute; PUT only encrypted bytes and key ID |
| `dispatch_workflow` | Exact validated workflow identity and explicit ref/inputs; return accepted-but-unobserved rather than claim a particular run completed |

For newly absent private names, a successful creation response establishes
identity; it does not authorize adopting a subsequently discovered existing
repository. When GitHub hides a private repository behind 404, a later 422
name conflict remains a collision. Never compensate by making a repository
public, taking another name, or requesting broader permissions automatically.

The initial adapter uses the fixed GitHub HTTPS API origin and an explicit API
version supported by its tested fixtures. It validates every path component,
never forwards credentials across an origin-changing redirect, and does not
include raw response bodies, request objects or secret values in exceptions.
The exact supported version and dependency pins are recorded in validation and
release policy; an API upgrade is a reviewed implementation change.
HTTP requests have a finite timeout; reads may make at most four attempts with
bounded backoff. A paginated operation has an explicit caller budget and
returns incomplete, not a fabricated complete inventory, when it is exceeded.
Rate-limit metadata is typed and redacted; callers can resume after a named
retry time without an unbounded loop inside the adapter.

### Uncertain writes and repeatability

No generic automatic retry applies to all writes. Reconcile each attempted
write from the exact intended identity before deciding another request is safe:

- Repository creation: inspect the exact name and provenance; uncertainty or a
  name-only match stops. Never repeat POST and adopt a conflict as success.
- Visibility and branch rename: reread exact repository ID, name/default/head
  and target. Accept only the exact expected postcondition; unrelated state is
  conflict. A rename cannot overwrite another existing target branch.
- Deploy key creation: exact key/permission readback can prove success; a
  title-only match cannot. Conflicting permission or another key is conflict.
- Secret PUT: GitHub cannot return the stored plaintext. Existence and updated
  time do not prove the intended value. Report uncertain on lost acknowledgement;
  a caller-authorized repeat must obtain a current public key and replace the
  same named secret with the same intended value. Never report value verification.
- Workflow dispatch: a lost acknowledgement stays uncertain; do not repeat POST
  on a timeout or infer run attribution from a nearby timestamp.

Results distinguish observed, applied-and-readback-verified, accepted,
uncertain, conflict, missing and denied. A successful secret acknowledgement is
accepted, not readback-verified. Mutation methods are library capabilities for
M6 and its tested drivers, not install commands exposed to M2 users. Tests call
those methods through the public protocol with an explicit fake sender and
operation intent; no live infrastructure is provisioned by this milestone's
normal validation.

## 6. Planning, collisions and resume

`plan_install(config, release, account, observations)` is pure and produces a
stable ordered `InstallPlan`: exact owner ID/login, normalized slug, three
role/name pairs, release identities, ordered HLD install steps and blockers.
Plans contain only public/non-secret installation metadata. They contain no
credential, private key, recovery material, acceptance data or alternate CLA
truth. Their in-process dataclasses are not a new persisted wire schema.
Render plain text by default; no second JSON command surface is required.

The step order is HLD §6.10.3.1's ten-step sequence. Planner items carry their
owning engine and state `needed`, `satisfied`, `blocked` or `unknown` plus
redacted reason/evidence references. These are planning observations, not
permissions to mutate. Unknowns block execution and never become absence,
completion or success by inference. M2 can validate release/naming and inspect
administration metadata; it cannot mark M3/M5/M6 control, key, wrapping or
bootstrap steps satisfied without their actual verifier evidence.

An existing repository name alone never authorizes reuse. Reuse requires the
HLD's per-repository provenance, root ancestry, numeric IDs, common stable
project ID, first keyring candidate commit `K`, install generation, canonical
manifests and initial `keys` head `B` recorded by control provenance.
M6 owns those exact bootstrap serializers and real provenance verifier.
Until that verifier is implemented, the live M2 path marks an existing
repository `blocked: provenance verifier unavailable`, not reusable or safe.
Permission failures and incomplete reads remain unknown and blocked.

M2 defines `plan_resume(previous_plan, fresh_observations)` by recomputing the
plan from the same immutable owner/slug/release intent. Previous step flags
have no authority. Drift in owner ID, repository IDs, policy or release is a
conflict that requires an explicit new plan; it is not silently adopted.
A pure verified-evidence input is produced only by the owning verifier port;
production M2 supplies no fabricated verifier. Tests use that port with exact
fixture identities, including mismatched and incomplete provenance.
No on-disk resume journal is added. Re-running the CLI obtains fresh remote
observations and gives the same plan for unchanged evidence. M6 later uses
this contract for real installer recovery; M2 does not claim installation
resume, key recovery or execution of the remaining installer steps.

`force` cannot clear uncertainty, change owner or slug, repair unrelated state,
ignore collisions or satisfy missing provenance. Actual confirmation is over
exact release and repository identities and is invalidated by drift; M6 owns
the interaction when it adds execution. HLD trust and deploy-key integrity
warnings always remain visible, including with `force` and during dry runs.

## 7. Delivery slices

The IDs below use the current delivery convention. Commit and PR titles begin
with the complete token, for example `[m2/1] Add validated no-write install planning`.
This changes no M1 IDs or historical commits. Four coherent slices are planned;
remapping requires a reviewed design change, not automatic size-driven splitting.
Each slice integrates its behavior through the public boundary and tests that
integration before review. There is no separate scaffolding or tests-only slice.

### m2/1 — Packaged no-write CLI and validated install plans

Own the package entry point, scoped Hydra composition, plain config validation,
release/dependency preflight consumer and deterministic naming/initial plan.
Installed-package invocation is the vertical acceptance boundary. It must
produce a plan or a truthful prerequisite failure without importing the legacy
spike or writing files. Include package config/resources and docs in this slice.

Acceptance: valid normalized/default/explicit slugs, suffix preservation and
M1 slug-grammar agreement; malformed input and release/dependency rejection
before credential acquisition; installed entry point and core imports; no
Hydra directories/logs/chdir; both module and console command dispatch; non-dry
and force fail closed while execution is unavailable. The reviewed B1 HLD
amendment is a prerequisite.

### m2/2 — Live administration discovery and collision-aware planning

Add the typed administration protocol, concrete read adapter and planner
integration for personal/org identity, exact repository discovery, privacy,
permissions and bounded pagination. A recorded-response/fake sender exercises
actual HTTP request and response mapping; an optional maintainer-owned read-only
integration target can validate real GitHub reads without changing resources.

Acceptance: full dry-run CLI against the read adapter, both account types,
missing versus concealed/inaccessible names, wrong numeric IDs, renames,
non-private repositories, incomplete pagination, limits/timeouts and redaction.
An existing name with no real provenance verifier is blocked. No writes.

### m2/3 — Guarded GitHub administration mutations

Add the concrete named mutation methods and their exact readback/uncertainty
behavior to the existing adapter. Exercise creation, private visibility,
initial-branch rename, deploy keys, sealed-box Actions secret PUT and dispatch
through the same public protocol and request sender. Do not add a CLI execute
handler or an installer engine.

Acceptance: exact account-specific endpoint/payload and numeric ID binding;
empty private creation; matching readbacks and conflicting existing state;
no blind retry after each injected response loss; secret redaction and genuine
sealed-box decryption with fixture keys; inability to claim secret plaintext
readback or dispatch completion. All tests use isolated fixture resources.

### m2/4 — Fresh-evidence resume planning and complete CLI seam gate

Integrate fresh observation and owning-verifier evidence into deterministic
resume classification. Complete installed-wheel cross-module checks over the
same dispatcher, release consumer, read adapter, planner and mutation protocol.
All earlier slices already test their seams; this slice adds the distinct
partial-run, stale-evidence and rerun behavior rather than deferring integration.

Acceptance: unchanged observations reproduce the same plan; changed IDs,
release or intent fail; arbitrary previous completion flags cannot grant reuse;
partial/missing/wrong provenance blocks; force cannot bypass a blocker; every
registered command has a real handler and every generated invocation resolves;
no placeholder workflow or unavailable engine is advertised as working;
complete zero-write dry-run proof, including the installed package, rejected
environment-resolver injection and all failure paths. M1 conformance and packaging gates remain unchanged and pass.

## 8. Required evidence and milestone closure

Every slice adds `core/tests/test_*.py` evidence and updates
`design/verification-matrix.md` with exact automated references. Required gates:

- existing complete Python suite and M1 cross-runtime conformance gate;
- focused CLI, release policy, discovery, mutation or resume tests for that slice;
- a built wheel installed into a temporary isolated environment, console and
  module invocation from outside the checkout, core imports without Hydra
  initialization, and declared resource/dependency constraints checked;
- dry-run seam fixtures that record every HTTP method and fail on any write;
  an isolated working directory checked before/after, with file and process
  spies covering Hydra logs/caches, local state and credential persistence;
- concrete positive/negative HTTP fixtures for each owned endpoint; no
  credential-dependent skip substitutes for these deterministic adapter tests;
- a real registered-command check on every invocation emitted by any artifact,
  plus a deliberate unknown-command negative case;
- current local design/code review and exact-head PR approval before landing.

Mutations against real repositories require a separately authorized disposable
integration environment; ordinary validation never treats this LLD as permission
to provision or change user repositories. This does not block deterministic
protocol, encryption, installed-package and error-path acceptance.

M2 is complete when all four slices are landed and the gates pass. It does
not close hosted setup, end-to-end installation, live recovery, or release
measurements A2/A3/A6. M3 consumes the administration seam for real reconciler
integration; M6 consumes it for actual provisioning and provenance-aware resume.

## 9. Platform evidence used during review

These are API/library feasibility references, not independent product authority:

- [Hydra Compose API](https://hydra.cc/docs/advanced/compose_api/): scoped
  programmatic composition avoids the decorator's run/log-directory lifecycle.
- [GitHub repository endpoints](https://docs.github.com/en/rest/repos/repos):
  personal/org creation and explicit empty/private request fields.
- [GitHub Actions secrets](https://docs.github.com/en/rest/actions/secrets) and
  [secret encryption](https://docs.github.com/en/rest/guides/encrypting-secrets-for-the-rest-api):
  public key IDs, libsodium sealed boxes and absence of secret plaintext reads.

The API/library versions actually adopted must be pinned and exercised by the
implementation fixtures; fetching current documentation does not prove that a
future release dependency combination works.

## 10. Machine-readable delivery inventory

This inventory and the headings above describe the same four boundaries.
Only future implementation slices are issued here; this design task is not an
implementation reservation or approval to run `deliver-design-stack`.

```swe-slice-inventory
{
  "schema_version": 1,
  "slices": [
    {
      "id": "m2/1",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m2/1] Packaged no-write CLI and validated install plans",
        "responsibility": "Validate installed CLI configuration, release/dependency preflight and deterministic repository planning without writes.",
        "paths": [
          "pyproject.toml",
          "core/dracla/cli/__init__.py",
          "core/dracla/cli/__main__.py",
          "core/dracla/cli/app.py",
          "core/dracla/cli/config.py",
          "core/dracla/cli/release.py",
          "core/dracla/cli/conf/__init__.py",
          "core/dracla/cli/conf/install.yaml",
          "core/dracla/provisioning.py",
          "core/tests/test_cli_planning.py",
          "docs/cli.md",
          "design/verification-matrix.md"
        ],
        "dependencies": [],
        "acceptance": [
          "Installed console/module commands produce a truthful plan or prerequisite failure.",
          "Release/dependency/config checks precede credentials; dry-run has zero local or remote writes.",
          "Normalized names match revision-14 M1 slug semantics."
        ]
      }
    },
    {
      "id": "m2/2",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m2/2] Live administration discovery and collision-aware planning",
        "responsibility": "Resolve GitHub account/repository identity and integrate bounded read observations into actual CLI planning.",
        "paths": [
          "core/dracla/administration.py",
          "core/dracla/github_admin.py",
          "core/dracla/provisioning.py",
          "core/dracla/cli/app.py",
          "core/tests/test_admin_discovery.py",
          "core/tests/test_cli_planning.py",
          "docs/cli.md",
          "design/verification-matrix.md"
        ],
        "dependencies": [
          "m2/1"
        ],
        "acceptance": [
          "Actual read adapter mapping is exercised through dry-run CLI.",
          "Personal/org identities, pagination, hidden names, permissions, privacy and numeric-ID drift fail safely.",
          "Missing real provenance never grants reuse."
        ]
      }
    },
    {
      "id": "m2/3",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m2/3] Guarded GitHub administration mutations",
        "responsibility": "Provide exact named administration writes with per-operation reconciliation and redaction, independently from installer execution.",
        "paths": [
          "pyproject.toml",
          "core/dracla/administration.py",
          "core/dracla/github_admin.py",
          "core/tests/test_admin_mutations.py",
          "docs/cli.md",
          "design/verification-matrix.md"
        ],
        "dependencies": [
          "m2/2"
        ],
        "acceptance": [
          "Create/private/rename/deploy-key/secret/dispatch protocol paths have deterministic positive and rejection fixtures.",
          "Response-loss tests prevent blind write retries and false success.",
          "Sealed-box fixture decryption and secret redaction pass; no live install handler is exposed."
        ]
      }
    },
    {
      "id": "m2/4",
      "parent": null,
      "state": "planned",
      "role": "implementation",
      "intent": {
        "title": "[m2/4] Fresh-evidence resume planning and complete CLI seam gate",
        "responsibility": "Recompute partial-run plans from fresh identity-bound evidence, and prove complete packaged CLI seams without fabricating installer readiness.",
        "paths": [
          "core/dracla/provisioning.py",
          "core/dracla/cli/app.py",
          "core/tests/test_provisioning_resume.py",
          "core/tests/test_cli_integration.py",
          "docs/cli.md",
          "design/verification-matrix.md"
        ],
        "dependencies": [
          "m2/3"
        ],
        "acceptance": [
          "Unchanged evidence is deterministic; ID/release drift and stale completion flags cannot authorize reuse.",
          "Installed-package dry-run and failure paths make zero writes; force cannot bypass blockers.",
          "Generated commands resolve to real handlers; full M1 conformance and wheel gates pass."
        ]
      }
    }
  ]
}
```
