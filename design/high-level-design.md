# DraCLA High-Level Design

Status: Locked
Date: 31 August 2026
Requirements baseline: `design/requirements.md` (Locked, revision 14, 31 August 2026)

This document proposes an implementation architecture for the locked
requirements baseline. Per `REQ` acceptance section 19, it maps major
components to requirement IDs and explicitly identifies every requirement it
deviates from or defers.

---

## 1. Design decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Pull request enforcement runs in the GitHub App's serverless handler, not GitHub Actions | Fork-triggered workflows receive no secrets, so they cannot read a private records repo. Deviates from `REQ-OPS-2`. See §2. |
| D2 | Three project-controlled private repositories per project: canonical records, an encrypted coverage projection, and a control repository for the key-bearing reconciler | The enforcer must not read canonical signer evidence, and the event-appending App must not be able to modify code that runs with unwrapped project keys. Repository separation makes both boundaries enforceable on GitHub Free. |
| D3 | Three narrowly scoped GitHub Apps: `dracla-records`, `dracla-enforcer`, and `dracla-reconciler-trigger` | Records and enforcement require separate data and credentials. The third App can dispatch only the protected control workflow; it has no contents, administration, workflow-file, or secrets write. It is not the rejected provisioning App of D11. |
| D4 | All three repositories remain private and project-controlled, and may live in an existing organization or personal account | `REQ-CONFIG-1`, `REQ-REC-1`, `REQ-OPS-6`, and principle 6 require project custody but not a dedicated organization. Auto-provisioning removes setup friction. |
| D4a | Authenticated application-layer encryption, not repository readership, is the private-record confidentiality boundary | Repository privacy and narrow GitHub permissions remain defense in depth. Ordinary repository readers and read-only Apps without a decryption capability see ciphertext and are not DraCLA records readers. |
| D5 | Coverage state is materialized into the projection repo synchronously by the signing path; Actions replays canonical to verify it | Gives O(1) coverage lookup with no Actions latency on the hot path, while keeping the projection strictly derived (`REQ-REC-6`). |
| D6 | Staleness is detected via operation-scoped in-flight markers inside the coverage repo | The enforcer has no canonical access, so it cannot compare against canonical head directly. See §5.4. |
| D7 | One three-repository set per **DraCLA project**, not per contributing GitHub repo | Each initial-release project has one immutable legal recipient and one agreement identifier, while DraCLA may enforce that project across many configured repositories. DraCLA does not derive legal scope from enforcement scope (`REQ-CONFIG-3`, `REQ-CONFIG-4`). See §5.5. |
| D8 | Python core owns the event model, replay, exports, and CLI; Cloudflare Workers in TypeScript host the thin serverless tier | `REQ` §1 implies a Python package. Python Workers run on Pyodide with cold-start and package limits unsuited to webhook latency. Keeping the edge thin makes the split cheap and reversible. |
| D9 | The initial release stores coverage in exactly 32 packed shards, not one file per user | Thirty-two bounds coverage reads below the 50-subrequest ceiling while keeping files small for the initial scale. Versioned projection metadata prevents a reader from silently interpreting an unsupported layout; live migration to another count is deferred. |
| D13 | Repository routing uses an eventually consistent signed KV projection guarded by one SQLite-backed Durable Object per contributing repository | The object stores only routing state, generation, and at most one transient authoritative-check publication identity. Every enforcement request compares it with the KV route, so a stale route fails closed without renewable leases, periodic writes, or adopter-owned Cloudflare credentials. See §7.2. |
| D14 | Exemptions and records readers use explicit source records: individual, team snapshot, or explicitly delegated continuous team | Snapshot is the default and freezes selected people. Continuous mode deliberately delegates future decisions to GitHub team membership administrators. Effective exemption is the union of active sources; no boolean overwrite can hide another source. See §6.8 and §6.10.4. |
| D15 | Every private artifact uses the versioned AES-256-GCM envelope in §4, with separate records and coverage data keys per project | AES-GCM is available in both Cloudflare Workers Web Crypto and the Python cryptography stack. Canonical associated data binds every ciphertext to its project, purpose, logical identity, schema, and key ID. |
| D16 | The key-bearing reconciler runs from the separate private control repository, never from an App-writable branch | Private-repository branch rules are not available on the GitHub Free baseline. Physical repository separation prevents both event Apps and the trigger-only App from modifying executable inputs while keeping adopter-controlled upgrade and rollback. |
| D17 | Successful authoritative merge-group publication is serialized against coverage mutations by one CAS-updated decision-fence file in the project's existing coverage repository and against routing transitions by a publication reservation in the existing strongly consistent routing gate | A check may evaluate optimistically, but it can publish success only while holding both reservations. The gate's `reserve_publication` method atomically validates the route and blocks `begin_pending` until GitHub completion under that identity is independently confirmed, so completion order matches `REQ-CHECK-3` and the strict routing barrier without another provider-managed subsystem. See §5.4 and §7.2. |
| D18 | Every mutation freezes its complete authorized operation in one encrypted records-repository cell before acquiring the coverage decision fence | A crash before canonical append must be recoverable without the original browser request, while records plaintext must not enter the coverage capability. The prepared/appending CAS is also the append right, so terminal recovery cannot race a delayed writer. See §5.4. |
| D11 | Provisioning runs in the `dracla` CLI with the administrator's own credentials, not a third GitHub App | A provisioning App would hold `administration`, `workflows`, and `secrets` write in the adopter's org. `workflows: write` retained is a code-execution channel into their PII repo (DR-011), and an uninstall that fails to fire leaves it. An exact `uvx dracla@<version>` invocation keeps the adoption cost to one versioned command against three consent screens. |
| D12 | The CLI is the reporting and read-out surface, not just an installer | Gives maintainers a zero-infrastructure path for common queries and demonstrates `REQ-REC-5` directly: the records are readable with the same tool an auditor would use. |
| D10 | Agreement currency changes are explicit: ordinary activation declares whether it invalidates prior acceptances, while restore names one prior activation state | A typo fix, a new patent grant, and recovery from a bad activation are different acts. `REQ-AGR-4` forbids inferring legal meaning from agreement text, so DraCLA records each choice as an attributable event. Implemented by `REQ-AGR-2`. |

---

## 2. Deviation from REQ-OPS-2

`REQ-OPS-2` states that background validation, index generation, exports, and
**pull request enforcement** SHOULD run in GitHub Actions. This design honors
that for the first three and deviates for the fourth.

**Why baseline enforcement does not run in contributing-repo Actions.** `REQ-REC-1` makes the records repo
private; `REQ-OPS-3` makes the contributing repo public on GitHub Free.
Enforcement must therefore read a private repo while reacting to events in a
different, public one. A workflow in the contributing repo cannot do this:

- `GITHUB_TOKEN` is scoped to the repo running the workflow and cannot read the
  separate private records repo.
- Reaching it requires a stored secret, and **GitHub withholds secrets from
  `pull_request` workflows triggered from a fork**.

Contributors to open source projects contribute overwhelmingly from forks, so
the Actions path fails closed for precisely the population the system exists to
check. A `pull_request_target` workflow runs the base repository's trusted
default-branch code, but it still creates a secret-bearing Actions surface that
parses attacker-controlled pull-request metadata and that an apparently harmless
future checkout of the head would make exploitable. DraCLA rejects that durable
parser and workflow-hardening obligation when the GitHub App path needs neither
repository secrets nor a per-PR Actions run.

The GitHub App path has no such problem: the webhook is delivered regardless of
fork status, and the installation token is minted server-side where no
contributor can influence it.

**This is a declared deviation, not an amendment.** `REQ-OPS-2`'s enforcement
clause is a `SHOULD`, so a justified deviation suffices; see §10.2.

**Two corrections to how this was argued.** First, "cannot run in Actions" is
too strong: §9's self-hosted control-computed variant runs enforcement in the project's
*private control repository*, which the fork-secret rule does not touch.
What is impossible is enforcement in a workflow in the *contributing* repo,
which is the configuration a project would naturally reach for. Second, "Actions
minutes are free on public repos" is true but does not apply to DraCLA's own
Actions usage: the reconciler runs in the private control repo, where minutes
are metered on Free (§9).

**Latency is still not the argument.** A check landing 30 s after a pull request
opens would be acceptable. The credential boundary is the disqualifier.

---

## 3. System context

```
                    ┌─────────────────────────────────────────┐
   contributor ────▶│  static portal + dashboard shell        │
                    │  (public assets, no private data)       │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │  serverless tier                        │
                    │  OAuth · sign · revoke · webhooks       │
                    │  + bounded routing generation gates     │
                    │  check runs · index proxy               │
                    └───┬──────────────────────────┬──────────┘
                        │                          │
              dracla-records App          dracla-enforcer App
              records + portal keys       coverage key only
                        │                          │
        ┌───────────────▼──────────┐   ┌───────────▼──────────────┐
        │ …-cla-records PRIVATE    │   │ …-cla-coverage PRIVATE   │
        │ encrypted canonical      │──▶│ encrypted coverage       │
        │ events + private derived │   │ user_id -> coverage      │
        └───────────────▲──────────┘   └───────────▲───────┬──────┘
                        │                          │       │ read-only
               read/write deploy keys             │       ▼
                        │                 checks on acme/widget
        ┌───────────────┴──────────┐      (public contributing repo)
        │ …-cla-control PRIVATE    │
        │ pinned reconciler code   │◀── dracla-reconciler-trigger
        │ Actions secrets + wraps  │    (Actions dispatch only)
        └──────────────────────────┘
```

---

## 4. Principals and permissions

Six principal classes. Each holds the minimum for its steady-state job, and
provisioning privilege never belongs to DraCLA at all (`REQ-REC-2`).

### `dracla-records` App — portal side
- OAuth: contributor login, signing, revocation, dashboard authorization
- `contents: write` on **canonical**
- `contents: write` on **coverage** (encrypted materialization, the in-flight
  marker, active-version updates, effective exemption decisions, and generic
  check-reason codes, §5.4)
- Organization `members: read` only where a configured continuous reader or
  exemption team must be observed. Repository reader enumeration is not a
  confidentiality control and is not required.
- A daily Cron Trigger in `worker-portal` drives continuous-rule observation
  and recovery. It uses the existing App key; adopters provide no additional
  GitHub credential (§5.4, §6.10.4).
- Holds separate service wrapping roots for records and coverage and unwraps
  only a route-verified project's keys. It never returns a raw key to a browser.
- Not installed on any contributing repo; receives no pull request webhooks

### `dracla-enforcer` App — check side
- Webhooks: `pull_request`, `merge_group`, and the event-wide `check_run`
  subscription. `checks: write` automatically subscribes the App; GitHub does
  not offer an action-only subscription, so signed `created` and `completed`
  deliveries for other Apps' check runs can reach this Worker. Before any gate
  call, the handler requires this App's numeric ID, fixed DraCLA name, expected
  repository/head, and supported action. A `completed` delivery additionally
  requires §7.2's exact authoritative `external_id` prefix and grammar;
  created, ordinary-check, other-App, and unknown-namespace deliveries are
  discarded before a gate RPC. `rerequested` starts a fresh evaluation, and
  this App's exact authoritative `completed` delivery clears only its matching
  routing publication reservation (§7.2; [GitHub `check_run` webhook
  contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_run))
- A daily Cron Trigger in `worker-enforce` uses the same App identity to recover
  missing and stranded checks and to verify installation boundaries; unlike the
  canonical reconciler, it can enumerate contributing repositories and write
  check runs
- `checks: write`, **`pull_requests: write`**, `contents: read` on
  **contributing** repos. Write is required to post the pull request comment of
  `REQ-PORTAL-3`; read alone cannot, and the earlier inventory made that
  requirement unimplementable.
- Organization `members: read` where an organization-wide enforcement-scope
  selector must be observed; repository metadata is used for live
  per-repository permission checks
- `contents: read` on **coverage** only
- Holds the coverage wrapping root only. It cannot unwrap a records key even if
  canonical ciphertext is supplied to it.
- Not installed on canonical

### `dracla-reconciler-trigger` App — control side
- `actions: write` on the project's **control** repository only
- DraCLA dispatches only the one pinned reconciler workflow and inspects its run
  status. The underlying GitHub permission can also manage that repository's
  Actions runs, so the control repo contains no second workflow and the
  credential's availability reach is documented in §8.1.2.
- Has no `contents`, `administration`, `workflows`, `secrets`, canonical, or
  coverage permission; it cannot alter code or obtain a project key
- Exists to recover a failed synchronous materialization within the five-minute
  derived-state target without giving either data App control-repository write

### `dracla` CLI — provisioning, configuration, reporting (D11, D12)
- Runs locally, `uvx dracla@<version> …`, using the **administrator's own** GitHub
  credentials. DraCLA holds no provisioning privilege at any point.
- Creates the three repositories and seeds the control workflow (§6.10). It writes no
  project configuration and publishes no agreement: those are portal actions,
  where each becomes an event with an actor
- Generates the records and coverage data keys, per-project control wrapping
  key, wrapped service copies, and adopter recovery material; proves both
  actual data keys recoverable before enabling the first private write
- Provisions repository-scoped canonical and coverage deploy keys in the
  control repository and rotates them through `dracla rotate-key`; DraCLA's
  hosted Apps never receive repository-administration or secret-write access
- Reporting surface thereafter (§6.9)

An earlier draft used a third **provisioning** App for this, holding org `administration`,
`workflows`, and `secrets` write. That is rejected: retained `workflows: write`
on canonical is a permanent code-execution channel into an adopter's PII repo
(DR-011), `administration: write` permits flipping that repo to public, and an
uninstall step that fails to fire leaves both in place. Provisioning is the
administrator's own act, performed with their own credentials, so those
permissions never exist as a DraCLA credential. The trigger-only App above is
not that principal: it can dispatch one workflow but cannot provision, edit,
read repository content, or manage secrets.

### Actions job inside the control repository — reconciler
- Runs from code and workflow content no event-appending App can modify
- Replays canonical events, regenerates the projection, and **reconciles** it
  against what the signing path wrote (§5.4)
- Verifies and repairs the sharded dashboard index, exact-status detail, and
  reader-authority state; produces JSON/CSV only for an explicit export request
- Reads/writes canonical and writes coverage through separate repository-scoped
  deploy keys held only as control-repository Actions secrets
- Unwraps records and coverage data keys with a per-project control wrapping
  key held as an Actions secret; the corresponding wrapped keyring is data, not
  executable configuration
- Before unwrapping, verifies the control repository is private and that the
  install manifest names its current numeric ID plus the exact records and
  coverage repository IDs; a mismatch stops the job
- Declares an explicit least-privilege `permissions:` block, and **never**
  interpolates event-derived values into `run:` or `env:`. Signer fields are
  untrusted input (`REQ-SEC-8`) and this job holds a cross-repo write
  credential; a `${{ }}` expansion of a supplied legal name would be command
  execution on a runner that can forge the merge gate. Event data is passed to
  the Python core as files, read by the core, never expanded by the shell.

### What the separation does and does not guarantee

**Unconditional:** the coverage projection contains no names, email addresses,
confirmation text, entity evidence, exact status reasons, exemption provenance,
or reader-authority sources (§5.3), so the check computation never reads them,
whatever else is true. It is not free of personal data — §8.4.

**Two layers:** the enforcer is not installed on canonical and has no records
wrapping root. An administrator can still widen its GitHub installation, but
that exposes only ciphertext; the cryptographic capability boundary remains.
The scheduled sweep reports the widened installation as a least-privilege
violation, but signer confidentiality does not depend on that report landing.

**Not covered:** compromise of `worker-portal`, the control workflow, their
wrapping roots, or the shared hosted operator can expose records plaintext.
These are declared key controllers. Worker and root separation ensures an
enforcer-only compromise cannot decrypt signer evidence; §8.3 states the
remaining hosted-operator trust.

### Encryption, key distribution, and access map

Repository readers see ciphertext. Decryption authority, not GitHub repository
visibility, controls access to private CLA data. A dedicated CLA organization
is optional defense in depth; existing-organization and personal-account
private repositories are conforming.

Each project starts with two independent 256-bit random data-encryption keys:

- the **records key** encrypts canonical private events and every private
  explanatory or authorization derivative, including sharded indexes,
  explicitly requested persisted exports, exact status reasons, exemption
  provenance, and reader-authority shards;
- the **coverage key** encrypts only data needed to compute the merge decision:
  coverage shards, effective exemption booleans, generic check-reason codes,
  in-flight markers, active-version state, overrides, and freshness metadata.

Keys have independent random 128-bit `kid` values and rotate independently.
Old keys remain decrypt-only while any retained artifact names them. Deleting a
key still referenced by append-only history is forbidden.

#### Version 1 encrypted-artifact envelope

Every private CLA data blob in GitHub contains a canonical JSON envelope, never
plaintext. For version 1, "canonical JSON" means the UTF-8 bytes produced by
RFC 8785 JSON Canonicalization Scheme (JCS), with no byte-order mark or trailing
bytes. Every base64url value uses the RFC 4648 URL-safe alphabet without `=`
padding. Wrapped-key files are the only structural exception and use the
separate authenticated format below; they contain no raw key or private CLA
value.

```json
{
  "envelope_version": 1,
  "algorithm": "A256GCM",
  "project_id": "stable-project-id",
  "artifact_kind": "project-config | materialization-generations | canonical-event | prepared-operation | derived-state | derived-index | status-detail | export-json | export-csv | coverage-source | coverage-shard | exemption-fold | inflight | decision-fence | active-agreement | reader-authority",
  "logical_id": "branch:repository-relative-path",
  "schema_version": 1,
  "kid": "base64url-128-bit-key-id",
  "nonce": "base64url-96-bit-random-nonce",
  "ciphertext": "base64url-ciphertext-and-tag"
}
```

The identity namespace is normative, not chosen by each implementation. Let
`P` be the exact ASCII repository-relative path after substituting the tokens
defined below. For every row in this table, `logical_id` is exactly
`<branch>:<P>`. The branch separator is one ASCII colon; paths use `/`, have no
leading slash, and contain no `.` or `..` segment. The reader derives the
expected kind, capability, schema, and logical ID from the branch and requested
path before decrypting, then rejects any mismatch.

| Repository branch and path `P` | `artifact_kind` | Key capability | `schema_version` |
|---|---|---|---:|
| records `events`: `config/project.enc.json` | `project-config` | records | 1 |
| records `events`: `config/materialization-generations.enc.json` | `materialization-generations` | records | 1 |
| records `events`: `events/<aa>/<bb>/<event_id>.enc.json` | `canonical-event` | records | 1 |
| records `operations`: `prepared-operation.enc.json` | `prepared-operation` | records | 1 |
| records `derived`: `derived/state.enc.json` | `derived-state` | records | 1 |
| records `derived`: `derived/index/<shard>.enc.json` | `derived-index` | records | 1 |
| records `derived`: `derived/status-detail/<shard>.enc.json` | `status-detail` | records | 1 |
| records `derived`: `derived/reader-authority/<shard>.enc.json` | `reader-authority` | records | 1 |
| records `derived`: `derived/exports/<request_id>.enc.json` | `export-json` | records | 1 |
| records `derived`: `derived/exports/<request_id>.enc.csv` | `export-csv` | records | 1 |
| coverage `coverage`: `source.enc.json` | `coverage-source` | coverage | 1 |
| coverage `coverage`: `inflight.enc.json` | `inflight` | coverage | 1 |
| coverage `coverage`: `decision-fence.enc.json` | `decision-fence` | coverage | 1 |
| coverage `coverage`: `users/<shard>.enc.json` | `coverage-shard` | coverage | 1 |
| coverage `coverage`: `agreements/active.enc.json` | `active-agreement` | coverage | 1 |
| coverage `coverage`: `exemptions.enc.json` | `exemption-fold` | coverage | 1 |

`<event_id>` is the server-computed identifier from §5.1; `<aa>` and `<bb>`
are its first and next two ASCII characters. `<shard>` is the zero-padded
two-digit decimal shard number `00` through `31`. `<request_id>` is an unpadded
base64url-encoded random 128-bit server-generated value. `<override_key>` is an
entry inside one subject's `users/<shard>.enc.json`, not a separately fetched
artifact. It is the unpadded base64url SHA-256 digest of the RFC 8785 bytes of
exactly `{"repository_id":<id>,"pull_request_number":<n>,"subject_user_id":<id>,
"tree_oid":"…"}`. `tree_oid` is the GitHub-reported root Git tree object ID
of the associated pull request's immutable head commit, never the merge-group
synthetic commit. One multi-subject override event therefore updates one entry
per subject across only the already bounded subject shards. The decrypted entry
repeats every dynamic identity, the grant event ID, and `active: true`; the
reader verifies their relation after decryption. Withdrawal removes that active
entry without erasing canonical grant or withdrawal history.

Agreement identifiers and versions are project-supplied strings, so they are
never inserted into paths directly. Define `segment(s)` as the unpadded
base64url SHA-256 digest of the exact UTF-8 bytes of schema-valid string `s`,
with no Unicode normalization. Agreement snapshots therefore use
`agreements/<segment(agreement_id)>/<segment(version)>.md` and the matching
`.meta.json` path. The metadata and canonical event retain the original strings
and digest; readers recompute both path tokens and reject a mismatch. These
agreement files are plaintext legal text and non-private metadata, not §4
artifact envelopes. Wrapped-key files are likewise outside this table because
they use the separate authenticated keyring format below.

The RFC 8785 encoding of the object containing every envelope field except
`nonce` and `ciphertext` is the AES-256-GCM additional authenticated data. The
nonce is exactly 12 bytes. `ciphertext` encodes the AES-GCM ciphertext followed
by its 16-byte authentication tag, in that order. JSON artifacts are encrypted
as their RFC 8785 UTF-8 bytes. CSV artifacts are encrypted as the exact
formula-neutralized UTF-8 CSV bytes defined by the export schema. Version 1
adds no compression, byte-order mark, or other transform.

Readers reject unknown envelope or schema versions, missing or extra fields,
duplicate fields, padded or otherwise non-canonical base64url, wrong decoded
lengths, non-canonical envelope bytes, wrong project/purpose/identity bindings,
unknown `kid`, and authentication failure. Repository identity is checked by
routing and installation-token authorization, not embedded in ciphertext; this
is what lets an unchanged backup be restored into a replacement repository.
Production nonces come from the platform CSPRNG and must never repeat under one
key.

Paths, filenames, commit messages, and refs contain only fixed labels, random
identifiers, shard numbers, and key IDs. They never contain names, email
addresses, GitHub logins, signer IDs, answers, exemption subjects, or reasons.
Repository-level timing, blob sizes, object counts, fixed artifact kinds, and
shard occupancy remain unavoidable metadata and are documented as such.

CSV formula neutralization happens before encryption. Authorized export
requests decrypt and stream plaintext directly to the requester; plaintext
exports are never committed, logged, or uploaded as workflow artifacts.

#### Wrapped key copies

The raw project keys are generated on the installer's machine and are never
stored in repository content. AES-256-GCM also wraps each key copy, with
canonical associated data containing `project_id`, capability (`records` or
`coverage`), data-key `kid`, wrapper identity, and wrap version:

```json
{
  "wrap_version": 1,
  "algorithm": "A256GCM",
  "project_id": "stable-project-id",
  "capability": "records | coverage",
  "data_kid": "base64url-128-bit-key-id",
  "wrapper_id": "portal-records | portal-coverage | enforcer-coverage | control | recovery",
  "wrapper_generation": "opaque-generation-id",
  "nonce": "base64url-96-bit-random-nonce",
  "wrapped_key": "base64url-ciphertext-and-tag"
}
```

The RFC 8785 encoding of the object containing every field except `nonce` and
`wrapped_key` is the wrap AAD. The wrapped plaintext is exactly the 32 raw bytes
of the AES-256 data key. The nonce is exactly 12 bytes, and `wrapped_key`
encodes the AES-GCM ciphertext followed by its 16-byte authentication tag.

A keyring file is exactly the RFC 8785 encoding of
`{"keyring_version":1,"keys":[...]}`, where `keys` contains the objects above
sorted by the lexicographic byte order of each object's RFC 8785 encoding. It
contains no raw key. Readers apply the same strict field, encoding, length, and
canonical-order checks as the artifact envelope and reject an unknown wrapper,
duplicate `(capability, data_kid, wrapper_id)` entry, wrong project/capability
binding, unknown generation, or authentication failure.

- `worker-portal` holds distinct hosted **records** and **coverage** wrapping
  roots and can unwrap only a route-verified project's matching copies;
- `worker-enforce` holds only the hosted coverage wrapping root and cannot
  unwrap a records-key copy;
- the control repository holds a per-project control wrapping key as an Actions
  secret and wrapped copies of both data keys as inert repository data;
- the adopter receives a random recovery wrapping key for offline storage; an
  encrypted recovery keyring on canonical's `keys` branch contains every
  retained records and coverage key version.

One hosted records root and one separate hosted coverage root may wrap keys for
all projects in one deployment environment; no root is reused across
environments or capabilities. A wrapped copy from another project, capability,
or wrapper fails authentication. A planned service-root migration may add a
successor, rewrap every live project key, verify the successor path, and retire
the old live path without changing project ciphertext. That is operational
maintenance, not revocation: a holder who retained the old root and old Git
objects can still recover those project keys.

A root-controller departure or suspected exposure additionally rotates every
affected project data key and rebuilds that project's current mutable coverage
and records-derived state under the successors. New events and state then stop
using keys the former controller knew. Append-only historical ciphertext stays
under retained old keys and may remain decryptable to anyone who copied the old
root, project key, or plaintext; DraCLA never describes that access as revoked.

The service access map is:

| Principal | Plaintext/key capability |
|---|---|
| Contributor | Portal may return only the contributor's own authorized status; no raw key |
| Authorized records reader | Portal may return only authorized plaintext results; no repository access or raw key required |
| `worker-portal` | Records and coverage keys for the one route-verified project |
| `worker-enforce` | Coverage key for the one route-verified project; never a records key |
| Control reconciler | Both project keys through control-only wrapping material |
| Installer | Generates keys transiently, installs wrapped copies, and verifies recovery before private writes |
| Backup operator or ordinary repository reader/App | Ciphertext only |
| Recovery custodian | Can recover every retained project key from repository backups |

Control-repository writers who can change the key-bearing workflow,
Actions-secret controllers, hosted wrapping-root and deployment controllers,
and recovery custodians are key controllers. An administrator or reader of only
the records or coverage repository is not one unless they also control one of
those capabilities. Encryption does not protect records from key controllers;
installation and the FAQ say so. Removing a key controller is forward-looking:
data-key rotation can protect new events and rebuilt current state, but cannot
make that controller forget old keys or plaintext. §6.10.2 defines first-write
and rotation transactions, §6.10.4 defines authorized plaintext reads, and §9.1
defines restore and hosted-to-self-hosted rewrapping.

---

## 5. Data architecture

### 5.1 Canonical records repo (private)

```
# events branch
config/project.enc.json        encrypted recipient and mutable portal configuration
config/materialization-generations.enc.json
                               current generation for each derived class
agreements/<agreement_token>/<version_token>.md
                               exact agreement content; tokens use §4 `segment`
agreements/<agreement_token>/<version_token>.meta.json
                               non-private digest/reference metadata; events canonical (§6.5)
events/<aa>/<bb>/<event_id>.enc.json

# derived branch
derived/state.enc.json         generations, shard hashes, and release-profile limits
derived/index/<shard>.enc.json dashboard rows (generated, private)
derived/status-detail/<shard>.enc.json
                               exact per-subject reasons and exemption provenance
derived/reader-authority/<shard>.enc.json
                               canonical reader sources and materialized membership
derived/exports/<request_id>.enc.json
derived/exports/<request_id>.enc.csv
                               explicit export snapshot only (generated, private)

# operations branch
prepared-operation.enc.json    bounded recoverable mutation cell (§5.4)

# keys branch
.dracla/bootstrap.json         initial key-discovery manifest (§6.10.2)
.dracla/keys/portal/*.json     records-key copies wrapped for worker-portal
.dracla/recovery/keyring.json  all retained project keys wrapped for adopter recovery
```

**Generated records artifacts live in canonical, never in coverage.** The
index, exact-status detail, reader-authority shards, and explicit exports contain private
records or authorization data before encryption. The enforcer has neither
canonical access nor the records key, preserving defense in depth even if an
encrypted blob is copied. They are committed to `derived/` on a **separate
branch** of canonical, so the
one-logical-event-per-commit rule on the events branch (`REQ-REC-3`) is not
disturbed. They are never written to Actions artifacts, which `REQ-SEC-2`
forbids for signer data, and their persisted bytes always use §4's envelope.
The separate `operations` branch holds one records-key-encrypted bounded
prepared-operation cell. It is recovery state rather than canonical evidence;
its commits never enter `events` ancestry, and the enforcer cannot read or
decrypt it.

The decrypted semantic event (`REQ-SIGN-4`, `REQ-REC-5`) is the closed JSON
object below. Its RFC 8785 bytes are always stored inside §4's
encrypted-artifact envelope; none of these values appears in paths, commit
messages, or plaintext repository blobs. Every listed top-level field is
required, no other top-level field is permitted, and every nested object is
also closed. `null` is explicit rather than represented by omission.

```json
{
  "schema_version": 1,
  "project_id": "stable-project-id",
  "event_id": "base64url-256-bit-id",
  "idempotency_key": "base64url-256-bit-key",
  "operation_nonce": "base64url-128-bit-nonce",
  "operation_sha256": "sha256:lowercase-hex",
  "type": "one closed value from the table below",
  "recorded_at": "2026-08-17T12:00:00Z",
  "dracla_version": "0.1.0",
  "actor": { "kind": "github", "github_user_id": 7654321,
             "login_snapshot": "maintainer" },
  "authorizations": [],
  "confirmed_canonical_oid": "… | null",
  "target": {},
  "payload": {}
}
```

`actor` is exactly one of
`{"kind":"github","github_user_id":<positive integer>,"login_snapshot":<string>}`
or `{"kind":"automation","principal":"worker-portal"}`. A human
administrative event carries a non-empty closed `authorizations` array defined
below and mapped to §6.8. Acceptance and revocation require the GitHub actor and
`authorizations: []` because the authenticated contributor is acting for
themself. Materialization events require the automation actor and also use the
empty array; their payload references the previously authorized standing rule
and contains the GitHub observation that caused the automation transition.
Every other v1 event requires the GitHub actor and the exact non-empty evidence
set specified below.
`confirmed_canonical_oid` is a Git object ID for acceptance and revocation and
`null` for every other v1 type.

The following table is the closed v1 event union. Object names such as
`coverage_tuple`, `subject`, `team`, `project_configuration`, and
`enforcement_scope` mean the version-1 closed
objects defined immediately below; arrays preserve order unless
the row explicitly calls them sets, in which case RFC 8785 lexical byte order
is required. Implementations reject a field belonging to another row.

| `type` | Exact `target` members | Exact `payload` members |
|---|---|---|
| `acceptance` | `coverage_tuple`, `recipient`, `version`, `digest` | `fields`, `confirmations`, `supersedes` (event ID or `null`) |
| `revocation` | `coverage_tuple` | `effect` fixed to `cutoff_all_prior_versions` |
| `agreement_published` | `agreement_id`, `version` | `recipient`, `ref`, `content_commit_oid`, `digest`, `snapshot_content_path`, `snapshot_metadata_path`, `snapshot_sha256` |
| `agreement_activated` | `agreement_id`, `version` | `published_event_id`, `supersedes_coverage`, `accepted_versions` (non-empty set of version strings) |
| `agreement_activation_restored` | `agreement_id`, `activation_event_id` | `accepted_versions` (non-empty set copied from the target activation), `reason` |
| `project_connected` | empty object | `recipient`, `repository_owner`, `project_slug`, `repository_ids`, `bootstrap`, `project_configuration`, `successor_of` (project ID or `null`) |
| `project_repository_owner_changed` | `prior_repository_owner` | `new_repository_owner`, `project_slug`, `repository_ids`, `registry_commit_oid`, `registry_generation` |
| `project_succeeded` | `successor_project_id` | `successor_connected_event_id` |
| `config_updated` | empty object | `project_configuration` (the complete successor value) |
| `keyring_activated` | empty object | `generation`, `keys_commit_oid`, `current_kids` |
| `enforcement_scope_requested` | `change_id` | `prior_scope`, `desired_scope`, `prior_registry_generation` |
| `enforcement_scope_activated` | `change_id` | `request_event_id`, `desired_scope`, `registry_commit_oid`, `registry_generation` |
| `enforcement_scope_abandoned` | `change_id` | `request_event_id`, `reason_code` |
| `override` | `repository_id`, `pull_request_number`, `tree_oid` | `subjects` (non-empty set of `subject`), `reason`, `instrument_ref` (string or `null`) |
| `override_withdrawn` | `override_event_id` | `reason`, `instrument_ref` (string or `null`) |
| `retry_requested` | `repository_id`, `check_kind`, `check_identity` | `github_delivery_id` (string or `null`) |
| `exemption` | `subject` | `source_kind` (`bot` or `individual`), `basis` (string or `null` for `bot`), `instrument_ref` (string or `null` for `bot`) |
| `exemption_snapshot` | `subjects` (non-empty set of `subject`) | `team`, `basis`, `instrument_ref` |
| `exemption_source_withdrawn` | `source_event_id`, `subject` | empty object |
| `exemption_rule_configured` | `team` | `basis`, `instrument_ref` |
| `exemption_rule_withdrawn` | `rule_event_id` | empty object |
| `exemption_materialized` | `rule_event_id`, `subject` | `result` (`add` or `withdraw`), `team`, `membership_evidence`, `prior_materialization_event_id` (event ID or `null`) |
| `records_reader_authorized` | `subject` | empty object |
| `records_reader_snapshot_authorized` | `subjects` (non-empty set of `subject`) | `team` |
| `records_reader_withdrawn` | `source_event_id`, `subject` | empty object |
| `records_reader_rule_configured` | `team` | empty object |
| `records_reader_rule_withdrawn` | `rule_event_id` | empty object |
| `records_reader_materialized` | `rule_event_id`, `subject` | `result` (`add` or `withdraw`), `team`, `membership_evidence`, `prior_materialization_event_id` (event ID or `null`) |

The named objects above have these exact v1 shapes; they are definitions, not
examples:

- `coverage_tuple` is
  `{"github_user_id":<positive integer>,"project_id":<non-empty string>,
  "agreement_id":<non-empty string>,"recipient_id":<non-empty string>}`.
- `recipient` is
  `{"recipient_id":<non-empty string>,"legal_name":<non-empty string>}`.
- `repository_owner` is
  `{"github_account_id":<positive integer>,"login_snapshot":<non-empty string>}`.
- `subject` is
  `{"github_user_id":<positive integer>,"login_snapshot":<non-empty string>}`.
- `team` is
  `{"organization_id":<positive integer>,"team_id":<positive integer>,
  "slug_snapshot":<non-empty string>}`.
- `membership_evidence` is
  `{"organization_id":<positive integer>,"team_id":<positive integer>,
  "github_user_id":<positive integer>,"state":"member"|"not_member",
  "checked_at":<timestamp>,"etag":<string|null>,
  "github_request_id":<string|null>}`.
- `repository_ids` is
  `{"records":<positive integer>,"coverage":<positive integer>,
  "control":<positive integer>}` and `current_kids` is
  `{"records":<non-empty string>,"coverage":<non-empty string>}`.
- `bootstrap` is
  `{"install_generation":<non-empty string>,
  "manifest_commit_oid":<Git object ID>,
  "manifest_sha256":<digest>,
  "records_keyring_candidate_oid":<Git object ID>,
  "repository_ids":<repository_ids>,"current_kids":<current_kids>}`. These
  values are the event-side pins for the manifest handshake in §6.10.2.
- `project_configuration` is
  `{"privacy_policy_url":<absolute HTTPS URL>,
  "retention_statement":<non-empty string>,
  "correction_procedure":<non-empty string>,
  "required_fields":[<field>,...],
  "confirmation_labels":[<non-empty string>,...]}`. A `field` is exactly
  `{"name":<non-empty ASCII identifier>,"label":<non-empty string>,
  "kind":"text"|"email","required":true}`. Field names are unique;
  confirmation labels are unique; both arrays preserve portal display order.
  Recipient identity and enforcement scope are deliberately outside this
  mutable object.
- An `enforcement_scope` is a set of `scope_selector` objects. A selector is
  exactly either
  `{"kind":"repository","repository_id":<positive integer>,
  "owner_snapshot":<non-empty string>,"name_snapshot":<non-empty string>}`
  or
  `{"kind":"organization","organization_id":<positive integer>,
  "login_snapshot":<non-empty string>}`. Stable numeric identity controls;
  names are evidence snapshots. The set is encoded in RFC 8785 lexical byte
  order with no duplicate stable identity.
- An `authorization_evidence` member is exactly
  `{"operation":<non-empty closed operation name>,
  "resource_kind":"account"|"repository"|"organization"|"installation",
  "resource_id":<positive integer>,
  "required_authority":<non-empty closed authority name>,
  "observed_authority":<non-empty string>,"authorized":true,
  "checked_at":<timestamp>,"github_request_id":<string|null>}`. The closed
  operation and authority names are the action and minimum-live-authorization
  columns of §6.8; an unrecognized pair is invalid. `authorizations` is a set of
  these objects encoded in RFC 8785 lexical byte order with no duplicate
  `(operation,resource_kind,resource_id)` identity.

The exact v1 event/action-to-authorization mapping is normative. A
slash-separated cell denotes the stated paired alternatives in order; it is
not a slash-containing token accepted on the wire.

| Event or action | Exact `operation` | `resource_kind` | Exact `required_authority` |
|---|---|---|---|
| `project_connected` owner | `project_connect_owner` | `account` | `repository_owner_control` |
| `project_connected` records repository | `project_connect_records_repository` | `repository` | `project_repository_admin` |
| `project_connected` coverage repository | `project_connect_coverage_repository` | `repository` | `project_repository_admin` |
| `project_connected` control repository | `project_connect_control_repository` | `repository` | `project_repository_admin` |
| `project_connected` records App | `project_connect_records_app` | `installation` | `records_app_binding` |
| `project_connected` enforcer App | `project_connect_enforcer_app` | `installation` | `enforcer_app_binding` |
| `project_connected` trigger App | `project_connect_trigger_app` | `installation` | `trigger_app_binding` |
| `project_repository_owner_changed` owner | `project_repository_owner_change_owner` | `account` | `repository_owner_control` |
| `project_repository_owner_changed` records repository | `project_repository_owner_change_records_repository` | `repository` | `project_repository_admin` |
| `project_repository_owner_changed` coverage repository | `project_repository_owner_change_coverage_repository` | `repository` | `project_repository_admin` |
| `project_repository_owner_changed` control repository | `project_repository_owner_change_control_repository` | `repository` | `project_repository_admin` |
| `project_repository_owner_changed` records App | `project_repository_owner_change_records_app` | `installation` | `records_app_binding` |
| `project_repository_owner_changed` enforcer App | `project_repository_owner_change_enforcer_app` | `installation` | `enforcer_app_binding` |
| `project_repository_owner_changed` trigger App | `project_repository_owner_change_trigger_app` | `installation` | `trigger_app_binding` |
| `project_succeeded` | `project_succeed` | `repository` | `records_repository_admin` |
| `keyring_activated` | `keyring_activate` | `repository` | `project_repository_admin` |
| `agreement_published` | `agreement_publish` | `repository` | `records_repository_admin` |
| `agreement_activated` | `agreement_activate` | `repository` | `records_repository_admin` |
| `agreement_activation_restored` | `agreement_activation_restore` | `repository` | `records_repository_admin` |
| `config_updated` | `project_config_update` | `repository` | `records_repository_admin` |
| repository scope bind | `enforcement_scope_repository_bind` | `repository` | `contributing_repository_admin` |
| repository scope widen | `enforcement_scope_repository_widen` | `repository` | `contributing_repository_admin` |
| repository scope narrow | `enforcement_scope_repository_narrow` | `repository` | `contributing_repository_admin` |
| repository scope remove | `enforcement_scope_repository_remove` | `repository` | `contributing_repository_admin` |
| organization scope bind | `enforcement_scope_organization_bind` | `organization` | `organization_owner` |
| organization scope widen | `enforcement_scope_organization_widen` | `organization` | `organization_owner` |
| organization scope narrow | `enforcement_scope_organization_narrow` | `organization` | `organization_owner` |
| organization scope remove | `enforcement_scope_organization_remove` | `organization` | `organization_owner` |
| bot `exemption` | `exemption_bot_add` | `repository` | `records_repository_admin` |
| individual `exemption` | `exemption_individual_add` | `repository` | `records_repository_admin` |
| `exemption_snapshot` | `exemption_snapshot_add` | `repository` | `records_repository_admin` |
| `exemption_source_withdrawn` | `exemption_source_withdraw` | `repository` | `records_repository_admin` |
| `exemption_rule_configured` / `exemption_rule_withdrawn` | `exemption_rule_configure` / `exemption_rule_withdraw` | `repository` | `records_repository_admin` |
| `records_reader_authorized` | `records_reader_individual_add` | `repository` | `records_repository_admin` |
| `records_reader_snapshot_authorized` | `records_reader_snapshot_add` | `repository` | `records_repository_admin` |
| `records_reader_withdrawn` | `records_reader_source_withdraw` | `repository` | `records_repository_admin` |
| `records_reader_rule_configured` / `records_reader_rule_withdrawn` | `records_reader_rule_configure` / `records_reader_rule_withdraw` | `repository` | `records_repository_admin` |
| `override` / `override_withdrawn` | `override_grant` / `override_withdraw` | `repository` | `contributing_repository_maintain` |
| `retry_requested` | `retry_request` | `repository` | `contributing_repository_write` |

`acceptance`, `revocation`, `exemption_materialized`, and
`records_reader_materialized` are the only v1 events with
`authorizations: []`, under the actor rules above. `project_connected` and
`project_repository_owner_changed` must each contain exactly the seven rows
named for that event, with repository IDs matching its payload and installation
IDs matching the live bound Apps. Every other event must match exactly one row,
except `keyring_activated`, which repeats its row once for every affected
project repository. For a requested/activated/abandoned scope-change chain,
all events repeat the same scope operation token and resource identity; a
different action or authority is not the same change.

The closed `required_authority` enum is exactly
`repository_owner_control`, `project_repository_admin`,
`records_app_binding`, `enforcer_app_binding`, `trigger_app_binding`,
`records_repository_admin`,
`contributing_repository_admin`, `contributing_repository_maintain`,
`contributing_repository_write`, and `organization_owner`. These and every
operation listed above are literal ASCII tokens, not labels.
`repository_owner_control` means current organization-owner authority when the
repository owner is an organization, or the same authenticated numeric account
when it is personal. `project_repository_admin` means current `admin` on the
one repository named by `resource_id`. `records_app_binding` names the
configured records App installation covering the payload's records repository;
`enforcer_app_binding` names the configured enforcer App installation covering
the payload's coverage repository; and `trigger_app_binding` names the
configured trigger App installation covering the payload's control repository.
Each is returned by a fresh GitHub installation/repository binding check and
has its §4 capability for that repository. No implementation may substitute a
GitHub UI label or event type.
`observed_authority` remains the action-time GitHub result or evidence string,
is schema-valid non-empty audit evidence, and is never interpreted as the
required-policy enum.

The remaining row members use these scalar rules. IDs and generations called
"event", "rule", "source", "change", or "project" are non-empty strings.
Repository, pull-request, organization, team, and GitHub user IDs are positive
integers. Keyring `generation` is a positive safe integer; registry generations
are non-negative safe integers. `supersedes_coverage` is a JSON boolean.
`fields` is a closed object whose keys are exactly the configured
field names and whose values are strings; `confirmations` is an array in the
configured display order with exactly
`{"label":<configured label>,"checked":true}` for every configured label.
`digest`, `snapshot_sha256`, and `manifest_sha256` use
`sha256:<64 lowercase hexadecimal characters>`. `tree_oid` and other Git
object IDs use the exact
lowercase hexadecimal object format reported for that repository. Timestamps
use UTC RFC 3339 with whole seconds and a trailing `Z`. Agreement references,
snapshot paths, basis text, instrument references, reasons, and reason codes are
schema-valid non-empty strings unless the table explicitly permits `null`.
`project_slug` is the lowercase ASCII form of the GitHub repository-name
component regex `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`; it is unique only within
`repository_owner.github_account_id`, and `-cla` has no special interpretation.
`check_kind` is `pull_request` or `merge_group`; `check_identity` is a positive
pull-request number for the former and the non-empty merge-group head SHA for
the latter. Unknown enum values, duplicate set members, invalid UTF-8, and
numbers outside JavaScript's safe-integer range are rejected before JCS
encoding.

Entity events are not valid v1 values. The words `entity_authorized` and
`entity_deauthorized` are reserved for the later requirements revision that
defines multi-agreement combination rules; a v1 parser rejects them rather
than guessing their payloads.

Envelope decisions, each closing a specific gap:

- **`payload.subjects` is a list and `actor` is separate.** `REQ-CHECK-2` requires an
  override to identify "the unresolved or uncovered subjects" (plural) and to be
  attributable. A single `subject` field conflated the covered contributor with
  the administrator issuing the override, and could not carry more than one.
- **The override `target` binds overrides to the associated PR's root Git tree
  object**, not to a commit SHA that changes on a history-only rebase and never
  to the merge queue's cumulative synthetic tree (§6.4). GitHub supplies the
  tree object ID; DraCLA does not invent a second content-hashing format.
- **Override grants and withdrawals carry a private reason and optional
  `instrument_ref`.** The reason explains the exceptional one-PR decision in
  the audit record; the reference is only a pointer such as a legal ticket,
  security incident, or dated external instrument, not the instrument's
  contents. Neither field enters the coverage projection or public output.
- **`project_succeeded` closes future legal activity without rewriting
  history.** It gives the old project an authoritative reciprocal link and
  lifecycle state while preserving every prior acceptance and decision.
- **`project_repository_owner_changed` changes routing identity, not legal
  identity.** It records a verified transfer of all three project repositories
  to one new GitHub owner while retaining project ID, slug, recipient, and
  evidence. Partial transfers never become routable.
- **Every mutating contributor or administrative form carries
  `confirmed_canonical_oid`; an acceptance or revocation event preserves that
  value, and a revocation target carries `coverage_tuple`, not
  an acceptance-event pointer.** The tuple is the contributor's stable numeric
  ID, project identity, agreement identifier, and immutable recipient identity.
  Agreement version and repository scope are deliberately absent. Canonical
  order makes the revocation a cutoff over every earlier acceptance for that
  tuple; `confirmed_canonical_oid` identifies the immutable canonical state the
  contributor saw before either action. For every action type, the authenticated
  form binds the exact canonical state that was confirmed and makes a semantic
  no-op or intervening change replay-stable as described in §5.4. `supersedes`
  remains only the `REQ-SIGN-5` correction link between acceptance events.
- **`payload.ref` and `payload.content_commit_oid`** record where the agreement came from and
  the Git commit object ID of its content — `REQ-REC-4` requires the latter
  alongside the digest, and `REQ-AGR-1` explicitly permits an immutable content
  reference in place of inlined text (§6.5). The snapshot in `agreements/` is
  what makes the record survive the reference being deleted.
- **`agreement_published`, `agreement_activated`, and
  `agreement_activation_restored` are separate types.** Publishing preserves
  any number of immutable versions; activating selects exactly one version as
  active and signable; restoring deliberately reinstates the currency state
  established by one prior activation. Keeping them distinct lets a project
  prepare a version without exposing it to contributors and prevents ordinary
  activation from becoming an implicit rollback (§6.5).
- **The published agreement and acceptance target bind immutable recipient
  evidence.** The legal recipient is
  bound into the version and every acceptance rather than read later from
  mutable project configuration. A recipient change creates a successor
  project (§5.5).
- **The `authorizations` array accompanies every administrative event.** Its
  ordered set records every exact operation, GitHub resource, required
  permission or other authority, observed result or evidence, and check time
  from `REQ-REC-8` and `REQ-SEC-6`; the stable actor ID and login snapshot
  remain in `actor`.
- **Automation does not impersonate the rule author.** An
  `exemption_materialized` or `records_reader_materialized` event instead uses
  `actor: { kind: "automation", principal: "worker-portal" }`, references the
  canonical rule or reader-authorization events it evaluated, and records the
  exact GitHub team observation. The earlier administrative rule event
  retains its human actor and action-time authorizations; the later event does
  not claim that human acted again (`REQ-REC-8`).
- **`payload.project_configuration` and scope payloads are event-type-specific.** An
  `enforcement_scope_requested` event carries the complete desired enforcement
  scope. Its later `enforcement_scope_activated` event immutably references that
  request, repeats the exact `desired_scope`, and names the registry generation
  it activates. The repeated value must equal the referenced request's value;
  only activated events enter the current-scope fold. An
  `enforcement_scope_abandoned` event closes a request that never became
  effective. The request keeps its form-issued operation nonce; each terminal
  event uses the deterministic child nonce defined below. Canonical replay
  permits at most one terminal event per request and rejects an activation and
  abandonment, or two different terminal events of one kind, that reference
  the same request. An acceptance omits configuration.
  Enforcement configuration is never copied into signer evidence.
- **`payload.bootstrap` appears only on the first `project_connected` event.** It binds
  the one-time §6.10.2 discovery manifest and candidate keyring to the canonical
  history. Later events omit it; later key selection follows
  `keyring_activated` events only.
- **`payload.fields` is derived from decrypted `config/project.enc.json`, not hardcoded.**
  `REQ-SIGN-3` makes the required set project-configurable and `REQ-SEC-1`
  forbids collecting anything the agreement and policy do not require. The
  schema validates submitted fields against the configured set and rejects
  extras; `confirmations` must carry the exact configured labels with
  `checked: true`, and a `false` is a rejected submission, not a recorded one.

**Naming.** `supersedes` (event linkage) and `supersedes_coverage` (agreement
flag, D10) are unrelated despite the shared word. Implementations should treat
the latter as `invalidates_prior_acceptances`; the requirement-facing name is
kept here only to match D10. `agreement_activation_restored` is the sole
currency operation allowed to reintroduce a retired version; it is not a
synonym for non-superseding activation.

Event files are sharded by `event_id` prefix so existence is a single content
read rather than a history scan.

**Identifier derivation.** An operation attempt starts with exactly 16 random
bytes from the platform CSPRNG. Its unpadded base64url encoding is
`operation_nonce`; a form carries that same value across retries and a new
explicit action receives a new value. For an automation materialization, the
16 bytes are instead the first 16 bytes of SHA-256 over
`"dracla-automation-transition-v1\0" || JCS({rule_event_id, subject_user_id,
result, prior_materialization_event_id})`; this makes one observed transition
retry-stable while a later opposite-and-back transition remains new. A
GitHub-triggered retry uses the first 16 bytes of SHA-256 over
`"dracla-github-retry-v1\0" || JCS({repository_id, check_kind,
check_identity, github_delivery_id})`.

An enforcement-scope terminal event instead uses the first 16 bytes of
SHA-256 over `"dracla-scope-terminal-v1\0" ||
JCS({request_event_id, terminal_type})`, where `terminal_type` is exactly
`enforcement_scope_activated` or `enforcement_scope_abandoned`. The request
event retains the random nonce issued with its authenticated form. Before a
terminal write, the coordinator derives the request, activation-child, and
abandonment-child idempotency keys and requires all three to be pairwise
distinct; an actual digest collision fails closed. The terminal-type
discriminator makes an exact retry derive the same child path while the two
possible outcomes have separate paths. No caller supplies `operation_nonce`
for a child event, or supplies `idempotency_key` or `event_id` directly. In
every quoted domain label, `\0` denotes one zero byte, not the two printable
characters backslash and zero.

```
idempotency_digest = SHA-256(
    ASCII("dracla-idempotency-v1\0")
    || JCS({"project_id": project_id, "operation_nonce": operation_nonce})
)
idempotency_key = base64url_unpadded(idempotency_digest)

operation_digest = SHA-256(
    ASCII("dracla-operation-v1\0")
    || JCS({"project_id": project_id,
            "actor_identity": stable_actor_identity(actor),
            "type": type,
            "target": target,
            "payload": payload,
            "confirmed_canonical_oid": confirmed_canonical_oid})
)
operation_sha256 = "sha256:" || lowercase_hex(operation_digest)

event_digest = SHA-256(
    ASCII("dracla-event-v1\0") || idempotency_digest
)
event_id = base64url_unpadded(event_digest)
```

`stable_actor_identity` is exactly
`{"kind":"github","github_user_id":<id>}` or
`{"kind":"automation","principal":"worker-portal"}`; mutable login snapshots
are evidence but do not change an operation's identity. `recorded_at`,
`dracla_version`, and the action-time authorization evidence set likewise are
recorded but excluded from `operation_sha256`, so a required live recheck does
not turn one retry into a different operation.

For an enforcement-scope terminal child, `request_event_id` and the closed
terminal type determine the child nonce, while the ordinary
`operation_sha256` still binds the exact actor, type, target, payload, and
confirmed canonical identity. Reusing that child key with a different
fingerprint is therefore a conflict, not a second outcome. Because both
potential child paths are derivable from the request, the writer direct-reads
both at the current canonical head before append and again after every
fast-forward race. If the matching child already exists with the same
fingerprint, the retry returns it. If either path contains a different
terminal event, the request is already closed and no append occurs. If neither
exists, one terminal event may append; branch serialization makes a competing
activation or abandonment revalidate against that terminal state and stop.

For acceptance, the target and payload include the agreement recipient,
version, digest, fields, confirmations, and correction link. For revocation,
the target is the complete coverage tuple and the payload states the
forward-looking cutoff. `confirmed_canonical_oid` is required for both. A fresh
nonce makes re-signing after revocation a distinct explicit action even when
the submitted values match an older acceptance; retaining that nonce across
retries makes a lost response collapse onto the original event (`REQ-SIGN-5`).
A derivation using only content would break the first property; one generating
a fresh random value on retry would break the second. `event_id` is a pure
function of the key, so the path existence check in §5.2 is also the
idempotency-key check.

One snapshot confirmation is one canonical event, even though its non-empty
`subjects` set creates one independently withdrawable source per account. The
confirmed set is frozen in RFC 8785 order and is part of `operation_sha256`;
the event ID is therefore the batch identity, one retry cannot change its
members, and the canonical append makes all selected sources effective
atomically. A later withdrawal names both the snapshot event and one subject,
so it removes only that account's source. This avoids a partially appended
N-event snapshot and does not require child nonces or a batch-completion event.

On retry, the server recomputes the key from the project and operation nonce,
then recomputes `operation_sha256` from the authenticated actor identity, type,
target, payload, and confirmed canonical identity. The in-flight entry and the
event both carry that fingerprint. Finding the same key with a different
fingerprint is the required conflict; finding the same key and fingerprint is
the same operation. Readers recompute both digests and require the event ID,
event path, idempotency key, and operation fingerprint to agree. Checked-in
golden vectors cover every valid v1 type, both actor variants, every exact
operation/resource-kind/required-authority row and listed scope operation,
changed-payload reuse, unknown or extra fields, and every encoding boundary
above. Vectors also reject a known token paired with the wrong event, resource
kind, or required authority.

### 5.2 Append-only commit protocol (`REQ-REC-3`)

One logical event per commit; commit ancestry is the authoritative order. An
event commit may also carry only the deterministic side artifacts assigned to
that event type below. Those files are part of the same atomic tree update,
not additional logical events or later commits.

```
0. validate the closed event schema; recompute its idempotency key,
   operation fingerprint, event ID, and path; validate every event-type
   side artifact (§5.4 — before any write)
1. read branch head H
2. derive the complete resulting side-artifact bytes from H and the event
3. encrypt the validated event for its final path and build tree =
   base tree of H
   + events/<aa>/<bb>/<event_id>.enc.json
   + every required event-type side artifact, if any
4. create commit C with single parent H
5. PATCH ref, force = false
6. on 409, or on a 422 specifically reporting a non-fast-forward update:
      reload head H'
      if events/<aa>/<bb>/<event_id>.enc.json exists at H':
         authenticate and validate enough of the event envelope to obtain its
         trusted operation_sha256; an envelope, event-ID, path, or key failure
         is corruption and fails closed
         if its operation_sha256 differs from this request
            -> return the required idempotency conflict without appending;
               the already-persisted valid event remains authoritative
         otherwise verify the complete event and every required side artifact
         against one another (including exact snapshot bytes and decrypted
         config value)
            -> done, idempotent; any mismatch after the matching fingerprint
               is corruption and fails closed
      else
         re-validate the operation against H'         <- may now be a no-op
                                                         or a conflict
         re-derive every side artifact and rebuild the complete tree on H'
         retry from 4 with H'
   on any other 422: report the validation or abuse error; do not retry it as a race
```

The event-type side-artifact set is closed:

- `agreement_published` adds the validated immutable agreement snapshot and
  matching non-private metadata at the two §4-derived agreement paths;
- `project_connected` and `config_updated` replace
  `config/project.enc.json` with the encrypted complete configuration resulting
  from that event;
- `project_connected` creates, and every event that changes a dashboard,
  status-detail, or reader-authority result updates,
  `config/materialization-generations.enc.json`. Each affected class is set to
  that event's `event_id`; unaffected class generations are carried forward;
  and
- every other event type adds no `events`-branch side artifact.

The snapshot bytes, metadata, digest, source commit OID, and event must agree
before publication. Likewise, the config payload, event, encrypted current
config, and any affected materialization generations must agree. A successful
ref update therefore exposes all required files at once; a crash cannot leave a
canonical event whose required side artifact was never committed.

Two things this spelling out prevents:

- **Step 3 must rebuild on `H'`'s base tree, not reuse the tree from the
  previous attempt.** Reusing it and merely re-parenting produces a commit
  GitHub accepts as a clean fast-forward while the concurrent event vanishes
  from the tree. Since §5.1 locates events by path existence, every reader
  short of a full history walk would then believe that event never happened.
- **Step 6 must re-validate, not just re-parent.** A revocation confirmed at
  canonical state `H` that loses the race to a later acceptance for the same
  tuple is stale against `H'`. Re-validation returns the original event if the
  same idempotency key already landed, otherwise requires fresh contributor
  confirmation; it never silently extends the revocation to an acceptance the
  contributor had not seen. A 409 and only the non-fast-forward form of 422 use
  this path. Other 422 responses are not concurrency evidence.

`force: false` is a **fast-forward check, not a compare-and-swap** on `H`. It
guarantees the new commit descends from the current ref, which combined with a
single parent and a tree built on `H'` gives linear history; it does not by
itself guarantee the ref is unchanged since step 1. Earlier drafts labelled
step 4 a compare-and-swap, and the difference is exactly what the tree-rebuild
rule above closes.

Bounded retries with jitter. On exhaustion the operation reports failure to the
caller with an explicit indeterminate marker (§5.4), because the commit may or
may not have landed. No merge commits are ever created. Timestamps never
resolve ordering.

### 5.3 Coverage projection repo (private and encrypted; no names or emails)

```
source.enc.json      { canonical_sha, built_at, dracla_version,
                       project_state: "active" | "succeeded",
                       successor_project_id: string | null }
decision-fence.enc.json
                     one bounded idle/mutation/success-reserved CAS cell (§5.4)
inflight.enc.json    { ops: { "<idempotency_key>":
                         { operation_sha256, started_at,
                           subjects: [user_id, ...],
                           project_wide: boolean } } }
users/<shard>.enc.json packed, keyed by user_id:
                       { "<user_id>": {
                           agreements: { "<agreement_id>": {
                             decision,    "covered" | "uncovered"
                             reason_code, fixed generic enforcement code
                             version, digest } },
                           overrides: { "<override_key>": {
                             repository_id, pull_request_number,
                             subject_user_id, tree_oid,
                             grant_event_id, active: true } } } }
agreements/active.enc.json { agreement_id, active_version,
                          accepted_versions, retired_versions,
                          activation_event_id,
                          projection_format: 1, shard_count: 32 }
exemptions.enc.json { "<user_id>": { active: true } }
.dracla/bootstrap.json       non-secret initial key-discovery manifest (§6.10.2)
.dracla/keys/portal/*.json   coverage-key copies wrapped for worker-portal
.dracla/keys/enforcer/*.json coverage-key copies wrapped for worker-enforce
```

Every listed data file contains §4's envelope. The decrypted projection
contains no legal name, email, confirmation text, entity evidence, exact status
reason, exemption source or instrument, or records-reader authority. Those
details remain in canonical events and records-key derivatives. The enforcer
receives only effective decisions and fixed generic codes needed to select the
bounded check output.

Every user-shard object requires both closed `agreements` and `overrides` maps.
An override member has exactly the six fields shown above; its
`subject_user_id` must equal the containing user key, and recomputing §4's tuple
digest must equal its map key. An empty map is encoded as `{}`; a missing map,
unknown field, duplicate canonical key, false `active` value, or identity
mismatch makes the shard invalid even when that subject's agreement decision is
covered.

An in-flight operation has exactly one scope shape. A subject-scoped operation
has `project_wide: false` and a sorted, duplicate-free, non-empty `subjects`
array. A project-wide operation has `project_wide: true` and `subjects: []`.
The matching mutation fence carries the identical scope. In v1,
`inflight.ops` contains zero or one entry: the single prepared-operation cell
and single mutation fence serialize all project mutations, regardless of
subject. The scope limits which ordinary checks become indeterminate; it does
not permit another mutation to run concurrently. `started_at` is the UTC
timestamp written by the successful CAS that first adds the marker entry. A
retry or recovery that finds the entry preserves its value; recovery that opens
an absent marker uses the time of its own successful marker-open CAS. The field
is operational display metadata only and never authorizes expiry, closure, or
ordering.

**Coverage MUST remain private.** Carrying no names or addresses does not make
it publishable: this is a complete `user_id → covered?` directory, exactly the
public signer lookup `REQ-PORTAL-5` forbids and the requirements' §17 lists as
a non-goal. §8.4 gives the reason in full: the harm is aggregation, not
secrecy. Install verifies private visibility; the records and enforcer scheduled
sweeps recheck it through their repository metadata permission and make the
project route unavailable if any data repository becomes public. DraCLA lacks
repository-administration authority and therefore cannot prevent an adopter
administrator from changing visibility. Every reader independently validates
§4's cryptographic boundary, so detection delay exposes ciphertext and metadata,
not plaintext.

**The shard is keyed by `user_id`; agreement decisions remain keyed by
`agreement_id` inside that user row.** The sibling `overrides` map is keyed by
the exact PR/tree tuple digest. The initial release permits exactly one
agreement identifier per project; keeping the nested agreement key avoids
conflating versions and leaves a compatible schema if a later requirements
revision defines multi-agreement combination rules. Inactive versions are never
signable, so there is no pending-version state.

**The edge performs a tuple cutoff and one bounded version test.** Replay keeps
the latest acceptance or revocation for the repository set's project and
recipient plus `(user_id, agreement_id)`. A revocation makes every earlier
acceptance of every version for that tuple uncovered. A later acceptance
restores coverage from its canonical position onward. If the latest tuple event
permits coverage, its acceptance row provides coverage only when its `version` is in
`agreements/active.enc.json.accepted_versions`. Activation or explicit restore
updates that small file synchronously. Ordinary activation cannot reintroduce a
retired version; restore reinstates one named activation state without changing
the tuple's latest event, so a later revocation or acceptance supersession remains
effective (§6.5). Enforcement scope is resolved by project routing before any
subject row is read; it is not part of the tuple, is not signer evidence, and
does not live in the row.

**Packed shards (D9).** The Free baseline uses 32 files selected by
`user_id % active.shard_count`. A check therefore reads at most 32 coverage
files regardless of subject count, keeping the ordinary pull-request path below
the Workers Free 50-subrequest cap. `projection_format` and `shard_count` are
read after decrypting the same committed `agreements/active.enc.json` revision as the shard
layout; neither value is inferred from which files happen to exist.

The count is projection metadata, not CLA evidence, but it is not configurable
in the initial release. Projection format 1 requires `shard_count: 32`; any
other value is unsupported and fails closed rather than being guessed from the
files. A future profile can in principle rebuild this derived projection from
canonical evidence without changing an acceptance or requiring re-signing, but
live migration is not implemented or specified here. Supporting another count
requires a later design that serializes the rebuild against every projection
writer, binds it to one canonical head, installs source, shards, and metadata
atomically, and defines crash recovery.

**Successful acceptance and revocation events are not capped.** Revision 11
removed the append guard because any finite cap can trap a contributor either
covered or uncovered. Canonical idempotency still returns an already-committed
result for the same operation. Section 5.4 makes every contributor and
administrative semantic no-op replay-stable with authenticated, event-backed
form state, while any non-no-op form becomes stale on an exact canonical-head
mismatch. Neither outcome appends an event or needs a separate receipt store.
The initial release adds no replacement abuse policy; a
future guard may control transport abuse only if it preserves immediate valid
revocation and fresh re-signing (`REQ-REV-1`, `REQ-REV-5`).

**Exemption is source-aware.** `active` is derived as `sources` non-empty, not
stored as an independently mutable truth. Withdrawing one source removes only
that source; another individual, snapshot, or continuous-team source keeps the
account exempt. The authenticated confirmation is generated from the same
source fold and lists every source that remains. The enforcer needs only the
derived `active` result, while the private portal and exports retain source
detail.

**Shard writes use the coverage branch-head compare-and-swap.** A shard is a
packed file, so a write is read-modify-write and racing or delayed writer
attempts would otherwise lose one row — silently keeping a revoked contributor
covered. The writer reads the shard and matching fence at one
immutable coverage head, validates the shard blob identity there, and commits
the complete transition with that head as `expectedHeadOid`. A head mismatch
writes nothing; the writer re-resolves the branch, re-reads the shard, and
re-applies only its own key. The blob SHA is validated read evidence, not a
separate GitHub write precondition. Activations and restores update only
`agreements/active.enc.json`; they do not rewrite all subject shards (§6.5).

### 5.4 Freshness guard (`REQ-CHECK-3`, `REQ-CHECK-4`)

The authoritative merge-group check must evaluate canonical state as observed
when it runs, but the enforcer cannot read canonical. The staleness signal is
therefore placed **inside the coverage repo**.

**Validation precedes every write.** An event and its complete event-specific
side-artifact package are fully validated before the prepared-operation cell is
written — not after, as an earlier draft had it. Canonical is
append-only and cannot be pruned (`REQ-REC-3`), so an invalid event committed
first is permanent, and recovering from it would mean teaching every reader to
filter. Validation before the commit means the log only ever contains events
that passed.

**A durable prepared operation exists before the coverage fence opens.** The
records `operations` branch contains exactly one
`prepared-operation.enc.json` cell, encrypted with the records key. Its closed
decrypted state is one of:

```
{ state: "idle", generation }
{ state: "prepared", generation, operation_id, operation_sha256, event_id,
  prepared_events_head, event_jcs_b64, side_artifacts: [...] }
{ state: "appending", generation, operation_id, operation_sha256, event_id,
  prepared_events_head, event_jcs_b64, side_artifacts: [...],
  append_head, append_claim }
{ state: "terminal", generation, operation_id, operation_sha256, event_id,
  result: "landed | semantic_noop | conflict", observed_events_head,
  canonical_commit }
```

`event_jcs_b64` is unpadded base64url of the exact RFC 8785 semantic-event
bytes. `side_artifacts` is sorted by path and contains no duplicate path; each
closed entry is exactly `{kind,path,bytes_b64,sha256}`, where `kind` is one of
`agreement_snapshot`, `agreement_metadata`, `project_config`, or
`materialization_generations`, `bytes_b64` is the exact final plaintext byte
sequence, and `sha256` is `sha256:` plus its lowercase digest. The array is
empty for an event with no §5.2 side artifact. Readers derive the required set,
paths, encodings, and encryption treatment from the event type and reject an
extra, missing, or mismatched entry. The release profile bounds the complete
cell bytes and rejects an oversized operation before preparation.

`append_claim` is unpadded base64url SHA-256 over
`"dracla-append-claim-v1\0" || JCS({operation_id,operation_sha256,
append_head})`. `canonical_commit` is the landed event commit OID only for
`landed` and is otherwise `null`. Every state transition resolves one immutable
`operations` branch head and validates the current cell blob SHA and state at
that head. An identical preparation returns the existing state; a different
operation cannot replace a non-idle cell. The cell contains the complete
authorized submission and exact side-artifact inputs, so recovery never needs
the original browser, session, or request body. It contains records plaintext
only inside the records-key envelope; the coverage fence carries only its
opaque commit, blob, and generation identities.

**Operations and coverage transitions are branch-wide CAS commits.** A writer
on the records `operations` branch or coverage branch resolves one immutable
branch head, reads and validates every input at that head, and uses GitHub GraphQL
[`createCommitOnBranch`](https://docs.github.com/en/graphql/reference/commits#createcommitonbranch)
with that exact
`expectedHeadOid` and the complete file-change set for the transition. A head
mismatch performs no write and forces a fresh read. This applies even when the
transition changes only one file. In particular, each coverage commit validates
the matching mutation fence from the same expected head as the marker or
projection files it changes. A delayed writer therefore cannot add an old
marker or projection after recovery returns the fence to idle: its expected
head is stale, while a fresh head exposes an idle or different fence and is
ineligible.
This branch-wide CAS contract does not apply to the canonical `events` branch.
Canonical append uses §5.2's Git Database commit plus non-forced fast-forward
ref update, followed on conflict by reload, rebuild, and semantic revalidation;
it is deliberately a different primitive.

**The marker is written before the commit and names the one current
operation.**

```
mutating contributor or administrative submission  (Worker):
  0. authenticate the exact server-issued form state below and its operation;
                                                        <- no write yet
     idempotent retry -> return the original event
     terminal_noop_event_id present -> direct-read and validate that immutable
       event from the exact confirmed commit; return the same no-op
       result on every retry; no write or event
     terminal_noop_event_id null -> require current events head exactly equals
       confirmed_canonical_oid; any advance is a terminal fresh-confirmation
       conflict, even when unrelated; no history scan and no write
     freeze the exact event and event-specific side-artifact package
  1. CAS prepared-operation.enc.json from idle to prepared
                                                        <- recovery payload durable
  2. CAS decision-fence.enc.json from idle to
     mutation { operation_id, operation_sha256, subjects, project_wide,
                prepared_commit_oid, prepared_blob_sha, prepared_generation }
                                             <- blocks authoritative success;
                                                scopes ordinary checks
  3. CAS-add idempotency_key ->
       { operation_sha256, started_at,
         subjects: [user_ids], project_wide: false }
     to an empty inflight.ops; an identical retry may observe its existing
     entry, but no different operation may coexist  <- marker OPENS here
  4. re-read and semantically revalidate while holding the prepared cell,
     mutation fence, and marker; a no-op/conflict moves prepared -> terminal,
     closes the marker, clears only the matching fence, then returns the cell
     to idle
  5. CAS prepared -> appending for the exact current events head and claim
  6. commit the frozen event and side artifacts to canonical        (§5.2)
  7. write users/<shard>.enc.json           (CAS, §5.3)
     write source.enc.json { canonical_sha, project lifecycle fold }
                                                        <- effective here
  8. remove idempotency_key from inflight.enc.json (CAS) <- marker CLOSES here
  9. read back the resulting projection; CAS appending -> terminal(landed),
     then CAS the exact mutation fence to idle with generation + 1
 10. after fence read-back, CAS that terminal operation cell to idle;
     re-evaluate the originating pull request, if any

enforcer, on every ordinary pull-request check:
  resolve the coverage branch once -> immutable coverage_sha C
  unwrap the route-bound coverage key; decrypt decision-fence.enc.json,
  source.enc.json, and inflight.enc.json at C; require schema-valid state and
  source.project_state == "active"
  succeeded -> action_required with the validated successor route
  missing, unknown, or inconsistent lifecycle -> unavailable
  idle fence -> require inflight.ops empty
  success_reserved fence -> require inflight.ops empty; coverage is unchanged
  mutation fence -> require every present inflight entry to match it exactly;
                    an absent entry is the bounded pre-open/post-close state
  if mutation.project_wide:
        the project is indeterminate -> in_progress; never pass
  if any of MY subjects appears in mutation.subjects:
        that subject is indeterminate -> in_progress; never pass
  if any in-flight entry is extra or mismatched -> unavailable
  else decrypt agreements/active.enc.json, exemptions.enc.json, and the
       required shards at C, validate every §4 binding, and decide

authoritative merge-group success:
  perform the same evaluation, but require the fence idle and reserve it by
  the protocol below before publishing success; any non-idle state is non-pass
```

**One check reads one projection commit.** The enforcer resolves the coverage
branch to immutable commit `C` once, then addresses every projection file by
that commit rather than through a moving branch ref. The marker, active
agreement, exemptions, subject rows, and wrapped-key metadata therefore
describe one internally consistent observation. The published check records
`C`, the coverage `kid`, and the projection generation for audit and retry.

**Successful authoritative publication has specified completion ordering.**
`decision-fence.enc.json` in the existing coverage repository is the one
coverage-side serialization cell that orders check publication against
mutations. It is a §4-encrypted bounded object whose
decrypted state is exactly one of:

```
{ state: "idle", generation }
{ state: "mutation", generation, operation_id, operation_sha256,
  subjects: [user_id, ...], project_wide,
  prepared_commit_oid, prepared_blob_sha, prepared_generation }
{ state: "success_reserved", generation, check_identity, projection_commit }
```

At one immutable coverage branch head, every transition validates the current
encrypted fence blob SHA and decrypted state, then supplies that branch head as
`expectedHeadOid` for the complete commit. The blob identity is the logical
state precondition validated at that immutable head; GitHub's remote write
precondition is the branch head. Identical retries return the existing state;
a stale or different transition conflicts. `operation_id` is
the event's server-computed
`idempotency_key`; the other mutation fields equal the request, prepared cell,
and later in-flight marker exactly. The three prepared identities bind the
mutation to one immutable records commit and envelope blob. Every
coverage-changing writer prepares that cell first, then changes `idle` to its
`mutation` state before opening `inflight.enc.json`; it may write canonical or
any projection file only while that exact mutation and its matching non-idle
prepared cell remain current. After canonical outcome, projection update,
read-back, and marker close, it changes only its own mutation state to `idle`
with the generation incremented, then clears only the matching terminal
prepared cell. A success reservation and a mutation therefore race on one
coverage branch-head CAS over the same fence state: exactly one can start,
without another database.

An authoritative merge-group check may publish success only through this
sequence:

1. resolve one immutable projection commit `C`, require its fence `idle`, retain
   that encrypted fence blob SHA, evaluate the remaining files at `C`, and
   derive a deterministic check identity from repository, merge-group head,
   associated PR, and delivery;
2. reserve success by replacing that exact idle fence blob with
   `success_reserved(check_identity, C)`. If any mutation or reservation changed
   the branch after `C`, the expected-head precondition conflicts and the check
   restarts;
3. while that reservation exists, new mutations cannot begin. Immediately
   before success, call §7.2's `reserve_publication(check_identity,
   expected_route)` method on the repository's strongly consistent gate. The
   method atomically repeats the complete signed-route comparison and installs
   a publication reservation on that exact active route. If pending,
   unavailable, another generation, or another publication wins first, create
   or confirm only the named non-passing result before clearing the coverage
   reservation;
4. while both reservations remain held, create the named GitHub check run
   directly as completed `success` and validate the create response's external
   identity, expected head, status, and conclusion. Then replace only the exact
   coverage reservation with `idle` at the next generation. The routing
   reservation is deliberately not cleared by this request: an authenticated
   `check_run` completion delivery, or scheduled recovery after an exact GitHub
   read, must independently confirm the completed run under `check_identity`
   before the gate's matching `confirm_publication` may clear it. Thus a
   `begin_pending` arriving after `reserve_publication` but before GitHub accepts
   success still conflicts. A missing or ambiguous create response keeps both
   reservations for recovery rather than issuing another success blindly; and
5. if reservation fails because a mutation is open or the coverage head is stale,
   publish no success—return a conservative non-passing result or restart from
   the newer coverage commit.

`check_identity` is the unpadded base64url SHA-256 of
`"dracla-authoritative-check-v1\0" || JCS({repository_id,
merge_group_head_oid, pull_request_number, github_delivery_id})`. The
authoritative check run's `external_id` is exactly
`"dracla-authoritative-v1." || check_identity`. Every ordinary pull-request
check uses the disjoint `dracla-ordinary-v1.` prefix, and no unknown or ordinary
namespace is eligible for publication confirmation. Recovery after a lost
create response lists only this App's check runs with the fixed DraCLA name,
exact authoritative prefix, and exact head, bounded to 100. A successful create
response needs no redundant normal-path read-back. A lost or ambiguous response
with zero matches creates and reads back one completed non-passing run under
that external ID before clearing the reservations. Exactly one match is read
back and either confirms completed success or is completed non-passing before
the matching coverage and routing reservations are cleared.
A truncated result or multiple matches remains reserved and requires operator
reconciliation; neither reservation clears from elapsed time.

Only successful authoritative publication needs the two reservations; a
conservative non-passing result cannot admit uncovered work. If the Worker
loses a response after reserving, repository state keeps mutations blocked and
the routing gate keeps transitions blocked. Recovery reads the check run by
stable external identity and either confirms its completed success or
creates/replaces it with a non-passing conclusion before clearing the exact
reservations through their separate conditional methods. Neither reservation
is cleared by elapsed time alone. For authoritative publication, a missing,
corrupt, unavailable, or non-idle fence, or a missing or mismatched gate
publication reservation, is non-passing. An ordinary pull-request check may
evaluate a schema-valid `success_reserved` state or a non-overlapping
subject-scoped `mutation` as specified above; neither permits authoritative
success.
Install creates the schema-valid idle fence alongside the empty projection and
the schema-valid idle prepared-operation cell on the records `operations`
branch;
reconciliation reconstructs it only from canonical replay plus a complete,
read-back-verified coverage rebuild while the project route is unavailable.

An open mutation is likewise never cleared because it is old or because its
separate in-flight marker is absent. Recovery verifies the fence's immutable
prepared commit, blob, generation, operation fingerprint, event ID, and
records-envelope binding before doing anything. A prepared cell with an idle
fence acquires that fence when it becomes available; a mutation fence repairs
or opens its marker. If the event exists, recovery verifies the exact frozen
package, completes projection, and lands the terminal state. If it does not,
recovery revalidates the frozen package against the current events head and
continues it without the original request.

The `prepared -> appending` CAS is the append right. Recovery may record a
terminal no-op or conflict only by winning that CAS race while the cell is
still `prepared`. If `appending` already won, recovery must finish or
idempotently discover that exact event; it cannot abandon the operation. A
non-fast-forward canonical race either finds the exact event or revalidates at
the new head and CAS-updates the append claim before retrying. Consequently, a
writer based on an older head cannot land after terminal recovery: its events
ref fast-forward update fails and its stale prepared-cell CAS cannot acquire a
new append right. No cell or fence state is cleared from elapsed time alone.

The same branch-head rule covers non-canonical delayed writes. Recovery from an
`appending` state opens or confirms the marker itself before proceeding, and
every later coverage transition uses the head that contained the matching
mutation fence. A delayed original marker, shard, source, or marker-close
commit based on an earlier head conflicts after recovery advances the branch;
it cannot recreate a stale marker or regress a repaired projection.

The fence returns to idle only after a terminal canonical outcome, complete
projection effect when one is required, marker close, and read-back are
established. The prepared cell returns to idle only after that fence transition
is read back. A crash before fence acquisition leaves a recoverable prepared
cell; a crash after fence acquisition leaves both identities cross-bound; a
crash after canonical append is repaired forward. A missing, mismatched, or
corrupt pair keeps the route unavailable and requires the control reconciler;
a different operation cannot replace it.

This fence makes the baseline's authoritative completion rule exact against
coverage mutations. A mutation that starts before authoritative publication
changes the fence state and makes the success reservation conflict. A check
whose success completes while holding the coverage reservation precedes any
later mutation, while §7.2's independent gate reservation orders that same
completion before any later routing transition. Neither kind of later change
retroactively rewrites the decision.

Opening the marker **before** the canonical commit is the whole point. A crash
anywhere after step 3 and before step 8 leaves the marker open, so affected
ordinary checks and every authoritative success fail closed. The
earlier ordering wrote the pointer *after* the commit, which meant a crash
between them left two pointers agreeing on stale state — reporting fresh while
canonical held a revocation. That failed **open**, at the authoritative gate,
and a contributor could induce it by retrying revocation under load.

The marker remains keyed by operation even though v1 permits at most one entry.
That key gives retries and closure an exact owner: an unrelated operation
cannot repair or close the current operation merely because it later writes a
valid projection. The map shape does not provide mutation concurrency.

For sign and revoke, the prepared cell and fence act as one project mutation
lock. A retry carrying the same idempotency key and `operation_sha256` resumes
or returns that operation; the same key with another fingerprint is an
immediate conflict. Any different mutation waits and retries after the current
operation settles, even when it names different subjects. Before it wins the
idle-to-prepared CAS, it is not accepted or durable. During the bounded wait,
the portal shows “Another project update is finishing; retrying.” Exhaustion
reports that the submission was not made and may be retried. Once prepared,
recovery no longer depends on the caller. After taking the lock, the writer
re-reads canonical tuple state at the still exact confirmed head so the request
becomes an idempotent result or one valid next event. A changed head was already
rejected before preparation as a fresh-confirmation conflict. Successful
acceptance and revocation are not capped.

**A no-op cannot become a later write, and proving that is bounded.** The
server-authenticated form state payload is the closed object
`{"v":1,"algorithm":"HS256","kid":<base64url 128-bit key ID>,
"session_jti":<session ID>,"github_user_id":<positive integer>,
"project_id":<string>,"type":<one exact Table 5.4-A value>,
"operation_nonce":<base64url 128-bit value>,
"confirmed_canonical_oid":<Git object ID>,
"operation_sha256":<digest>,"terminal_noop_event_id":<event ID|null>,
"issued_at":<timestamp>,"expires_at":<timestamp>}`. Timestamps are UTC RFC 3339
whole-second values. `issued_at <= expires_at` and `expires_at` is no later than
both `issued_at + 7 h 55 min` and the parent session's absolute expiry. The
dedicated action-form HMAC key ring is a `worker-portal` secret capability
separate from session AEAD and private-read proof keys.

Let `P` be the exact RFC 8785 bytes of that payload and `T` be
`HMAC-SHA-256(key[kid], ASCII("dracla-action-form-v1\0") || P)`. The one hidden
POST field is exactly `base64url_unpadded(P) || "." ||
base64url_unpadded(T)`. The handler requires one separator, strict unpadded
decoding, a 32-byte tag, byte-for-byte canonical payload encoding, `v: 1`,
`algorithm: "HS256"`, and a known active or still-eligible predecessor `kid`
before constant-time tag verification. It then requires the current live
session, actor, project, operation, and recomputed digest to match, and requires
`issued_at <= current_time < expires_at` under the bounds above.
Unknown fields, algorithms, versions, keys, or encodings fail closed. Eligible
state cannot be renewed without rendering the complete action again.

`type` is the exact canonical event type hashed into `operation_sha256`, not a
second UI-only name. Table 5.4-A is the closed form-action registry; no other
event type may be submitted through an authenticated portal form.

| Table 5.4-A form `type` | Event write for a non-no-op | Allowed `terminal_noop_event_id` type |
|---|---|---|
| `acceptance` | `acceptance` | `acceptance` |
| `revocation` | `revocation` | `revocation` |
| `project_connected` | `project_connected` | `project_connected` |
| `project_repository_owner_changed` | `project_repository_owner_changed` | `project_repository_owner_changed` |
| `project_succeeded` | `project_succeeded` | `project_succeeded` |
| `keyring_activated` | `keyring_activated` | `keyring_activated` |
| `agreement_published` | `agreement_published` | `agreement_published` |
| `agreement_activated` | `agreement_activated` | `agreement_activated` |
| `agreement_activation_restored` | `agreement_activation_restored` | the named target `agreement_activated`, or an `agreement_activation_restored` that names the same target activation |
| `enforcement_scope_requested` | fixed `enforcement_scope_requested` → `enforcement_scope_activated` protocol (§7.1) | `enforcement_scope_activated`, whose repeated `desired_scope` exactly equals the form operation |
| `exemption` | `exemption` | `exemption` |
| `exemption_snapshot` | `exemption_snapshot` | `exemption_snapshot` |
| `exemption_rule_configured` | `exemption_rule_configured` | `exemption_rule_configured` |
| `exemption_rule_withdrawn` | `exemption_rule_withdrawn` | `exemption_rule_withdrawn` |
| `exemption_source_withdrawn` | `exemption_source_withdrawn` | `exemption_source_withdrawn` |
| `records_reader_authorized` | `records_reader_authorized` | `records_reader_authorized` |
| `records_reader_snapshot_authorized` | `records_reader_snapshot_authorized` | `records_reader_snapshot_authorized` |
| `records_reader_withdrawn` | `records_reader_withdrawn` | `records_reader_withdrawn` |
| `records_reader_rule_configured` | `records_reader_rule_configured` | `records_reader_rule_configured` |
| `records_reader_rule_withdrawn` | `records_reader_rule_withdrawn` | `records_reader_rule_withdrawn` |
| `override` | `override` | `override` |
| `override_withdrawn` | `override_withdrawn` | `override_withdrawn` |
| `retry_requested` | `retry_requested` | none; the field must be `null` |
| `config_updated` | `config_updated` | `config_updated` |

The handler requires the submitted `type`, its target and payload schema, and
any non-null terminal event type to match exactly one table row before it
interprets the operation. Internal automation and recovery types — including
`enforcement_scope_activated`, `enforcement_scope_abandoned`,
`exemption_materialized`, and `records_reader_materialized` — are never form
types. Unknown, unsupported, or mismatched action/event pairs fail before any
write. At issuance, the portal reads
one immutable canonical head and the operation's current replay fold. If the
exact desired effect is already true, it sets `terminal_noop_event_id` to the
canonical event that establishes that effect; otherwise it sets the field to
`null`. This includes, for example, an already-active agreement and an
already-current configuration. The event is
required to belong to the same project, use one terminal-evidence event type
allowed for that portal action, and carry the target and payload fields that
establish the form's exact desired effect. For a scope action, the direct-read
`enforcement_scope_activated` event's `desired_scope` must exactly equal the
form operation; no request-event dereference is needed on this replay path.
Its actor, nonce, idempotency key, and `operation_sha256` may differ because it
is the prior event that made the new submission a no-op; the authenticated form
separately binds the new actor, nonce, and operation digest.

For an agreement restore no-op, the terminal event must be the current currency
transition in the replay fold. A target `agreement_activated` qualifies only
when its event ID is the form's named `activation_event_id`; a prior
`agreement_activation_restored` qualifies only when it names that same target.
In either case its resulting or repeated `accepted_versions` must exactly equal
the requested set. `reason` is attributable audit context for a transition that
actually writes, not part of currency-state equality. These checks require one
deterministic event read and never a history scan or agreement-text comparison.

An eligible no-op retry reads that event's deterministic path from the exact
`confirmed_canonical_oid` commit and verifies those fields; it returns the
original no-op even if a later event changed current state. It can never enter
the prepared state. An eligible request may enter preparation only while the
current events head exactly equals `confirmed_canonical_oid`; any head advance,
expiry, or malformed state requires a freshly rendered action. The mutation
lock then preserves that head through final semantic revalidation. This makes
every contributor and administrative no-op replay-stable for the form's
eligible lifetime, adds at most one direct read only on the no-op path, and
requires no append, suffix scan, receipt database, or unbounded receipt store.
Expiry can require a new form but can never turn the old submission into a
write.

**Scoping to subjects where possible** bounds the ordinary-check blast radius.
A sign or revoke makes only its own subjects indeterminate; an ordinary check
whose subjects do not overlap may continue from its one immutable projection
commit. An activation is deliberately project-wide because it changes version
currency for every subject; only administrators can open that marker under
`REQ-SEC-6`. The single fence remains global for authoritative merge-group
success: any mutation state prevents the success reservation, even when its
subjects do not overlap.

**Ownership is explicit.** On the normal path, only the Worker that opened a
marker entry may remove it in step 8. The reconciler may close it only through
the same prepared state machine: an existing exact event is projected and completed; an absent
event causes revalidation and continuation of the frozen operation; and only a
still-`prepared` operation may become an explicit terminal no-op or conflict.
Neither event absence nor age authorizes closure, and recovery may never
regress `source.enc.json`. Without that rule the reconciler, regenerating both
from its own replay head, could overwrite a newer marker and make a stale
projection look fresh — passing a contributor who had already revoked.

**Every canonical writer participates**, not just sign/revoke: agreement
publication, overrides, exemptions, and administrator commits all open and
close a marker and begin and finish a project-fence mutation — a guard
that only one code path maintains is a liveness
signal for that path, not a freshness proof for canonical. Agreement currency
transitions carry their own project-wide marker, append canonical, update
`agreements/active.enc.json`, and then close the marker (§6.5), using the same
open-before-commit, interrupted-operation-recovery lifecycle as every other
writer.

**Recovery has two drivers.** An operation interrupted by a crash would
otherwise wedge its scope indefinitely, and `REQ-OPS-3` forbids a durable job
queue.

*Opportunistic, in the Worker.* Any later portal request that encounters the
non-idle prepared cell or fence drives recovery before attempting another
mutation. The Worker checks whether that operation's event actually landed in
canonical. If it did, the Worker completes the materialization and closes the
marker itself. If it did not, the Worker revalidates and continues the frozen
operation under the prepared/appending protocol above; it never closes the
marker merely because the event is absent or the operation is old. This costs
nothing and repairs most interrupted operations promptly.

*Dispatched and scheduled, in Actions.* After a synchronous materialization
fails or remains unresolved, `worker-portal` asks the trigger-only App to
dispatch the pinned control-repository workflow. A **daily** control-repository
`schedule:` is the missed-dispatch backstop. Both run the same replay and repair
path; neither executes code from canonical or coverage.

*Scheduled, in the enforcer service.* A daily Cron Trigger in
`worker-enforce` uses the enforcer App installation to find in-scope pull
requests with absent checks and to re-evaluate checks left `in_progress`. This
is deliberately not an Actions duty: the control reconciler has only
records/coverage transport keys and cannot enumerate contributing repositories or write
their check runs.

*Scheduled, in the portal service.* A daily Cron Trigger in `worker-portal`
drives membership observations for continuous reader and exemption teams. The
Cron coordinator reads the registry and fans out bounded service-binding calls
so each project scan is a separate Worker invocation with its own subrequest
limit. Fan-out pages are stateless and derived from the registry; no durable
queue or cursor becomes a source of truth. A project scan that exceeds its
documented pagination bound is indeterminate and never authorizes a partial
team result.

A GitHub membership change or an observation of it is not itself authoritative
DraCLA state. The derived source changes only when its canonical automation
event commits. For continuous **exemptions**, failure before the subject marker
opens or before that event commits leaves the prior canonical source valid and
schedules the ordinary webhook/daily retry; check correctness never depends on
unrecorded live membership. For continuous **records readers**, the same rule
governs canonical materialization, but a materialized source does not by itself
authorize plaintext: every disclosure also performs §6.10.4's live membership
check. An absent, unavailable, or indeterminate result denies the response
immediately and schedules materialization or withdrawal. A newly joined member
is not authorized until the canonical addition commits; a departed member is
denied before the canonical withdrawal commits. Once a marker opens, the
existing generation guard independently keeps the affected subject fail closed
until the event and projection update complete or reconciliation repairs them.

For continuous exemption rules, the portal obtains team membership from the
records installation when it can observe that organization, or asks
`worker-enforce` for a service-authenticated membership observation from the
bound enforcer installation. A rule is rejected unless one of those paths can
enumerate the team. Each observed join or departure is one serialized mutation:
it opens the affected subject marker, appends one automation-attributed
materialization or source-withdrawal event, updates the source fold, and closes
the marker before the scan starts another mutation. If a scan stops before the
idle-to-prepared CAS, no operation is durable and a later observation may retry
it. If it stops after preparation or marker open, §5.4 recovery completes that
exact frozen operation before the scan proceeds. Only the current operation's
scope is indeterminate; already completed changes remain effective.
Organization membership webhooks are a latency-reducing doorbell; the daily
full observation is the recovery path.

Daily rather than six-hourly because the dispatch path handles failed
materialization promptly, while opportunistic repair handles most marker
interruptions. Agreement activation or restore and successful bounded
derived-shard updates are request-driven; exports are explicit only. Check
recovery has the separate enforcer schedule above; team observation has no
Actions-minute cost. §9.2 gives the remaining cost.

That re-drive is a recovery optimization; per `REQ-CHECK-4` core correctness
does not depend on either driver, because the guard fails closed without them.

**Retry exhaustion is explicit.** If §5.2's bounded retries are exhausted the
operation may or may not have committed. The decision fence and any opened
marker stay non-idle, the subject stays indeterminate, and the operation remains
blocked until settled. The caller is told the submission is unresolved rather than
failed, and the reconciler settles it on its next run.

This is what lets the merge-group result honestly be called authoritative.

---

### 5.5 How many repository sets a project needs

A DraCLA *project* has a stable project identity, one immutable legal recipient,
exactly one initial-release agreement identifier, and an independently
configured enforcement scope. It is not a GitHub repository. Each project has
exactly one three-repository set and independent data keys, routing, recovery,
and evidence. That set enforces the project's agreement across every repository
in its enforcement scope. Whether one acceptance legally covers those
repositories is stated by the agreement, not inferred by DraCLA.

```
one project, many code repos       ->  one set
  acme/acme-cla-records                private encrypted evidence
  acme/acme-cla-coverage               private encrypted projection
  acme/acme-cla-control                private key-bearing workflow
    recipient: Acme Foundation
    enforcement_scope: acme/*, acme-labs/widget  <- the CODE repos
    agreements/<agreement_token>/…       one agreement, versioned (§6.3, §4)

two projects, even for one recipient -> two sets
  foundation/projx-cla-records         project: Project X
  foundation/projy-cla-records         project: Project Y
```

No project shares canonical history, data keys, recovery material, or coverage
with another project. This keeps the project and recipient fields distinct and
makes the cross-project isolation required by `REQ-OPS-6` structural.

**The recipient is fixed when the project is connected, and is immutable
thereafter.** `REQ-CONFIG-2` makes it a required configuration input, and the
portal collects it at connect time (§6.10.3) — install prompts for nothing and
takes only where to put the repositories. The legal identity is recorded as an
event with an actor.

It cannot later be edited: past acceptances granted rights to a
specific legal entity, and those grants cannot be retroactively reassigned.
Changing recipient is therefore a **new project with a new repository set** — the
contributors sign the new agreement, and the existing records remain as
evidence of what was granted to the original entity. Editing it in place would
leave grants to two different legal entities in one repository, the exact
mixing this section exists to prevent.

When the new project is a legal successor rather than unrelated, its first
`project_connected` event carries `successor_of: <old-project-id>`. After the
portal verifies that event and the successor's active agreement, the old project
appends `project_succeeded`, naming the successor project and connection event.
That old-side event is materialized under the ordinary project-wide marker and
decision fence into `source.enc.json` as `project_state: "succeeded"` with the
immutable successor identity. The portal and enforcer resolve that ID through
the signed registry to the successor's current owner-qualified route, so a
later account rename or authorized repository-owner transfer cannot strand the
old project's link. The portal
checks the canonical fold before every write; the enforcer checks that
coverage-side state before every decision. It immediately closes new signing,
agreement publication or activation, exemptions, overrides, configuration
changes, repository-owner transfer, and new enforcement bindings. Future
checks still routed to the old
project return non-passing `action required` with the successor link until
their scope entries move. Missing, stale, or inconsistent lifecycle state fails
closed like any other projection mismatch.
Revocation, scope removal, reader-policy maintenance, key rotation, audit,
export, backup, and recovery remain available. Existing acceptances and checks
completed before the event keep their original recipient and decision.

The event validator encodes that state machine, rather than relying on disabled
buttons. After `project_succeeded`, only revocation, enforcement-scope removal,
reader-source or reader-rule withdrawal and maintenance, key rotation, retry,
audit/export, backup, recovery, and the automation needed to finish those
operations are admissible. A second or conflicting successor closure is a
semantic conflict. Replaying the event always reconstructs the same closed
state; deleting or rolling back the projection cannot reopen the project.

Successor migration explicitly removes each old enforcement-scope entry, waits
for that registry generation, and then binds it to the successor, as §7
requires. The old portal becomes a historical page headed “Succeeded by …” and
cannot silently resume future legal activity. Partial spin-outs that leave the
old project active are ordinary new projects and scope moves, not legal-successor
closure.

**Repository naming keys on the project slug**, scoped by the GitHub account
that owns the three project repositories. For the first project, the slug
defaults exactly from that account's case-folded login; no suffix has special
meaning (§6.10.3):

```
hydra-ecosystem/hydra-ecosystem-cla-records  first project; slug defaulted
hydra-ecosystem/projx-cla-records             another project; explicit slug
```

**Initial release.** One `dracla install` provisions one project set and
defaults its project slug from the owner name. Explicit same-owner project slugs
are an additive CLI input; they do not change the one-set-per-project rule.

Consequences of a project spanning many contributing repositories:

- A key controller for the set can cause authorized code to expose signer data
  across everything it covers; ordinary repository read access reveals only
  ciphertext.
- A substantive version activation applies to every current acceptance for the
  agreement at once. The `supersedes_coverage` flag (D10) confines this to
  genuinely substantive changes, but within a project it is all-or-nothing.
- A later spin-out to a different recipient means splitting records, which is
  harder than transferring a repository.

## 6. Key flows

### 6.1 Signing (`REQ-SIGN-1..5`, `REQ-PORTAL-1`)

The project page lives at a stable, owner-qualified registry path. The default
project uses `/p/<repository-owner-login>`; an additional project uses
`/p/<repository-owner-login>/<project-slug>`. The registry resolves these
human-readable aliases to immutable `(repository_owner.github_account_id,
project_slug, project_id)` identity, so an account rename changes the preferred
alias and leaves an authenticated redirect rather than changing the project.
Badges and check outputs use the current preferred path (`REQ-PORTAL-1`,
`REQ-PORTAL-2`).

1. Contributor opens the project page. The agreement, recipient, version, and
   required fields are readable **before** login (§6.6), as `REQ-AGR-3`
   requires; authentication via `dracla-records` OAuth is needed only to see
   personal status or to act.
2. Portal renders the complete agreement, recipient, version, required fields,
   the project privacy policy link (`REQ-SEC-3`), and a retention
   statement — evidence is retained after revocation. `REQ-SEC-7` requires this
   on the signing flow, not only on revocation, and per-project retention and
   correction procedures come from decrypted `config/project.enc.json`. Any legal-scope
   language comes from the agreement text itself.
3. After authentication, the portal issues a form that binds a fresh operation
   nonce and the current canonical head as `confirmed_canonical_oid` to the
   displayed agreement, recipient, version, fields, and confirmations. The
   contributor submits that bound affirmative action.
4. Handler validates the binding and applies §5.4's bounded outcome rule. An
   event-backed no-op form always returns that same no-op. Any other action
   commits an acceptance and materializes coverage only when the current
   canonical head still exactly matches the displayed head; otherwise the
   contributor must view and assent again.
5. If a PR context was carried in the browser-bound `state` (§8.2), the handler
   re-evaluates that specific pull request (`REQ-CHECK-4`) — no global rescan.
   Failure here is retried, and the enforcer's scheduled sweep re-drives any
   pull request left unevaluated; the contributor cannot re-request the check
   themselves, since GitHub restricts that to users with write access.

**The status a viewer sees is their own, and is read by session.** The portal
never accepts a user id parameter. `REQ-PORTAL-5` forbids the unauthenticated
version of that lookup outright; this design also declines the *authenticated*
version for viewers without current records-reader authorization, on §8.4's aggregation
argument — §6.3's graded disclosure, gated on the same authorization as the
dashboard, is the one deliberate exception. The viewer's subject comes from the
verified session, exactly as on the write path.

**During the materialization window** the portal reads canonical, not the
projection, and labels the state *recorded, taking effect*. `REQ-PORTAL-1`
requires exact status: reading the projection would show "not signed" moments
after signing, and reading canonical without the label would show "signed" while
checks still fail. Naming the intermediate state is the only accurate answer.

Corrections require a fresh signing flow producing a new event linked via
`supersedes`; the original is never modified (`REQ-SIGN-5`).

### 6.2 Revocation (`REQ-REV-1..5`)

The portal lists status and actions separately for each agreement; v1 exposes
no cross-project, cross-agreement, or cross-recipient revoke-all action. The
confirmation screen identifies the project, agreement, and immutable legal
recipient. It states that revocation affects future merge decisions in every
repository where that tuple is enforced, including repositories added later,
but neither deletes evidence nor withdraws rights already granted, and it
repeats the retention statement (`REQ-SEC-7`).

The form binds the §5.4 authenticated action state, including a fresh operation
nonce and `confirmed_canonical_oid`, to the complete coverage tuple. On
submission, an event-backed no-op form returns its original result; otherwise
the handler requires an exact canonical-head match, then appends one revocation event and folds it as a
canonical-order cutoff over every earlier acceptance of every version for the
tuple. A retry with the same nonce returns the original result. Reusing the
nonce with changed data is a conflict. If a later acceptance lands after
confirmation but before append, the stale revocation is rejected and the
contributor must confirm again.

The success screen says that revocation succeeded, names the project,
agreement, and recipient, and explains that the earlier acceptances remain in
history but no longer cover future merge decisions. It immediately offers
**Restore coverage**, which opens the active agreement with the tuple already
selected and still requires the contributor to read it and assent again. That
fresh acceptance restores coverage only from its own canonical position; it
never mutates an acceptance or the revocation.

### 6.3 Pull request check (`REQ-CHECK-1`, `REQ-CHECK-2`)

```
pull_request opened / synchronize
  -> authenticated repository or installation facts differ
     from the signed route                                      -> temporarily unavailable;
                                                                  reconcile (§7.2)
  -> signed route and strongly consistent gate do not match     -> temporarily unavailable (§7.2)
  -> registry route is a multiple-project conflict             -> action_required (§7)
  -> registry route is pending or unavailable                  -> temporarily unavailable (§7)
  -> repository is verified unmanaged                          -> no DraCLA check (§7)
  -> resolve subjects:
        PR opener
        every commit author        (GitHub-resolved user ID)
     dedupe by numeric user ID
     Co-authored-by: trailers are collected but NOT subjects  (§6.3.1)
  -> commit listing incomplete (pagination bound or >250)  -> action_required
  -> any subject unresolved to a user ID                   -> action_required
  -> resolve the associated PR number and its current head's root tree OID;
     ordinary checks take the tree from the exact event head in the complete
     commit response, and merge-group checks use §6.4's mapped PR head;
     missing, changed, or ambiguous identity               -> action_required
  -> resolve coverage branch once to immutable coverage_sha C
  -> unwrap the route-bound coverage key; missing, wrong,
     corrupt, or unavailable key material                  -> temporarily unavailable
  -> decrypt and validate decision fence, source, and in-flight state at C;
     missing, malformed, extra, or mismatched state         -> temporarily unavailable
  -> project-wide mutation fence at C                       -> in_progress  (§5.4)
  -> any subject in mutation.subjects at C                  -> in_progress  (§5.4)
  -> non-overlapping subject mutation or a valid success reservation
                                                            -> continue ordinary evaluation
  -> drop subjects exempt in exemptions.enc.json at C — after the
     freshness guard, so a pending exemption change still
     holds its subject                                       (§6.8)
  -> read agreements/active.enc.json at C, including projection metadata
  -> map subjects with active.shard_count and fetch each
     distinct shard at C once (at most 32 on the Free baseline) (D9)
  -> for each subject: row = shard[user_id]
       covered = row.agreements[agreement_id].decision == "covered"
                 AND row.agreements[agreement_id].version
                     ∈ active.accepted_versions             (§6.5)
       if not covered:
         derive override_key from repository, associated PR, subject, and
         current PR root tree; require row.overrides[override_key] to be the
         closed active entry with those exact identities and a valid grant
       neither covered nor actively overridden
                                                           -> failure / action_required
  -> all subjects ok -> success
```

**One agreement per project, in v1.** A project has one CLA; change arrives
as *versions* of it (§6.5), not as a second agreement. The check therefore
evaluates each subject against exactly the agreement named by
`agreements/active.enc.json`. The user-keyed row's nested
`agreements[agreement_id]` map and the event schema deliberately reserve room
for more than one — entity and corporate
agreements are the anticipated case, and they are *alternatives* to the
individual one, not conjuncts — but how several agreements combine is a rule
this design defers along with entity support (`REQ-CONFIG-4`, §13) rather than
one the enforcement gate should improvise.

**Enforcement scope is routing, not signer evidence.** `REQ-CONFIG-3` decides
whether this repository is routed to the project before this flow starts.
Acceptances do not copy that configuration, and changing it neither changes the
legal grant nor triggers re-consent. The agreement text is the only source of
legal scope; DraCLA does not interpret it.

**Any bound fails closed.** `REQ-CHECK-2` requires every commit to be
evaluated, and the GitHub pull request commits endpoint truncates at 250
regardless of intent. Where the listing cannot be completed — pagination bound
from the §9 CPU budget, or the API limit — the result is *action required*, never
a pass on a partially enumerated subject set.

Public surfaces disclose only *CLA satisfied*, *action required*, or
*temporarily unavailable*. Detail follows the explicit tiers in
`REQ-PORTAL-6`. The sole extra public sentence is §7's repository-local
conflict message: the repository is covered by more than one CLA project and
an administrator must resolve it. It never names a matching project or scope
entry or exposes signer status or private configuration.

**Exemptions are consulted here.** Individual, team-snapshot, and continuous
team source events fold under the records key, and only their effective boolean
materializes into coverage's `exemptions.enc.json` (§5.3). The enforcer, which
cannot read canonical, drops a subject when that boolean is true before
evaluating signature coverage. It neither needs nor receives the source kind,
basis, instrument, rule, or asserting administrator.

**Check output carries the retry contract.** `REQ-CHECK-5` requires the result
to explain how evaluation is retried or how an authorized user can request a
retry. The check run's `title` and `summary` are drawn from a fixed string table
keyed only by state — never by subject identity, subject count, or any
record-derived value — and the *action required* and *temporarily unavailable*
texts name the retry path: push a new commit, sign at the portal link, or
re-request the check. Re-request authorization needs no DraCLA control; GitHub
restricts it to users with write access. Annotations and comment bodies use the
same table. Nothing may `@`-mention a subject, which is the convention among CLA
bots and a direct `REQ-PORTAL-3` / `REQ-PORTAL-5` violation.

**Where the exact reason is actually shown.** `REQ-CHECK-1` requires the
authenticated portal to give the exact reason for an action-required result, but
on a multi-author pull request that reason usually concerns *someone else* — an
uncovered co-author, an unresolved identity — while `REQ-PORTAL-1`'s portal
shows only the viewer's own status and `REQ-PORTAL-5` bars turning it into a
lookup for others. There is therefore a **pull-request-scoped authenticated
view** at `/p/<repository-owner>[/<project-slug>]/pr/<number>`, with disclosure graded by what the viewer is
already entitled to see:

| Viewer | Sees |
|---|---|
| Anyone authenticated | Their own subject status in this pull request, and nothing about others |
| Write access on the contributing repo | Aggregate only: counts by reason — *n* uncovered, *n* unresolved identity, *n* on an insufficient agreement version |
| Current records-reader authorization (`REQ-REC-1`, `REQ-SEC-6`) | Named subjects and per-subject reasons |

The middle row is what makes the result actionable for a maintainer without
becoming a per-user lookup: a maintainer learns *what to do* (ask the
contributor to sign, or issue an override) without learning any specific
person's CLA status. Naming subjects requires the same authorization as the
dashboard, because it is the same disclosure. Even that tier shows only GitHub
numeric IDs and login snapshots with records-key-decrypted data from the
subject's `derived/status-detail/<shard>.enc.json`; legal names, email addresses, signer fields,
and raw evidence never appear in a pull-request view. The coverage projection
supplies only generic reason classes for aggregate counts.

For a private contributing repository, `worker-portal` cannot check the middle
row with its records credential. It asks `worker-enforce` for a signed yes/no
permission result bound to the viewer, repository, and short expiry. No token
crosses the boundary, and the response carries no repository data beyond that
authorization bit. This preserves D3 while making the tier implementable.

#### 6.3.1 Co-authored-by trailers do not block

A `Co-authored-by:` trailer is unauthenticated commit-message text that any
commit author can write. Treating it as a blocking public subject produced three
defects at once, and `REQ-CHECK-2` revision 2 removes the cause rather than
mitigating each:

- **A coverage oracle.** Naming any GitHub user in a trailer on a throwaway pull
  request made the public check state reveal whether that user had signed —
  functionally the lookup `REQ-PORTAL-5` forbids.
- **A jamming vector.** Naming a contributor who later revoked made every pull
  request carrying those commits unlandable (former risk R10).
- **Failure in the ordinary case.** GitHub offers no reliable email-to-user
  lookup; only `<id>+<login>@users.noreply.github.com` parses directly to a user
  ID, so most legitimate trailers were unresolvable and failed closed (former
  risk R1).

Trailers are still collected and still matter — they are the project's only
signal that someone else contributed:

```
public check          opener + commit authors only
                      -> state cannot be steered by an injected trailer

/p/<repository-owner>[/<project-slug>]/pr/<n>
                      trailer co-authors listed with coverage status,
                      under §6.3's graded disclosure
                      -> maintainer requires signing, records an exemption,
                         or issues an override
```

**The residual gap, stated plainly:** a co-author declared only by a trailer can
contribute without signing unless a maintainer acts on the surfaced list. That is
the cost of the change, and it is why a project may configure trailers to block
its own checks where its threat model prefers the older behaviour.

**This does not close the oracle entirely.** Commit author email is equally
attacker-controlled: authoring a commit as
`<TARGET_ID+x@users.noreply.github.com>` still makes that user a subject and
still leaks their coverage. The attack now requires authoring a commit under
someone else's address rather than typing a line in a message — more visible,
auditable in the commit list, and blocked outright by repositories requiring
signed commits. Reduced, not eliminated.

**Attribution is as strong as git author metadata, and no stronger.** Commit
author email is attacker-controlled, and a noreply address is derivable from any
public profile, so "GitHub-resolved author" is unauthenticated email matching
rather than proof of authorship. Two consequences are documented rather than
solved, because `REQ-CHECK-2` mandates this resolution rule: a contributor can
attribute commits to a covered user, and an attacker can put a target account's
email in the Git author field to make that account a blocking subject. The
honest claim the evidence supports is *some account whose email appeared in an
author field has signed* — §8.2's attestation language is scoped accordingly.
Verified-signature enforcement is offered as documented hardening for projects
that need more.

**Concurrent evaluations are conditioned on the head SHA.** Two `synchronize`
deliveries for the same pull request can race, and a late-completing stale
evaluation must not overwrite a newer one. Each check write records the head SHA
it evaluated and is skipped if the pull request has moved on, so the failure
mode is a missing update that the next event repairs, not a stale `failure`
sitting on a covered pull request with nothing to re-trigger it.

### 6.4 Authoritative merge-group check (`REQ-CHECK-3`)

The repository merge queue is configured with GitHub's `ALLGREEN` grouping
strategy: every pull request entry receives its own merge-group commit and must
pass required checks. `HEADGREEN`, where only the cumulative group head must
pass, is not a supported DraCLA configuration because it would omit the
independent decision required by `REQ-CHECK-3`.

On `merge_group.checks_requested`, the enforcer maps the event to exactly one
official GraphQL `MergeQueueEntry`. It first requires `base_ref` to have the
canonical form `refs/heads/<non-empty branch>` and strips exactly the
`refs/heads/` prefix; an empty or non-branch ref is unavailable. It passes that
branch name to `repository.mergeQueue(branch: ...)` and queries its first 100
`entries`, including
`configuration.mergingStrategy`, `configuration.maximumEntriesToBuild`, each
entry's `headCommit.oid`, and its `pullRequest`. GitHub's documented
`maximumEntriesToBuild` is at most 100, so an entry for which checks were
requested must be in this bounded build window. Exactly one entry must have
`headCommit.oid == merge_group.head_sha`, its `pullRequest` must be non-null,
and `mergingStrategy` must still be `ALLGREEN`. Zero matches, multiple matches,
a null pull request, a changed queue mode, API failure, or disagreement between
returned repository/base facts and the authenticated event produces a
non-passing unavailable result. The enforcer does not parse queue ref names or
commit messages and does not ask a cumulative synthetic commit to identify all
associated pull requests.

The selected entry supplies the one PR number and opener. The enforcer then
re-resolves that PR's current commit authors and head root tree through the
same bounded commit path used in §6.3, applies the freshness guard (§5.4),
evaluates exemptions, active-version currency, subject-shard overrides, and
enforcement routing, and reports on the event's merge-group head SHA. Changes
from entries ahead of this PR may be present in that synthetic commit, but
their independently completed decisions are not reconstructed or re-evaluated
here.

Completion of this check is the authoritative CLA decision for this PR's
landing attempt; the ordinary PR check is early feedback only. A later
canonical change does not rewrite the completed result. If GitHub rebuilds the
entry or emits another `checks_requested`, the new event repeats the mapping and
fresh evaluation and supersedes the earlier result. §9.2 therefore models one
delivery per PR normally and ten per PR as rebuild sensitivity. The exact
GraphQL mapping, base-ref normalization, one- and two-entry queues, an opener
who authored no commit, rebuild/reordering, and all fail-closed cases are
mandatory real-account probes under A2.

**Overrides are keyed to the associated PR's root Git tree, not to either commit
SHA.** At grant time the portal resolves the immutable PR head commit and reads
its root `tree.oid` from GitHub. One grant materializes an active entry in each
subject's existing `users/<shard>.enc.json`, keyed by
`(repository_id, pr_number, subject_user_id, tree_oid)`. A history-only rebase
with identical paths, modes, symlinks, submodules, and blob contents has the same
root tree object ID and keeps the override. A content change has another tree
object ID and lapses it. The merge-group check maps the queue entry back to the
one associated PR and resolves that PR head's root tree; it never uses the
cumulative synthetic merge-group tree. Missing, changed, or ambiguous tree
identity is non-passing. Python and TypeScript consume GitHub's exact Git object
ID and do not hash an API response or reconstructed file listing.

The private grant and withdrawal forms require a plain-language `reason` and
explain that optional `instrument_ref` is a pointer such as a legal ticket,
security incident, or dated external instrument—not a copy of that evidence.
The grant form additionally explains that the decision covers the displayed PR
content and named subjects only. Neither field is projected to the enforcer.
`override_withdrawn` requires the same fields and references the original grant
event. It withdraws the entire grant
prospectively: every completed check that used the grant remains recorded and
unchanged, while future evaluations and rebuilt queue entries cannot use it.
The original grant stays in append-only history. Retaining only some subjects
requires withdrawing the grant and issuing a fresh grant for that subset.
Grant and withdrawal both require current `maintain` permission, are
idempotent, synchronously update the projection under §5.4, and trigger a fresh
ordinary PR evaluation; the merge-group evaluation remains authoritative.
The projection update changes only the affected user shards through their
branch-head CAS and stores no reason or instrument text. Evaluation already
fetches those shards for the named subjects, so applying an override adds no
request-path subrequest and cannot evade the 32-shard bound.

**Fallback without a required merge queue.** `REQ-CHECK-3` already forbids
claiming a final pre-landing check in this configuration. DraCLA additionally
re-verifies on push to the default branch and, if a commit landed uncovered,
opens an issue that carries **only the commit SHA and the generic state**, with
a link to the authenticated portal. It must not name the subjects: on a public
contributing repo that would be a permanent, indexable, public statement that a
named user is uncovered, which `REQ-CHECK-1`, `REQ-PORTAL-3`, and
`REQ-PORTAL-5` all forbid. This is detection, not prevention, and is documented
as such.

**Administrator bypass must be documented.** `REQ-CHECK-3` requires stating
that repository administrators may retain a GitHub-supported bypass capability
(ruleset bypass actors, admin merge). DraCLA cannot prevent it and does not
claim to; adopter documentation states plainly that a required merge-group check
constrains everyone except principals the repository's own rules exempt.

### 6.5 Agreement activation and restore (`REQ-AGR-1`, `REQ-AGR-2`, D10)

**An agreement is published by reference, and snapshotted.** `REQ-AGR-1` asks
for "the exact agreement content **or an immutable content reference**", and the
reference is the better primitive: the project keeps its legal document where it
already lives — a file at a commit SHA in its own repository, or a gist revision
— and DraCLA records a pointer to it rather than becoming its custodian.

```
publish:
  fetch the immutable ref     github.com/acme/acme/blob/<sha>/ICLA.md
  compute and verify digest
  build one event commit       agreement_published { ref, digest,
                                content_commit_oid, recipient,
                                snapshot_content_path,
                                snapshot_metadata_path, snapshot_sha256 }
                              common envelope recorded_at is publication time
                              + agreements/<agreement_token>/<version_token>.md
                              + matching .meta.json
                                (tokens are derived by §4 `segment`)
  fast-forward events ref     event, snapshot, and metadata appear atomically
```

Each of the three does a distinct job:

| | |
|---|---|
| **ref** | Provenance. Immutability is content-addressed, so the pointer cannot drift, and anyone can verify the snapshot against the original. |
| **snapshot** | Durability. A gist or repository can be deleted; a legal record that then points at nothing fails `REQ-REC-5`'s requirement that records be readable without DraCLA. This is where a pointer-only design — CLA Assistant's, for instance — leaves a gap. |
| **digest** | Binding. A later force-push at the source becomes detectable rather than silent. |

The snapshot lands in the adopter's own records repository (D4, D4a), so custody is
unchanged: DraCLA writes it, the adopter owns it. Unlike signer data, the
agreement is public by construction — `REQ-AGR-3` requires contributors to read
it *before* authenticating — so there is no confidentiality reason to route it
around the portal. §6.6's agreement endpoint already serves it unauthenticated.

**Publishing and activating are separate acts.** Publishing records an
immutable version — recipient, reference, digest, content commit OID, and
snapshot — and invalidates nothing. The OID is the `<sha>` the reference names,
recorded as its own field because `REQ-REC-4` requires it alongside the digest
(§5.1); a reader must not have to parse it out of a URL. Any number of versions
may be published, but the portal offers none of them for signing until one is
active.

Activation is immediate and selects exactly one active, signable version. Its
append-only event carries `supersedes_coverage` and the exact resulting
`accepted_versions` set:

- `true` replaces `accepted_versions` with only the newly active version;
  contributors with older acceptances must re-sign.
- `false` adds the newly active version to the existing `accepted_versions`
  set. It preserves acceptances that were current immediately before the
  activation, but cannot revive a version removed by an earlier superseding
  activation.

The portal compares that event set with the authenticated current active
projection before preparation. For a superseding activation it must equal the
singleton target version; for a non-superseding activation it must equal the
current set union the target version. Either ordinary form rejects a target
already in `retired_versions`. A superseding activation produces:

`retired_versions = (current retired_versions ∪ current accepted_versions) − {target version}`

A non-superseding activation leaves `retired_versions` unchanged. The active
version must be a member of `accepted_versions`, and the
accepted and retired sets are closed, duplicate-free, lexically ordered, and
disjoint.

The flag and resulting set live in the activation event, not in published
snapshot metadata. DraCLA never inspects agreement text to choose either. The
`agreements/` tree is the durable human-readable snapshot; the events remain
canonical.

**Rollback is a distinct restore event.**
`agreement_activation_restored` names one earlier `agreement_activated` event
for the same project and agreement, repeats that event's exact
`accepted_versions`, and records a non-empty administrator-supplied reason.
The target event is read from its deterministic canonical event path at the
confirmed head; it is never selected by timestamp, version ordering, mutable
configuration, or agreement-text comparison. The restore makes the target
activation's version active and reinstates exactly its accepted-version set.
It moves every currently accepted version outside that restored set into
`retired_versions` and removes the restored set from retirement. The exact
result is:

`retired_versions = (current retired_versions ∪ current accepted_versions) − restored accepted_versions`

Thus only the explicit restore operation can reintroduce retired currency.
For either transition, the active projection's legacy-named
`activation_event_id` records the event that produced its current currency
state: the ordinary activation ID after activation, or the restore event ID
after restore. The restore's target activation remains in the canonical restore
event rather than being conflated with that latest-transition field.

Restore changes version currency, not a contributor's signature history. An
earlier acceptance provides coverage again only if it is still that
contributor's current signature basis and was excluded solely by
`accepted_versions`. A later revocation, correction, superseding acceptance, or
other independently invalid basis remains effective. This keeps rollback O(1)
in subject count and avoids rewriting coverage shards.

**Both transitions use the ordinary freshness guard and are O(1).** The
portal:

1. validates the published target for ordinary activation, or the exact prior
   activation target for restore, and verifies the actor's action-specific
   records-repository authorization;
2. prepares the frozen operation, acquires the mutation fence, and opens
   `{ operation_sha256, started_at, subjects: [], project_wide: true }` in
   `inflight.enc.json`;
3. appends `agreement_activated` or `agreement_activation_restored` to
   canonical;
4. updates `agreements/active.enc.json` by compare-and-swap and advances
   `source.enc.json` to the canonical commit while preserving the replayed
   project lifecycle fields; and
5. closes the marker.

While the marker is open, every check for the project is indeterminate and
cannot pass. A crash after the canonical append is completed by replay; a crash
before it leaves the frozen activation or restore prepared for recovery, which revalidates
and continues it or records an explicit terminal no-op/conflict as §5.4 allows.
It is never discarded because the event is absent or the operation is old. No
subject shard is rewritten, and the normal transition waits for no scheduler;
recovery may use §5.4's drivers. There is no pending or early-signature state.

The contributor page reads the canonical active version. A project with no
activation has no signable agreement. A published inactive version has no
signing route, so a contributor cannot accept an agreement before it is active.

**Enforcement-scope activation is not agreement activation.** A scope change
uses the requested/activated publication protocol in §7 after the required
owner authorization. It decides where DraCLA checks run; it does not change
agreement version currency, alter a legal grant, or require re-consent.

### 6.6 Dashboard and exports (`REQ-DASH-1..5`, `REQ-REC-5`)

The normal Worker path never performs a full replay or export. It updates only
the affected encrypted derived shard or shards plus `derived/state.enc.json` on
the separate `derived` branch (§5.1). There are exactly 32 shards per derived
class in the initial Free profile:

- index and status-detail rows use `github_user_id % 32`;
- reader-authority source records use the first five bits of the SHA-256 digest
  of their server-computed source ID, which is the `event_id` of the canonical
  source-creating event and remains stable across later materializations; and
- `derived/state.enc.json` records each class generation, the SHA-256 digest of
  every encrypted shard envelope, `shard_count: 32`, and the profile's exact
  maximum ciphertext bytes per shard and members per reader source. The initial
  Free profile also fixes `max_continuous_reader_rules: 10` per project; the
  portal rejects an eleventh active rule before canonical append.

The canonical `config/materialization-generations.enc.json` at the resolved
`events` head says which event generation each class must reflect. A derived
branch commit atomically writes every affected shard and a state file carrying
the same generation and new shard digests. Unchanged shard digests are carried
forward. Readers reject a class when its canonical and derived generations
differ, any selected envelope exceeds the installed profile, or any shard
digest differs.

One ordinary subject mutation touches at most one index shard, one status shard,
and the small state file. One reader-source mutation touches one reader source
shard and the state file. A bounded bulk snapshot may touch several shards;
the portal fans those updates into separate bounded service invocations and
publishes the new class generation only in the final state commit. Until then
that class fails closed, and the portal reports no completed administrative
operation. A reader addition or bulk administrative input exceeding the release
profile's tested member, shard, or fanout limit is rejected before its canonical
event is appended. Acceptance and revocation retain the limit behavior stated
in §9: evidence and coverage complete, while an overflowing private derived
class fails closed pending repair or a larger tested profile. The checked-in
release profile contains numeric values—never `unlimited` or an unevaluated
placeholder—and setup displays them.

A failed or indeterminate shard update dispatches the protected control
reconciler, which performs a full replay and repairs the same sharded format;
the daily run is the missed-dispatch backstop. No full-project artifact is
rewritten by a successful ordinary Worker mutation.

**Exports are explicit work.** `dracla export` replays and streams JSON/CSV
locally using repository access and adopter recovery material. A hosted export
request dispatches the protected control workflow, which writes only the
encrypted request-scoped pair under `derived/exports/<request_id>` with its
source `events` OID; it never uses an Actions artifact. The portal rechecks
reader authorization before decrypting and streaming that snapshot. Exports
are not regenerated by signing, revocation, or administrative mutation, and
their source OID is shown rather than implying they track later events. A
hosted export exceeding its tested blob/job limit directs the administrator to
the streaming CLI path, which remains the service-independent portable export.
CSV cells are neutralized before encryption while JSON retains the canonical
value (`REQ-SEC-8`).

Dashboard index responses are one shard page per authorized request. Filtering
and sorting may combine those bounded pages in the browser. Exact status reads
fetch only the subject's status shard.

**Index schema** (`REQ-DASH-2`, `REQ-DASH-4`). One row per subject per
agreement, carrying only what the mandated filters need:

```
github_user_id, login_snapshot, login_as_of,
agreement_id, version, enforcement_scope,
status: current | exempt | revoked | superseded | indeterminate,
accepted_at, revoked_at
```

`exempt` means coverage rests on a recorded exemption rather than a signature
(§6.8) and is never folded into `current`. A signer correction advances this
single row to the corrected acceptance; the prior acceptance remains in
canonical history through its `supersedes` linkage but has no separate dashboard
row. `superseded` means an activation invalidated the row's current acceptance
version;
`indeterminate` means the subject sits in
`inflight.ops`, an operation exhausted its retries, or replay could not resolve
the record. Both statuses are required by `REQ-DASH-2` and neither existed in
the projection before. Legal name, email, and confirmation text are **not** in
the index — they appear only in the exports, which `REQ-DASH-4` keeps separate
by requiring the index carry no more private data than the dashboard needs.

**Index and private-read authorization.** An authorization request authenticates
the GitHub user, resolves exactly one project, resolves the current `events`
head and materialization generations, then resolves one immutable `derived`
head. It validates the state file and all 32 bounded reader-authority source
shards against that state's digest table. The derived reader generation must
equal the canonical reader generation. A mismatch, oversize shard, missing
shard, or digest failure denies the read and schedules repair.

Successful authorization returns a short-lived compact JWS. Its protected
header is exactly
`{"alg":"HS256","kid":<active proof-key ID>,"typ":"dracla-private-read-proof+jwt"}`.
Its RFC 8785-serialized payload is exactly:

```
{"v":1,
 "session_jti":<current session ID>,
 "github_user_id":<authenticated positive integer>,
 "project_id":<non-empty string>,
 "result_class":"reader_index"|"reader_subject_status",
 "subject_scope":{"kind":"project"}|
                 {"kind":"subject","github_user_id":<positive integer>},
 "reader_generation":<canonical reader-generation event ID>,
 "authorizing_source":{"source_id":<canonical event or rule ID>,
                       "kind":"individual"|"snapshot"|"continuous_team",
                       "organization_id":<positive integer|null>,
                       "team_id":<positive integer|null>},
 "issued_at":<UTC RFC 3339 whole-second timestamp>,
 "expires_at":<UTC RFC 3339 whole-second timestamp>}
```

`reader_index` requires the project scope; `reader_subject_status` requires the
one named subject scope. Individual and snapshot sources set both team fields
to `null`; a continuous-team source sets both to the stable numeric IDs in its
canonical `team` object. The portal signs and verifies the JWS with the
`worker-portal` private-read proof key selected by `kid`. It rejects unknown
members, algorithms, key IDs, result/scope combinations, expired or
not-yet-issued payloads, a parent session mismatch, and any user, project,
query, generation, or source mismatch.

Individual or snapshot sources are preferred. If authorization depends on a
continuous-team source, the portal uses the records App's current
organization-membership endpoint before issuing the proof and binds that exact
source plus its stable organization, team, and subject IDs into the payload.
Missing, unavailable, or indeterminate membership cannot issue a proof.

Every data-page request authenticates the same user, re-resolves the canonical
reader generation, and rejects a proof naming any other generation before
reading one fixed data shard. A proof bound to a continuous-team source also
rechecks that exact membership immediately before disclosure. A failed check
denies the page and invalidates the proof; the client may obtain a new proof,
which can select another source from the union. The proof is therefore not an
authority cache: a reader addition or withdrawal invalidates it by generation,
and a missed continuous-team departure is caught by the live check. Withdrawing
one source denies the next read only when no other active source can issue a new
proof. A contributor may read only their own exact status under `REQ-PORTAL-6`
without being a records reader.

The endpoint serves only fixed, server-computed query/result classes; it accepts
no `path`, `ref`, filename, arbitrary subject, or raw-decrypt parameter. It
decrypts only the required project-bound envelope and returns a filtered
plaintext result, never a raw key or ciphertext oracle. Responses are
`Cache-Control: private, no-store`. Unknown project and unauthorized viewer
both return a uniform 404.

### 6.7 Badges and public surfaces (`REQ-PORTAL-2..4`)

Badges are **static assets, not a dynamic endpoint**. A per-pull-request badge
image served by the Worker would be both a coverage oracle (§6.3) and an
anonymous amplifier into the fail-closed request budget (§9). There are exactly
three SVGs plus the project badge, served from Pages:

```
cla-sign-or-check.svg    "CLA: sign or check status"   <- CONTRIBUTING.md badge
cla-satisfied.svg        "CLA: satisfied"
cla-action-required.svg  "CLA: action required"
cla-unavailable.svg      "CLA: temporarily unavailable"
```

The `CONTRIBUTING.md` badge is deliberately viewer-independent: a
GitHub-rendered image cannot identify who is looking at it, so it shows the
generic prompt and links to the owner-qualified project path
(`/p/<repository-owner>[/<project-slug>]`, `REQ-PORTAL-2`).

The pull request surface is a **comment posted by `dracla-enforcer`**, which is
why that App needs `pull_requests: write` (§4). It carries one of the three
generic states, the same fixed string table as the check output (§6.3), and a
link to the authenticated portal. It encodes no coverage detail, no subject
identity, and no subject count (`REQ-PORTAL-3`, `REQ-PORTAL-5`). The only
exception is the bounded multiple-project conflict sentence from §7; the
comment still reveals none of the matching project identifiers or entries. The
comment is updated in place rather than appended, so a pull request accumulates
one.

**Wording rules** (`REQ-PORTAL-4`). Every state is legible from text alone —
colour is never the only signal, and each badge carries its state in its alt
text. Contributor-facing copy is factual and avoids implying that signing
transfers copyright: the portal says the agreement "grants the rights described
below to <recipient>", with the recipient and the agreement text supplying the
actual claim, since `REQ-AGR-4` forbids DraCLA characterizing what an agreement
means.

### 6.8 Administrative flows (`REQ-AGR-1`, `REQ-CHECK-2`, `REQ-OPS-4`)

Every administrative action is an append-only event with an `actor`, authorized
the same way and through the same portal — there is no separate admin console
and no source-code edit, which `REQ-OPS-4` requires.

Every **mutating** row below uses §5.4's authenticated form state with its exact
Table 5.4-A event type and mapping, canonical target and payload digest, fresh
operation nonce, and `confirmed_canonical_oid`. Rendering an
already-satisfied action binds the terminal canonical event that proves that
result; retrying that form can only return the same no-op. A form rendered for
a write can append only while its confirmed head is still current. Read-only
conflict inspection has no mutation form or idempotency key.

| Action | Event | Minimum live authorization | Effect |
|---|---|---|---|
| Connect a project or explicit successor | `project_connected` | owner control for the repository-owner account; `admin` on all three project repositories; GitHub authorizes every bound App installation | Records immutable repository-owner/slug identity and the independent recipient, plus `successor_of` when applicable |
| Complete transfer of all three project repositories to a new owner | `project_repository_owner_changed` | control of the new owner; `admin` on all three transferred repositories; every App binding reverified | Moves only the owner-qualified route claim through one bound registry generation; recipient and evidence do not change |
| Close an old project in favor of its connected legal successor | `project_succeeded` | `admin` on the old records repository; successor connection is verified | Stops new signing and legal-state expansion while preserving revocation, scope removal, reader maintenance, recovery, and history (§5.5) |
| Activate a verified project-key generation | `keyring_activated` | `admin` on every repository whose project-key material changes | Pins the `keys` commit and current records/coverage `kid` values after live and recovery verification (§6.10.2) |
| Publish a version | `agreement_published` | `admin` on records | Records the immutable recipient, reference, digest, and snapshot (§6.5) |
| Activate a version | `agreement_activated` | `admin` on records | Selects the active signable version immediately; `supersedes_coverage` decides currency (§6.5) |
| Restore a prior agreement activation | `agreement_activation_restored` | `admin` on records | Reinstates the exact active version and accepted-version set established by the named activation; ordinary activation cannot do this (§6.5) |
| Bind, widen, narrow, or remove a repository scope | `enforcement_scope_requested`, then `enforcement_scope_activated` | `admin` on that contributing repository | Publishes one reconciled routing generation; evidence is preserved (§7) |
| Bind, widen, narrow, or remove an organization selector | `enforcement_scope_requested`, then `enforcement_scope_activated` | owner of that organization | Publishes one reconciled routing generation; evidence is preserved (§7) |
| Inspect a multiple-project conflict | none (read-only) | `admin` on the affected contributing repository | Shows only the affected repository, matching project IDs and scope entries, and required resolution authorities (§7) |
| Exempt a non-human account | `exemption` (`kind: bot`) | `admin` on records | Materializes to `exemptions.enc.json`; consulted by §6.3 |
| Exempt an individual | `exemption` | `admin` on records | Records one source, basis, and instrument |
| Exempt a selected team snapshot | one `exemption_snapshot` event with a frozen subject set | `admin` on records | Atomically creates one independently withdrawable source per selected account; later membership changes do nothing |
| Configure or withdraw a continuous exemption team | `exemption_rule_configured` / `exemption_rule_withdrawn` | `admin` on records | Explicitly delegates future source changes to that team's membership administrators |
| Withdraw one exemption source | `exemption_source_withdrawn` | `admin` on records | Removes only the selected source and reports every source still active |
| Authorize an individual records reader or withdraw one source | `records_reader_authorized` / `records_reader_withdrawn` | `admin` on records | Changes canonical intended-reader policy; it does not mutate GitHub ACLs |
| Authorize a selected records-reader snapshot | one `records_reader_snapshot_authorized` event with a frozen subject set | `admin` on records | Atomically creates one independently withdrawable reader source per selected account |
| Configure or withdraw a continuous reader team | `records_reader_rule_configured` / `records_reader_rule_withdrawn` | `admin` on records | Explicitly delegates future reader authorization to team membership administrators |
| Grant or withdraw a check override | `override` / `override_withdrawn` | `maintain` on contributing repository | Whole-grant, forward-looking withdrawal; keys use `(repository_id, pr_number, subject_user_id, tree_oid)` (§6.4) |
| Request administrative retry | `retry_requested` | `write` on contributing repository | Re-evaluates only the named pull request or merge group |
| Edit project config | `config_updated` | `admin` on records | Required fields, privacy policy, retention text (encrypted resolved data, §6.9) |

**Authorization is action-specific.** Records-side actions use the actor's
user-to-server token to check the resource and minimum permission in the table,
never the records installation token that would answer for the App itself. The
event's `authorizations` array records the stable numeric resource IDs, exact
operations, required authorities, observed authorization results or evidence,
and check times for every required action-time check; `actor` records the stable
numeric actor ID and login snapshot. Project connection and owner transfer
therefore record all seven owner, repository-admin, and App-binding checks, not
one representative decision. Authorization is rechecked when the action
occurs; a session or permission on another project is not enough. Read-only
conflict inspection is authorized separately and grants neither mutation nor
signer-record access.
Install and repository-scoped credential rotation use the administrator's own
credentials and require `admin` on every affected repository. App operations
use whatever exact authorization GitHub currently requires for that operation
rather than an invented uniform installation permission (§6.10).

Narrowing or removing scope never removes acceptance, revocation, agreement, or
administrative evidence. It records the authorized request before staging and
records activation before the prepared routing generation can pass a check.
Every later resolution mutation is checked independently; permission to inspect
a conflict is not permission to resolve it.

The records App cannot inspect a private contributing repository. For a
contributing-side row, `worker-portal` sends the authenticated numeric user
identity and requested resource to `worker-enforce` over the
service-authenticated boundary. The enforcer uses its installation's repository
permission or organization-membership endpoint and returns the resource, exact
operation, required authority, observed result or evidence, and check time. No
user or installation token crosses the boundary; the records event stores that
result as authorization evidence.

**Human exemptions carry an asserted basis.** Exempting a bot is a statement
about identity plumbing — the account holds no authorship claim and the work
belongs to whoever configured it. Exempting a *person* is a legal assertion: that
their grant already exists by another instrument, typically employment or a prior
assignment. The common real case is staff of the recipient entity, for whom a CLA
is redundant.

DraCLA records the assertion; it does not evaluate it, because `REQ-AGR-4`
forbids it inferring legal meaning. The event therefore carries
`basis` (`employment | prior_assignment | other`), a free-text
`instrument_ref`, and the asserting administrator, so an audit can follow the
claim to its source.

**Individual and snapshot flows create explicit sources.** The portal always
allows direct account selection. Selecting a team first displays its current
members with all or any subset selectable. Confirmation freezes the selected
numeric identities in one `exemption_snapshot` event; that one append is the
submission's batch identity and atomically creates one source per selected
account. Retrying the same nonce must present the same frozen set or conflict,
and returning success means the event and complete derived effect were read
back and verified. Later membership changes do nothing. Snapshot is the default
and the UI never silently upgrades it to a continuous rule.

**Continuous is an explicit delegation.** Choosing it presents the team,
asserted basis, instrument reference, and a warning that team membership
administrators can add or remove exemptions without another DraCLA admin act.
The canonical rule event retains the configuring actor and current records-admin
authorization. Later membership observations are separate automation events
that reference that rule and GitHub evidence; they do not pretend the original
administrator acted again. Until such an event commits, the previously recorded
membership state remains authoritative. Only teams observable through one of
§5.4's bound App installations are accepted.

**An exemption is reported distinctly from an acceptance**, never merged into
`current`. The dashboard and exports carry `exempt` as its own status (§6.6), so
a records reader is never shown something that looks like a signature but is not
one. `REQ-CHECK-2` requires this separation.

**Sources combine by union.** An account may be exempt individually, through
one or more snapshots, and through one or more continuous rules. Replay keeps
every source independently. Withdrawal targets one source, never a user-wide
boolean, and its success screen says either "no longer exempt" or "still
exempt" with every remaining active source. The original assertion, rule, and
author remain in history. A coverage decision depends only on materialized
events, which keeps the projection rebuildable (`REQ-REC-6`).

**The recipient is never editable** (§5.5). `config_updated` rejects any change
to it; changing recipient is a new project.

### 6.9 The `dracla` CLI (D12, `REQ-REC-5`, `REQ-OPS-4`)

Python, distributed on PyPI, run without installation:

    uvx dracla@<version> install

`<version>` is a concrete released version such as `0.1.0`, never `latest`, a
range, or an omitted selector. Release notes publish that version's source
commit, PyPI provenance identity, and canonical allowed-artifact manifest. The
manifest lists every release distribution filename and SHA-256 and has its own
SHA-256 identity. The package carries an identical release-declared copy.
Before requesting GitHub authorization or creating anything, the installer
displays and records in the three bootstrap manifests its exact package
version, source commit, release-workflow identity, allowed-artifact-manifest
identity, and dependency-constraint identity; the operator confirms that
release-declared identity with the repository plan. Runtime dependencies are
constrained to the release-tested set, and the installer validates its resolved
distribution versions against those bundled constraints before authorization.

This contract does **not** claim that the already-running DraCLA child can
discover whether its parent `uvx` invocation downloaded a wheel, built an
sdist, or reused a cached environment. Plain `uvx dracla@<version>` supplies no
stable selected-artifact receipt to the child. The bootstrap therefore records
the release-declared allowed set, not a filename or digest purportedly observed
at runtime.

This is a proportionate one-time local-install contract, not a claim that the
shell can cryptographically enforce what the operator typed. Independent
artifact/provenance verification is documented as an optional higher-assurance
step before `uvx`; the mandatory digest pin and provenance verification remain
on the recurring key-bearing control workflow (§9), where a later mutable
download could affect every adopter repeatedly.

The CLI is not merely an installer. It is the service-independent recovery and
reporting surface. It reads ciphertext repositories directly with the
operator's GitHub credentials and decrypts only after receiving the project's
recovery key through an interactive prompt or local secret-manager command; the
key is never accepted as a command-line value or written to shell history.

**The CLI provisions and reports. It does not administer.**

| Command | Purpose | Status |
|---|---|---|
| `dracla install github.owner=<account>` | Provision the records, coverage, and control repositories, keys, recovery material, Apps, and workflow; everything else is configured in the portal (§6.10.3) | designed — implementation removed pending this redesign |
| `dracla config show` | Print the resolved configuration the portal wrote | designed |
| `dracla status <user>` | Coverage for one contributor | designed |
| `dracla export --json --csv` | Portable formats (`REQ-REC-5`) | designed |
| `dracla reconcile` / `dracla verify` | Replay canonical and check the projection matches | designed — M2 |
| `dracla audit <pr>` | Why a check decided what it did | designed |
| `dracla rotate-key --capability records|coverage|transport` | Rotate a project data key or repository transport key with recovery verification (§6.10.2) | designed |

**Agreements are managed in the portal, not here** (§6.8). Publishing and
activating a version are attributable events, and the portal is where
authorization is checked live against current GitHub permissions
(`REQ-SEC-6`) and an `actor` is recorded. A CLI running under a personal access
token is a weaker attribution story for an act with legal weight, and §6.8
already states there is no separate admin console. A CLI surface for agreements
may follow if there is demand; it is not the first-class path.

Only `install` is specified here. A first attempt was implemented without
§6.10 and removed after review rather than patched; its reimplementation
follows this design.

Two things this buys beyond convenience. `REQ-REC-5` requires records to be
readable without the DraCLA service when the adopter has repositories and
recovery material; direct CLI decryption demonstrates that portability. And
`REQ-OPS-4` requires installation be driven by configuration without editing
source, which is exactly what `install` and `config` are.

`verify` runs the same replay the reconciler runs (§5.4), so a maintainer can
reproduce the integrity check on their own machine rather than trusting a
workflow's word for it.

**One workspace, many projects.** A maintainer often runs several projects, and
a single organization may hold several independent repository sets — one per
DraCLA project (§5.5). The CLI works across all of them from one place:

```
dracla status --all              coverage across every project in the workspace
dracla export --all              one export per project, or a merged view
dracla verify --all              replay and check every projection
```

The workspace is a local file listing the projects the maintainer administers.
It grants nothing: every command runs with their own credentials against
repositories they already control and recovery material they explicitly
provide, so a cross-project view adds no DraCLA service trust surface.
`REQ-CONFIG-1`'s rule that each
project owns its own configuration and records is untouched — the workspace
*references* projects, it does not consolidate them.

Note the asymmetry with the dashboard: a federated **local** view is fine
because the maintainer holds credentials for each project, whereas a federated
hosted view would mean one surface aggregating several projects' signer PII.

**Config composition.** Those projects share almost everything and differ in
recipient, agreement, and enforcement scope. The CLI composes their configurations with
[Hydra](https://hydra.cc) on the 1.4 development line, so a base configuration
is defined once and each recipient is an override rather than a copy — which is
where composition starts paying for itself rather than being ceremony over a
single file. Hydra 1.4 sets the floor at Python 3.10 for the CLI; `core` has no
such constraint, since it depends on nothing.

**Composition stays on the client.** Hydra composes the CLI's *own*
configuration locally (§6.10.3), and whatever reaches `core` is a resolved plain
dict. `config/project.enc.json` is materialized by the portal from the initial
`project_connected` event and later `config_updated` events (§6.8), not by the
CLI — but the same rule governs it: what is committed is inert. No `defaults:`,
no `${...}` interpolation, no config-group references, and no dependency on the
composition engine to know what it says.

JSON for the committed artifact because it is machine-consumed — the Worker
serves the agreement and required fields from it (§6.6) and parses it natively.
Human readability is `dracla config show`'s job, not the wire format's; that is
precisely what D12 makes the CLI for. It reads that file — it does not write it.

Canonical **events** are JSON for the same reason (§5.1): machine-written,
machine-read, and the format an external reader parses.

**Agreement and config delivery.** The portal is static and the agreement,
immutable recipient, required fields, and confirmation labels live in the
private canonical repo. Enforcement scope is routing configuration and is not
presented as part of the grant. A read-only Worker endpoint serves the signing
payload with the records installation token, without requiring login —
`REQ-AGR-3` requires the agreement be readable before acceptance. It is cached at the edge keyed by
`(project, agreement_version)`, which is safe because the payload is
project-public by construction and contains no signer data. Its traffic belongs
in the A3 envelope.

---

### 6.10 `dracla install` (design before implementation)

A first implementation of this command was written without this section and
removed after review. Four of its defects were decisions absent from the design
rather than mistakes in code, so those are decided here first.

#### 6.10.1 Branch layout

**`events` is the records repository's default branch.** In steady state it
holds encrypted config, agreements, and events. It never holds wrapped-key
metadata or executable workflow content. At install time it holds only the
mandatory README root: no event, agreement, configuration, or private data
exists yet.

`auto_init` creates the owner-configured default branch, whose name DraCLA does
not control. Install creates the repository empty, uses the Contents API to
create the mandatory README root commit on GitHub's initial default branch,
reads that branch name, and immediately renames it to `events`. An earlier
design claimed the Git references API could make `events` the first ref of an
empty repository; GitHub does not permit creating that first ref directly.

Every later `events` commit carries exactly one logical event. Project
connection, configuration, agreement, reader, and scope changes are events, so
no non-event configuration commit is needed. Replay identifies encrypted event
paths and decrypts their bound envelopes; it never infers event identity from
commit position.

`derived/` (bounded derived shards and explicit exports) stays on a **separate branch**, so repairing
it never appends non-event commits to canonical ancestry.

The bounded records-key-encrypted prepared-operation cell stays on a separate
**`operations` branch**. Install creates it from the mandatory README root only
after the records key exists and writes the schema-valid idle cell. Every later
commit is a same-file CAS transition from §5.4. The branch contains no
canonical event, agreement snapshot, keyring, export, or executable input, and
its head can be rebuilt only to idle after canonical replay and coverage
reconciliation prove that no operation remains open.

Wrapped records and recovery keyrings stay on a separate **`keys` branch**.
Install creates that ref from the mandatory README root, commits the first
wrapped keyring candidate, then adds the immutable bootstrap manifest described
in §6.10.2 as its child. DraCLA updates the branch only with descendants; it
never force updates the ref or changes that manifest. The initial
`project_connected` event and each later
`keyring_activated` event pin an activated generation, its `keys` commit OID,
and the current records and coverage `kid` values. A reader accepts only a
keyring whose history contains the newest activated commit and whose
authenticated contents agree with that event. Missing history, rollback before
the activated commit, an unknown current key, or invalid wrapping fails closed.
Later wrapper-only rewrap commits may descend from the activated commit without
changing the active data-key generation.

The private-repository Free baseline cannot rely on GitHub branch protection.
Paid adopters may enable it as defense in depth. Authentication and activation
checks detect modification or rollback; deletion by a repository administrator
causes unavailability rather than acceptance of altered key material.

The coverage repository has one `coverage` branch containing encrypted
projection data, its immutable non-secret bootstrap-manifest copy, and wrapped
coverage-key copies. The separate control
repository has a normal default branch containing only the pinned workflow,
provenance and bootstrap manifests, and inert wrapped control keyring. It
contains no CLA event or derived plaintext.

| Branch | Holds | Written by |
|---|---|---|
| `events` (records default) | README | `dracla install` — mandatory root commit (§6.10.3.1) |
| | encrypted config | the portal, from `project_connected` and `config_updated` events (§6.8, §6.10.3) |
| | agreements | the portal — the `agreement_published` event and its snapshot (§6.5, §6.8) |
| | encrypted events | the signing path (§5.4) |
| `operations` (records) | one encrypted bounded prepared-operation cell | portal prepares and advances synchronous mutations; control reconciler repairs them (§5.4) |
| `keys` (records) | immutable bootstrap manifest plus wrapped records, coverage-recovery, and portal key copies | installer initially; authorized key-rotation paths thereafter (§6.10.2) |
| `derived` (records) | encrypted state plus index, status-detail, and reader-authority shards; explicit request-scoped JSON/CSV exports | portal writes bounded affected shards; control reconciler repairs and serves hosted export jobs |
| `coverage` (coverage default) | immutable bootstrap-manifest copy, encrypted projection, and wrapped coverage keys | installer initially; portal writes projection synchronously; control reconciler repairs |
| control default | pinned workflow, provenance/bootstrap manifests, and inert wrapped control keyring | installer initially; administrator-controlled upgrade/rollback thereafter |

#### 6.10.2 First-write, transport-key, and data-key lifecycle

The control reconciler needs repository transport credentials and both project
data keys, but neither event App may control its code or secrets.

**Repository transport.** The CLI creates a write-capable deploy key for the
records repository and another for coverage. Their public halves are scoped to
one repository each; private halves are Actions secrets in control. A manifest
in control records key ID, public fingerprint, repository numeric ID,
capability, creation time, and a successful challenge commit OID. The pinned
control workflow proves each key by writing a fixed non-private challenge to a
generation-specific temporary probe branch, reading it back, and deleting that
ref. It never adds a non-event commit to the records `events` branch or mutates
coverage state. Rotation adds and verifies the successor before deleting the
predecessor. A missing or mismatched manifest forces rotation rather than
trusting secret metadata.

Immediately before generating either private half, install and transport-key
rotation display the repository name and numeric ID, the key's write
capability, where its private half will be stored, and this warning:

> This deploy key is an integrity credential. Anyone who obtains it can read
> encrypted repository data and can rewrite, delete, roll back, or replay that
> data, which may affect CLA check results. This deploy key cannot decrypt CLA
> records by itself.

The same screen explains that people or workflows able to read or execute with
the control Actions secret are integrity controllers. `force=true` may suppress
the interactive confirmation but never the warning; `dry_run=true` prints it
without creating a key. The completion summary repeats the repository, key ID,
fingerprint, capability, integrity reach, secret location, and the
exposure-response command and runbook link. Installer documentation and the FAQ
repeat the warning. The confidentiality qualification is narrow: the deploy
key cannot edit the separate control repository or unwrap a project data key,
but pairing it with control-workflow or wrapping-key access changes that result.

**Initial project keys and recovery.** Before any private record or derived
artifact is written:

1. the CLI generates the actual records and coverage data keys, their `kid`
   values, a per-project control wrapping key, and a random recovery wrapping
   key;
2. it creates project-and-capability-bound control and recovery copies and
   prepares equally bound portal and enforcement wrap requests;
3. it unwraps both actual data keys through the recovery copy and uses each to
   decrypt a fresh challenge;
4. for the shared service, after displaying the hosted-operator trust disclosure
   and receiving explicit confirmation, it sends each raw key over the
   authenticated bootstrap channel only long enough for the capability-specific
   service to return its wrapped copy and decrypt the matching challenge; the
   endpoint persists neither plaintext key nor challenge. The CLI similarly
   verifies the control copy by dispatching the pinned workflow with the
   administrator's own Actions authority;
5. it gives the recovery key to the adopter with a
   prominent instruction to keep it in a password manager or other safe
   storage, then creates the records `keys` and `operations` branches, stores
   the wrapped keyrings in `keys` and in the repositories that consume them,
   and writes the non-secret bootstrap manifest plus the encrypted idle
   prepared-operation cell alongside encrypted empty state;
6. after the three Apps are installed, Connect asks the hosted or self-hosted
   portal and enforcer plus the protected control workflow to unwrap their
   copies and decrypt fresh records/coverage challenges; and
7. only after those repository-bound live-path proofs succeed does Connect
   append the first `project_connected` private event, which activates the
   exact bootstrap manifest, `keys` head and candidate commit, generation,
   repository IDs, and current `kid` values.

**One-time bootstrap anchor.** The first wrapped keyring commit on `keys` is
`K`. Its child `B` adds `.dracla/bootstrap.json`, whose RFC 8785 bytes have this
closed schema:

```json
{
  "bootstrap_version": 1,
  "project_id": "stable-project-id",
  "install_generation": "opaque-generation-id",
  "release": {
    "package_version": "0.1.0",
    "allowed_artifacts_sha256": "sha256:lowercase-hex",
    "source_commit_oid": "Git object ID",
    "provenance_identity": "release-workflow identity",
    "dependency_constraints_sha256": "sha256:lowercase-hex"
  },
  "repository_ids": { "records": 1, "coverage": 2, "control": 3 },
  "records_keyring_candidate_oid": "K",
  "current_kids": { "records": "…", "coverage": "…" }
}
```

The identical bytes are stored on the records `keys` branch at `B`, in the
coverage repository at `.dracla/bootstrap.json`, and in the control repository
beside its install provenance. `K` must be the unique first keyring commit
descending from the mandatory README root, and `B` must be its child. Initial
wrapped copies use the same `project_id`, capability, and `kid`, and their
authenticated `wrapper_generation` equals `install_generation`. The manifest
contains no key or private CLA value and is not independently treated as
authority. Initial Connect compares all three copies before appending the first
event; recovery compares them against the backed-up refs.

`release.package_version` is the normalized exact version displayed by §6.9;
`allowed_artifacts_sha256` identifies the exact release-published canonical
manifest of permitted PyPI filenames and SHA-256 values, without claiming
which artifact the parent resolver used. `source_commit_oid` is the release's
Git source commit, `provenance_identity`
is the non-empty published workflow/subject identity the package reports, and
`dependency_constraints_sha256` hashes the exact bundled constraint bytes.
Connect treats these as pinned install provenance, not as independent proof
that a compromised package told the truth; optional external verification is
what raises that assurance for the one-time local installer.

A records reader with no prior canonical state bootstraps as follows:

1. verify the live records repository ID against its manifest, or verify its
   source ID through the backup manifest before an authorized
   replacement-repository rebind;
2. validate the canonical manifest bytes, require the declared `K`/`B`
   ancestry, and select exactly one wrapped records-key candidate matching the
   declared project, generation, and `kid`;
3. unwrap that candidate through the reader's authorized wrapper and use it
   only to decrypt the sole event in the first post-README `events` commit;
4. require that event to be `project_connected` and to pin `B`, `K`, the
   SHA-256 digest of the manifest bytes, the same install generation,
   repository IDs, and both current `kid` values; and
5. only after every comparison succeeds accept the event and use canonical
   activation events for all current-key selection and later replay.

Missing or duplicate candidates, changed manifest bytes, wrong ancestry,
unwrap or event-decryption failure, a different first event type, or any field
mismatch fails closed. This handshake lets the manifest identify the key needed
to open the first event without letting the manifest declare that key trusted;
the event completes that trust decision. Afterward the manifest is ignored for
key authority and retained only for recovery/provenance.

`keys_ready` is only an in-memory Connect progress condition meaning that the
installer-recorded recovery proofs for both actual keys are present and the
portal, enforcer, and control challenges passed in the current authenticated
operation. It is never committed, placed in the registry, or used after
`project_connected` succeeds. A lost response revalidates the install
provenance, reruns the live challenges and idempotent first-event append, and
creates no second durable setup state.

The bootstrap channel authenticates the GitHub administrator, verifies `admin`
on the newly created records repository and its install provenance, binds the
request to the three numeric repository IDs and one install generation, and
returns only wrapped objects and challenge results. It is not a general key-wrap
oracle and creates no registry entry. A self-hosted install uses the same
protocol against adopter-controlled wrapping roots.

The installer retains no recovery key or raw project key after successful
handoff. Failure before step 5 leaves empty/bootstrap repositories and no
private write authority; rerun either resumes the same verified generation or
abandons it and creates fresh keys.

**Data-key rotation.** `dracla rotate-key --capability records|coverage`
generates a successor, appends all required wrapped copies as a non-current
candidate, and verifies the actual new key through the live service, control,
and adopter recovery paths. Before activation it opens the project-wide marker
and prepares a complete current coverage projection or records-derived snapshot
under the successor; otherwise unchanged current data would remain readable
with the predecessor indefinitely. The authorized administrator then appends
one `keyring_activated` event, encrypted under the prior records key, that pins
the candidate `keys` commit, generation, and new current `kid`. Replay makes
that event the activation point; the prepared current-state commit is published
and the marker closes. New events and subsequent state use the successor.

Append-only canonical history is never rewritten. Old keys remain decrypt-only
while any retained artifact names them, so someone who copied a predecessor may
still decrypt historical data. An unactivated descendant may be used only to
obtain keys needed to replay the activation decision; it is not current by
itself. A failure before activation leaves the prior event-selected key current;
a failure after activation is repaired forward and never removes the prior key.

No placeholder workflow or unused credential is seeded. Install refuses a
release that lacks the real pinned reconcile command and its verification
manifest.

#### 6.10.3 What install collects, and what it does not

**One account, one repository set, one optional project slug.**

```
uvx dracla@<version> install github.owner=hydra-ecosystem
```

`github.owner` names the organization or personal account that will own the
three private repositories. A dedicated organization is optional.

Hydra-style `key=value` rather than a positional argument or a flag, uniform
with the rest of the CLI. An explicit project slug is additive when one owner
hosts more than one project.

```
uvx dracla@<version> install github.owner=hydra-ecosystem                v1 default
uvx dracla@<version> install github.owner=foundation project.slug=projx  explicit project
```

Install's inputs are overrides onto a small config tree, of which exactly one
key is required today:

```yaml
github:
  owner: ???                                 # required organization or user
project:
  slug: ${github.owner}                       # exact case-folded owner login
```

`???` rather than a value: there is no sensible default for which organization
gets the repositories, so it is reported as missing rather than guessed. The
slug default is the owner's login exactly after GitHub's case-insensitive
normalization. `-cla` is ordinary text: an owner named `acme-cla` defaults to
slug `acme-cla`.

The repositories are `<project.slug>-cla-records`,
`<project.slug>-cla-coverage`, and `<project.slug>-cla-control`.

**The prefix is the owner-scoped project slug.** It is a lowercase ASCII GitHub
repository-name component, unique among DraCLA projects under the repository
owner. The default is the owner login; an explicit slug is taken as given after
the same case-folding and syntax validation. No prefix or suffix is stripped,
added, or interpreted. An explicit slug is the whole of what another
same-owner project needs:

```
github.owner=hydra-ecosystem
  hydra-ecosystem/hydra-ecosystem-cla-records    v1 — slug defaulted
github.owner=hydra-ecosystem project.slug=projx
  hydra-ecosystem/projx-cla-records              later — explicit slug
```

The owner login scopes the public claim while the slug identifies one repository
set. Neither is the legal recipient: the recipient remains the independently
entered immutable legal person or entity in `project_connected`. The default
project route elides the repeated default slug (`/p/hydra-ecosystem`); the
explicit example uses `/p/hydra-ecosystem/projx`.

Install collects only what requires the administrator's own credentials and
therefore cannot be deferred: **where to create the repositories**. Everything
else is project configuration, and the portal is a better place for all of it:

| Deferred to the portal | Why |
|---|---|
| Recipient legal name | `REQ-CONFIG-2` data, recorded in the initial `project_connected` event with an `actor` — stronger provenance than a command-line flag, the same argument that moved agreements (§6.5) |
| Enforcement scope | The portal can list the organization's repositories to tick, rather than having the operator type them and hope |
| Privacy policy URL | `REQ-SEC-3` needs it before *signing*, not before provisioning |
| Required fields, confirmation labels | Form design, validated live |
| Retention statement | A paragraph of prose; a text area, not a shell argument |
| Agreement | Published by reference in the portal (§6.5) |

**Install therefore writes no `config/project.enc.json`.** The absence of a
`project_connected` event is how the portal recognizes a repository as
provisioned-but-unconfigured, so no stub is needed — and the recipient's
immutability (§5.5) begins at that event rather than at a flag someone typed
once.

**One project per install invocation.** The owner may hold several projects;
each invocation provisions one independent set. The first may use the defaulted
slug, while another supplies `project.slug`. The immutable recipient remains
portal configuration and never doubles as routing identity.

#### 6.10.3.1 Sequence

Install is **idempotent and re-runnable**; a partial run is the expected failure
and re-running is the recovery. It is not transactional — GitHub offers no way
to make it so — so each step is individually safe to repeat, and the order puts
the cheapest failures first.

```
1. preflight the owner and release   resolve org or personal account; require
                                     an exact package version; display and record
                                     allowed-artifact-manifest, source/provenance,
                                     and dependency-constraint identity;
                                     verify three private repos and real reconciler
                                     exist
2. confirm with the operator         unless force=true or dry_run=true
3. create all three repositories     auto_init: false; read back to verify
   EMPTY                             every repository is private
4. PUT the records README via the    creates GitHub's initial default branch
   Contents API                      and the mandatory root commit
5. read and rename that branch       Branch Rename API -> `events`; verify it
                                     is now the default branch
6. seed control                      pinned workflow and provenance manifest;
                                     no event App is installed with contents access
7. provision transport credentials  show the mandatory integrity warning;
                                     records and coverage deploy keys live only
                                     in control Actions secrets; verify them and
                                     repeat their reach in the completion summary
8. generate and verify project keys display hosted trust disclosure; complete
                                     recovery, service-wrap, and control proofs;
                                     deliver recovery material before private state
9. initialize operation, coverage,   create `keys` and `operations` from the
   and keyring state                 README root; write wrapped copies, the
                                     identical non-secret bootstrap manifests,
                                     the idle prepared-operation cell, and the
                                     empty §4-encrypted projection; no signer
                                     data exists
10. print the three App install links records, enforcer, and trigger-only
```

**Reuse requires provenance, per repository.** Re-running finishes only a
repository this command made: records must carry its `events` branch rooted at
the exact DraCLA genesis README plus `keys` and `operations` branches descended
from that root, with a schema-valid idle or recoverable prepared-operation
cell; coverage must carry its `coverage` genesis and encrypted empty
projection, and control the exact release manifest plus pinned workflow. The
three bootstrap copies bind
all repository numeric IDs, `K`, and one install generation; the control install
provenance additionally records the resulting initial `keys` head `B`. The
first `project_connected` event must later pin the same values. A name collision
without matching provenance is refused; encryption does not authorize DraCLA
to take over an unrelated repository.

**Why empty rather than `auto_init`.** `auto_init` hides the provenance and
content of the root commit behind repository creation. Starting empty lets
install make the exact mandatory README root itself. GitHub still chooses the
initial branch name, so install reads and renames that branch rather than
assuming `main` or trying to create an impossible first Git ref.

**Bootstrapping needs the Contents API plus Branch Rename, not the Git Data
API.** GitHub's Git references endpoint cannot create the first branch in an
empty repository. `PUT /contents/README.md` initializes the repository with the
required root commit; install then reads the created default branch and renames
it to `events` through the branch rename endpoint. Subsequent commits use the
Git Data API.

A consequence: the records branch begins with exactly the mandatory README root
and no workflow commit. The first later records commit is the first private
event and has that current head as its single parent.

**Install does not write the registry entry.** The registry lives in DraCLA's
own organization (§7), and the CLI runs as the adopting administrator, who has
neither the credentials nor any business writing there.

The entry is written only after the administrator completes **Connect** in the
portal — an explicit act, not a side effect of installing an App:

```
1. uvx dracla@<version> install github.owner=acme
                                         three repos and verified recovery exist
2. install the three Apps                GitHub consent; the Setup URL callback
                                         stores nothing and only directs the
                                         administrator to Connect
3. portal: Connect                       the administrator authenticates,
                                         DraCLA verifies `admin` on records,
                                         resolves the repositories' stable owner
                                         ID/current login and owner-scoped slug,
                                         GitHub authority for each App binding,
                                         and the authority required for every
                                         contributing-repo or org selector
                                         (§7); personal accounts use the same
                                         repository checks
4. same session: configure               recipient, enforcement scope, privacy
                                         policy, required fields, and initial
                                         reader authorizations;
                                         verify portal, enforcer, and control
                                         challenges, then atomically append
                                         `project_connected` (including the
                                         repository owner, project slug,
                                         independent recipient, and exactly
                                         seven owner, repository-admin, and
                                         App-binding authorization records)
                                         plus encrypted config;
                                         publish any agreement versions, then
                                         activate one when it should become
                                         signable (§6.5)
5. portal activates initial scope        only after `project_connected`, run
                                         §7.1 once for the complete configured
                                         scope: append the authorized
                                         `enforcement_scope_requested` from an
                                         empty prior scope and the current
                                         registry generation, prepare the
                                         generation and pending gates, append
                                         `enforcement_scope_activated`, then
                                         publish routes and commit gates. Each
                                         entry carries its own required
                                         authority evidence. No route is
                                         published directly from
                                         `project_connected` (§7)
```

Making this deliberate rather than automatic is what allows the slug claim of §7
to be verified at all. An entry created as a side effect of an App installation
cannot establish that whoever claimed `acme` administers `acme`, which is the
look-alike-portal attack §7 exists to prevent. A connect step can, because there
is an authenticated human whose organization permissions can be checked.

The install links carry no token, and the callback is trusted for nothing.
GitHub documents that its `installation_id` can be spoofed, so the callback
does not persist it. Connect independently lists the authenticated
administrator's installations from GitHub and verifies them there; an App
installed straight from its GitHub page — no CLI-printed link involved —
connects identically.

R5's "routable registry entry published last" therefore still holds, and
holds more strongly: a prepared generation is non-routable, and the project
cannot become routable until the scope activation protocol has reverified the
required ownership and per-entry authority.

**Install never produces a signable project, by design.** Configuration,
agreement publication, and activation happen in the portal, so install finishes
by directing the operator there rather than implying the project is ready. An earlier
implementation exited successfully and printed a portal URL after provisioning
nothing signable; separating the two operations removes that confusion rather
than patching it.

#### 6.10.4 Reader authorization and plaintext delivery

Repository access and DraCLA reader authorization are independent. An ordinary
owner, collaborator, organization member, backup process, or read-only App may
clone ciphertext without becoming a records reader. A dedicated organization
and a narrow repository ACL reduce exposure and operational mistakes, but
neither is required for confidentiality or portal access.

A records administrator authorizes one of three canonical source types:

- **individual** — one stable GitHub numeric account ID;
- **team snapshot** — all or a selected subset of the team's current members,
  captured atomically in one canonical event and materialized as independently
  withdrawable per-account sources; this is the default team action; or
- **continuous team** — an explicit standing delegation to current and future
  team membership administrators, with the required warning.

Sources combine by union. Withdrawal removes only the selected source and the
confirmation lists every source that still authorizes the reader. A continuous
membership observation appends an automation event referencing the rule and
GitHub evidence; it never rewrites the original administrator's act.

**Every reader-source addition and removal is one synchronous, idempotent
operation.** An individual action carries one subject; a snapshot action freezes
its complete selected set in one `records_reader_snapshot_authorized` event, so
there is no partially appended N-event batch. The event commit advances the canonical reader generation. The
portal then read-modify-writes only the source's bounded reader-authority shard
or the snapshot's bounded set of affected shards and atomically updates the
derived state with that generation and each shard's new envelope digest. It
reads them back and verifies every requested source effect,
generation, and digest before returning success. Retrying the same operation
resumes or returns the same result. If the request stops after the event commits
but before verification, it returns no success; the canonical change remains
authoritative and private reads fail closed on the generation mismatch until
the retry or existing reconciler finishes the shard. The reconciler improves
recovery time but is not part of the authorization proof.

For every private authorization and read, `worker-portal` performs this
sequence. The initial Free profile permits at most ten active continuous reader
rules per project, so the cold path can check every continuous candidate without
exceeding §9.2's subrequest ceiling; configuration rejects an eleventh active
rule before appending it.

1. authenticate the GitHub user and resolve exactly one signed project route;
2. to issue a proof, resolve the canonical reader generation and one immutable
   `derived` head, validate state plus all 32 reader-authority shards, authorize
   the exact query/scope, and select one exact source; prefer an individual or
   snapshot source, otherwise check continuous sources in stable source-ID order
   through the records App until one currently contains the authenticated user,
   denying on GitHub error or an indeterminate result, then issue the exact
   §6.6 proof bound to that source's stable identity, query scope, session, and
   generation;
3. to use a proof, authenticate the same user, re-resolve the canonical reader
   generation, and require an exact proof match; when its source is continuous,
   repeat that exact GitHub membership check immediately before fetching one
   fixed, server-selected encrypted data shard, denying and invalidating the
   proof on absence, error, or indeterminate state so a later proof request may
   select another source;
4. validate all §4 bindings and the state-recorded shard digest, decrypt, and
   filter to the permitted result class; and
5. return `Cache-Control: private, no-store` with no raw key, raw decrypt
   operation, arbitrary path, or arbitrary subject parameter.

No proof is usable without the canonical generation recheck, and no proof bound
to a continuous source is usable without its live membership recheck.
Isolate-local decrypted data may be reused only within one request. A stale or
mismatched generation, missing, oversized, corrupt, unavailable, or
wrong-project key material, and absent or indeterminate continuous-team
membership deny the read. Unknown project and unauthorized viewer return the
same bounded response.

Reader authorization does not grant GitHub repository access, and GitHub
repository access does not grant portal or dashboard plaintext. Giving a person
repository access is therefore an ordinary custody choice, not part of the
DraCLA reader flow. The operator README recommends least privilege and explains
that control-workflow writers, secret and wrapping-root controllers, hosted
decryption services, and recovery custodians remain key controllers even if
they are not ordinary records readers. Records- or coverage-only administrators
without such a capability control integrity but see ciphertext.

The installer verifies only that all three repositories are private and that
the configured Apps and wrapped-key capabilities match §4. It does not inspect
or constrain base permissions, owners, teams, collaborators, or unrelated
read-only Apps. Organization and personal-account custody use the same
encryption and authorization rules.

#### 6.10.5 Module boundaries

The removed implementation reached through `GitHubHost` into its private
transport at six call sites, because the `GitHost` protocol (§5.2) models
append-only records and says nothing about creating repositories or reading
organization settings.

Administration is therefore its own surface — repository creation, visibility,
deploy keys, organization settings — separate from the records protocol and
substitutable in tests. Nothing in the CLI mutates `sys.path`; `core` is a
sibling package in the same distribution.

#### 6.10.6 What the tests must cover

The four blocking findings were all **seams**: modules individually plausible
and never exercised together. The workflow template passed five tests while
invoking a subcommand that did not exist. Unit coverage would not have caught
any of them, so these properties are asserted across modules:

- every `dracla` subcommand a generated artifact invokes is registered
- `dry_run=true` issues no write of any kind
- no event App can modify the control workflow, dependency pins, or any
  executable/control input used by its key-bearing job
- Connect cannot write the registry entry until it has validated the
  installer-recorded recovery proofs for both actual project keys and its
  current authenticated operation has passed repository-bound portal,
  enforcer, and control challenges;
  `keys_ready` remains transient and the first `project_connected` event must
  confirm the exact bootstrap manifest, keyring ancestry, repository IDs,
  generation, and key IDs
- a fresh records reader and a service-independent recovery run can discover
  `K` from repository state, decrypt and authenticate the first event with the
  appropriate wrapper, and then replay activation events without service
  state; changed or disagreeing manifest copies, wrong `K`/`B` ancestry,
  duplicate candidates, and any first-event mismatch fail closed
- ordinary readers and read-only Apps see only authenticated ciphertext and
  gain no portal authorization
- an enforcer-only key can decrypt effective merge-decision fields and generic
  reason codes, but no exact reason, exemption provenance, or reader-authority
  source
- a continuous-exemption observation failure before materialization leaves the
  prior canonical source effective and retryable, while failure after the
  subject marker opens remains fail-closed until repair; for continuous readers,
  a missed or failed departure observation still makes the next live membership
  check deny plaintext before canonical withdrawal, and a join cannot authorize
  plaintext before its canonical addition
- reader-source additions and removals return success only after the encrypted
  source shard and derived state are read back with the requested effect,
  canonical reader generation, and envelope digest; a crash after the event
  append leaves later private reads fail-closed until idempotent retry or
  reconciliation repairs the shard and state
- reader-source union is validated across all 32 bounded shards when a proof is
  issued; every plaintext page rechecks the canonical reader generation and any
  bound continuous-team membership, so a withdrawn source or missed team
  departure invalidates an older proof; unavailable or indeterminate membership,
  wrong user/project/query scope, stale generations, oversized shards, or
  state/shard digest mismatches are rejected, while a fresh proof may bind to
  another still-active source
- ordinary subject mutations rewrite only the affected index/status shards and
  small state file; reader mutations rewrite only one source shard and state;
  bounded bulk fan-out does not publish its generation or report success until
  every shard is complete
- signing, revocation, and administrative mutations never regenerate JSON/CSV;
  hosted exports run only in the protected control workflow and local exports
  stream from the CLI, with source OIDs and profile limits verified
- checked-in golden vectors use fixed test-only keys and nonces to require the
  Python and TypeScript implementations to produce identical artifact bytes,
  AAD bytes, envelopes, and wrapped-key files, and to reject tampered,
  non-canonical, padded, or wrong-length inputs; vectors cover every row of
  §4's identity table, including dynamic event, shard, and agreement
  path tokens, and reject wrong branch, path, kind, capability, schema, and
  payload-to-path relations
- authorization vectors cover every literal operation, resource kind, and
  required-authority combination in §5.1, including every scope-change action,
  and reject unknown tokens and valid tokens in the wrong pair. Connection and
  owner-transfer vectors require exactly seven correctly ordered evidence
  members with payload-matching repository IDs and live bound-App installation
  IDs; they reject a missing, extra, duplicate, or mismatched member.
  Key-activation vectors require one entry per affected project repository
- a mutation starting after evaluation but before authoritative publication
  wins the shared coverage branch-head CAS while replacing the fence state and
  makes the stale success reservation conflict; success held under a
  reservation completes before a later mutation begins; crash recovery never
  clears a reservation from elapsed time alone
- a routing transition starting after evaluation races
  `reserve_publication`; pending or a changed generation winning first produces
  only a non-passing result, while a winning publication reservation makes
  every later `begin_pending` conflict until an exact completed GitHub check is
  independently confirmed. Vectors pause after reserve, during the GitHub
  write, after GitHub completion but before webhook delivery, and after a lost
  response; no transition overtakes completion and age never clears the row
- routing-gate rebuild vectors observe the exact coverage fence before
  restoring an active row: a matching `success_reserved` check identity
  recreates the publication reservation, an idle fence is accepted only under
  the acquire-first/release-after-completion invariant, and every unavailable,
  malformed, or mismatched observation leaves the route unavailable
- initial-connect vectors prove that `project_connected` alone publishes no
  route. The complete initial desired scope runs through the ordinary §7.1
  request, prepared generation, pending-gate, activation, route-publication,
  and gate-commit sequence from an empty prior scope; a failure at every pause
  leaves every initial binding non-routable
- event-wide check-run vectors deliver created and completed events for other
  Apps and for DraCLA ordinary checks and prove that App mismatch or any
  non-authoritative `external_id` namespace is rejected before a gate RPC. Only
  the exact `dracla-authoritative-v1.` grammar may reach
  `confirm_publication`, and malformed, ordinary, unknown, wrong-head, and
  wrong-name inputs never clear a reservation
- mutation crash vectors stop after each prepared-cell transition, after
  preparation but before fence acquisition, after fence acquisition but before
  marker open, after append-right acquisition but before canonical ref update,
  and after canonical append but before each projection/fence/cell close; every
  case recovers from repository state without the original request. A terminal
  no-op/conflict CAS defeats a delayed append claimant, an already-appending
  claimant must be repaired forward, and delayed marker or projection commits
  conflict on the advanced coverage head. The vectors distinguish
  `expectedHeadOid` CAS on the operations and coverage branches from the
  canonical events branch's non-forced fast-forward/reload/rebuild protocol.
  Mismatched cross-repository identities fail closed. If the event is absent,
  recovery revalidates and continues the frozen operation or records an
  explicit terminal no-op/conflict while still `prepared`; neither absence nor
  age clears any state
- contributor and administrative idempotency vectors bind the authenticated
  §5.4 form state, including a server-issued nonce, exact Table 5.4-A event
  type, and confirmed canonical OID. Contributor vectors cover a request already
  satisfied at that OID, two concurrent acceptances from the same OID, an
  intervening revocation or agreement/lifecycle change, and a delayed retry
  after a no-op followed by revocation. Table-driven administrative vectors
  cover every mutating §6.8 action type and include an already-active agreement
  and an already-current configuration, then change each example state before
  retrying the old form. A no-op form directly reads and
  validates its bound event from the exact confirmed commit and returns the
  same result after the later change; a non-no-op form requires an exact
  current-head match and otherwise returns a fresh-confirmation conflict. No
  delayed request appends; only a newly rendered, freshly authorized action may
  append the later contributor or administrative event. The vectors cover
  every Table 5.4-A row and allowed terminal type, and reject every internal
  automation type, wrong terminal type, and unlisted action/event pair.
  The scope-action no-op fixture direct-reads one
  `enforcement_scope_activated` event whose repeated `desired_scope` equals the
  form operation; a mismatch is rejected without dereferencing the request
  event or entering preparation.
  Scope-terminal identity vectors derive the request, activation-child, and
  abandonment-child keys and paths from one fixed request and prove them
  pairwise distinct; an injected digest collision fails closed. Exact child
  retries reproduce one path and fingerprint, while changed actor, target, or
  payload reuse conflicts. Fast-forward race vectors reuse an occupied event
  path with a changed fingerprint and require the operation conflict while the
  valid persisted event remains authoritative; with a matching fingerprint,
  a malformed event or missing, malformed, or mismatched required side
  artifact instead fails closed as corruption. Race vectors pause activation
  and abandonment at the same canonical head in both orders: exactly one
  terminal child lands, the loser re-reads both paths and performs no append or
  opposite gate transition, and replay rejects fixtures containing both
  terminal kinds or two different same-kind terminal events for one request.
  Crash vectors retry each terminal child before and after its ref update and
  recover the same terminal result without creating a second scope change.
  Form-envelope vectors cover exact JCS and one-dot encoding, actor/session/
  operation binding, absolute parent-session expiry, successor and eligible
  predecessor `kid`s, constant-time tag validation, and rejection of unknown,
  expired, padded, non-canonical, wrong-key, or malformed values
- mutation serialization vectors hold Alice's operation in each non-idle cell
  state and prove that a different Bob operation cannot prepare or add a second
  `inflight.ops` entry. Bob receives the bounded wait/retry response, then
  revalidates and proceeds only after Alice returns the cell and fence to idle;
  continuous-team transitions follow the same sequence. Subject-scoped and
  project-wide marker fixtures both require `started_at`; recovery preserves an
  existing value and, when opening an absent marker, writes the successful CAS
  time without using it for ordering or expiry
- ordinary-check scope vectors open a subject mutation for Alice and prove that
  Alice's check is `in_progress` while a disjoint Bob check can continue from
  the same immutable projection; a project-wide mutation blocks both. The same
  subject mutation prevents every authoritative merge-group success
  reservation, and `project_wide: true` with subjects or `project_wide: false`
  without a non-empty duplicate-free subject set is rejected
- owner `acme-cla` defaults to slug `acme-cla`; two explicit slugs under one
  repository owner coexist; the same slug under another owner is independent;
  every public alias resolves through the immutable owner-ID/slug/project-ID
  tuple, never through recipient identity; a partial owner transfer is
  unavailable and a complete transfer moves the claim only through its bound
  event and registry generation
- one multi-subject exemption or reader snapshot retry either returns the same
  complete frozen set or conflicts, and never exposes a partially appended
  canonical batch; per-subject source withdrawal remains independent
- override vectors derive the exact projection key from the JCS repository/PR/
  user/GitHub-root-tree-OID tuple in §4; history-only rebase preserves it,
  content change lapses it, merge-group evaluation uses the associated PR tree,
  ordinary and merge-group evaluation consume the closed active entry from the
  subject's already-fetched shard, and whole-grant withdrawal removes that
  entry for only future decisions while retaining canonical history. Fixtures
  prove that uncovered subjects fail without the entry, pass with the exact
  entry, and fail for a missing, withdrawn, malformed, wrong-repository,
  wrong-PR, wrong-subject, or wrong-tree entry without extra shard reads
- a succeeded project rejects every closed action, materializes its successor
  into coverage, keeps prior completed decisions unchanged, allows only the
  documented maintenance and recovery actions, and transfers each scope entry
  only through the two-generation remove-then-bind protocol
- OAuth uses PKCE `S256`; its encrypted browser-bound pre-auth cookie and signed
  state expire at ten minutes, the verifier is never stored in KV, and the
  callback deletes the pre-auth cookie after the one-time code exchange; cookie
  and KV session expiry match the access-token expiry minus five minutes without
  sliding; refresh tokens are absent; private-read proofs expire at five
  minutes; missing or mismatched state/cookie/verifier fails, racing the same
  callback mints at most one session, and a code from another PKCE flow cannot
  use this browser's verifier; `401` restarts OAuth without a write while `403`
  denies only the action
- release-documentation checks reject an omitted or floating package selector;
  installer integration tests display and persist the exact release-declared
  version/allowed-artifact-manifest/source/provenance/dependency-constraint
  identity before authorization, never label one artifact as runtime-observed,
  and
  keep external artifact verification an optional local-install hardening step
  rather than a bootstrap dependency
- `agreement_published` exposes its event, exact snapshot, and matching metadata
  in one commit or none; `project_connected`, `config_updated`, and every event
  that changes a derived class expose their event plus the matching config or
  generation file in one commit or none; race retries rebuild and revalidate
  the complete event-specific tree
- the records `events` branch remains README plus one-logical-event commits while
  install and rotation write keyrings only on `keys` and mutation recovery state
  only on `operations`; missing, rewritten, or rolled-back activated key history
  or a corrupt prepared-operation cell fails closed
- a rewrap-only migration preserves old-key historical access, while a tested
  security cutoff rotates every affected project data key, rewrites all current
  mutable state under the successors, and leaves append-only history readable
  only through retained predecessor paths
- a created repository is read back and confirmed private
- existing-organization and personal-account installs do not require a
  dedicated organization or a particular repository reader set

---

## 7. Multi-tenancy and isolation (`REQ-OPS-6`)

One shared deployment serves all projects; no function per project. Request
handling remains stateless except for the repository-scoped routing gates
permitted by `REQ-OPS-2` and defined in §7.2. The bounded project decision fence
of §5.4 is an encrypted file in the project's existing coverage repository, not
provider-managed application state.

```
dracla/dracla-registry            <- its own repository, not a monorepo dir
  project: acme
    repository_owner:
      github_account_id: 123456
      login_snapshot: acme
    project_slug: acme
    records:  acme/acme-cla-records
    coverage: acme/acme-cla-coverage
    control:  acme/acme-cla-control
    key_generation: 7                       <- no raw or wrapped keys in registry
    enforcement_scope:                       <- the CODE repos
      - entry: acme/*
        request_event: 8b8c…        # canonical request with actor and org-owner evidence
      - entry: acme-labs/widget
        request_event: 9c9d…        # canonical request with actor and repo-admin evidence
    registry_generation: 42
    routing_gate_namespace: repository-routing-v1
    installations:
      records:  [ … ]        # a set, not one id — see below
      enforcer: [ … ]
    claim_authority: repository_owner
    claim_verified_at: 2026-08-18T…
```

**The registry is its own private repository.** D2's argument applies to it
directly: tokens cannot be path-scoped, so a credential able to write
`registry/` inside the monorepo could also write `api/` and `core/` — making
security-critical routing data writable by anything that can touch the
codebase. It also must not be public, since it enumerates every adopter, their
private repository names, enforcement scope, and installation ids.

Human registry changes use pull requests with `CODEOWNERS` and required review.
The one exception is the registry installation of `dracla-records`: branch
rules explicitly allow only that App to bypass review for the portal's fixed,
validated operations. Force pushes and branch deletion remain forbidden. The
App necessarily has repository-wide `contents: write`, so review does not
protect against compromise of that automated writer; the security boundary is
its narrow API, live authorization checks, overlap validation, fast-forward
compare-and-swap, and permanent canonical administrative event. A human pull
request must reference the same kind of prior canonical request event. For an
administrative mutation, registry sync may prepare that exact generation but
refuses to publish it when the request is absent, describes different content,
or lacks the matching canonical activation event. GitHub-side reconciliation
generations follow §7.1's separate observation path because no administrator
changed a selector. Thus human review protects human changes, while the
automated path is explicitly trusted and audited rather than falsely claimed to
have been reviewed.

**Owner-scoped slug claims are verified at connect and never reassigned
silently.** The
claim is established when an administrator connects in the portal
(§6.10.3.1), after GitHub returns the stable numeric account ID and current
login for the account that owns all three project repositories. The actor must
be a current organization owner when that account is an organization, or be
that same authenticated numeric account when it is personal; delegated admin
on one repository is not public-namespace authority. The actor must also have
`admin` on all three project repositories and pass the App-binding checks. The
unique claim key is
`(repository_owner.github_account_id, project_slug)`, so `foundation/projx`
requires authority over `foundation`, not an unrelated account named `projx`.
Personal-account ownership requires the authenticated account itself. Owner
rename updates the login snapshot and preferred route only; project ID and
claim identity do not change. Transferring project repositories to another
numeric owner is an explicit migration. Detection makes the project route and
checks unavailable until all three recorded repository IDs have the same new
owner, their App bindings and administrator access are reverified, the actor
proves control of that owner, and the new-owner/slug pair is unclaimed. The
portal stages the exact registry generation that removes the old claim and
creates the new one, puts every affected route gate into `pending`, then appends
`project_repository_owner_changed` under the project-wide marker and decision
fence, binding that registry commit and generation. It publishes the staged
routes and commits the gates only afterward, using §7.1's conditional methods.
A failure before the event restores the prior gates; a failure after it leaves
them pending until that exact generation finishes. The old owner-qualified route is
removed rather than redirected because the old owner may legitimately reuse
that namespace; account rename is the only case that retains an authenticated
alias redirect. The event changes no project ID, recipient, agreement, or
evidence. A partial transfer or publication failure remains unavailable and is
retryable; it never routes through whichever repository moved first. The
recipient is always the separate immutable legal person or
entity recorded in `project_connected`; GitHub ownership never proxies it.

**What an enforcement-scope entry means.** An entry in a project's enforcement
scope routes that repository's pull requests to this project — a repository in
no project's enforcement scope receives no check at all — names this project's
agreement as the one its contributors are asked to sign, and directs their signatures into this
project's records repository. It grants the project no access to the
repository: every permission comes from the enforcer installation, which the
repository's organization controls and can restrict or remove. And it blocks
nothing by itself — merges are gated only once that repository's own
administrators make the check required. The current enforcement scope decides
only which repositories are checked. It is not copied into acceptances and does
not define or change the agreement's legal reach. An entry is therefore
effective only where three consents meet:
the organization installed the enforcer, a repository administrator or
organization owner bound the applicable entry (below), and the repository's
administrators required the check.

**Enforcement scope is bound by the exact action matrix** (`REQ-CONFIG-5`,
`REQ-SEC-6`). An entry is `owner/name` or `owner/*`; the owner segment is a
literal account name, and anything else is rejected at write. Binding,
widening, narrowing, or removing a repository entry requires current `admin`
on that repository. The same four operations on `owner/*` require current
organization-owner authority. There is no records-admin shortcut for removal.

Every mutation first appends an `enforcement_scope_requested` event containing
a stable change ID, the complete desired scope, the prior active scope and
generation, and the actor, exact operation, affected resource, required
authority, observed result or evidence, and check time. A request is durable
authorization and intent, **not effective configuration**. Only a later
`enforcement_scope_activated` event enters the current-scope fold. It
immutably references the request, repeats that request's exact desired scope,
and names the exact prepared registry commit and generation. Replay requires
the two desired-scope values to be equal before applying the activation. If
preparation cannot complete before activation, an
`enforcement_scope_abandoned` event closes the request and the old scope remains
current. One stable change ID ties the request and terminal evidence together,
but they do not reuse one idempotency key: the request keeps its form key and
activation or abandonment uses its role-specific deterministic child key from
§5.1. An exact retry resumes or returns the matching event. Once either
terminal child lands, the other child and every different same-kind terminal
fingerprint are conflicts, so the request can close only once.

The first scope request after `project_connected` is the same protocol, not a
bootstrap exception: its prior scope is the empty set and its
`prior_registry_generation` is the current registry generation, even though
that generation has no route for the new project. `project_connected` alone
can never make a repository routable.

§7's state machine performs the handoff. It rechecks the same live authority,
stages and validates the registry and signed KV generation, and puts each
affected repository's strongly consistent routing gate into `pending` before
activation. The old scope remains canonical while the new generation is
prepared, but no new enforcement request may use its old route after the gate
is pending. After the workflow rechecks authority and appends the activation
event, it publishes the new KV generation and switches the gate to the derived
final state and generation. KV locations that still see an old value fail on
the generation comparison until their route refreshes. Once activation is
recorded it may not be abandoned: failure to publish leaves affected
repositories pending until reconciliation completes that exact generation.
Scope changes never delete or alter acceptance, revocation, agreement, or
administrative evidence and never require a contributor to re-sign.

An `owner/*` entry is standing consent for present and future repositories —
the same semantics as installing an App on all repositories — and the
organization keeps two continuing controls regardless:
the enforcer installation itself, whose coverage every enforcement-scope entry requires
and which the org can restrict or remove unilaterally, and per-repository
required-check configuration, without which nothing blocks. Without the owner
check, anyone whose installation access merely *covered* an unclaimed
repository could bind it into their own project and have the App direct that
repository's contributors to sign their agreement at a genuine portal — the
same attack this section closes for slugs, through the side door.

Different authorized people may add different scope entries in separate portal
actions; no one actor needs authority over every owner. Each action is complete
only for its named repository or organization selector and carries its own
canonical authorization event. This supports federated enforcement scope
without turning one administrator's permission into authority over another
owner.

Every org and repository in `enforcement_scope` must be covered by the enforcer
installation, and claims are first-come and never transferred silently.
First-come is enforced by the write, not by a scan: the portal lands registry
commits under the same fast-forward conflict discipline as §5.2, and a claim that
loses the race re-validates against the new head and fails because that exact
`(repository_owner.github_account_id, project_slug)` pair is taken. Without
this, self-serve install plus a user-chosen slug could let an attacker publish
a look-alike route beneath an account they do not administer, under a genuine
OAuth consent screen, collecting real legal names and emails into their own
repository. §7's token/repo binding rule cannot catch that on its own, because
a poisoned entry naming the attacker's own installation and repositories is
internally consistent.

**One coordination domain, one project per repository.** A coordination domain
is one deployment plus its authoritative registry: the shared hosted service is
one domain, and each independent self-hosted deployment is another. Every
registry mutation atomically validates the complete selector set and refuses a
repository binding or organization selector that would overlap another
project. A move is always two visible operations: remove the old binding and
wait until that generation is active, then bind the new project. DraCLA never
creates simultaneous membership or chooses a winner by precedence.

### 7.1 One routing and reconciliation state machine

Repository routing combines four things that change independently:

1. canonical per-project events are the authority for administrator-approved
   selectors;
2. GitHub is the authority for a repository's numeric identity, current owner
   and name, existence, and current enforcer installation;
3. an immutable registry generation is the coordination-domain snapshot that
   combines those selectors with the observed GitHub facts and their match
   result; and
4. signed KV entries are the runtime projection of one registry generation,
   while a repository-scoped Durable Object holds only that repository's
   strongly consistent routing state, generation, and at most one transient
   authoritative-check publication identity.

The registry coordinator runs in `worker-portal`, which holds the records App
credential, registry write access, routing-signing key, and the Durable Object
namespace binding. It never receives the enforcer App key. `worker-enforce`
verifies lifecycle webhooks and can read
current contributing-repository facts with that App. It sends only the verified
repository ID and delivery trigger to the coordinator, and answers the
coordinator's fresh observation request over §6.8's service-authenticated
boundary with the repository ID, owner/name, existence, installation ID,
observed permission result, and check time. The response is bound to that exact
request and cannot authorize a registry mutation by itself. Conversely,
`worker-enforce` reads only the signed routing projection and calls a narrow
internal gate service. It may compare a route and conditionally reserve or
confirm only the transient publication fields for an exact check identity; it
cannot change route state, generation, prepared identity, or registry data and
receives neither namespace-transition capability, registry access, nor a
records-App token.

No layer is silently substituted for another. A prepared registry generation
records the exact canonical request event IDs it used, the GitHub repository
ID, owner/name snapshot and installation ID it observed, and the resulting
state. The later canonical activation event points to that immutable generation;
the generation does not point back to the activation event, which would create
a circular identity. For a GitHub-side change with no administrative scope
mutation, the generation instead records the lifecycle delivery or
scheduled-observation evidence. The Durable Object row contains only the
repository ID, derived state, generation, registry commit OID, and signed-route
digest needed to reconstruct and compare it. This history and gate state are operational routing
evidence, not CLA evidence and not signer data.

Registry generations are immutable coordination-domain snapshots, but runtime
publication remains repository-local. A gate names the newest registry
generation that changed or re-established that repository's derived row; an
unaffected repository may continue using an older signed row and matching gate
after the global registry advances. The coordinator computes the complete diff
before activation and must put every repository whose derived row changes into
`pending`. It cannot carry a row forward merely because its project identifier
looks unchanged: repository identity, installation coverage, derived state,
and the canonical unsigned route payload must all be identical. The signature
key and signature bytes are an envelope over that payload, not part of its
semantic identity; rotating the signing key does not by itself change a gate.

Each known repository has exactly one derived state:

| State | Meaning | Request behavior |
|---|---|---|
| `active(project, generation)` | Exactly one project matches; repository identity and one current enforcer installation are verified; the signed KV entry and routing gate name the same generation | Use only that project's route and credentials |
| `conflict(matches, generation)` | More than one project matches after a GitHub-side change | Fail closed; publish only the bounded conflict result below |
| `pending(change, prior_generation)` | An authorized DraCLA change or observed GitHub change is crossing the publication boundary | Only the affected repository fails closed as temporarily unavailable |
| `unavailable(reason, generation)` | GitHub facts, installation binding, signatures, freshness, or generation agreement cannot be established | Fail closed; retry and reconcile automatically |
| `unmanaged(generation)` | The existing repository was verified to match no project | Create no DraCLA check and perform no project access |

A deleted repository has no runtime route. Its numeric-ID tombstone remains in
the registry generation so restoration is observed and matched again rather
than silently inheriting the deleted name's route.

`unmanaged` does not edit GitHub branch rules. Before activating a removal or
offboarding, the portal warns when the DraCLA check is still required and gives
the repository administrator the exact rule to remove. If they leave it
required, its absence continues to block merges; DraCLA never fabricates a
passing final check merely to offboard itself.

**DraCLA-side change protocol.** A bind, widen, narrow, remove, move, or
offboarding action follows one recoverable sequence:

1. append the authorized `enforcement_scope_requested` event described above;
2. verify current GitHub facts, installation coverage, and the complete
   selector set, then commit an immutable **prepared** registry generation
   referencing the request and stage its signed KV entries under internal
   `prepared/<generation>/<repository_id>` keys; neither is routable yet;
3. update each affected repository's Durable Object gate, one strongly
   consistent object at a time through the conditional `begin_pending` method,
   to
   `pending(change, prior_generation, prepared_generation)`, and do not proceed
   until every update is acknowledged; there is no cross-object transaction,
   but the old scope remains canonical until all affected gates are pending;
4. recheck the request's same live authority and append
   `enforcement_scope_activated`, binding the request and fresh authorization
   evidence to the exact registry commit and generation and repeating the
   request's exact `desired_scope`; derive its activation-child identity and
   direct-read both deterministic terminal paths first. A mismatch or an
   existing abandonment is invalid and cannot enter the current-scope fold;
5. publish and actively revalidate each affected signed route at the stable
   `routes/<repository_id>` KV key; and
6. replace each pending gate through the conditional `commit` method with the
   prepared generation's `active`, `conflict`, or `unmanaged` state, then
   re-evaluate affected open
   pull requests. An edge that still reads the old KV generation continues to
   fail closed until that route refreshes.

A failure before step 3 leaves the old generation active. A partial failure
during step 3 does not permit activation: the coordinator restores every gate
it already made pending, and any restoration it cannot complete remains safely
pending for reconciliation. A failure after step 3 but before activation leaves
only the affected repositories unavailable; the request may be completed or
explicitly abandoned through its deterministic abandonment-child identity,
after first proving that neither terminal path exists, after which the
coordinator restores the prior gate state and generation. An activation and
abandonment race is serialized by the canonical branch: the loser re-reads the
winner's terminal path and performs no write or opposite gate transition. A
failure after activation cannot
make the old route canonical again: affected repositories remain pending until
reconciliation publishes that exact prepared generation. A rollback after
activation is a new, independently authorized scope change. Canonical replay
requires at most one terminal child per request and folds only activation
events, so it always names the generation that is allowed to become active;
request and abandonment events remain audit evidence without changing current
scope.

**Every gate transition is conditional and idempotent.** Strong consistency
orders calls to one object; it does not make a delayed older call logically
current. The object therefore exposes only local-storage transactions with
these rules:

- `begin_pending(transition_id, expected_row, prepared_identity)` writes
  pending only when the complete current row equals `expected_row` **and no
  publication reservation exists**. When no row yet exists for a newly known
  repository, `expected_row` is the explicit absent-row value and matching it
  conditionally creates the first pending row. Otherwise the caller supplies
  the exact complete stable row, including an existing `unmanaged`, `active`,
  `conflict`, or `unavailable` row. Repeating the identical call returns the
  existing pending row; a different or stale expectation, or any publication
  reservation, is a conflict. The caller retries after publication recovery;
  it may not queue a hidden transition behind the reservation.
- `reserve_publication(check_identity, expected_route)` succeeds only when the
  row is active, has no transition or publication fields, and exactly matches
  the signed route's repository, generation, registry OID, and digest. It
  atomically installs the check identity and route digest. An identical retry
  returns that reservation; every other call conflicts.
- `confirm_publication(check_identity, observed_check)` clears only that exact
  reservation after the trusted caller has independently verified the terminal
  GitHub check identity described in §7.2. A missing or mismatched reservation
  or observation conflicts. It cannot change route state or generation.
- `commit(transition_id, prepared_identity, final_state)` succeeds only from
  pending for that exact transition and prepared generation, OID, and semantic
  route digest. If the current row already equals that complete final row, an
  identical retry returns it; any other current row conflicts.
- `restore(transition_id, expected_prior_row, prepared_identity)` succeeds only
  while that exact pre-activation transition is still pending and restores the
  prior row preserved by `begin_pending`. If the current row already equals
  `expected_prior_row`, an identical retry returns it; restoring the explicit
  absent-row value deletes only that exact first-binding pending row. Any other
  row conflicts. The coordinator may call restore only after confirming no
  activation event made the prepared generation canonical.
- Reconciliation and `unavailable` transitions use the same expected-row and
  observation-ID discipline. No method performs GitHub, registry, KV, or other
  external I/O while its local state transition is open.

A stale or out-of-order call is rejected. A generation never regresses except
for the matched restore of its own still-pending, pre-activation transition;
once another transition or final state has replaced it, that restore cannot
match.

**GitHub-side change protocol.** Creation, rename, transfer, ownership change,
deletion, restoration, or App installation restriction/removal can change the
match or make it unverifiable without a DraCLA administrator action. The
enforcer lifecycle webhook is a doorbell; scheduled reconciliation is the
backstop. Either path first puts the affected repository's gate into `pending`,
then re-reads current GitHub state, creates a new immutable registry generation
when the observed facts or match result changed, stages and actively revalidates
the prepared KV entry, publishes it at `routes/<repository_id>`, and finally
switches the gate to the new derived state and generation through the same
conditional transition methods. The lifecycle delivery or scheduled
observation ID is the transition identity. The coordinator then re-evaluates affected open
pull requests. There is no administrative canonical event because no DraCLA
selector changed. Failure to read or uniquely bind current GitHub state
produces `unavailable`, never an intentional choice to reuse a possibly stale
route.

An `owner/*` selector is standing consent for future repositories, so a newly
created repository may move directly from unknown to `active` after current
GitHub facts and installation coverage are verified. A rename or transfer is
matched by current owner/name but correlated by numeric repository ID. A
restored repository is re-evaluated from scratch. A missed lifecycle webhook is
therefore a delay, not a different algorithm.

**Conflict reporting is the one no-project token exception.** When the derived
state is `conflict`, DraCLA has deliberately selected no CLA project. The
conflict entry nevertheless carries the affected numeric repository ID and the
one current `dracla-enforcer` installation verified to cover it. A dedicated
repository-control route may mint that installation's token without choosing a
project, re-verify the token/repository binding, and use it only to:

- write the fixed public check/comment: **action required: this repository is
  covered by more than one CLA project; an administrator must resolve it**; and
- recheck `admin` on that repository for the authenticated conflict inspector.

That capability cannot read either project's records or coverage repository,
cannot mint a records-App token, and cannot authorize a resolution mutation.
If one current covering enforcer installation cannot be established, no token
is guessed: the required check remains absent or non-passing, the repository
stays unavailable, and reconciliation plus operator alerting continue.

The public result reveals no project identifier, scope entry, signer status, or
private configuration. After the separate `admin` check, the conflict tool
shows only the affected repository, matching project identifiers, matched scope
entries, and the authority required for each possible resolution. Each remove,
narrow, or new binding is then authorized separately using the matrix above.
Permission to inspect is not permission to mutate. Only the affected repository
fails closed and every unaffected repository continues normally. No conflict or
resolution changes CLA evidence or asks anyone to re-sign.

### 7.2 Runtime publication and freshness

Workers read the signed KV route rather than GitHub or the registry on the
request path. The published entry is keyed by the stable
`routes/<repository_id>` key, because a new request knows the repository ID but
does not yet know its current generation. Its canonical payload carries the
schema version, numeric repository ID, owner/name snapshot, current enforcer
installation ID, registry commit OID, generation, derived state, and the
project route when the state is active. An outer envelope carries `kid` and the
signature. Internal generation-qualified keys may stage prepared bytes, but
they are never the request-path lookup.

`route_sha256` is SHA-256 over the canonical **unsigned payload**, not the
signature envelope. `worker-enforce` first verifies the signature against the
accepted `kid` set and separately compares the semantic digest to the gate.
Re-signing an unchanged payload during key rotation therefore does not change
the gate; changing repository identity, installation, project, state,
generation, or registry OID does.

The corresponding SQLite-backed Durable Object is named from the numeric
repository ID and persists one bounded gate row:

```
repository_id, state, generation, registry_oid, route_sha256,
transition_id, prepared_generation, prepared_registry_oid,
prepared_route_sha256, prior_row,
publication_check_identity, publication_route_sha256,
publication_started_at, changed_at
```

Transition fields and `prior_row` are non-null only while pending and are
cleared by a matching commit or restore. Publication fields are non-null only
while an active route has one authoritative success reservation; they bind the
check identity to the row's exact generation, registry OID, and route digest.
Pending and publication fields are mutually exclusive. They exist solely to
enforce the conditional methods in §7.1 and do not create history outside the
registry.

It contains no project configuration, agreement, signer identity, acceptance,
revocation, exemption, or coverage evidence. The registry and current GitHub
repository facts reconstruct its routing fields from empty state. Before such
a rebuild may become active, the coordinator obtains an exact enforcer-side
read of the project's coverage fence. A matching `success_reserved` identity
reconstructs the transient publication fields; a non-idle, unavailable, or
ambiguous observation keeps the route unavailable. An idle fence needs no
publication field because §5.4 acquires the coverage reservation first and
releases it only after GitHub has already returned a validated completed check.

After webhook signature verification, every `pull_request`, `merge_group`, and
`check_run.rerequested` request compares the authenticated event's repository
ID, owner/name, and installation ID with the signed route payload. Every
route-bearing enforcement request also presents the repository ID, signed KV
state, generation, registry OID, and semantic route digest to the gate-check
service. Authorization requires **both** comparisons. An event mismatch rejects
the route and sends only the verified repository ID and delivery trigger to the
coordinator's conditional pending/reconciliation path; event data may
invalidate a route but never select a replacement project, and no hot-path
GitHub read is added.

The service accepts an active route only when the Durable Object is `active` at
the exact same generation, OID, and digest. A `conflict` or `unmanaged` projection is
usable only when the object names that same state, generation, OID, and digest;
`pending`, `unavailable`, missing state, a
mismatch, an object error, or exhausted Durable Object quota fails closed for
that repository. The gate returns no route or project identifier. The
coordinator alone holds the namespace-transition binding. `worker-enforce`
receives the comparison RPC and only the two publication methods below; it
cannot call `begin_pending`, `commit`, `restore`, reconciliation, or
unavailable transitions.

Workers KV may briefly retain an old value or cached negative lookup. That no
longer creates a wrong-project window: after the coordinator changes the gate,
an old KV generation cannot match it. Before the final gate change, a newly
visible KV generation cannot match the still-pending or prior gate. Active KV
revalidation and later cache expiry reduce the time an affected repository is
blocked, but neither is the safety proof. No witness expiry, renewable lease,
convergence wait, or periodic per-repository write is required.

Registry pushes and GitHub lifecycle events wake the same reconciliation code;
their payloads are discarded after signature verification and current sources
are re-read. The schedule runs the same full derivation and repairs drift. An
unchanged derivation performs no gate or route write. If GitHub or the registry
cannot be read while processing an observed change, the affected gate remains
or becomes `unavailable`; request Workers never fetch GitHub merely to renew
routing state, and no repair asks a contributor to sign again.

Successful authoritative publication never relies on its starting routing
snapshot. After obtaining the coverage success reservation, the enforcer calls
`reserve_publication` immediately before the GitHub success write. In one local
transaction the repository-scoped object repeats the exact signed-route
comparison and installs the check identity on the unchanged active row.
`begin_pending` requires those publication fields to be null, so a transition
that arrives after this RPC cannot begin before GitHub completion is confirmed.
If the transition wins first, reservation fails and the check is non-passing.
This adds no last-second GitHub read; it rechecks only the existing strongly
consistent gate and exact signed route.

The reservation is cleared only by
`confirm_publication(check_identity, observed_check)`. The observation must be
one completed check run created by this App on the exact merge-group head, with
the fixed DraCLA name and `external_id == "dracla-authoritative-v1." ||
check_identity`; success and the recovery-created non-passing terminal result
are both valid terminal evidence. The webhook handler rejects every other
namespace before a gate call. An authenticated authoritative `check_run`
completion webhook is the normal trigger, and the scheduled coordinator
performs the same bounded GitHub read as a missed-webhook backstop. The method
clears only an exact current reservation. Missing,
truncated, duplicate, in-progress, or mismatched observations leave it held;
age is never evidence. The Durable Object performs no external I/O inside its
transaction. This conservative asynchronous release adds no subrequest to the
successful enforcement invocation and may delay a later route transition, but
cannot let that transition overtake successful check completion.

No separate rate-limit KV or successful-event counter exists. Before a sign or
revoke append, the portal acquires the project's single mutation lock and
semantically revalidates against the current canonical state (§5.3–5.4).
Idempotency returns duplicate submissions without another append, and semantic
no-ops write nothing. Valid revocation and fresh re-signing remain available
regardless of earlier successful-event count. This deliberately does not
prevent raw request flooding, which remains the account-wide residual risk R9;
any future transport abuse control must preserve both operations.

Isolation rules:

- An `active` coverage or records request resolves exactly one project before
  project-repository access. Repository handles come from its signed registry
  entry, never request input.
- Its installation token must belong to one of that project's recorded
  installations and cover the exact repository; a mismatch is a hard failure,
  not a fallback. Plural is expected because records and contributing
  repositories may have different owners and installation IDs.
- The repository-control exception above resolves only a repository and one
  verified enforcer installation. It is available solely for fixed
  `conflict`, `pending`, or `unavailable` check output and the conflict-admin
  probe; it never creates project or records authority.
- Every project authorization is recomputed for that project and request. A
  session carries identity only; no authorization result is cached across
  projects.
- An `unmanaged` repository receives no DraCLA check. A repository with an
  uncertain match or installation is `unavailable`, not unmanaged.
- A write-created overlap is rejected before preparation. A GitHub-side overlap
  produces `conflict`, never a precedence rule.

Independent domains share no registry, so global uniqueness across them is
impossible and unsupported double-targeting is stated in operator
documentation.

**Multiple projects in one GitHub account may share one App installation.** An
installation token can therefore fetch ciphertext from every selected project
repository in that account. Cross-project isolation is enforced by the signed
route, exact repository-token check, distinct per-project data keys, and
project/purpose-bound ciphertext and wrapped keys. A request routed
to project A cannot authenticate project B's envelopes or wraps. This does not
protect against the hosted operator, who controls the shared roots and is
explicitly trusted (§8.3). A project requiring separate App credentials and
wrapping roots uses an independent self-hosted deployment.

Migration to self-hosting does not convert repository data. Using its recovery
material, the project verifies both retained data-key families, creates wrapped
copies for self-hosted records and coverage roots, verifies those live paths,
then revokes the shared Apps and roots. The encrypted repositories never move
and their ciphertext is not rewritten (`REQ-OPS-6`, §9.1).

---

## 8. Security model

| Concern | Mechanism | Req |
|---|---|---|
| Signer PII exposure | Every private repository artifact is authenticated ciphertext; records and coverage keys are separate, and the enforcer has coverage authority only (§4) | `REQ-SEC-2` |
| Session state | Short-lived **encrypted** (AEAD) cookies with `kid`; no application database | `REQ-OPS-2`, `REQ-SEC-4` |
| CSRF / OAuth callback replay | Single origin, `__Host-` prefix, `SameSite=Lax`, signed browser-bound `state`, encrypted pre-auth cookie, PKCE S256, and GitHub's one-time authorization-code exchange (§8.2, §9) | `REQ-SEC-4` |
| Webhook authenticity | Signature verification; duplicate deliveries idempotent | `REQ-SEC-5` |
| Authorization | Administrative actions use current GitHub authority; plaintext reads use current canonical reader sources independently of repository read access, and a continuous-team source additionally requires live membership before proof issuance and every plaintext page | `REQ-SEC-6` |
| Untrusted content | Contextual escaping everywhere; allowlist sanitization under restrictive CSP; CSV formula neutralization | `REQ-SEC-8` |
| Secrets | Never stored in records repos or exposed to browser code | `REQ-SEC-4` |
| Observability | Correlation IDs and failed-event identifiers, no PII or credentials | `REQ-OPS-5` |

### 8.1 Threat model: the authenticated contributor

A contributor need not have access to any project repository. What
authentication grants is the ability to make the Worker act while it holds an
installation token and, for private reads, a narrowly scoped authority to
return plaintext. The whole surface is therefore confused-deputy.

| # | Attack | Control |
|---|---|---|
| 1 | **Path or control injection** — using untrusted values as paths, workflow input, or executable configuration could leak a key or run code in the control job | Private paths derive from server-computed opaque IDs and fixed allowlisted prefixes; the records App cannot modify the separate control repo; the pinned reconciler treats decrypted repository content only as schema-validated business data |
| 2 | **Unbounded append** — repeated valid sign/revoke cycles grow a repo that `REQ-REC-3` forbids pruning | Idempotency collapses identical resubmission; authenticated event-backed form state makes semantic no-ops replay-stable, while exact-head mismatch makes every other stale confirmation write-free. Revision 11 deliberately rejects a successful-event cap because it traps contributors covered or uncovered. Deliberately distinct cycles remain an accepted storage-abuse residual; monitoring and a future transport control may respond only if both immediate revocation and re-signing remain available (§5.3–5.4). |
| 3 | **Stored injection** via signer fields into dashboard, JSON, CSV | `REQ-SEC-8` escaping and CSV formula neutralization, plus length and charset caps at ingest |
| 4 | **IDOR on identity** — acting as another user | Subject is read from the verified session, never from the request body (§8.2) |
| 5 | **Privilege confusion** — a contributor submitting override or exemption events | Admin events require a separate authorization check against current GitHub permissions |
| 6 | **Cross-tenant aim** — steering the installation token at another project | Repo handles come only from the registry entry (§7) |
| 7 | **Budget exhaustion** — burning the shared daily ceiling | Signature verification before downstream work; paid hosted capacity and monitoring; no persistent edge counters; residual anonymous quota risk R9 (§9) |
| 8 | **Clickjacking** the accept button — defeating `REQ-SIGN-2`'s affirmative action by UI redress | `frame-ancestors 'none'` and `X-Frame-Options: DENY` on the portal, delivered by whichever origin serves the portal assets (§9); the agreement itself renders in a sandboxed frame the portal owns (§9) |

### 8.1.1 Principals beyond the contributor

The table above models only the authenticated contributor. Three further
principals exist and were previously unmodelled:

**Hostile tenant.** Self-serve install creates one for free: anyone can claim a
project and supply agreement markup that the portal renders. On a shared origin
that converts "project admin supplies HTML" from a self-inflicted risk into a
cross-tenant one, reaching every other tenant's session. Controlled by rendering
agreement content on a separate cookieless origin in a sandboxed frame (§9), by
verified slug claims (§7), and by allowlist sanitization plus CSP as defense in
depth rather than as the boundary.

**Compromised Worker.** Covered in §9's two-Worker split; the residual is
stated in §8.3 rather than claimed away.

**DraCLA operator.** Fully trusted in the hosted deployment. See §8.3.

### 8.1.2 Credential and webhook handling

**Webhook verification** (`REQ-SEC-5`). The signature is verified **before** the
body is parsed or routed, using constant-time comparison, with a per-App secret
selected by the receiving route — a single route that tries both secrets would
let the records App's secret inject `merge_group` events. `sha1=` signatures are
rejected. GitHub signs the body but supplies no authenticated timestamp or
nonce, so DraCLA makes no age claim. `X-GitHub-Delivery` deduplication is a
short-lived optimization, not a freshness proof. Every valid delivery re-reads
current GitHub and DraCLA state, conditions writes on the current head, and
uses operation idempotency so a delayed, duplicated, or replayed body is either
the same harmless result, a currently valid operation, or a conflict.

**Installation tokens are not persisted.** They carry `contents: write` on a
project's private records repository, so neither Worker stores them in KV or
any other durable cache. A Worker mints one on demand from its App key. A warm
isolate may reuse an unexpired token from process-local memory, but eviction at
any time is expected and no correctness, availability, or rate-limit claim may
depend on that reuse. Repository handles still come only from registry-resolved
values, never request input.

**Project credential rotation** (`REQ-SEC-9`). Data-key, wrapping-key, recovery,
transport, and App credentials rotate independently. A project data-key
successor is not active until the live service or control path and the adopter
recovery path have both recovered a challenge protected by the actual new key.
The predecessor remains decrypt-only while any retained artifact names it. A
wrapping-key rotation that merely rewraps retained project keys is a routine
migration and does not revoke the old holder's access. A departure or suspected
compromise of a wrapping-key controller requires successor project data keys
for every affected capability plus a rebuild of current mutable coverage and
records-derived state under those keys. Repository deploy keys do not expire
and rotate on a fixed schedule and on any departure of a principal able to read
the corresponding control secret. `dracla rotate-key` runs with the
administrator's own authority and stages each successor transaction defined in
§6.10.2.

`REQ-SEC-9` applies to every long-lived credential DraCLA provisions or
requires:

| Credential | Holder | Rotation | Departure response | Reach if leaked |
|---|---|---|---|---|
| Records data keys, all retained `kid`s | Wrapped for portal, control, and recovery; never raw in repository content | Verify successor through live and recovery paths, activate it, retain predecessors decrypt-only | Rotate when a records key controller departs or exposure is suspected | Decrypt or forge one project's canonical history and private records derivatives |
| Coverage data keys, all retained `kid`s | Wrapped for portal, enforcer, control, and recovery; never raw in repository content | Same verified transaction, independent of records keys | Rotate when a coverage key controller departs or exposure is suspected | Decrypt or forge one project's coverage and private enforcement state, hence its merge gate; cannot decrypt signer evidence |
| Hosted records and coverage wrapping roots | Separate `worker-portal`/`worker-enforce` secret bindings by environment and capability | Routine migration: add successor, rewrap and verify every project key, then retire the predecessor live path | Departure or suspected exposure rotates each affected root **and every affected project's matching data key**, then rebuilds current mutable state | An old records root can retain historical records access; an old coverage root can retain historical coverage access. Only data-key successors cut off future/current-state access |
| Per-project control wrapping key | Control-repository Actions secret | Routine migration stages a successor, rewraps both project key families, verifies a pinned control run, and retires the predecessor live path | A controller departure rotates the control key and both project data keys, then rebuilds current mutable state | A retained old control key can recover historical records and coverage keys; rewrapping alone does not revoke that reach |
| Adopter recovery wrapping key | Adopter password manager or other safe offline storage | Routine migration generates a successor, verifies every retained data key through it, then retires the predecessor live path | Recovery-custodian departure rotates the recovery key and both project data keys, then rebuilds current mutable state | A retained old recovery key can decrypt historical project keys and bootstrap from an old backup; that historical reach cannot be revoked |
| Records and coverage deploy keys | Control-repository Actions secrets, one repository scope each | Administrator stages and tests a successor, then removes predecessor | Departure of anyone able to read or execute with one of those secrets rotates each affected key | Read ciphertext; create, delete, or force-update refs; roll back history; or replay old authenticated ciphertext. The records key can alter the apparent canonical source and the coverage key can alter merge-check inputs. Neither deploy key decrypts records by itself; paired control-workflow or wrapping-key access adds that capability |
| Session AEAD keys | `worker-portal` secrets, identified by `kid` | Add a successor, encrypt new cookies with it, accept the predecessor only until its last absolute session expiry (at most 7 h 55 min), then remove it | DraCLA **operator** departure rotates it and invalidates outstanding sessions at the end of that bounded overlap | Decrypt and forge every hosted portal session issued under that key |
| Action-form HMAC keys | Separate `worker-portal` secrets, identified by `kid` | Add a successor, sign new forms with it, accept the predecessor only until its last parent-session-bounded form expires (at most 7 h 55 min), then remove it | DraCLA **operator** departure rotates it; outstanding forms under the predecessor fail closed and must be rendered again | Forge contributor or administrative form state, but not satisfy the required live parent session, matching actor, current authority, exact Table 5.4-A type/event mapping, or exact-head checks |
| Private-read proof HMAC keys | `worker-portal` secrets, identified by `kid` | Add a successor, sign new proofs with it, accept the predecessor only until its last proof expires (at most 5 min), then remove it | DraCLA **operator** departure rotates it and invalidates outstanding proofs at the end of that bounded overlap | Forge a scoped reader proof, but not bypass its parent-session, canonical-generation, or continuous-team live-membership checks |
| GitHub App OAuth client secret | `dracla-records` App config and `worker-portal` secrets | Add a successor at GitHub, deploy it alongside the predecessor, complete a test OAuth exchange, then revoke the predecessor | DraCLA **operator** departure rotates it | Complete or interfere with OAuth exchanges; it does not mint installation tokens without the App private key |
| App private keys, all three Apps | DraCLA operators | GitHub Apps hold two keys concurrently: add successor, redeploy, revoke predecessor — no downtime | DraCLA **operator** departure rotates every key the operator could read | Records: append encrypted evidence and invoke records decryption; enforcer: write checks and decrypt coverage; trigger: dispatch, rerun, cancel, or disable Actions in project control repos and inspect non-PII run metadata, but cannot change code or read contents/secrets |
| Webhook secrets, per webhook-receiving App | App config + Worker secrets | Stage the new secret beside the old on the same App's route, update App config, then drop the old; never try different Apps' secrets on one route | Operator departure rotates every secret they could read | Forge webhook deliveries to that App's route |
| KV entry signing key | `worker-portal` secrets; public verification keys in `worker-enforce` configuration | Add the new key beside the retiring one and verify against either; re-sign and revalidate every stable route entry, whose unsigned-payload digest and gate remain unchanged, then drop the retiring key (§7.2) | Operator departure rotates it | Forge cross-project routing consumed by the honest enforcer and therefore misapply one project's coverage to another repository; token/repository binding still prevents access outside the named installation and repository |
| Cloudflare deployment, KV, and Durable Objects API tokens | DraCLA deployment secret store, scoped separately by environment and capability | Issue a least-privilege successor, deploy and reconcile KV and gate state with it, then revoke the predecessor | DraCLA **operator** or CI administrator departure rotates every token they could read | Deploy Worker code or read/write the bindings, KV namespaces, and routing gates permitted by that token |

The last column is the reach documentation `REQ-SEC-9` requires. A holder of
only a repository credential can read or write ciphertext but cannot decrypt
it; a holder that also controls the matching workflow secret or wrapping key is
a key controller and can cause trusted code to reveal or forge plaintext.
Every write-deploy-key holder, and every person or workflow able to exfiltrate
its private half from the control Actions secret, is nevertheless an
**integrity controller** for that repository. Authenticated encryption prevents
undetected invention or modification of a ciphertext payload without its data
key; it does not prevent deletion, ref rewriting, whole-history rollback, or
replay of ciphertext that was valid at an older point.

**Departure and incident procedure.** First make every affected hosted route
unavailable, revoke the controller's live credentials, and install successor
wrapping material. For every project and capability that controller could
decrypt, generate and verify a successor data key, rebuild all current mutable
coverage and records-derived artifacts under it, activate the successor through
§6.10.2, and only then restore the route and re-run the affected checks. Do not
rewrite canonical history or delete predecessor keys needed for recovery. The
incident report and adopter notice state the historical exposure window and
that copied old keys, ciphertext, or plaintext cannot be recalled. With a
shared hosted root, this procedure fans out to every project wrapped by that
root; projects return independently as their cutoff completes.

For exposure limited to a records or coverage deploy key, make the affected
route fail closed, revoke and replace that deploy key immediately, and compare
the live repository identity and replacement-key fingerprint with the control
transport manifest. Compare every live ref and its ancestry with the latest
trusted backup-manifest heads. Preserve newer descendants only when full replay
authenticates them; otherwise restore the last adopter-verified heads. Then run
coverage/derived-state rebuild, sweep and re-run open pull-request checks, and
only then restore the route. Project data-key rotation is not required merely
because a deploy key leaked, but it becomes required if the matching decryption
or wrapping capability may also have been exposed. The incident report
distinguishes integrity exposure from confirmed plaintext exposure.

**No OAuth scopes are requested, and no scope tiering exists.** An earlier
draft proposed minimal scopes for contributors and elevated `repo` scope on
demand for dashboard viewers. That is not implementable: `read:user`,
`user:email`, and `repo` are **OAuth App** scopes, and GitHub *App*
user-to-server authorization has no `scope` parameter — permissions are fixed
at App configuration and apply to everyone who authorizes it. There is no
incremental escalation for a GitHub App.

Repository read access is deliberately not the fallback. It would authorize
ordinary collaborators and read-only Apps merely because they can fetch
ciphertext, while excluding a canonically authorized reader with no repository
access. `REQ-SEC-6` is instead satisfied by resolving the authenticated numeric
GitHub ID against the project's current canonical individual, snapshot, and
continuous-team reader sources when issuing a scoped proof, then rechecking
that proof's exact canonical reader generation before each private data page.
When the proof relies on a continuous source, the portal also checks the bound
team membership live before issuance and again immediately before every
plaintext response (§6.6). The portal unwraps the route-bound records key only
inside that protocol and returns the requested plaintext result, never a raw
key.

### 8.2 How browser authentication reaches the writer

```
Worker               issue state nonce N and PKCE verifier V;
                     set encrypted __Host-preauth cookie = {N,V,expires_at},
                     HttpOnly, Secure, SameSite=Lax, Max-Age=10 min
browser -> GitHub    OAuth authorize, state = signed{ N, project, pr, return },
                     code_challenge = BASE64URL(SHA256(V)), method = S256
GitHub  -> Worker    callback: code + state
Worker               verify state signature and expiry,
                     AND state.N == encrypted preauth cookie.N
Worker  -> GitHub    code + client secret + exact redirect_uri + V
                     -> expiring user token; GitHub enforces PKCE binding
Worker               delete preauth cookie after the exchange response
                     discard refresh token
Worker  -> GitHub    GET /user  -> { id, login }             <-- trust created
Worker               mint NEW session cookie + KV entry, both expiring
                     5 min before the GitHub access token
browser -> Worker    POST /sign + cookie
Worker               verify cookie; subject read FROM COOKIE, never body
Worker  -> GitHub    mint installation token on cache miss; commit event
```

**`state` and PKCE are both mandatory.** GitHub.com's current GitHub App OAuth
flow supports PKCE and strongly recommends it. DraCLA uses only `S256`, stores
the verifier in the encrypted `__Host-preauth` cookie, and supplies it with the
exact callback URI during exchange. Signed `state` protects the project, pull
request, and return context from modification; the cookie proves this browser
started that state; PKCE prevents an authorization code minted for another
browser flow from being exchanged with this cookie. No correctness claim
depends on an atomic Workers KV read-and-delete.

Without browser binding and PKCE, the attacker can start a flow for **their
own** account and send its callback to a victim. The Worker could then mint the
attacker's session in the victim's browser, after which the victim signs in
good faith and commits append-only evidence carrying the **attacker's** user ID
with the **victim's** legal name and email. Matching state, cookie nonce, and
PKCE verifier prevents that session swap. A duplicated callback cannot mint a
second session because the same temporary GitHub authorization code cannot be
successfully exchanged again. The `return` path is additionally validated
against an allowlist so the same channel is not an open redirect.

GitHub's assertion is converted into a token the Worker itself signed, so the
browser never carries identity as data it can influence. The Worker, not the
contributor, is the author of record; the commit history is the attestation
chain.

**What the record attests** is precisely: *the Worker observed a
GitHub-authenticated session for user N submitting explicit assent to agreement
X at time T.* Not that the contributor cryptographically signed anything. The
evidence fields of `REQ-SIGN-4` are scoped to that claim.

**Session state.** The cookie is **encrypted** (AEAD), not merely signed, and
carries a `kid` so keys can be rotated without either mass logout or accepting a
revoked key. The user access token is **not** in the cookie — a signed-only
cookie carrying a GitHub token would put it in browser-readable storage, which
`REQ-SEC-4` forbids outright. It lives in Workers KV keyed by `jti` with a
matching TTL. Every sensitive request requires that live-session entry, so it is
the server-side liveness and revocation signal for the bearer cookie; `jti`
identifies the lookup but does not make the cookie single-use. Workers KV is
eventually consistent, so logout deletes the entry and browser cookie as a
best-effort revocation request but cannot promise that every location observes
the deletion immediately. A copied cookie may remain replayable until a request
observes the deletion or the absolute expiry below; current action-specific
authority and private-read checks still run before every sensitive result.

**Expiry is absolute and derives from GitHub's token, not browser activity.**
The GitHub App requests expiring user-to-server tokens. On exchange, the portal
uses the returned access-token expiry and discards any returned refresh token;
no refresh token is persisted or used. The session expiry is exactly five
minutes before that access-token expiry. Both the `__Host-` cookie and its KV
entry carry that same absolute `expires_at`; neither read nor write slides it.
With GitHub's default eight-hour user-token lifetime, a newly issued session is
therefore at most seven hours and fifty-five minutes. If GitHub returns an
expiry less than five minutes away, the exchange creates no session and starts
a fresh authorization flow.

The browser-bound OAuth `state`, PKCE verifier, and encrypted pre-auth cookie
expire after ten minutes. The verifier is never stored in KV; callback replay
is rejected by GitHub's one-time code exchange and code/verifier binding, and
the Worker deletes the pre-auth cookie after the exchange response. A scoped
private-read proof expires after five minutes and never later than its parent
session. Its canonical reader-generation check—and, when applicable, its live
continuous-team membership check—still runs on every page, so five minutes is
only a replay bound, not an authorization cache.

Every sensitive request checks cookie authentication, the live KV session, its
absolute expiry, and then the action-specific authority described below. An
expired session or GitHub `401` deletes the KV entry and cookie and restarts
OAuth before any mutation or plaintext response. A GitHub `403` or a current
permission result below the required authority denies only that action and
keeps the otherwise valid session, so the user can still use permitted
surfaces. No failed refresh path exists because the design never stores a
refresh credential.

**Decay, and where it is not acceptable.** The cookie is a bounded cached
identity assertion, so a revoked OAuth grant can precede its absolute expiry.
The portal therefore
revalidates GitHub authentication and current action-specific authority for
**sign, revoke, every administrative or override event, and every private
read**. For a private read it resolves current canonical reader sources to
issue a scoped proof and rechecks that proof's generation on every data page.
When the bound source is continuous, both proof issuance and every page also
require the same stable team's live membership; absence, API failure, or an
indeterminate result fails closed. No cached repository-access or unversioned
reader verdict authorizes plaintext. The `REQ-VERIFY-2`
loss-of-authorization criterion is therefore concrete: a withdrawn final
canonical source or missing live continuous-team membership denies the next
private read, and lost GitHub administrative authority denies the next
administrative action.

**Optional hardening, and its limit.** For projects wanting non-repudiation
beyond OAuth, GitHub publishes users' signing keys
(`/users/{login}/ssh_signing_keys`, `/gpg_keys`), so a CLI-produced signed
acceptance could be verified against a binding GitHub already vouches for. Not
the core flow: browsers cannot reach those private keys, and `REQ-PORTAL-1`
requires an in-browser accept flow. Note the endpoint is **login-keyed** and
GitHub releases logins when accounts are deleted, so verification must re-derive
the login from the pinned numeric ID at check time, never trust a stored login.

**No decision keys on login, ever.** `REQ-SIGN-1` makes the numeric ID primary
and `login_snapshot` historical, and that rule extends past the envelope to
every surface: legacy `<login>@users.noreply.github.com` addresses must not be
resolved by login lookup; the dashboard and exports render `login_snapshot`
only alongside the numeric ID and its capture date (§6.6). Otherwise a recycled
login misattributes a legal instrument to a different human — the failure a CLA
system exists to prevent.

### 8.3 Trust model

Per `REQ-REC-4`, repository administrators are trusted for repository
integrity. DraCLA never force-updates or deletes canonical history and documents
that it cannot detect rewriting by an administrator controlling both the
repository and every backup. A records- or coverage-only administrator without
a decryption capability is not thereby a confidentiality key controller.

**In the hosted deployment the DraCLA operator is also fully trusted.** Repo
custody is not key custody: the operator controls the deployed portal code, the
records App key, and the hosted records wrapping root. It can therefore cause
the service to decrypt every hosted project's signer PII and can append events
that are **byte-indistinguishable** from genuine ones. The Worker is the sole
author of the attestation chain; there is no contributor counter-signature or
external checkpoint, and the reconciler will faithfully replay a forged event
into coverage. Tenant and capability binding prevents accidental or
cross-project substitution, not deliberate action by this key controller.
`REQ-REC-4` waives detection of administrator *rewriting*; it does not waive
operator *forgery of new events*.

Concretely, hosted adopters trust the operator for signer confidentiality,
evidence integrity, and merge-gate integrity. **Self-hosting is the only
configuration in which that is not so**, which is what product principle 6 is
actually buying. §8.2's "the commit history is the attestation chain" should be
read with this bound: it attests against non-administrator, non-operator
tampering.

Independent event signatures and external checkpoints remain available as the
optional future hardening `REQ-REC-4` anticipates, and they are what would
narrow this.

### 8.4 Data protection

DraCLA collects legal names and email addresses, which are personal data. This
section states the design's position so an adopter's counsel has something to
assess. It is not legal advice, and the lawful basis is the adopter's to
determine.

**Roles.** The adopting project — specifically the legal recipient named in
`REQ-CONFIG-2` — is the **controller**: it decides why the data is collected and
what happens to it. In the shared hosted deployment the operator is a
**processor**, because a contributor types their name into the operator's Worker
before it reaches the adopter's repository. `REQ-SEC-2` permits that transient
processing but forbids retaining plaintext
outside encrypted project repositories or an explicitly requested authorized
export. The relationship it creates is a processing agreement between operator
and adopter.

Self-hosting removes the processor entirely — the adopter is controller and
operator both. That is a substantive reason to self-host beyond the trust
argument of §8.3.

**Erasure, and why the records are append-only anyway.** `REQ-REC-3` makes the
records append-only — a rule DraCLA enforces, not a physical impossibility
(§8.3 bounds it) — which collides directly with a right to erasure. The design's position is that a CLA record is retained for the
establishment, exercise, and defence of legal claims — the agreement exists to be
provable years later, possibly in a dispute — and that this is what the common
exemption for such processing is for.

Two things follow, and both are already in the design rather than bolted on:

- Revocation exists and works (§6.2). A contributor can withdraw coverage for
  future contributions at any time; what they cannot do is unmake evidence of a
  grant already made.
- `REQ-SEC-7` requires both the signing and revocation flows to say that
  evidence is retained afterwards, so this is disclosed before consent rather
  than discovered later.

An adopter whose counsel disagrees cannot be accommodated by configuration: the
append-only record is the product. That should be known before adoption, not
after.

**Minimization.** `REQ-SEC-1` collects only fields the agreement and project
policy require, and forbids collecting an IP address merely because a workflow
can observe it. The initial release adds no successful-event limiter. Any
future transport-only abuse control may key on authenticated GitHub user ID but
not IP and must preserve valid revocation and re-signing (§8.4.1).

**The coverage projection.** It carries no names, email addresses, exact status
reasons, exemption provenance, or reader-authority data. This is what lets the
enforcement path answer with a narrowly scoped coverage key instead of a records
key (§5.3). It is still private derived data and is always encrypted with the
project's independently rotatable coverage key. A public check discloses one
bounded result for the subjects of one pull request; it does not justify
exposing the complete projection.

What privacy protects is **aggregation**. A check run discloses one subject at a
time, only for people who opened a pull request, and only to someone willing to
crawl and correlate. The projection discloses every user against every agreement
in a single fetch, and it is a *superset*: someone who signed early and never
contributed, or who signed and never opened a pull request, appears only there.
Its per-subject generic reason code is restricted to the fixed class needed to
select check copy or produce authorized aggregate counts; it carries no
free-form explanation. Exact reasons, exemption-source details, and
reader-authority shards are records-key artifacts. Repository readers without a
coverage capability see only envelopes and unavoidable repository metadata.

That is the recognised aggregation harm: individually available facts become a
different exposure once assembled. It is also what makes §5.3's enforcement rule
principled rather than arbitrary — probe one subject at a time, never enumerate.

**This does not weaken `D2` or `D3`.** Their rationale is both what an
enforcement credential can reach and what it can decrypt. Names, email
addresses, confirmation text, and entity evidence remain absent from coverage;
separate repositories, Apps, and data keys make a compromised enforcer unable
to decrypt canonical evidence.

**Considered and rejected.**

*Moving the projection into canonical*, so there is one repository. GitHub
permissions are per repository with no path scoping, so `dracla-enforcer` — a
public App anyone can install — would gain read on `events/**` and
the records keyring as ciphertext. Encryption would still prevent decryption,
but the layout would discard an inexpensive repository and credential boundary,
expose more metadata to the Internet-facing App, and make a permission or key
distribution mistake more consequential. The separate repo remains defense in
depth; it is not claimed as the confidentiality boundary.

*One key for records and coverage.* Rejected because it would let the
Internet-facing enforcement path decrypt signer evidence and would turn a
coverage-only compromise into a records breach. Independent keys and wrapping
roots are mandatory even though both artifact families use the same envelope.

*Repository ACL as the confidentiality boundary.* Rejected because DraCLA
cannot reliably enumerate every App that can read repository contents and can
only react after plaintext may already have been copied. Private repositories
remain mandatory defense in depth; authenticated encryption is the boundary.

*Per-row keys.* Rejected as unnecessary for the initial release. One records
DEK and one coverage DEK per project, with a random nonce per envelope and
strong project/purpose/identity binding, provide the required isolation and
rotation semantics without deriving or distributing a key per subject.

**Where the data lives.** Encrypted canonical, coverage, and private derived
artifacts sit in project-controlled private GitHub repositories. The portal and
enforcement tiers run on Cloudflare and transiently process the plaintext their
authorized operation requires. Both providers are US-headquartered, so an
adopter subject to transfer rules assesses that against its own obligations.
DraCLA adds no application database or durable plaintext store.

**Breach.** Repository read leakage exposes ciphertext and metadata, not signer
plaintext. Compromise of a matching data key, wrapping root, recovery key, or
key-bearing workflow crosses the confidentiality boundary and is handled as a
potential private-record breach. Removing a canonical reader source denies
future portal reads; a continuous-team departure denies the next live-checked
read even before its canonical withdrawal is materialized. Neither control can
claw back plaintext a previously authorized reader or key controller already
obtained.

**Subject access.** A contributor can see their own record through the portal
(`REQ-PORTAL-1`). An authorized records reader can request a scoped portal
view or plaintext `dracla export` (§6.9). Service-independent access uses the
repositories plus adopter recovery material; a repository clone alone is
ciphertext (`REQ-REC-5`).

### 8.4.1 Observability (`REQ-OPS-5`, `REQ-SEC-2`)

Signer PII passes through the Worker in the sign request body, so the default
posture of every observability tool is the risk. `REQ-SEC-2` forbids signer data
in logs; meeting it requires explicit configuration, not restraint in DraCLA's
own log statements:

- Request-body logging, `wrangler tail`, Logpush, and any error-reporting
  integration must exclude the sign and revoke request bodies. A default-on
  integration violates `REQ-SEC-2` without DraCLA writing a single log line.
- OAuth callback query strings carry `code` and `state` and must be scrubbed
  from access logs (`REQ-OPS-5` forbids credentials in logs).
- The reconciler runs inside the repo where PII legitimately lives; its logs are
  the most likely accidental leak path and must emit identifiers only.
- Correlation IDs propagate Worker → GitHub API → reconciler so a failed event
  can be traced end to end without carrying any field value.

**Data minimization** (`REQ-SEC-1`). Collected fields derive from
`config/project.enc.json` (§5.1); nothing is stored because a workflow could observe
it. Successful acceptance and revocation events are not capped, and DraCLA
creates no edge counter or IP-derived identifier for them. Canonical
idempotency makes an exact retry write-free, while authenticated event-backed
form state makes contributor and administrative semantic no-ops replay-stable
and exact-head mismatch makes other stale confirmations terminal, without an
append or receipt store.
Request-flooding risk #7 is monitored and
handled operationally rather than by collecting another identifier (§5.3,
§5.4, §8.4).

---

## 9. Deployment

**Platform.** Cloudflare, chosen because Workers cover the stateless request
paths and SQLite-backed Durable Objects provide the bounded strongly consistent
repository routing gates permitted by `REQ-OPS-2`; the free tier covers the
target envelope. GitHub repositories remain the system of record, including
the encrypted coverage decision-fence file. Routing objects are small
rebuildable operational projections.

```
Workers        webhook handlers, OAuth, sign/revoke, check runs, index proxy
Durable Objects repository-scoped routing gates only
Pages          static portal + dashboard shell
Secrets        App keys, capability-separated wrapping roots, session,
               action-form, and private-read proof keys
Actions        pinned Python core in private control repos; project wrapping
               keys and repository-scoped deploy keys
```

The Worker tier is deliberately thin: it authenticates, compares each routed
enforcement request with the repository gate, unwraps only the route-bound
project capability it needs, reads packed encrypted coverage shards, and writes
encrypted events, bounded event-specific derived-shard deltas, and check runs.
Full replay, verification, repair, and explicit hosted-export logic lives in the
pinned Python core running in control-repository Actions;
§5.3's `decision` field is precomputed so the edge decrypts a boolean, performs
one active-version membership test, and validates any exact active override in
the already-fetched subject row rather than re-implementing the rule engine.
The routing gate stores no CLA evidence and can be rebuilt,
keeping the platform replaceable (`REQ-OPS-2`).

**Single origin.** The shell and the API are served from **one origin** per
deployment — the Worker serves the static assets, or Pages with Functions.
Pages and Workers on separate origins would make the index fetch a credentialed
cross-origin request, forcing `SameSite=None` (deleting the CSRF control in §8's
table) and a CORS policy whose usual implementation reflects `Origin` with
credentials — turning any page a logged-in records reader visits into a
drive-by read of the dashboard index, and any page at all into a forced
acceptance, which fabricates a legal grant. Cookies are `__Host-` prefixed,
`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, with no `Domain` attribute.

**Agreement content renders on an isolated origin.** Tenants supply agreement
markup and the hosted deployment is self-serve, so a hostile tenant is a
principal the install flow creates for free (§8.1). Agreement content is
rendered in a sandboxed frame on a separate cookieless origin, so a sanitizer
gap cannot reach the session cookie or same-origin API of any other tenant.
Allowlist sanitization and CSP remain, as defense in depth rather than as the
boundary.

**Worker isolation.** One deployment holding both data-App private keys, the session
key, the OAuth client secret, and every webhook secret means a single Worker
compromise defeats the §4 split entirely — the attacker simply uses the other
key, and the highest-value payload is forging `success` on authoritative
merge-group checks across all adopters. The deployment is therefore split into
**two** Workers with disjoint secret bindings:

```
worker-enforce    webhook secret + enforcer App key + coverage wrapping root
                  + signed-routing verification keys
                  + route-compare and exact-check publication-reservation RPCs
                  most exposed (anonymous internet), least privileged
worker-portal     OAuth client secret + session, action-form, and private-read
                  proof keys + records App key
                  + records and coverage wrapping roots
                  + reconciler-trigger App key
                  + registry write + routing-signing key
                  + routing-gate namespace mutation binding
```

There is no third public Worker. The third App is the trigger-only principal:
`worker-portal` may use it to dispatch the pinned workflow in one project's
control repository, but the App has no contents, administration, workflows, or
secrets permission. Provisioning still runs in the CLI on the administrator's
machine (D11), so no hosted isolate holds those setup powers. The gate check is
a narrow Cloudflare service-binding RPC entrypoint, not an Internet route. It
returns only match or fail-closed state and exposes no mutation method to
`worker-enforce`. The project decision fence is an encrypted coverage-repository
file accessed through the already-bound project credentials (§5.4), not a
service binding. The Setup URL route in `worker-portal` persists nothing: it
only directs the browser to Connect, which authenticates and discovers
installations independently (§6.10.3).

This split is asymmetric, not complete compromise containment.
`worker-enforce` compromise can forge checks but cannot read canonical signer
PII. `worker-portal` compromise can read or forge canonical evidence and,
through its routing-signing key and gate mutation binding, can misroute the
honest enforcer into applying one project's coverage to another repository; the
enforcer's token/repository check still prevents access outside the named
installation and repository. What the split prevents is either Worker directly
possessing both data-App private keys and both decryption capabilities. The
trigger App adds no repository-content or key capability. This does not claim
that either Worker compromise leaves merge-gate integrity intact; §8.3's
hosted-operator trust bound remains.

**Published limits** (verified 18 August 2026):

| | Free | Paid ($5/mo) |
|---|---|---|
| Requests | 100,000/day | no limit |
| CPU per invocation | **10 ms** | 5 min (default 30 s) |
| Subrequests per request | 50 | 10,000 |
| Memory | 128 MB | 128 MB |
| Script size (gzipped) | 3 MB | 10 MB |

**Durable Objects limits** were verified on 22 August 2026 against Cloudflare's
[pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
and [limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
documentation. The Free plan supports SQLite-backed objects and includes
100,000 object requests/day, 13,000 GB-s/day, 5 million rows read/day, 100,000
rows written/day, and 5 GB total stored data. Exceeding a free operation limit
makes further operations of that type fail until the daily reset, which the
enforcement path treats as unavailable rather than passing without a gate.

How the design sits against them:

- **Subrequests — bounded for ordinary and merge-group checks.** An ordinary
  pull-request check costs route
  and gate lookup (2) + token mint (1) + paginated commit listing (1–3) +
  coverage-ref snapshot (1) +
  fixed coverage reads for the enforcer-wrapped keyring,
  `decision-fence.enc.json`, `source.enc.json`, `inflight.enc.json`,
  `exemptions.enc.json`, and `agreements/active.enc.json` (6) + subject
  coverage shards, including active overrides (1–32) + check run write (1), or
  13–46 against a cap of 50.
  The 32-shard Free layout (D9)
  provides that bound; it does not assume a many-author pull request happens to
  concentrate in one or two files. A merge-group check adds one bounded
  GraphQL queue-entry query and then evaluates one PR through the same path. A
  successful authoritative result additionally reserves the project fence,
  atomically compares and reserves the strongly consistent routing gate, and
  finishes the coverage reservation. The successful GitHub create response is
  validated directly; its authenticated completion webhook clears the routing
  reservation in a separate invocation, and only lost-response recovery
  performs the bounded read-back. The successful hot path therefore remains
  17–50 subrequests. Any bound fails closed; the real-account release probe
  must exercise this mapping and complete encrypted path rather than reuse the
  ordinary-PR result.
- **Ordinary pull-request CPU — the pre-encryption one-shard path is measured;
  the complete encrypted 32-shard maximum is a release gate.** Workers bill CPU
  rather than I/O wait, so
  awaiting GitHub is free. Workerd measurements from 18 August 2026
  (`api/bench/`) report 0.26 ms for a typical 10-commit request, 0.50 ms for 100
  commits, and 1.26 ms for 250 commits with a cold App key. Those fixtures parse
  exactly one plaintext coverage shard and predate revision 12. They do not
  measure keyring parsing, AES-GCM unwrap, envelope validation, or shard
  decryption, and do not establish the maximum 32-shard path. Before Free is
  claimed, the release matrix must measure a request touching all 32 encrypted
  shards at the maximum supported shard size, including a cold
  installation-token mint and cold coverage-key unwrap. Token minting itself
  cost about 0.4 ms in the old fixture and does not require persistent caching.

  Read those figures only as pre-encryption lower bounds: workerd is the
  production runtime, but it ran on a development machine, excludes isolate
  startup and Cloudflare's own CPU accounting, and lacks the new cryptographic
  work. No correction factor turns that fixture into revision-12 evidence. No
  Free-tier CPU conclusion is made for the ordinary encrypted, 32-shard, or
  merge-group queue-entry paths until their A2 release probes pass.
- **Authorized private reads are bounded.** A cold authorization proof uses one
  route lookup, one installation-token mint, two ref snapshots, one wrapped
  records-key read, one canonical generations read, one derived-state read, and
  all 32 reader-authority shards: 39 subrequests before a continuous-team
  membership check. An individual or snapshot source stays at 39. A
  continuous-only authorization checks at most the initial profile's ten rules,
  one GitHub membership request each, and therefore remains at or below 49. A
  proof-bound index or status page rechecks the canonical generation, rechecks
  one bound continuous source when applicable, and reads one data shard,
  remaining below 11 subrequests. No request combines all reader and index
  shards.
  Maximum-size proof issuance, proof-bound page reads, and proof invalidation
  after withdrawal are A2 release probes under the 10 ms CPU limit.
- **Portal mutations are bounded by the installed release profile.** The
  profile states maximum encrypted derived-shard bytes, reader-source members,
  prepared-operation bytes, bulk fanout, retries, and total subrequests below
  50. Release probes exercise signing, revocation, one-shard administration,
  and maximum bulk fanout with cold key unwrap; the records-operation prepare,
  coverage-fence, in-flight-marker, canonical append, and projection
  transitions; compare-and-swap conflicts; and recovery from every persisted
  transition. Reader additions and bulk
  operations exceeding a known bound are rejected before append; reader
  withdrawals remain available because they remove state. Acceptance and
  revocation are never discarded because a private derived shard reached its
  profile: canonical evidence and coverage complete, the affected private class
  stays fail-closed, and the administrator is directed to the control repair or
  larger tested profile rather than being served stale data.
- **Requests — a ceiling shared across all tenants** in the hosted deployment.
  Under the normal inputs, 8 pull-request + 1 merge-group + 20 event-wide
  check-run deliveries allocate 29 webhook requests per pull request before
  portal and maintenance traffic. The 100,000/day Free ceiling therefore admits
  roughly 3,400 such pull requests per day across all adopters; GitHub provides
  no check-run-delivery bound, so telemetry must reduce that envelope (risk R7).
- **Actions minutes are metered where the reconciler runs.** §2's "Actions
  minutes are free on public repos" is true and irrelevant here: the reconciler
  runs in the private **control** repo, where GitHub Free meters minutes
  (2,000/month). Normal successful mutations materialize synchronously and do
  not dispatch Actions. A failed synchronous materialization dispatches one
  repair run, and the daily schedule performs verification and recovery. This
  is a real Free-baseline constraint that A3 budgets separately from ordinary
  signing volume.

**Limits are per Cloudflare account, not per Worker or project.** Workers and
Durable Objects have separate Free usage dimensions, all shared by the projects
inside that account. This scopes the two deployment modes differently:

- **Hosted shared** — one account, so the Workers and Durable Objects daily
  allowances are divided across every adopter (risk R7). The stated initial
  250-project envelope uses 44.5% of Workers requests, 13.75% of Durable Objects
  requests, and 13.22% of Durable Objects duration in the normal merge-group
  and check-run-delivery case. The ten-delivery/100-check-run sensitivity uses
  155.75%, 47.5%, and 45.67%
  respectively under the one-second-per-gate-call design budget. The full
  32-page dashboard sensitivity uses 83.25% of Workers requests while leaving
  Durable Object usage unchanged. Normal and dashboard cases fit Free at 250
  projects; the event-heavy sensitivity requires Paid or an envelope below 160
  projects. Paid remains the growth and abuse-response path rather than a
  prerequisite under the explicit normal assumptions.
- **Self-hosted** — each project runs in its own Cloudflare account and
  receives the full per-account Workers and Durable Objects allowances.

**This is how `REQ-OPS-3` is satisfied.** Both the shared hosted deployment at
the stated 250-project envelope and a self-hosted single-project deployment fit
the published Free limits. Adopters are not required to provide Cloudflare
credentials for the shared service. If the required real-account verification
shows that Worker CPU or Durable Object duration does not fit, the initial
capacity claim must be reduced to the measured envelope or the documented free
provider must change before release; the design must not silently make paid
service or adopter credentials mandatory.

**Fail-closed is mandatory.** On exceeding the Workers daily limit Cloudflare either
fails open — "Bypasses the Worker. Requests behave as if no Worker is
configured" — or fails closed with a 1027 error. Fail-open would silently drop
webhooks and let a pull request proceed with no CLA evaluation at all. Routes
MUST be configured **fail closed** so an absent required check blocks rather
than passing unevaluated. A Durable Object error or exhausted object operation
limit independently makes routing fail; the design never falls back to KV
alone. A missing, corrupt, conflicting, or unavailable coverage fence likewise
blocks mutation start or authoritative publication.
GitHub does **not** automatically redeliver failed
webhook deliveries; recovery is the scheduled enforcer sweep, or an authorized
manual redelivery after service returns.

**But be accurate about what exhaustion looks like.** An earlier draft said the
check "remains `queued`". That holds only if a check run already exists. If the
Worker never ran for `pull_request.opened`, **no check run exists** — absent,
not queued. A required-but-absent check does block the merge queue, which is the
safe direction, but it shows the contributor nothing, offers no retry
affordance, and does not self-heal through GitHub: failed webhook deliveries are
not automatically redelivered, and `check_run.rerequested` routes to the same
dead Worker. The enforcer's scheduled sweep (§5.4), once the service and its
request budget are available, detects in-scope pull requests with no check and
creates one carrying the *temporarily unavailable* state and its retry text.
That is what eventually makes `REQ-CHECK-5`'s explanation requirement visible;
during a total edge outage the required-but-absent check can only block.

**Exhaustion is reachable by an outsider, and this is the sharpest availability
risk in the design.** `dracla-enforcer` is a public App, so anyone can install
it on a throwaway org and script pull request churn; and every request counts
against the per-account cap whether or not its webhook signature verifies. With
fail-closed routing that halts checks *and* signing *and* revocation for every
adopter — so the documented remediation ("sign, and the check re-evaluates")
is down at the same moment, and the portal revocation capability `REQ-REV-1`
requires is unavailable for the duration. "Per-project rate accounting"
cannot help, because the exhausted resource is per account and the offending
traffic belongs to no
project. Signature verification at the edge avoids downstream work but cannot
refund a counted request. DraCLA deliberately has no IP-based control, so the
hosted mitigation is paid Workers and Durable Objects capacity, monitoring, and
operator response; the outsider-exhaustion path remains residual. The §9 route
split isolates secrets and request handlers, **not** the account-wide request
quotas; quota isolation would require separate Cloudflare accounts. Risks R7
and R9.

**Default adoption path.** Shared DraCLA-operated serverless deployment
(`REQ-OPS-1`), with all three private repositories in an adopter-controlled
organization or personal account (`REQ-OPS-6`). Before authorization, install
states that the hosted operator controls the records wrapping service and can
technically obtain every hosted project's signer PII; projects that reject that
trust use the supported self-hosted path. The confirmation links to the FAQ,
which names the portal Worker, records App key, records wrapping root, control
workflow, and their operator/secret controllers; explains that the enforcer has
coverage authority but no records key; and gives the migration procedure. Both
surfaces also state that removing a key controller cannot revoke historical
access, that a future-access cutoff requires project data-key rotation and a
current-state rebuild, and that compromise of a shared hosted root triggers that
work for every affected hosted project. The install warning, completion summary,
and FAQ separately identify each repository deploy key as an integrity
credential: it cannot decrypt CLA records by itself, but it can rewrite,
delete, roll back, or replay encrypted repository state and may thereby affect
CLA checks. They identify the exact repository, control-secret location, who is
an integrity controller, and the immediate rotate/verify/rebuild procedure in
§8.1.2.

```
1. admin runs:  uvx dracla@<version> install github.owner=<account>
                                                        (own credentials)
     -> one argument: the account that will own the project repositories. No
        prompts for recipient, agreement, or enforcement scope — those are
        portal actions (§6.10.3)
     -> create <slug>-cla-records, <slug>-cla-coverage, and
        <slug>-cla-control, all private; create the mandatory README-only root,
        rename the records default branch to `events`, initialize coverage, and
        seed the pinned control workflow (§6.10.1)
     -> generate records and coverage data keys, control wrapping material,
        repository-scoped deploy keys, and adopter recovery material; prove the
        actual two data keys recoverable through every initial path before
        enabling private writes (§6.10.2)
     -> recommend storing the recovery key in a password manager or other safe
        storage, discard installer copies after handoff, and print three App
        install links

2. admin clicks:  install dracla-records on records and coverage
     -> GitHub redirects to the Setup URL, which stores nothing and points the
        administrator to Connect

3. admin clicks:  install dracla-enforcer on coverage and contributing repos,
                  and dracla-reconciler-trigger on control only
     -> same stateless redirect. The slug claim is established at connect
        (step 4), not as a side effect of installing an App (§7)

4. admin connects in the portal: recipient, agreements, enforcement scope,
   policy text, initial reader intent
     -> each coverage- or evidence-affecting change becomes an event with an
        actor and authorization evidence; readers are authorized individually,
        by selected team snapshot, or by an explicitly chosen continuous team
        rule. Repository read access grants no plaintext authority
     -> verify App bindings and the live key paths; one agreement version is
        activated explicitly before signing is enabled
     -> the registry entry is written here, last, so a half-provisioned
        project is never routable (R5)
```

**Why the installation links rather than an API call.** A GitHub App cannot
install another GitHub App; installation is a user action through GitHub's own
UI. Offering the link is therefore not a workaround but the intended flow, and
it is better than anything DraCLA could build: GitHub owns the consent screen,
the repository picker, and the permission display. The link needs no privilege
to offer — it is an anchor.

**Why provisioning is the CLI and not a provisioning App** (D11): provisioning needs
`administration` and `workflows` write on the adopter's organization, and
`secrets` write once the reconciler's key exists (M2). Running it as the
administrator means DraCLA never holds those permissions, so there is nothing to leave behind if an uninstall fails.
`uvx dracla@<version>` makes it one explicitly versioned command with no
environment to manage; §6.9 defines the release identity it displays before
authorization.

**Readers are authorized, not inferred from repository access.** Connect writes
administrator-attributed canonical events for individual accounts, selected
team snapshots, and explicit continuous-team rules. Snapshot is the default
when a team is selected. Active sources combine by union; withdrawing one
source reports any other source that still authorizes the reader. Before every
private read, the portal authenticates the requester, resolves those current
sources, and, when the selected source is continuous, verifies that exact team
membership live before decrypting the permitted result. Absence, provider
failure, or an indeterminate result denies plaintext. Repository readers and
read-only Apps without a key see ciphertext and need not be enumerated. The
daily portal job observes only configured continuous teams and materializes
membership changes; it is a recovery and projection mechanism, not the live
confidentiality check (§6.10.4).

Adding a second project later re-runs the same flow and creates another
three-repository set (§5.5). The recipient within each project is immutable
once chosen.

**`dracla` org holds software and service; project data uses a separate
three-repository set:**

```
dracla/dracla              PUBLIC   monorepo
  core/                    Python: event model, replay, validation, exports
  cli/                     dracla command (uvx-runnable — §6.9)
  api/                     Cloudflare Workers (TypeScript)
  dashboard/               static shell + badge assets (Pages)
  design/  docs/

dracla/dracla-registry     PRIVATE  project routing (§7)
dracla/dracla-example      PUBLIC   sample adopter — a contributing repo
dracla/dracla-example-two  PUBLIC   second sample (release scope item 11)

created by `dracla install`, not by hand — these project-controlled private
repositories may live in an existing organization, a personal account, or an
optional dedicated organization (§6.10.4):
  <owner>/dracla-cla-records     PRIVATE, encrypted canonical
  <owner>/dracla-cla-coverage    PRIVATE, encrypted enforcement projection
  <owner>/dracla-cla-control     PRIVATE, pinned workflow and key-bearing secrets
```

Two samples with **different legal recipients**, so release item 11 exercises
two independent projects and the workspace composition of §6.9 rather than
testing them as an afterthought. Each sample has its own repository set and
exactly one agreement identifier, preserving the initial-release rule.

**DraCLA's own contribution terms are a DCO, not a CLA.** Apache-2.0 §5 already
makes contributions inbound-equals-outbound and carries §3's patent grant, so a
CLA would add only relicensing ability and consolidated enforcement standing —
neither of which this project needs. A tool that recommended CLAs
indiscriminately would be self-serving; dogfooding happens in the sample
projects, which are real installations, rather than by imposing signing friction
on people fixing typos.

Workers and Pages both deploy from subdirectories, so a monorepo costs nothing
and keeps the Python core and the edge handlers versioned together.
`dracla-example` must be a separate repository because it has to behave like a
real adopter project under enforcement. The **registry is its own private
repository** (§7), not a monorepo directory — D2's own argument that tokens
cannot be path-scoped applies to it, and it must not be public.

**Supply chain (`REQ-SEC-10`).** The reconcile workflow seeded into every
adopter's control repo consumes the Python core and unwraps both project keys,
so a mutable reference would mean one push to `dracla/dracla` executes
attacker-chosen code inside every adopter's key-bearing runner — simultaneous
hosted compromise of confidentiality and merge-gate integrity.
Therefore:

- The seeded workflow pins actions and the core by **digest**, never by branch
  or floating tag.
- Releases are signed, publish provenance attestation, and the workflow verifies
  it before running.
- The key-bearing process imports no module, command, dependency, workflow
  fragment, or control configuration from records or coverage. Decrypted
  repository content is schema-validated business data consumed only by the
  pinned core and cannot select executable behavior.
- Version bumps are an explicit adopter action (a pull request into their own
  control repository), not a silent upgrade. The same pull request records the prior
  verified digest, and rollback restores that digest and reruns verification.
- The published source of the hosted Worker is attested to the deployed build,
  since open-sourcing the code otherwise provides an adopter no assurance
  whatever about what the operator is actually running (§8.3). Health and
  evidence endpoints expose that immutable deployed release identity.

**Optional variants**

- *Self-hosted*: the same released two-Worker code, three App manifests,
  per-repository routing gate, control workflow, and envelope formats deployed
  in the adopter's Cloudflare and GitHub accounts. It uses adopter-controlled
  records and coverage wrapping roots and a single-entry registry. The normal
  installer targets that endpoint; clean install, operation, upgrade, rollback,
  and hosted migration are release-matrix scenarios, not best-effort support.
- *Self-hosted control-computed enforcement*: a project's protected control
  workflow may decrypt coverage and return only the bounded decision to an
  enforcer that relays the check. This keeps decryption in adopter-controlled
  runtime but costs a dispatch hop, latency, and metered private-repo Actions
  minutes. The workflow remains in control, never in an event-appending repo.

**GitHub Free baseline** (`REQ-OPS-3`): public contributing repo, private
records, coverage, and control repos, required merge queue with the DraCLA
merge-group check required. No durable job queue, reverse PR index, or global
rescan.

This split is not a preference — it is forced, and now measured (A4, §11).
Rulesets carrying `merge_queue` and `required_status_checks` are available on a
**public** repository in a Free organization; the identical ruleset on a
**private** repository is refused with *"Upgrade to GitHub Pro or make this
repository public"*. So enforcement must live where the contributing code is
public, and private project data must live where it is private. D2 further
separates encrypted records, encrypted coverage, and key-bearing control code.

### 9.1 Backup and recovery (`REQ-REC-7`, `REQ-REC-4`)

`REQ-REC-7` requires a documented backup and recovery procedure for the records
repository and any keys needed to interpret protected content. `REQ-REC-4`
additionally requires backups to preserve commit history **and recorded
branch-head identities**, and `REQ-VERIFY-2` requires a restore-then-rebuild
acceptance scenario. None of this existed in earlier drafts.

**What is backed up**

| Artifact | Why | Where |
|---|---|---|
| Records repo, full history, all branches | The source of truth, including encrypted configuration, `events`, `derived`, and the wrapped-key `keys` branch | Adopter-controlled mirror clone |
| Coverage repo, full history, all branches | Encrypted rebuildable enforcement state and service-wrapped coverage keys | Same mirror schedule |
| Control repo, full history, all branches | Pinned workflow and inert wrapped-key inputs; useful for auditable restoration | Same mirror schedule |
| Backup manifest with every source repository numeric ID, branch name, and head OID | `REQ-REC-4`; records snapshot origin and exactly which refs it must restore; a replacement gets a separately authorized new ID | Stored and versioned with that backup snapshot |
| Adopter recovery wrapping key | Required to interpret every retained records and coverage key without the former operator | Adopter password manager or other safe storage, separate from repository backups |
| App, session, deploy, control-wrapping, and service-root credentials | Needed to resume a particular deployment, but replaceable from recovery material | Operator or adopter secret stores, never repository content (`REQ-SEC-4`) |

A repository backup alone is intentionally **not** interpretable: ordinary
readers and backup operators see authenticated ciphertext. The repositories,
documented envelope and event schemas, and adopter recovery material together
are sufficient to decrypt without the DraCLA service (`REQ-REC-5`). Losing the
only recovery key while also losing every live wrapping path can make retained
history unrecoverable; install tests the actual initial records and coverage
keys and prominently asks the adopter to store that recovery key safely before
the first private write.

**Snapshot manifest, not a second log.** Each backup atomically records the
snapshot time and every backed-up branch name and head OID in a manifest stored
with that snapshot. Recovery checks that each named commit exists and each
restored ref equals the manifest before replay starts. This detects an
incomplete or mismatched restore. It is not an external checkpoint and makes no
tamper-detection claim against an administrator who controls both repository
and backups, which is the explicit `REQ-REC-4` trust boundary. Independent
signed checkpoints remain optional future hardening.

**Recovery procedure**

```
1. restore records, coverage, and control repos (all refs, full history)
2. verify every source identity and restored branch/head OID against the
   manifest; if restoring into replacement repositories, record their new IDs
   for the later administrator-authorized rebind
3. follow §6.10.2's bootstrap algorithm with the adopter recovery wrapper to
   authenticate the initial records key and first `project_connected` event;
   replay activation events, then unwrap every retained records and coverage
   key and authenticate a recovery challenge for each current key
4. create replacement portal, enforcer, and control wrapped copies; provision
   replacement deploy keys and verify each live path before activating it
5. run the pinned control reconciler in full-replay mode to rebuild encrypted
   coverage and the sharded derived index, status detail, and reader authority
   from encrypted canonical events; generate an export only if explicitly
   requested
6. rebind Apps and re-point the registry entry if repository identities changed
7. invoke the enforcer sweep for open pull requests in enforcement scope
```

Step 5 is the same code path the reconciler already runs, which is what
`REQ-REC-6`'s rebuildability requirement buys. Hosted-to-self-hosted migration
uses steps 3–7 against the existing repositories and does not require the former
operator. An ordinary migration may rewrap the same project keys and converts
neither envelopes nor canonical events; that changes the live operator but does
not revoke a former operator who retained old material. A migration intended as
a security cutoff additionally rotates both project data keys and rebuilds the
current coverage and records-derived state under them. Canonical history remains
unchanged and may remain readable with copied old keys.

---

### 9.2 Capacity envelope (`REQ-OPS-3`)

`REQ-OPS-3` requires the documented deployment to state its request and compute
assumptions, the applicable provider limits, and the behaviour on reaching them.
The existing Worker model is `core/capacity.py`, parameterised so it answers for
any adopter count rather than depending on one guessed number. The core slice
above this design must add the Durable Objects request, row-read, row-write,
storage, duration, and repository-count dimensions shown below before release;
until then those rows are design arithmetic rather than model output. Re-run
the completed model whenever an assumption changes.

**Assumptions**, per project per day unless noted. Each is an input, not a fact:

| | Value | Where it came from |
|---|---|---|
| Pull requests | 5 | assumed |
| `pull_request` webhook deliveries per pull request | 8 | sampled from live repos: median 3.5 (`astral-sh/uv`) to 10.5 (`cli/cli`) |
| `merge_group` deliveries | 1 per pull request normally; 10 per pull request sensitivity | one is the no-rebuild case; ten exposes rebuild sensitivity, but GitHub supplies no per-PR upper bound because failures and queue reordering can rebuild groups |
| Event-wide `check_run` deliveries | 20 per pull request normally; 100 per pull request sensitivity | assumed allocation across all `created`, `completed`, and other delivered actions for every App's checks in contributing repositories; includes DraCLA's own created/completed pair and is not a provider bound |
| Signings | 2 | assumed |
| Requests per signing | 8 | OAuth start and callback, agreement fetch, POST, status |
| Daily project maintenance | 2 Worker requests per project | one portal pass for configured continuous-team materialization and data-repository visibility, plus one enforcer pass for visibility and check recovery; there is no repository ACL scan |
| Dashboard views | 5 × 3 requests normally; 5 × 34 full-scan sensitivity | shell, one authorization proof, and one index page normally; a complete 32-page scan reuses the proof but rechecks its generation per page |
| Badge requests | 0 | badges are static Pages assets (§6.7) |
| Routed repositories | 10 | assumed per project for Durable Object storage sizing |
| Routing-gate requests | 11 per pull request in the normal case | all 8 sampled pull-request deliveries plus the merge-group's initial comparison, publication reservation, and authoritative completed-check confirmation are charged to the repository gate; disjoint `external_id` namespaces discard ordinary completions before a gate call, and the sensitivity adds three calls per additional merge-group delivery |
| Routing-gate row writes | 2 per successful merge-group delivery in steady state | publication reserve and exact terminal confirmation each update the one row; a routing change separately writes `pending` and one final row, with no periodic refresh |
| Durable Object active duration | 1 s per gate call | deliberately conservative design budget for one local row read; release measurement must fit it |
| CPU per ordinary pull-request check | 1.26 ms pre-encryption lower bound | measured by the old `api/bench/` fixture; encrypted ordinary and merge-group queue-entry paths remain A2 release probes |

**Deliveries are driven by pull request *activity*, not pull request count.**
GitHub App webhook subscriptions are per event **type**, not per action, so
DraCLA receives all 23 `pull_request` actions and acts on 4. The other 19 —
labelling, assignment, review requests — are discarded on arrival but still cost
a Workers request. The same rule applies to `check_run`: with Checks write the
App is automatically subscribed, and signed `created` and `completed` events
for other Apps' checks reach the Worker even though DraCLA discards them after
checking the check-run App ID. The normal model therefore charges the explicit
20-delivery-per-pull-request assumption above, not merely DraCLA's own
completion. This App's ordinary completions additionally fail the exact
`dracla-authoritative-v1.` namespace check before a gate RPC, while matching
authoritative completions perform the one confirmation call budgeted above.
The merge-group and 100-check-run-delivery sensitivities are stress assumptions,
not provider guarantees. Release telemetry must record both
observed multipliers and reduce the stated project envelope if either exceeds
the modelled case.

An agreement activation or restore costs one project-wide marker update and one
encrypted `agreements/active.enc.json` compare-and-swap regardless of how many
contributors it affects (§6.5); no shard fold is required, so the transition does not appear in
the per-subject request budget.

**Result** (Cloudflare requests, normal one-delivery merge-group case,
including the daily project-maintenance allowance)

| Projects | Requests/day | % of Free | % of Paid | Pre-encryption CPU lower bound/day |
|---|---|---|---|---|
| 10 | 1,780 | 1.8% | 0.5% | ≥1.0 s + crypto/team/publication/filter probes |
| 50 | 8,900 | 8.9% | 2.7% | ≥4.8 s + crypto/team/publication/filter probes |
| 100 | 17,800 | 17.8% | 5.3% | ≥9.6 s + crypto/team/publication/filter probes |
| 250 | 44,500 | 44.5% | 13.4% | ≥24.0 s + crypto/team/publication/filter probes |

Cloudflare Free saturates at roughly **560 projects** under the normal
check-run-delivery assumption. This remains above the initial 250-project
envelope, but it is an assumption-sensitive constraint rather than a provider
guarantee.

If all five assumed dashboard views instead scan all 32 index pages, each
project produces 333 Worker requests/day. The 250-project envelope then uses
83,250 requests/day (83.25% of Free), and the request ceiling moves to roughly
300 projects. This is a dashboard-volume sensitivity, not extra work hidden
inside one invocation; every page still has the private-read bound above.

At ten `merge_group` deliveries and 100 event-wide `check_run` deliveries per
pull request, each project instead produces 623 Worker requests/day. The
250-project envelope produces 155,750 requests/day (155.75% of Free and 46.7%
of Paid), and the Free request ceiling moves to roughly 160 projects. The
initial 250-project hosted envelope therefore requires Paid capacity under this
sensitivity. Per-entry merge-group CPU and subrequests remain the separate A2
release probe.

The daily continuous-team materialization pass requires its own real Free-tier
CPU probe at the maximum supported configured-team and team-member page count.
I/O wait is not CPU, but signature verification, JSON parsing,
authorization-source comparison, decryption, encryption, and fan-out
bookkeeping are. The initial release may keep a bounded pagination profile that
fails closed; it may not claim the 250-project envelope until one invocation
stays below 10 ms and its fan-out stays below 50 subrequests. Projects with no
continuous rules skip this work; ordinary repository readers are never scanned.

**Result** (Durable Objects, normal one-delivery merge-group case and treating
every sampled webhook as a routing-gate check)

| Projects | Gate requests and rows read/day | % of Free requests | Duration at 1 s/call | % of Free duration | Approximate object storage at 10 repositories/project |
|---|---|---|---|---|---|
| 10 | 550 | 0.55% | 68.75 GB-s | 0.53% | 1.2 MB plus gate rows |
| 50 | 2,750 | 2.75% | 343.75 GB-s | 2.64% | 6 MB plus gate rows |
| 100 | 5,500 | 5.50% | 687.50 GB-s | 5.29% | 12 MB plus gate rows |
| 250 | 13,750 | 13.75% | 1,718.75 GB-s | 13.22% | 30 MB plus gate rows |

At the Workers-request saturation point of roughly 560 projects, this bound
is about 30,800 Durable Object requests/day, 3,850 GB-s/day at the
one-second duration budget, and about 67.2 MB of empty SQLite object overhead
plus one small row per repository, using Cloudflare's documented
[approximately 12 KB empty-database size](https://developers.cloudflare.com/durable-objects/reference/faq/#does-metadata-stored-in-durable-objects-count-towards-my-storage).
It remains below the separate Free request, duration, row-read, and storage limits.
Each successful normal merge-group publication consumes two row writes, so 250
projects consume 2,500 publication-row writes/day (2.5% of Free). Routing
changes separately consume two writes per affected repository in the normal
handoff. The one-second duration figure is a design budget, not a measurement.
Real-account verification must measure object duration, row writes, and gate
latency before release and must reduce the stated envelope if the budget is not
met; quota or RPC failure blocks only the affected check.

At the ten-delivery merge-group sensitivity, each project makes 190 gate calls
per day. At 250 projects that is 47,500 Durable Object requests and row reads
(47.5% of Free), 5,937.5 GB-s at the one-second budget (45.67% of Free), and
25,000 publication-row writes (25% of Free). Storage is unchanged.

That separates two risks. **R7** — one busy adopter consuming the shared
ceilings — remains assumption-sensitive because unrelated Apps' check runs are
delivered to the enforcer; the normal and stress inputs make that dependence
explicit. **R9** — an outsider deliberately exhausting the public endpoint,
which needs no adopter activity at all — remains the sharper exposure. The
hosted paid budget and monitoring reduce their likelihood and duration but do
not prevent them; the two Workers' route split and repository-scoped objects
cannot isolate shared account quotas (§9).

**Subject to A2's continuous-team CPU probe, the binding modelled constraint remains
GitHub Actions minutes, not Cloudflare requests.**

The reconciler runs inside each project's private **control** repository, where
GitHub Free meters 2,000 minutes per month against the org's whole private-repo
allowance — not a DraCLA-specific budget. Jobs bill whole minutes, so schedule
frequency dominates:

| Schedule | At 1 min/run | At 2 min/run |
|---|---|---|
| Every 15 min | 2,940 min — **147%, over Free** | over Free |
| Hourly | 780 min — 39% | 1,560 min — 78% |
| Every 6 h | 180 min — 9% | 360 min — 18% |
| **Daily** | **30 min — 1.5%** | **60 min — 3%** |

Normal successful sign, revoke, and administrative mutations do not start an
Actions run: the portal materializes encrypted coverage synchronously. The
normal Actions envelope is therefore the daily schedule alone, **30–60
minutes/month**, or **1.5–3%** of the organization's Free allowance. Each failed
synchronous materialization may dispatch one exceptional repair run; release
telemetry reports those separately rather than charging every signature. Each
hosted export request also starts one explicit user-requested control run; its
minutes are reported separately and the local streaming CLI avoids that cost.

**Decision: daily.** These minutes bill to the **adopting organization's**
account — Actions bills the repository owner — so they come out of that org's
whole 2,000 min/month, shared with all their other private repos. Spending 39%
to 78% of an adopter's entire CI allowance on a component that is not their
product is an unreasonable adoption cost. The normal daily schedule uses 1.5%
to 3%; failure-triggered repair and explicit hosted-export runs are exceptional
or user-driven and measured separately.

Daily is defensible because only one scheduled duty is latency-sensitive:

| Scheduled duty | Cadence needed |
|---|---|
| From-scratch verification replay | Daily or weekly — it is an integrity check |
| Derived index/status/reader shards | Affected bounded shards are generated synchronously; the daily run verifies and repairs them |
| JSON/CSV exports | Never scheduled or mutation-driven; explicit control-workflow or local CLI request only |
| Agreement activations and restores | Not scheduled; each transition is immediate and request-driven (§6.5) |
| Interrupted mutation recovery | Minutes, ideally — but the Worker repairs opportunistically (§5.4), and an unfinished mutation fails closed |

Keeping agreement currency transitions off the schedule also *improves* correctness: the
project-wide freshness marker blocks checks during the O(1) active-version
update, leaving no clock-driven transition window.

**Opportunistic interrupted-operation recovery** removes most of that latency
without spending minutes: any later portal request that encounters the non-idle
operation state drives §5.4 recovery. If the exact event landed, the Worker
completes materialization and closes the marker; if it did not, the Worker
revalidates and continues the frozen operation. The scheduled pass catches
projects whose portal receives no later request.

**Behaviour on reaching a limit** (`REQ-OPS-3` requires this stated): Cloudflare
routes are fail-closed, so checks stop being written rather than passing
unevaluated. A missing, errored, or quota-exhausted routing gate likewise cannot
authorize a route. No unavailable check can be created while the enforcer
service is down; after service or quota recovery, its scheduled sweep creates
that check (§9). Exhausting Actions minutes stops projection reconciliation
and hosted exports only; signing, revocation, and checks continue while their
routing gates remain available and consistent. A records-derived profile limit
never serves stale plaintext: reader additions or oversized bulk administration
are rejected before append, while acceptance and revocation evidence plus
coverage still complete and leave the affected private class unavailable until
control repair or migration to a larger tested profile. Reader withdrawal
remains available because it removes state. The CLI can still replay and export
directly from canonical with recovery material.

## 10. Requirement alignment history

### 10.1 Amendments — approved and incorporated

The original two amendments were approved on 18 August 2026 in requirements
revision 2. Revision 4, approved on 21 August 2026, replaced the staged part of
`REQ-AGR-2` with the immediate-activation rule shown here. Requirements section
20 preserves both decisions and identifies the supersession. Revision 11,
approved on 22 August 2026, defines source-aware exemption and reader behavior
and uncapped successful revocation and re-signing. Revision 12, approved on
23 August 2026, supersedes revision 11's plaintext records-ACL boundary with
authenticated encryption, canonical reader authorization, capability-separated
key control, and adopter-controlled recovery. Revision 13, approved on
24 August 2026, makes merge-queue enforcement independently authoritative per
pull-request queue entry, removes cumulative predecessor reconstruction, and
defines completion of each entry's check as its decision time.
Revision 14, approved on 31 August 2026, adds one explicit authorized agreement
activation restore. It reinstates the exact currency state of a named prior
activation while ordinary activation remains unable to revive retired versions;
it does not revive an independently invalid contributor signature basis.

The 29 August 2026 HLD true-up resolves §6.6's single-row supersession
contradiction. A signer correction advances the subject-agreement row and
remains auditable in canonical history; only activation produces the dashboard
status `superseded`.

| Req | Change | Where |
|---|---|---|
| `REQ-AGR-2` | Publishing is separate from immediate activation; only the active version is signable; ordinary activation never revives retired currency; an explicit authorized restore may reinstate one prior activation state without reviving independently invalid signature bases | §6.5, D10 |
| `REQ-CHECK-2` | `Co-authored-by` trailers no longer determine a public check result, and are surfaced to authorized viewers instead; exemptions use individual, snapshot, and explicit continuous sources whose effective result is their union; exact PR/tree/subject overrides are consumed from the already-fetched subject shards | §5.3, §6.3, §6.3.1, §6.4, §6.8, D14 |
| `REQ-CHECK-3`, `REQ-CHECK-4` | Every merge-queue entry resolves and freshly evaluates exactly one associated pull request; preceding entries retain their completed decisions, while a rebuilt entry observes current canonical state; successful publication holds both the coverage fence and a routing-gate publication reservation until GitHub completion is confirmed | §5.4, §6.4, §7.2, §9, A2 |
| `REQ-SIGN-5` | Every mutating contributor and administrative form is bound to one exact canonical head and action digest; an already-satisfied action binds its terminal canonical event, so a delayed no-op retry cannot become a later write | §5.4, §6.8 |
| `REQ-REC-1`, `REQ-REC-2`, `REQ-SEC-2`, `REQ-SEC-6` | Private GitHub artifacts are authenticated ciphertext; records and coverage keys are separate; canonical individual and snapshot sources authorize plaintext independently of repository read access, while a canonical continuous source additionally requires live membership before proof issuance and every plaintext page | §4, §5.4, §6.6, §6.10.4, §8 |
| `REQ-REC-5`, `REQ-REC-7`, `REQ-SEC-9`, `REQ-OPS-6` | A documented envelope, retained key generations, verified adopter recovery, protected key-bearing execution, and rewrapping support service-independent readout and hosted-to-self-hosted migration | §4, §6.9, §6.10.2, §8.1.2, §9.1 |
| `REQ-REV-1`, `REQ-REV-5` | Successful acceptance and revocation are uncapped; idempotent retries remain write-free, authenticated event-backed form state makes semantic no-ops replay-stable, and exact-head mismatch rejects every other stale confirmation | §5.3, §5.4, §6.1, §6.2 |

The `REQ-CHECK-2` change narrows who must be covered, so its residual gap is
recorded rather than glossed: a co-author declared only by a trailer may
contribute without signing unless a maintainer acts (§6.3.1). It also does not
close the coverage oracle, only its cheap path (§6.3).

### 10.2 Deviations declared, not amendments

`REQ-OPS-2`'s enforcement clause is a **`SHOULD`**. A justified deviation needs
no baseline change, and an earlier draft escalated it into an amendment
unnecessarily — triggering requirements §19's Draft cycle for nothing. It is
recorded here as a deviation instead.

The argument also overreached. §2 said enforcement **cannot** run in Actions,
which §9's self-hosted control-computed variant contradicts: a workflow inside
the private control repo is not subject to the fork-secret rule. The accurate
claim is that the Actions path costs latency, metered private-repo minutes, and
a dispatch hop, so the App path was chosen — not that the Actions path is
impossible.

### 10.3 Previously undeclared deviations, now declared

An earlier draft asserted "No other requirement is deviated from." That was
false. Each item below is either now resolved in the design or is a deviation
that requires acknowledgement:

| Req | Status |
|---|---|
| `REQ-CHECK-1`, `REQ-PORTAL-3`, `REQ-PORTAL-5` | **Resolved** — the post-merge issue no longer names subjects (§6.4) |
| `REQ-SEC-6` | **Resolved** — the index proxy validates canonical reader sources to issue a scoped proof, rechecks its exact canonical generation before every private page, and rechecks live membership at issuance and every page when the bound source is continuous rather than trusting a cached session or repository-access verdict (§6.6, §8.2) |
| `REQ-CHECK-2` | **Resolved** — any pagination bound fails closed (§6.3) |
| `REQ-REC-7` | **Resolved** — backup and recovery is §9.1 |
| `REQ-SEC-1` | **Resolved** — fields derive from config; acceptance and revocation use no edge counter or IP-derived identifier (§5.1, §8.4) |
| `REQ-CHECK-3` | **Resolved** — admin bypass is documented (§6.4) |
| `REQ-OPS-3` | **Deviation acknowledged** — the reconciler consumes metered private-repo Actions minutes on the Free baseline (§9); bounded by incremental reconciliation, and must be sized in A3 |
| `REQ-AGR-2` | **Resolved** — activation and restore are immediate, inactive versions are not signable, ordinary activation cannot revive retired currency, and explicit restore reinstates one prior activation state without scheduled behavior (§6.5) |
| `REQ-PORTAL-5` | **Residual risk, not met in spirit** — the public check is an arbitrary-target coverage oracle by construction (§6.3). Its output is bounded and the residual is documented, not claimed closed. |
| `REQ-CONFIG-1` | **Limitation acknowledged** — two recipients in one org share an installation, so their separation is software-only in the hosted model (§7) |
| `REQ-REC-3` | **Resolved** — the mandatory README root is created through Contents API initialization, then the actual initial branch is renamed to `events`; wrapped keyrings use a separate `keys` branch and every later `events` commit contains one event (§6.10.1) |
| `REQ-CONFIG-3` | **Resolved** — repository entries require current repo `admin`, organization selectors require current organization-owner authority, and one coordination domain rejects or quarantines overlap without treating enforcement configuration as legal scope (§7) |

### 10.4 Verification resolved — no amendment needed

`REQ-OPS-3`'s merge-queue clause stands as written. A4 verified on 18 August
2026 that merge queue and required status checks are available for public
repositories on GitHub Free, and that the same enforcement on a private
repository requires a paid plan (§11). The conditional amendment previously
noted here is withdrawn: the condition did not occur.

**Release verification is required, not deferred.** Before any release, the
release owner maintains `design/verification-matrix.md` with one row for every
in-scope `MUST`, its automated test or explicitly recorded manual procedure,
evidence reference, and pass/fail result. It also enumerates every acceptance
scenario in `REQ-VERIFY-2`, including the concrete authorization-loss (§8.2),
backup restore (§9.1), overlap recovery (§7), and GitHub Free (§11) criteria
already defined here. It must also include stale-KV/gate mismatch, pending and
unavailable gate states, gate reconstruction, quota exhaustion, unaffected
repository isolation, and real-account Durable Object latency and duration.
An unmet or unverified row blocks release unless the requirements themselves
explicitly defer it.

### 10.5 Baseline status

Resolved. The baseline is **Locked at revision 14** and this document is
written against it. Revision 2 incorporated the two amendments of §10.1;
revision 3 ratified rules this design had declared on its own authority —
scope authorization (`REQ-CONFIG-5`, §7), credential lifecycle (`REQ-SEC-9`,
§8.1.2), and the `REQ-REC-3` event-commit reading (§10.3) — through the
requirements review loop rather than a design-proposed amendment, alongside
the derived-data enumerability and per-App boundary amendments. Revision 4
separates legal scope from enforcement routing, removes staged activation,
requires the README root and credential/ACL boundaries, and closes the remaining
identity, authorization, replay, disclosure, and supply-chain findings.
Revisions 5 and 6 lock one agreement identifier per initial-release project,
the complete administrative authorization evidence contract, and uniqueness
within a coordination domain. Revision 7 defines tuple-wide, forward-looking
revocation and its retry and restore behavior. Revision 8 adds repository-local
fail-closed handling and administrative recovery for overlaps created by GitHub
lifecycle changes. Revision 9 permits only the bounded public conflict message
needed to reach that recovery path. Revision 10 permits one bounded,
rebuildable strongly consistent routing gate per repository so stale KV cannot
select a replaced route; it requires no periodic write and stores no CLA
evidence. Its transient check-publication identity is coordination state, not
CLA evidence. Revision 11 added individual, snapshot, and explicit continuous
exemption and reader sources, a plaintext records-ACL verifier, and uncapped
successful acceptance and revocation. Revision 12 supersedes that ACL boundary:
all private GitHub artifacts are encrypted, plaintext reads use canonical
reader sources plus a live membership check for continuous-team sources,
records and coverage have separate key authority, protected control execution
cannot be modified by an event App, and verified adopter recovery enables
service-independent readout and self-hosted migration.
Revision 13 makes the required merge-group check authoritative per pull-request
queue entry, forbids rediscovering preceding entries from a cumulative
temporary commit, and treats a rebuilt or newly requested check as a fresh
decision against current canonical state.
Revision 14 adds an explicit, separately authorized, append-only agreement
activation restore that names one prior activation state. Ordinary activation
cannot target retired currency, and restore does not undo contributor
revocation, correction, acceptance supersession, or another independently
invalid signature basis.
Requirements section 20 records each change with its rationale,
affected IDs, and what it does not resolve, as section 19 requires.

---

## 11. Assumptions and open items

- **A1 — Edge platform. CLOSED.** Cloudflare Workers and Pages, TypeScript at
  the edge, Python core in Actions (D8, §9).
- **A2 — Subrequests bounded; enforcement, mutation, private-read, export, continuous-team, and Durable Objects measurement required before release.**
  An ordinary pull-request check uses at most 46 subrequests, including route
  and gate lookup, the immutable coverage-ref snapshot, the enforcer-wrapped
  coverage keyring, decision fence, lifecycle source, and all 32 Free-profile
  coverage shards, against a cap of 50
  (§9, D9, D13). Those already-fetched subject shards include active override
  maps, so the exact override-key lookup adds no request-path subrequest. A
  merge-group check adds one bounded GraphQL queue-entry query
  and evaluates one PR; successful authoritative publication adds the
  decision-fence reservation, atomic routing-gate publication reservation, and
  coverage finish calls, while validating the successful create response
  without a redundant read-back. The separate completion delivery clears the
  routing reservation, so the successful hot path still reaches at most 50
  subrequests. Any exceeded bound fails closed. CPU for
  the existing one-shard fixture was measured in workerd — 0.26 ms for a
  typical pull request and 1.26 ms for its 250-commit case (§9,
  `api/bench/README.md`) — but that fixture did not exercise the selected shard
  distribution, exact active-override validation, or revision-12 key unwrap and
  decryption. Seven things remain:
  measure the complete encrypted ordinary path and all 32 shards at the maximum
  supported shard size; confirm ordinary and per-entry merge-group CPU-time
  percentiles and the exact GraphQL entry mapping on a real GitHub and
  Cloudflare account, including signature verification, exact external-ID
  namespace filtering before gate calls, and early rejection of the
  100-delivery event-wide check-run sensitivity; measure signing, revocation,
  one-shard administration, and maximum bounded bulk fanout, including the
  records-operation prepare, coverage-fence, in-flight-marker, canonical, and
  projection transitions and recovery from every persisted crash point;
  measure maximum
  reader-proof issuance and proof-bound private pages, including the maximum ten
  continuous-source checks and 49-subrequest cold issuance path, one bound live
  check on each page below 11 subrequests, immediate generation invalidation
  after canonical withdrawal, and denial after a missed continuous-team
  departure; verify hosted control-workflow and
  streaming CLI exports at their declared limits; measure the maximum supported
  configured continuous-team materialization below 10 ms and 50 subrequests;
  and measure Durable Object comparison, publication reserve/confirm, row-write,
  crash-rebuild, latency, and duration behavior against A3's one-second budget
  rather than extrapolating them from a development machine. The shared daily request
  ceilings are volume questions for A3 rather than per-request ones.
- **A3 — Capacity assumptions complete; model update and release measurements pending.**
  §9.2 states the assumptions, their provenance, the resulting envelope, and
  the behaviour on reaching each limit, as `REQ-OPS-3` requires. The existing
  `core/capacity.py` model remains parameterised for Worker traffic; it must
  incorporate the new Durable Objects dimensions and reproduce the table before
  release.

  Two conclusions worth carrying: under the normal assumptions, neither the
  Workers nor Durable Objects Free request ceiling is a constraint at the
  250-project envelope; the event-heavy sensitivity exceeds Workers Free at
  that size. Workers saturates first, near 560 projects under the normal
  check-run assumption, near 160 under the ten-delivery/100-check-run
  sensitivity, and near 300 when every assumed dashboard view scans all 32
  pages. Actions minutes in each
  adopter's private control repository — billed to *their* org, not DraCLA's —
  set the reconciler schedule. The daily schedule costs 1.5% to 3% of the
  allowance; failure-triggered repair and explicit hosted-export runs are
  exceptional or user-driven and measured separately. A shared-root security
  cutoff is also an incident workload, not a
  steady-state allowance: affected projects remain unavailable and return in
  batches, and release verification measures one full project cutoff so the
  runbook can estimate fleet recovery time.
- **A4 — Merge queue on GitHub Free. CLOSED, verified 18 August 2026.**
  Tested empirically against a throwaway public repository in a Free-plan
  organization (`plan: free`, 1 seat):

  - A ruleset combining `merge_queue`, `required_status_checks`, and
    `pull_request` was created with `enforcement: active` and read back as
    effective on the default branch. Merge queue **is** available for public
    repositories on Free, so `REQ-CHECK-3`'s strong-enforcement baseline holds
    and no `REQ-OPS-3` amendment is needed.
  - Flipping the same repository to **private** immediately returned
    `403 Upgrade to GitHub Pro or make this repository public to enable this
    feature` on the rulesets API — confirming the other half of
    `REQ-OPS-3`'s baseline: ruleset and branch-protection enforcement on a
    private contributing repository requires a paid plan.

  Both halves of the documented Free baseline — public contributing repository
  with enforcement, private records repository without — are therefore verified
  rather than assumed.
- **A5 — Federated enforcement scope. CLOSED by the authorization-event
  model.** Different repository administrators and organization owners bind
  their own entries through separate attributable actions (§7). No actor's
  permission is reused for another owner, and routing changes only after each
  independently authorized event lands.
- **A6 — Write-deploy-key integrity reach and recovery probe required before
  release.** In a disposable private repository on GitHub Free, the release
  test creates the same write-capable deploy key as install, records which ref
  deletion, force-update, rollback, and replay operations GitHub permits on
  that baseline, and verifies that the installer warning describes the observed
  reach. It then treats the key as exposed, makes the route fail closed, rotates
  the key, compares refs with recorded backup-manifest heads, restores verified
  state, runs full replay and projection repair, and rechecks open pull requests.
  The test also confirms that the key alone cannot modify the separate control
  repository or decrypt a records envelope. Any stronger protection available
  only on a paid plan is documented as optional hardening, not assumed by the
  Free baseline.

---

## 12. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | ~~Co-author emails unresolvable, so co-authored PRs fail by default~~ **Closed** by `REQ-CHECK-2` rev 2 — trailers no longer block (§6.3.1) | Residual: a trailer-only co-author may contribute unsigned unless a maintainer acts on the surfaced list |
| R2 | A substantive version activation invalidates every contributor at once | Publish the immutable version in advance for project communication, then activate deliberately; `supersedes_coverage: false` handles non-invalidating changes, but DraCLA intentionally offers no early signing (§6.5, D10) |
| R3 | Non-atomic write across records and coverage repos (§5.4 steps 1–10) | The records-key prepared-operation cell makes the complete authorized request durable before the coverage fence blocks success; immutable cross-binding, append-right CAS, and the in-flight marker let the control reconciler recover every crash point without timeout or the original browser request |
| R4 | Index proxy carries all dashboard traffic and records-key decryption through the portal tier | Bound every shard; issue authorization only after all reader shards validate; recheck its canonical generation on every page and its bound continuous-team membership before issuance and each page; fail closed on absent or indeterminate membership; return `private, no-store`; include proof issuance, live checks, unwrap, decrypt, and full-page-scan sensitivities in A2/A3 |
| R5 | Provisioning failure leaves a half-installed project | `dracla install` is idempotent and re-runnable locally; the three App installs are GitHub's own flow and resumable; encrypted bootstrap state follows actual-key recovery and wrapping/control challenges, while no private event or route is enabled before repository-bound live checks; the Setup URL callback persists nothing, and the registry entry is written last by the portal when the administrator **connects** (§6.10.3.1) |
| R6 | An encrypted ordinary or merge-group check may exceed the 10 ms Free CPU limit when it unwraps its key and parses/decrypts the maximum coverage-shard distribution | The old plaintext one-shard fixture measured 1.26 ms but is only a lower bound; the encrypted ordinary path, selected 32-shard maximum, and per-entry merge-group path are mandatory A2 release probes. Any exceeded bound fails closed. Larger projects require a separately designed and verified future profile; v1 does not promise live re-sharding (§5.3, §9, A2). |
| R7 | One busy adopter's pull-request and unrelated-App check-run traffic consumes the shared hosted ceiling | The A3 model makes the event-wide input explicit: normal saturation is near 560 projects, the ten-delivery/100-check-run sensitivity near 160, and the full-dashboard sensitivity near 300 (§9.2). No persistent per-project counter is added; release telemetry must track both merge-group and check-run multipliers, while a reduced envelope, paid capacity, and monitoring are the operational guards |
| R8 | A daily Workers or Durable Objects limit is exceeded while routing is changing or checks are running | Routes, routing gates, and coverage-repository decision fences fail closed (`REQ-CHECK-5`, §5.4, §7.2, §9); after service recovers, reconciliation rebuilds gate state, repairs any open fence, and the enforcer sweep creates the *temporarily unavailable* check the dead route could not |
| R9 | `dracla-enforcer` is a public App, so an outsider can exhaust the shared per-account Workers or Durable Objects budget and halt checks, signing, and revocation for every adopter | Residual: signature verification limits downstream work but not counted requests; DraCLA uses no IP logic. Paid capacity, monitoring, and operator response reduce impact. The Worker split and repository-scoped objects limit state-corruption blast radius but do not isolate an account-wide quota (§9) |
| R10 | ~~Revocation-as-griefing via co-authoring~~ **Closed** by `REQ-CHECK-2` rev 2 — an injected trailer cannot block (§6.3.1) | Residual: a griefer who authors commits under their own identity can still revoke, but only affects pull requests containing their own authored work |
| R11 | Reconciler and hosted exports consume the project owner's private-repo Actions allowance, shared with the owner's other private repos | Normal operation uses one daily control-repository run, modelled at 1.5–3% of the Free allowance. Successful mutations do not dispatch; failed synchronous materializations and explicit hosted exports add separately measured runs, while local CLI export uses none (§9.2) |
| R12 | Loss of the adopter recovery key plus every live wrapping path makes retained ciphertext unrecoverable | Verify both actual initial data keys before the first private write and every successor before activation; recommend password-manager or equivalent safe storage; retain older key generations while referenced (§6.10.2, §9.1) |
| R13 | Compromise of hosted wrapping roots, the control wrapping key, or key-bearing pinned code exposes plaintext beyond ordinary reader authorization | Treat every controller as trusted and disclose its reach; separate records and coverage capabilities; bind wraps to project and purpose; pin executable inputs; support self-hosting with adopter roots (§4, §8.1.2, §8.3) |

---

## 13. Traceability

| Area | Requirements | Covered by |
|---|---|---|
| Project config, enforcement scope, recipient | `REQ-CONFIG-1..5` | §4, §5.1, §7, D4, D7 |
| Agreement versions and presentation | `REQ-AGR-1..4` | §5.1, §6.1, §6.5 |
| Individual signing | `REQ-SIGN-1..5` | §6.1, §5.1, §5.2 |
| Revocation and re-signing | `REQ-REV-1..5` | §6.2 |
| Entity CLAs | `REQ-ENTITY-1..5` | Deferred by `REQ-CONFIG-4`; event schema reserves the types |
| PR enforcement | `REQ-CHECK-1..5` | §2, §6.3, §6.4, §5.4 |
| Records | `REQ-REC-1..8` | §4, §5.1, §5.2, §6.6, §6.8, §9.1 |
| Privacy and security | `REQ-SEC-1..10` | §8, §8.1, §8.2, §8.4, §4, §5.3, §9.1 |
| Portal and badges | `REQ-PORTAL-1..6` | §6.1, §6.3, §6.7 |
| Dashboard | `REQ-DASH-1..5` | §6.6 |
| Administrative flows | `REQ-SIGN-5`, `REQ-AGR-1..2`, `REQ-CHECK-2`, `REQ-OPS-4` | §5.4, §6.5, §6.8 |
| Backup and recovery | `REQ-REC-7`, `REQ-REC-4` | §9.1 |
| Data protection | `REQ-SEC-1..3`, `REQ-SEC-7`, `REQ-REC-3` | §8.4 |
| Observability and minimization | `REQ-OPS-5`, `REQ-SEC-1` | §8.4.1 |
| CLI: reporting, portability | `REQ-REC-5`, `REQ-OPS-4` | §4, §6.9, §6.10, §9.1 |
| Deployment and portability | `REQ-OPS-1..6` | §2, §7, §9 |
| Release verification | `REQ-VERIFY-1..2` | Mandatory pre-release matrix and acceptance evidence (§10.4); an unmet or unverified `MUST` blocks release |
