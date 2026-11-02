# GitHub App configuration (phase 0)

Three service Apps, created in the `dracla` organization at
`https://github.com/organizations/dracla/settings/apps/new`.

The data Apps are separate because a single App holding both records and
enforcer permissions defeats the capability split — an attacker with one
credential simply uses the other. The third App can only dispatch the pinned
control workflow; it is not a provisioning principal (design D3, D11, D16).
Provisioning uses administrator credentials (§4 below). The separate adopter-owned
transport App has no provisioning authority (§5 below).

Origin: **`dracla.cli.dev`**. Design §9 requires the shell and API share one
origin, so the portal and the Worker routes are the same host — that is what
avoids `SameSite=None` and a reflected-CORS policy (DR-009).

Emit portal links in exactly one canonical form everywhere —
`https://dracla.cli.dev/p/<repository-owner-login>` for the default project and
`https://dracla.cli.dev/p/<repository-owner-login>/<project-slug>` for an
explicit additional project — in badges, check output, and pull request
comments. Always use the owner's current login.

---

## 1. `dracla-records` — portal side

Signs, revokes, and authorizes the dashboard. Never sees a contributing repo.

| Field | Value |
|---|---|
| Name | `dracla-records` |
| Homepage | `https://dracla.cli.dev` |
| Callback URL | `https://dracla.cli.dev/auth/callback` |
| Request user authorization (OAuth) during installation | **No** — users authorize at signing time, not install time |
| Expire user authorization tokens | **Yes** |
| Webhook | **Disabled** — this App receives no events |
| Where can this be installed | Any account |

**Repository permissions**

| Permission | Access | Why |
|---|---|---|
| Contents | Read and write | Append events to canonical; materialize coverage (§5.2, §5.4) |
| Metadata | Read | Mandatory; also backs the `REQ-SEC-6` dashboard check via `GET /repos/{owner}/{repo}` with a user-to-server token |

**Organization permissions**

| Permission | Access | Why |
|---|---|---|
| Members | Read | Observe only configured continuous reader or exemption teams (§4, §5.4) |

**Account permissions:** none.

> Deliberately **not** requesting *Email addresses: read*. `REQ-SEC-1` forbids
> collecting what the agreement does not require, and the signer types their
> email on the form. Prefilling is not worth the extra data.

**Events:** none.

---

## 2. `dracla-enforcer` — check side

The only App exposed to arbitrary pull request traffic, and the only one
installed on contributing repositories. **Must not be installed on canonical**
(§4); the reconciler asserts this on each run, because GitHub gives the adopting
org's admin control over installation scope and DraCLA cannot enforce it.

| Field | Value |
|---|---|
| Name | `dracla-enforcer` |
| Homepage | `https://dracla.cli.dev` |
| Callback URL | not used |
| Request user authorization (OAuth) | **No** |
| Webhook URL | `https://dracla.cli.dev/webhook/enforcer` |
| Webhook secret | generate; store in Worker Secrets, never in a repo (`REQ-SEC-4`) |
| Where can this be installed | Any account |

**Repository permissions**

| Permission | Access | Why |
|---|---|---|
| Checks | Read and write | Publish the check result (`REQ-CHECK-1`) |
| Contents | Read | List commits on contributing repos; read coverage shards |
| Pull requests | Read and **write** | Post and update the PR comment (`REQ-PORTAL-3`). Read alone cannot — this was a real gap in an earlier draft. |
| Metadata | Read | Mandatory |

**Organization permissions**

| Permission | Access | Why |
|---|---|---|
| Members | Read | Observe organization-wide enforcement-scope selectors (§4, §7) |

**Events to subscribe**

- `Pull request`
- `Merge group`
- `Check run` — for `check_run.rerequested` (`REQ-CHECK-5`)

> Subscriptions are per event **type**, not per action. DraCLA receives all 23
> `pull_request` actions and acts on 4; the rest are discarded on arrival and
> still cost a Worker request. That is the volume driver in §9.2's model.

---

## 3. `dracla-reconciler-trigger` — control side

Installed only on a project's control repository. It may dispatch and inspect
the one pinned reconciler workflow, but cannot read or modify repository
content, workflow files, secrets, or repository administration settings.

| Field | Value |
|---|---|
| Name | `dracla-reconciler-trigger` |
| Homepage | `https://dracla.cli.dev` |
| Callback URL | not used |
| Request user authorization (OAuth) | **No** |
| Webhook | **Disabled** — this App receives no events |
| Where can this be installed | Any account |

**Repository permissions**

| Permission | Access | Why |
|---|---|---|
| Actions | Read and write | Dispatch, rerun, cancel, or inspect the pinned control workflow |
| Metadata | Read | Mandatory repository identity access |

**Organization permissions:** none.
**Account permissions:** none.
**Events:** none.

> Deliberately no Contents, Administration, Workflows, or Secrets permission.
> The underlying Actions permission can affect run availability, so the control
> repository contains no second workflow and the credential's reach is included
> in the operational warning and rotation procedure.

---

## 4. Provisioning — no App

Provisioning is **not** a GitHub App. The conforming `dracla` CLI is not
implemented yet; HLD §6.10 specifies that it will run with the administrator's
own credentials using a concrete released version:

    uvx dracla@<version> install github.owner=<account>

A provisioning App would need org `administration`, `workflows`, and `secrets`
write. Retained `workflows: write` is a permanent code-execution channel into
an adopter's PII repository (DR-011), `administration: write` permits flipping
that repository to public, and an uninstall step that fails to fire leaves both.
Running provisioning as the administrator means DraCLA never holds those
permissions at all — see design D11.

When provisioning is implemented, its completion flow will print the App
installation links specified by HLD §6.10.3. GitHub owns the consent screen,
the repository picker, and the permission display.

## After creating each service App

1. Note the **App ID** and generate a **private key** (`.pem`). The key
   downloads once.
2. Store every key and webhook secret in **Cloudflare Worker Secrets**, in the
   isolate that needs it and no other (§9 splits these across two Workers:
   `worker-enforce` and `worker-portal`).
3. Never commit a key or secret to any repository — `REQ-SEC-4` prohibits it.
4. App IDs and per-project installation IDs go in the registry repository
   (§7), which is private and separate from the monorepo.

## Setup URLs

All three service Apps need a **Setup URL** so GitHub can redirect back after
installation. Any callback query parameters, including `installation_id`, are
untrusted:

    dracla-records             https://dracla.cli.dev/install/records/callback
    dracla-enforcer            https://dracla.cli.dev/install/enforcer/callback
    dracla-reconciler-trigger  https://dracla.cli.dev/install/reconciler-trigger/callback

The callback stores nothing and trusts no query parameter as an App binding. It
only directs the administrator to Connect; the authenticated Connect operation
independently lists and verifies all three installations before registry
publication (§6.10.3, §7).


## 5. Adopter-owned private transport App

This is the control reconciler's repository credential (HLD D19), separate
from the three service Apps above. The administrator creates or selects a
private GitHub App owned by the account containing the data repositories.
The reviewed design requires the following configuration; live acceptance of
the implementation remains an M3 gate, and automated setup remains M6 work.

| Setting | Required value |
|---|---|
| Repository permissions | Contents: read and write; implicit Metadata: read |
| Organization/account permissions | None |
| User authorization and webhooks | Disabled; no contributor interaction |
| Installation selection | Selected repositories: assigned records and coverage repos only |
| Excluded repositories | Every control repository and contributing source repository |
| Private key custody | Administrator transiently; Actions secrets in assigned control repositories |

Never store the transport key in Cloudflare, a service App's secret store,
Git content, logs, outputs or artifacts. A hosted DraCLA endpoint must not
receive it or an App-registration conversion response containing it. The
installer may prefill GitHub's creation flow; the account owner must confirm
creation and selected-repository installation. It cannot promise unattended
registration. The administrator's own credentials perform repository creation,
workflow installation and secret writes. Do not grant the transport App
Administration, Secrets, Workflows, Actions, Checks, Pull requests or Members
permissions to make those operations convenient.

### Dedicated or shared

A CLA arrangement is a DraCLA project with its own legal recipient, agreement,
records/coverage/control repositories and independent encryption/recovery keys.
It can enforce the same agreement across multiple code repositories. Hydra and
OmegaConf need separate arrangements only if their intended CLA arrangements
are separate; the number of code repositories does not decide this.

| Choice | Setup and maintenance | Credential exposure |
|---|---|---|
| Dedicated App per arrangement | More App registrations and rotations | A stolen key reaches that arrangement's selected data repositories |
| One App for several arrangements in the same owning account | Fewer registrations; coordinated rotation and suspension | A stolen key reaches every assigned arrangement's selected data repositories |

> Anyone who obtains this App private key can mint credentials for every
> arrangement assigned to it. They can read encrypted data and may rewrite,
> delete, roll back or replay it, affecting CLA checks. This key alone cannot
> decrypt CLA records or edit an excluded control repository.

Each key-bearing control job has that shared integrity reach even when its
normal token is limited to one arrangement. Separate private keys for the same
App do not isolate arrangements. Sharing an App never shares encryption keys,
canonical history, legal grants or acceptance evidence. Independent Apps provide
credential separation; each control job still holds its own project's data keys.

The installation planner emits this App integrity warning in its read-only
output, including shared-assignment reach, the decryption limitation and control
exclusion. `force` and a dry run do not remove the disclosure or grant authority.

Protected control configuration records exact App, installation and owner IDs
and the approved arrangement-to-repository-ID assignment. Before project keys
are accessed, verify the full grant and selected-repository union; unexpected
permissions, any extra/missing repo, an all-repositories selection, or access to
a control repo stops the job. Changes to a shared assignment require explicit
administrator action and updates to each affected protected configuration.
Routine data tokens are short lived and restricted to the current arrangement.
They are renewed from returned expiry and never persisted. Probe writes use
fixed non-private data on temporary branches, never the canonical events branch.
The protected job revokes its known inventory and data tokens on exit. A cleanup
failure fails the job. This is not proof that unknown tokens are inactive.

### Verified control execution

`control/reconcile.yml` is the private control repository's workflow template.
Copy it to `.github/workflows/reconcile.yml`. Protect that workflow, the control
configuration, the bootstrap image variable and the repository secrets from
contributing users and from the transport App. The baseline uses repository-
scoped Actions secrets, not a deployment environment, so a private repository
in a GitHub Free organization does not require a paid environment feature.
Review actions and bootstrap image updates before enabling secrets. No record,
coverage file or dispatch payload selects executable code.

Only trusted adopter administrators may write control. Set the organization
base permission to read (or none), grant write or admin access only through a
dedicated trusted-administrator team, and audit this repository's inherited
team grants and direct collaborator grants. Every account with control write
access is a trusted key-bearing-code administrator. Contributors and event
Apps have no control contents write access. The job admits only the
private repository's default-branch workflow and checks its exact workflow
identity before checkout; it then checks out `github.workflow_sha`. Manual
dispatch from another branch or tag, a foreign workflow, missing context or
malformed fixed inputs fails before the secret step. Private branch rules and
required environment approvals are not the authority on GitHub Free. Team or
Enterprise environment and branch protections may be added as optional
hardening, but the baseline does not depend on them.

Set `DRACLA_BOOTSTRAP_IMAGE` to the reviewed OCI image **digest**, not a tag.
The image is built by `.github/workflows/bootstrap-image.yml` using the pinned
base, Python, tool wheels, CLI archive and trusted-root snapshot in
`release/build-inputs.lock.json`. Review its published provenance before
installing that digest. The digest is an adopter-approved trust anchor; the
container cannot authenticate itself by printing its own version or digest.
No bootstrap tool or trust-root update occurs during a key-bearing job.
The image installs the bootstrap tool closure, including the pinned Snappy
decoder for GitHub's public attestation bundle URLs. Bundle downloads receive
no credentials and remain subject to signature and identity verification.
The wheel builder installs the build-tool closure and the exact runtime
dependencies needed by its packaging-test subprocesses. Its separate checked
production installation receives only the runtime closure and DraCLA wheel.
These sets use the same locked bytes where a wheel is shared.

Create the protected `control/production-profile.json` using
`control/production-profile.schema.json` and LLD §3.1. All identities are
required. Select the actual reviewed source commit, publisher and reusable
builder identities, release ref, exact wheel hash, both lock hashes, bootstrap
image digest and root snapshot hash. The supported profile is CPython 3.12.16,
CPython ABI `cp312`, Debian bookworm x86-64 (`manylinux_2_36_x86_64`). This is a
tested profile selection, not an automatic upgrade policy. Unsupported profiles,
mutable selectors, placeholders and unknown fields fail closed. Do not invent
pins from an example, a package version or an earlier successful workflow flag.

The release producer uses the same-commit reusable builder, downloads and hashes
the locked wheel inputs, then disables container networking before installing
tools and building. It assembles the M2 policy and version constraints from the
actual source context and runtime lock. It builds one wheel without isolation
or resolution, tests that installed wheel, and attests the exact subject with
standard SLSA v1 provenance. The publisher sends that same wheel to PyPI with
its standard publish attestation. Publication needs the separate protected
`pypi-release` environment and PyPI Trusted Publisher configuration. Adding the
workflow files does not publish a release or create a Trusted Publisher.

Before either App or wrapping secret is supplied, the external checker verifies
the live numeric source repository ID, exact wheel/dependency hashes, publisher,
source and reusable builder identities, witnessed log inclusion and the complete
declared build input set. It converts the public PyPI format to a standard
Sigstore bundle and verifies it with the pinned CLI and roots. A publish
attestation alone fails. The checker installs only those wheels offline with
hashes, no dependencies, no build and no resolver.

The key-bearing step re-verifies evidence and derives the installed file map
from the verified wheels and pinned pip's generated files. It rejects changed
or additional files, links and executable paths. It then starts isolated Python
with only that installed environment. The installed `RECORD` and a workflow
success flag cannot authorize different bytes. The environment and wheelhouse
stay in the same protected workspace; no workflow artifact transfers this trust.

The adopter's protected `control/control-binding.json` has exactly these fields:

| Field | Value |
|---|---|
| `control_version` | Integer `1` |
| `project` | Exact `project_id`, numeric `owner_id`, ordered `repositories` objects with `role`, `owner`, `name`, `id` for records, coverage and control |
| `installation` | Exact `app_id`, `client_id`, `installation_id`, `owner_id`, `assignments` and `excluded_repository_ids` |
| `assignments` entries | Objects containing `project_id` and the ordered pair `repository_ids` for records and coverage |
| `keyrings` | Immutable key-commit OID to base64-encoded protected control keyring; include the required historical copies |
| `export_request` | `null` for verify/reconcile; otherwise only the closed LLD §6.1 request |

Configure `DRACLA_TRANSPORT_APP_KEY` and `DRACLA_CONTROL_KEYS` as repository-
scoped Actions secrets in the private control repository. Do not place these
baseline secrets in a deployment environment. The first is the App PEM key.
The second is a JSON object mapping control wrapping generations to 64
lowercase hexadecimal characters. The job validates the complete App
installation before reading wrapping keys. This guide does not authorize an
installer to provision secrets or resources.

`verify` and `reconcile` call the existing M3 engines. The export engine still
requires M5's authenticated request and membership adapter. The template fails
closed for export until that adapter is integrated; it does not use a transport
token, administrator status or recovery access as reader authority. No export
plaintext goes to logs or workflow artifacts.

The template also runs reconciliation daily at 03:17 UTC as the missed-dispatch
backstop. Its explicit `probe` operation first verifies the App assignment, then
writes fixed non-private markers on unique `dracla-probe/` branches in the two
data repositories. It verifies whole-commit readback and removes each temporary
ref with GitHub's `updateRefs` exact-head precondition. A competing writer leaves
its branch intact and fails the probe. Lost acknowledgements use readback, not
blind replay. Canonical refs and live coverage are not probe destinations.
After cleanup, the probe runs the real authenticated verification engine and
revokes known credentials before emitting a non-private receipt. That receipt
binds repository/App/installation IDs, release policy, source commit and actual
protected control workflow identity. This capability challenge does not replace
the separately authorized A6 rotation and unknown-token incident exercises.

Use the [control recovery runbook](../control/README.md) for full-ref backup,
independent identity/ref preflight and the remaining hosted recovery gates.
The transport App cannot read or restore control on the operator's behalf.

Keep the last verified profile, image, wheel and locks for explicit rollback.
Verify the selected rollback artifacts with the same gate before releasing
keys. Never roll back or rewrite canonical events as part of package rollback.
Authentic DraCLA build/publish evidence and the least-privilege live transport,
CAS, expiry, rotation and unknown-token containment probes remain production
gates. Deterministic fixtures and a locally built image do not close them.

### Rotation and incident response

Stage and verify a successor key in every assigned control repository before
retiring a predecessor during routine rotation. App keys do not automatically
expire. During suspected key compromise, stop every affected arrangement's
routes. Remove the exposed key's minting ability and establish the last possible
issuance, including outstanding signed authentication requests. Permanently
invalidate every potentially issued token, or wait from that last possible
issuance through the maximum token lifetime plus the live-tested safety margin.
Temporary suspension alone does not prove invalidation after service resumes.
If those facts cannot be established, keep the routes closed. Revoking only known tokens is
insufficient when an attacker could have minted unknown ones. Do not resume
routes merely because a replacement key works. Verify scope, trusted backup
heads and authenticated replay; repair projections and recheck open pull
requests before restoring routes. HLD §8.1.2 and release probe A6 govern this
procedure. A compromised control job can also expose its data keys; apply the
separate decryption-key incident procedure when that capability was exposed.

Contributors do not install or authorize this transport App and do not accept
new App terms as a result of this choice. Existing portal login and explicit
CLA acceptance remain the contributor flow. Administrator installation approval
is separate from any contributor's legal acceptance.

GitHub references: [installation token scope and expiry](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app),
[private-key rotation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps),
and [credential revocation](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types).
