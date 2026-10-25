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

Protected control configuration records exact App, installation and owner IDs
and the approved arrangement-to-repository-ID assignment. Before project keys
are accessed, verify the full grant and selected-repository union; unexpected
permissions, any extra/missing repo, an all-repositories selection, or access to
a control repo stops the job. Changes to a shared assignment require explicit
administrator action and updates to each affected protected configuration.
Routine data tokens are short lived and restricted to the current arrangement.
They are renewed from returned expiry and never persisted. Probe writes use
fixed non-private data on temporary branches, never the canonical events branch.

### Rotation and incident response

Stage and verify a successor key in every assigned control repository before
retiring a predecessor during routine rotation. App keys do not automatically
expire. During suspected key compromise, stop every affected arrangement's
routes. Remove the exposed key's minting ability and invalidate all potentially
issued tokens, or wait through their maximum lifetime after verified revocation,
including the live-tested safety margin. Revoking only known tokens is
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
