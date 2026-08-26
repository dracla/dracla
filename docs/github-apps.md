# GitHub App configuration (phase 0)

Three Apps, created in the `dracla` organization at
`https://github.com/organizations/dracla/settings/apps/new`.

The data Apps are separate because a single App holding both records and
enforcer permissions defeats the capability split — an attacker with one
credential simply uses the other. The third App can only dispatch the pinned
control workflow; it is not a provisioning principal (design D3, D11, D16).
Provisioning is not an App at all (§4 below).

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

## After creating each App

1. Note the **App ID** and generate a **private key** (`.pem`). The key
   downloads once.
2. Store every key and webhook secret in **Cloudflare Worker Secrets**, in the
   isolate that needs it and no other (§9 splits these across two Workers:
   `worker-enforce` and `worker-portal`).
3. Never commit a key or secret to any repository — `REQ-SEC-4` prohibits it.
4. App IDs and per-project installation IDs go in the registry repository
   (§7), which is private and separate from the monorepo.

## Setup URLs

All three Apps need a **Setup URL** so GitHub can redirect back after
installation. Any callback query parameters, including `installation_id`, are
untrusted:

    dracla-records             https://dracla.cli.dev/install/records/callback
    dracla-enforcer            https://dracla.cli.dev/install/enforcer/callback
    dracla-reconciler-trigger  https://dracla.cli.dev/install/reconciler-trigger/callback

The callback stores nothing and trusts no query parameter as an App binding. It
only directs the administrator to Connect; the authenticated Connect operation
independently lists and verifies all three installations before registry
publication (§6.10.3, §7).
