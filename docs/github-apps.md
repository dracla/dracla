# GitHub App configuration (phase 0)

Two Apps, created in the `dracla` organization at
`https://github.com/organizations/dracla/settings/apps/new`.

They are separate because a single App holding both the records and enforcer
permissions defeats the point of the two-repo split — an attacker with one
credential simply uses the other (design §4, D3). Provisioning is not an App at
all (§3 below).

Origin: **`dracla.yadan.net`**. Design §9 requires the shell and API share one
origin, so the portal and the Worker routes are the same host — that is what
avoids `SameSite=None` and a reflected-CORS policy (DR-009).

`cli.dev` is assigned but its transfer is pending and may take months. Do not
plan around it: callback and Setup URLs are editable in App settings at any
time and apply to every existing installation instantly, with no adopter
action. If the move happens after adopters exist, keep a permanent redirect on
`dracla.yadan.net` — one DNS record and one route rule.

Emit portal links in exactly one canonical form everywhere —
`https://dracla.yadan.net/p/<slug>` — in badges, check output, and pull request
comments. A future redirect is then one rule rather than a pattern-matching
exercise.

---

## 1. `dracla-records` — portal side

Signs, revokes, and authorizes the dashboard. Never sees a contributing repo.

| Field | Value |
|---|---|
| Name | `dracla-records` |
| Homepage | `https://dracla.yadan.net` |
| Callback URL | `https://dracla.yadan.net/auth/callback` |
| Request user authorization (OAuth) during installation | **No** — users authorize at signing time, not install time |
| Expire user authorization tokens | **Yes** |
| Webhook | **Disabled** — this App receives no events |
| Where can this be installed | Any account |

**Repository permissions**

| Permission | Access | Why |
|---|---|---|
| Contents | Read and write | Append events to canonical; materialize coverage (§5.2, §5.4) |
| Metadata | Read | Mandatory; also backs the `REQ-SEC-6` dashboard check via `GET /repos/{owner}/{repo}` with a user-to-server token |

**Organization permissions:** none.
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
| Homepage | `https://dracla.yadan.net` |
| Callback URL | not used |
| Request user authorization (OAuth) | **No** |
| Webhook URL | `https://dracla.yadan.net/webhook/enforcer` |
| Webhook secret | generate; store in Worker Secrets, never in a repo (`REQ-SEC-4`) |
| Where can this be installed | Any account |

**Repository permissions**

| Permission | Access | Why |
|---|---|---|
| Checks | Read and write | Publish the check result (`REQ-CHECK-1`) |
| Contents | Read | List commits on contributing repos; read coverage shards |
| Pull requests | Read and **write** | Post and update the PR comment (`REQ-PORTAL-3`). Read alone cannot — this was a real gap in an earlier draft. |
| Metadata | Read | Mandatory |

**Organization permissions:** none.

**Events to subscribe**

- `Pull request`
- `Merge group`
- `Check run` — for `check_run.rerequested` (`REQ-CHECK-5`)

> Subscriptions are per event **type**, not per action. DraCLA receives all 23
> `pull_request` actions and acts on 4; the rest are discarded on arrival and
> still cost a Worker request. That is the volume driver in §9.2's model.

---

## 3. Provisioning — no App

Provisioning is **not** a GitHub App. It runs in the `dracla` CLI with the
administrator's own credentials:

    uvx dracla install

A provisioning App would need org `administration`, `workflows`, and `secrets`
write. Retained `workflows: write` is a permanent code-execution channel into
an adopter's PII repository (DR-011), `administration: write` permits flipping
that repository to public, and an uninstall step that fails to fire leaves both.
Running provisioning as the administrator means DraCLA never holds those
permissions at all — see design D11.

After provisioning, the CLI prints the two installation links above. GitHub owns
the consent screen, the repository picker, and the permission display.

## After creating each App

1. Note the **App ID** and generate a **private key** (`.pem`). The key
   downloads once.
2. Store every key and webhook secret in **Cloudflare Worker Secrets**, in the
   isolate that needs it and no other (§9 splits these across three Workers:
   `worker-enforce`, `worker-portal`, `worker-admin`).
3. Never commit a key or secret to any repository — `REQ-SEC-4` prohibits it.
4. App IDs and per-project installation IDs go in the registry repository
   (§7), which is private and separate from the monorepo.

## Setup URLs

Both Apps need a **Setup URL** so GitHub can redirect back after installation
with `installation_id` and the signed `state`:

    dracla-records   https://dracla.yadan.net/install/records/callback
    dracla-enforcer  https://dracla.yadan.net/install/enforcer/callback

That redirect is how the registry learns each installation id (§7).
