# dracla CLI

Provisioning for DraCLA maintainers. Runs on your machine with your own GitHub
credentials — DraCLA the service holds no provisioning privilege at any point
(design D11), which is why this is a CLI and not a hosted flow.

Design: [§6.10](../design/high-level-design.md). Rationale:
[FAQ](../docs/faq.md).

## Install a project

```
dracla install github.org=hydra-ecosystem
```

Hydra-style overrides, uniform with the rest of the CLI. `github.org` is the
only required value; `recipient.slug` defaults to it.

| Override | Effect |
|---|---|
| `github.org=ORG` | required — which organization gets the repositories |
| `recipient.slug=SLUG` | defaults to the org; needed only when one org holds pairs for more than one legal recipient (§5.5) |
| `dry_run=true` | report what would happen, write nothing |
| `force=true` | skip the confirmation prompt — **required** when stdin is not a terminal |
| `accept_org_read=true` | proceed despite an organization read default (see below) |

`--show-config` prints the resolved configuration without contacting GitHub.

## What it does, and deliberately does not

Creates `<slug>-cla-records` and `<slug>-cla-coverage`, both private and both
**empty** — `events` becomes the first ref that ever exists and is promoted to
default, so there is no `main` to demote or delete. It seeds the reconcile
workflow in that single genesis commit and initializes the coverage projection.

It does **not** write project configuration, publish an agreement, create a
deploy key, or register the project. Those are configured in the portal when you
connect, where each becomes an attributable event rather than a flag typed once
(§6.10.3).

Install therefore never produces a signable project. That is by design, and it
says so on exit.

## The organization gate

Install **blocks** if the organization grants members read on new repositories.
The records repository holds contributors' legal names and email addresses, and
nothing but its privacy protects them — DraCLA does not encrypt them, on the
basis that a private repository is itself the boundary.

**This cannot be fixed on the repository.** A base permission is a floor:
repository settings can raise a member's access, never lower it. There are no
negative permissions in GitHub, so every member keeps read access regardless of
what you set on the repository itself.

Three ways past it, in order of preference:

**Install into a dedicated organization.** Free, and the base permission there
governs only the people who administer the CLA. It also gives the reconciler its
own Actions allowance instead of consuming the project's.

You will probably need to create it — GitHub has no API for that, so:

```
# 1. create <org>-cla at https://github.com/organizations/plan  (Free is enough)
gh api -X PATCH /orgs/<org>-cla -f default_repository_permission=none
dracla install github.org=<org>-cla
```

**Who should be in it.** Everyone in that organization can read contributors'
legal names and email addresses. Membership should be the people who would
actually use that evidence if the agreement were ever tested — whoever the
agreement grants rights to, their counsel, and whoever administers agreement
versions — rather than the project's maintainers generally. Being a committer
is not a reason to see who signed and with what email address.

**Change the organization default**, if the organization is small enough that
everyone in it should see signer data anyway:

```
gh api -X PATCH /orgs/YOUR-ORG -f default_repository_permission=none
```

**Accept it.** `accept_org_read=true` records that you accept organization-wide
read access to signer names and email addresses. It is an acceptance, not a
mitigation — there is nothing further to restrict afterwards.

## Credentials

`GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token`.

## Tests

The CLI needs `hydra-core`; `core` does not and must keep running without it.

```
python3 -m unittest discover -s core/tests -t .          # stdlib only
PYTHONPATH=cli:core <python-with-hydra> -m unittest discover -s cli/tests -t .
```

No network: `cli/tests/fake.py` fakes the administration surface, and the
records host is core's own `FakeGitHost` — the one whose fidelity was verified
against the live API — rather than a second implementation that could drift.
