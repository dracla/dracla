# dracla CLI

Provisioning for DraCLA maintainers. Runs on your machine with your own GitHub
credentials — DraCLA the service holds no provisioning privilege at any point
(design D11), which is why this is a CLI and not a hosted flow.

Design: [§6.10](../design/high-level-design.md). Rationale:
[FAQ](../docs/faq.md).

## Install a project

```
dracla install github.org=hydra-ecosystem-cla
  ->  hydra-ecosystem-cla/hydra-ecosystem-cla-records
      hydra-ecosystem-cla/hydra-ecosystem-cla-coverage
```

Hydra-style overrides, uniform with the rest of the CLI. `github.org` is the
only required value, and it names the organization **dedicated** to CLA records
(see below) — not the one holding the project's code.

| Override | Effect |
|---|---|
| `github.org=ORG` | required — the dedicated organization the repositories go in |
| `recipient.slug=SLUG` | defaults to the org with a trailing `-cla` removed (case-insensitively, as GitHub logins are), since that organization is conventionally `<project>-cla` and the recipient is `<project>`. Needed only when one org holds pairs for more than one legal recipient (§5.5) |
| `dry_run=true` | report what would happen, write nothing |
| `force=true` | skip the confirmation prompt — **required** when stdin is not a terminal |

`--show-config` prints the resolved configuration without contacting GitHub.

## What it does, and deliberately does not

Creates `<slug>-cla-records` and `<slug>-cla-coverage` in that organization,
both private and both
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

Two ways past it, in order of preference:

**Install into a dedicated organization.** Free, and the base permission there
governs only the people who administer the CLA. It also gives the reconciler its
own Actions allowance instead of consuming the project's.

You will probably need to create it — GitHub has no API for that, so:

```
# 1. create <org>-cla at https://github.com/organizations/plan  (Free is enough)
gh api -X PATCH /orgs/<org>-cla -f default_repository_permission=none
dracla install github.org=<org>-cla
```

**Who should own it.** With the base permission at `none`, it is *ownership*
that carries access: that setting governs what members get by default, while
owners hold admin on every repository in the organization and it cannot be
lowered. So the owner set should be the people who would actually use that
evidence if the agreement were ever tested — whoever the agreement grants rights
to, their counsel, and whoever administers agreement versions — rather than the
project's maintainers generally. Being a committer is not a reason to see who
signed and with what email address.

**If more people need to read it than should own the organization**, give a team
read on the records repository. Adding owners hands them administrative control
of the whole organization, and raising the base permission re-opens what the
gate above exists to close; a team grants the access and nothing else:

```
gh api -X PUT /orgs/<org>/teams/<team>/repos/<org>/<slug>-cla-records \
  -f permission=pull
```

`dracla install` does not create it. Who should read signer data is not a
provisioning decision.

**Change the organization default**, if the organization is small enough that
everyone in it should see signer data anyway:

```
gh api -X PATCH /orgs/YOUR-ORG -f default_repository_permission=none
```

There is deliberately **no override flag**. In an organization created for CLA
records there is no legitimate reason to decline, and an override would mostly
serve to install into the wrong organization by accident.

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
