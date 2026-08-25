# GitHub App capability inventory

This is an implementation inventory, not a claim that the Apps are deployed.
The source of truth is `design/high-level-design.md` §4 and §9.

## `dracla-records`

- OAuth for contributor and records-reader authentication.
- `contents: write` on the project's records and coverage repositories.
- Organization `members: read` only where a configured continuous rule needs
  it.
- No installation on contributing repositories and no pull-request webhooks.
- Hosted deployments hold capability-separated records and coverage wrapping
  roots and never return raw keys to browsers.

## `dracla-enforcer`

- Subscribes to `pull_request`, `merge_group`, and the event-wide `check_run`
  webhook. Checks-write Apps are automatically subscribed, so the Worker
  receives created and completed runs from other Apps as well as DraCLA's
  `rerequested` action. It rejects other-App, ordinary, malformed, and unknown
  external-ID namespaces before any routing-gate RPC; only an exact DraCLA
  authoritative completion may confirm a publication reservation.
- `checks: write`, `pull_requests: write`, and `contents: read` on contributing
  repositories; `contents: read` on coverage only.
- Holds only the coverage wrapping root and cannot unwrap records keys.
- Must not be installed on the records repository.

## `dracla-reconciler-trigger`

- `actions: write` on the project's control repository only.
- Can dispatch and inspect the single pinned reconciler workflow.
- Has no contents, administration, workflow-file, secrets, records, or coverage
  permission.

## Provisioning

Provisioning is not a GitHub App. A future exact-version `dracla` CLI uses the
administrator's own credentials to create three private repositories and then
prints links for all three Apps. The Setup URL callback persists nothing;
Connect independently authenticates the administrator and verifies current App
installations and repository authority.

No App keys, webhook secrets, wrapping roots, or project keys belong in this
repository.
