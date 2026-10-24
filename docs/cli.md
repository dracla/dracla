# CLI and administration

M2 provides planning and independently tested administration seams. It does
not install a project. The reconciler, hosted challenge service and complete
installer arrive in M3, M5 and M6.

The registered command is:

```sh
dracla install github.owner=Acme dry_run=true
python -m dracla.cli install github.owner=Acme project.slug=Example dry_run=true
```

Both entrypoints call the same dispatcher. `--help` lists the supported input.
`verify`, `reconcile`, `export` and rotation commands are not registered.
Only `github.owner`, `project.slug`, `dry_run` and `force` overrides are accepted.
The booleans accept `true` or `false` and default to `false`. An owner is required.
The slug defaults to the ASCII case-folded owner and follows the revision-14
project grammar. Input is not trimmed, and a `-cla` suffix is retained:
`Acme-CLA` produces `acme-cla-cla-records`, `acme-cla-cla-coverage` and
`acme-cla-cla-control`. Configuration cannot load external paths, execute
resolvers, read environment secrets or instantiate Python objects.

Configuration validation runs before release preflight. Release preflight runs
before credential acquisition. It reads the installed package's canonical
`release-policy.json` and `dependency-constraints.txt`, validates their version
and digest bindings and the complete active runtime dependency closure. The
closed policy has exactly five fields: `release_policy_version`,
`package_version`, `source_commit_oid`, `provenance_identity`, and
`dependency_constraints_sha256`. Each packaged read is limited to 1 MiB, with
one extra byte read to detect oversize input. Preflight performs no network
requests and has no external release-manifest requirement.

The displayed package/source/workflow, policy and constraint identities are
release declarations. Their local consistency does not authenticate a publisher
or identify the artifact selected by a parent `uvx`. One-time execution keeps
the normal package-distribution trust boundary; verification with existing
tools before execution is optional. M3 owns production publication and the
mandatory verification of exact artifacts, executable dependencies, reviewed
source and build inputs before execution and project-key access.
Current development wheels intentionally contain no fabricated
release policy: they report unavailable release evidence and exit 2 before
credentials. Positive release fixtures exist only in the test suite.

After successful release preflight, `m2/2` obtains `GH_TOKEN`, falling back to
`GITHUB_TOKEN`, through the credential provider. The token stays outside Hydra
and plan objects. One adapter reads the account, authenticated actor, exact
three repository names and a bounded repository inventory. It binds numeric
owner/repository IDs, privacy and explicit repository permissions. The report
prints the actual owner ID and observed repository IDs; absent repositories
have unassigned IDs. Plans contain no credential or private recovery material.

A bare 404 means missing or inaccessible. It does not prove that a name is
available. The initial complete-visibility proof supports classic `repo` scope
with an authenticated personal owner or active organization administrator,
matching account identity and public/owned-private repository counts, and a
complete unrestricted inventory whose counts match. Missing count, permission,
scope or SSO evidence stays unknown. A fine-grained token's visible subset
alone cannot prove absence. The CLI does not ask for broader permissions
automatically. GitHub may withhold private account counts without `read:user`
or private organization details without `admin:org`; this yields an unknown
plan rather than a claim of absence. Existing repository names always block on the unavailable
provenance verifier, even when private and administrable. `force` cannot enable
reuse, clear uncertainty or repair a collision.

The adapter pins GitHub REST API `2022-11-28` at the fixed HTTPS API origin.
It uses standard-library HTTP, refuses redirects and bounds each body at 1 MiB.
Each read has a 10-second timeout and at most four attempts with bounded backoff.
Long rate limits return a typed retry time rather than sleep indefinitely.
Discovery allows ten pages of up to 100 repositories by default; its library
caller can select a budget of 1–100 pages. Repeated/inconsistent pages,
unexpected next links, missing permissions, identity drift and incomplete reads
produce blocked plans. All adapter requests in this slice are GET requests.
The [GitHub version contract](https://docs.github.com/en/rest/about-the-rest-api/api-versions),
[repository endpoints](https://docs.github.com/en/rest/repos/repos),
[organization membership endpoint](https://docs.github.com/en/rest/orgs/members)
and [scope definitions](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
govern the tested mappings. Scope declarations alone never grant user authority.

The ordered plan keeps later execution steps visibly blocked under their owning
M3/M5/M6 engines. A ready read-only plan means current discovery found no
collision; it does not mark any provisioning, key or bootstrap step complete.

A dry run performs no application writes or confirmations. Hydra uses scoped
composition without a run directory, logging setup or working-directory change.
No local progress journal or credential store is created. `force=true` never
clears a blocker or enables missing installation engines. Non-dry M2 execution
always exits 2 before mutations.

Exit codes: 0 is help or a complete collision-free read-only plan; 2 is rejected
input, unavailable/invalid release evidence or a blocked plan; 1 is an unexpected
internal failure with a fixed redacted diagnostic. A successful plan never means
installed, connected, signable or routable.

Validation: `.venv/bin/python -m unittest core.tests.test_admin_discovery core.tests.test_cli_planning -v` covers
configuration, release validation, dependency closure, deterministic planning,
redaction, bounded concrete discovery, concealed names, collisions, scoped
no-write behavior and console/module invocation from a wheel installed outside
the checkout. Its temporary release fixture also runs the actual installed
read adapter through the dispatcher with an isolated HTTP sender.
`conformance/gate.py` retains the complete M1
Python/TypeScript, shared-vector and installed-conformance gate.
