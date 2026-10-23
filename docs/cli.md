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
and digest bindings and the complete active runtime dependency closure, then
fetches the declared exact-version public HTTPS artifact manifest. The manifest
must be canonical JSON with the exact policy/source/workflow/constraint bindings
and a sorted unique list of DraCLA distribution filenames and digests.
The fetch has bounded bytes, time, retries and same-origin HTTPS redirects. It
uses no credentials, cookies, disk cache or local output.

The manifest digest identifies the declared final artifact list. It does not
identify which artifact a parent `uvx` used and does not independently prove
that a compromised executing package is authentic. M3 owns final production
publication. Current development wheels intentionally contain no fabricated
release policy: they report unavailable release evidence and exit 2 before
credentials. Positive release fixtures exist only in the test suite.

`m2/1` prints deterministic intended names and initial steps when given valid
release evidence through the test boundary. It reports live discovery as an
unavailable prerequisite; it does not infer account IDs, permissions or safe
repository reuse from names. `m2/2` adds the actual read adapter.

A dry run performs no application writes or confirmations. Hydra uses scoped
composition without a run directory, logging setup or working-directory change.
No local progress journal or credential store is created. `force=true` never
clears a blocker or enables missing installation engines. Non-dry M2 execution
always exits 2 before mutations.

Exit codes: 0 is help or a complete collision-free read-only plan; 2 is rejected
input, unavailable/invalid release evidence or a blocked plan; 1 is an unexpected
internal failure with a fixed redacted diagnostic. A successful plan never means
installed, connected, signable or routable.

Validation: `.venv/bin/python -m unittest core.tests.test_cli_planning -v` covers
configuration, release validation, dependency closure, deterministic planning,
redaction, scoped no-write behavior and console/module invocation from a wheel
installed outside the checkout. `conformance/gate.py` retains the complete M1
Python/TypeScript, shared-vector and installed-conformance gate.
