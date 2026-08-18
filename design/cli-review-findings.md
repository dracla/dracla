# CLI review findings — input to the install design

Status: input, not a work list
Date: 18 August 2026

A six-pass deep review of the first `cli/dracla_cli/` implementation found 28
defects in 522 lines. That code has been removed rather than patched, because
patching it would have preserved its central problem: it was written with no
design, so several "defects" were really decisions nobody had made.

This file exists so the rebuild starts informed. **Read it as a list of
questions the install design must answer**, not as a list of bugs to fix. Four
of them are design decisions; the rest are the kind of mistake that follows from
not having made those decisions.

## The four that are decisions, not bugs

**Branch layout.** Design §5.1 shows one canonical tree holding `config/`,
`agreements/`, `events/` and `.github/workflows/`. The implementation put config
on the default branch and events on `events`, and the workflow checked out
`events` — so the reconciler could not see the config it needed to validate
against. Neither arrangement was wrong; no arrangement had been chosen.

A constraint neither the design nor the code accounted for: GitHub reads a
`push:` workflow from the branch being pushed, but runs `schedule:` workflows
only from the **default** branch. A reconciler that must fire on both can live
on one branch only if that branch is the default. The design must state which
branch is default and what lives where.

**Deploy-key lifecycle.** §9 says install seeds the coverage deploy key. Nothing
specifies who generates the keypair, where the private half is stored, how it is
rotated, or what happens on re-install. The implementation defined
`add_deploy_key` and never called it, and seeded a workflow that read a secret
nobody created.

**What install guarantees on exit.** The implementation exited 0 and printed a
portal URL after an install with no agreement published — a project nobody can
sign. The design must say what a successful install means, and what a partial
one leaves behind.

**Whether the organization-permission check blocks.** `REQ-SEC-2` exempts DraCLA
from encrypting signer fields *on the basis that* the private records repository
is a sufficient access boundary. When an organization grants members read by
default that basis is false. The implementation detected this correctly, warned,
and proceeded anyway. Blocking versus warning is a product decision with a real
adoption cost, and it was made by omission.

## The rest, grouped by what they teach

**Seams, not units (the four blocking findings were all here).** Every module
was individually plausible and the seams between them were never exercised. The
workflow template passed five tests while invoking a subcommand that did not
exist. Any rebuild should assert that every command a generated artifact invokes
is registered, and that dry-run issues no writes — properties that span modules.

**Assuming instead of reading.** `main` was hardcoded as the default branch;
`auto_init` names it from the *owner's* setting, so an organization defaulting to
`master` would have got a second, divorced branch. Repository visibility was
requested but never read back, though organization policy can override it.

**Reporting what did not happen.** `--dry-run` printed repositories as
`created`. The one output whose entire purpose is to be trustworthy was wrong.

**Interface.** `--version` meant the tool version at top level and the
*agreement* version under `install` — the second being the legally significant
one. `config show` demanded the records repository name, leaking a naming
convention users should never need to know.

**Docs drifting from code within the hour.** The README said the CLI did not
exist; the design listed seven subcommands of which two were built; §9 described
an install that seeds a deploy key it did not seed.

**Layering.** Two modules mutated `sys.path` at import time to reach `core`, and
six call sites reached through `GitHubHost` into its private `_req` because the
GitHost protocol models append-only records and says nothing about creating
repositories or reading organization settings. The rebuild needs an explicit
administration surface.

## Full finding list

Kept for reference. Severity reflects the original review.

## A1 — install seeds a workflow that cannot run (HIGH, architecture/correctness)
Ref: cli/dracla_cli/seed.py:79-81, cli/dracla_cli/main.py:81-84
The seeded workflow runs `dracla reconcile --coverage-key-file ...` and reads
secret DRACLA_COVERAGE_DEPLOY_KEY. Neither exists:
  - no `reconcile` subcommand is registered in main.py:106-135
  - add_deploy_key (seed.py:140) is defined but never called from cmd_install
  - the Actions secret is never created
Impact: install reports success; the workflow fails on its first push to
`events`, i.e. on the first signature. The projection never materializes.
Contract: design 9 says install seeds the coverage deploy key.
Follow-up: either wire key generation + add_deploy_key + secret creation into
cmd_install, or stop seeding the workflow until M2 lands and say so.

## A2 — dependency direction is inverted via sys.path (MEDIUM, architecture)
Ref: cli/dracla_cli/provision.py:19, cli/dracla_cli/seed.py:16
Modules mutate sys.path at import time to reach `core`. pyproject.toml:39
already declares both packages in one wheel, so the installed artifact imports
`dracla` normally; the insertion only serves the source tree.
Impact: import-time side effect, order-dependent; masks a real packaging error
until someone runs from an installed wheel. Two modules do it, main.py does not
(it imports dracla lazily at main.py:99).
Follow-up: drop the insertions; make tests set PYTHONPATH (they already do it
themselves at cli/tests/test_cli.py:14-16).

## A3 — CLI reaches through the core public API into _req (MEDIUM, architecture)
Ref: provision.py:50,67,76,82,111 and seed.py:152
Six call sites use GitHubHost._req directly. GitHubHost's public surface is the
GitHost protocol (head/read/exists/commit/update_ref/put); repo and org
administration is not modelled at all.
Impact: the CLI depends on a private method's signature and error contract. The
retry/timeout policy added for the protocol layer silently applies to admin
calls too, which may not be desired for POST /orgs/{org}/repos.
Follow-up: give core a small admin client, or move these calls into the CLI with
their own thin transport.

## A4 — Provisioner constructs GitHubHost(repo="") (LOW, architecture)
Ref: provision.py:43
A repo-scoped type used with an empty repo, then only via _req with absolute
paths. The type says something untrue about the object.
Follow-up: falls out of A3.

## B1 — missing --agreement file crashes with a traceback, after repo creation (HIGH, correctness/UX)
Ref: cli/dracla_cli/main.py:86-88
`open(args.agreement)` is unguarded. Verified: exit 1 with a raw
FileNotFoundError traceback, printed *after* "created dracla/...-cla-records".
Impact: on a real (non dry-run) install the two repositories are already
created and seeded when the crash happens, so the user sees a stack trace
following apparently successful output. The file is read late for no reason.
Follow-up: read and validate the agreement *before* any provisioning, and raise
CliError with a hint. Validating inputs before side effects is the general rule
this violates.

## B2 — "main" is hardcoded as the default branch (MEDIUM, correctness)
Ref: cli/dracla_cli/seed.py:95,104 and main.py:101
Newly created repos get `main` via auto_init, so the create path is fine. The
reuse path is not: install is documented as idempotent and re-runnable (R5), and
an existing records repo whose default branch is not `main` fails — read 404s,
then the write targets a branch that does not exist.
Follow-up: read the repo's default_branch once and thread it through, or pin the
records repo to `main` explicitly at creation and assert it on reuse.

## B3 — dry-run reports repositories as "created" that were not (MEDIUM, correctness)
Ref: cli/dracla_cli/provision.py:96-97,119-138; verified against a slug whose
repos do not exist.
Output is `created dracla/probe2-cla-records, ...` with no dry-run marker,
while the seeding lines below it are correctly suffixed "(dry-run)".
Impact: the most consequential line in the output is the one that does not say
it is hypothetical.
Follow-up: mark the created list in dry-run, as the seed lines already do.

## B4 — _token() is invoked once per collaborator, up to 3x per command (LOW)
Ref: main.py:70,81,100
Each call may spawn `gh auth token`. Impact is latency and needless subprocesses.
Follow-up: resolve once in main() and pass it down.

## B5 — redundant API calls in the provision path (LOW, efficiency)
Ref: provision.py:74-83,87-97,119-135 and 141-163
repo_exists is called for each repo in preflight, again in provision, and a
third time inside create_repo; owner_kind is called by base_permission and again
by create_repo. Roughly 8 avoidable round trips per install.
Follow-up: cache owner_kind on the Provisioner and have provision() reuse the
existence probe it already performed.

## C1 — `--version` means two different things (MEDIUM, interface)
Ref: main.py:110 (tool version) vs main.py:125 (agreement version)
`dracla --version` prints the tool version; `dracla install --version v2` sets
the AGREEMENT version. Same spelling, unrelated meanings, and the second is the
legally significant one.
Impact: a user reasonably types `dracla install --version` expecting tool info
and silently sets an agreement version.
Follow-up: rename to `--agreement-version`.

## C2 — install without --agreement leaves an unusable project (MEDIUM)
Ref: main.py:86-90
--agreement is optional; without it the project has config, a workflow, and an
events branch, but no agreement to sign. The message says "skipped", which reads
like an option rather than a missing prerequisite. The command still exits 0 and
prints the portal URL as if the project were ready.
Follow-up: either require --agreement, or downgrade the closing "your project
page will be ..." to say the project is not yet signable.

## C3 — `config show` asks for the repo name, not the project (LOW, interface)
Ref: main.py:132
Users think in owner+slug; every other command takes those. Requiring
`--records owner/slug-cla-records` leaks the naming convention into the UI.
Follow-up: accept --owner/--slug and derive, keeping --records as an override.

## C4 — no confirmation before creating two repositories (LOW, interface)
Ref: main.py:75
A non-dry-run install creates two repos and pushes commits with no prompt.
--dry-run exists but is opt-in.
Follow-up: prompt unless --yes, or state clearly in --help that install is
immediate.

## C5 — warning formatting (LOW, ergonomics)
Ref: main.py:73
Warnings print with a two-space prefix and a trailing blank line to stderr,
while the finding text itself is already indented, producing ragged output.

## D1 — provision.py has zero test coverage (HIGH, tests)
Ref: cli/tests/test_cli.py:14-19 imports config, errors, main, seed. Never
provision. 164 lines untested, including the only code that creates real
repositories.
Impact: B3 (dry-run mislabelling) and B5 (redundant calls) would both have been
caught by a fake-transport test. The org-permission check of C4/DR-033 — the one
guarding REQ-SEC-2's access boundary — has no test asserting it fires.
Follow-up: a fake transport like core's FakeGitHost, then test create-vs-reuse,
public-repo refusal, dry-run truthfulness, and preflight warning emission.

## D2 — Seeder behaviour is untested; only its template string is (HIGH, tests)
Ref: test_cli.py:106-141 asserts properties of RECONCILE_WORKFLOW as text.
Nothing exercises _put, seed_config, ensure_events_branch, or add_deploy_key.
Impact: the created/updated/skipped logic, the orphan-branch creation, and the
"main" assumption (B2) are all unverified. A1 — a workflow calling a subcommand
that does not exist — is exactly the class of defect an integration test catches.
Follow-up: run Seeder against a fake host; assert the events branch is created
parentless, and that re-seeding identical content reports "skipped".

## D3 — cmd_install is never invoked by a test (MEDIUM, tests)
Ref: test_cli.py:143-163 tests build_parser and _install_links only.
Impact: the ordering defect in B1 — the agreement file being read after
provisioning — lives entirely in cmd_install and is invisible to the suite.
Follow-up: test the command function with injected Provisioner/Seeder doubles.

## D4 — no test asserts the seeded workflow's command actually exists (MEDIUM, tests)
Ref: seed.py:79 invokes `dracla reconcile`; main.py registers no such command.
Follow-up: assert every command the generated workflow invokes is present in
build_parser(). Cheap, and it would have failed A1 immediately.

## E1 — the CLI is absent from the README's inventory (MEDIUM, docs)
Ref: README.md "What exists" table lists design/, core/, api/bench/. cli/ is
missing, and "What does not exist" still says "the CLI".
Impact: the README is the front page of a now-public repository and understates
what shipped. A reader cannot discover `dracla install` from it.
Follow-up: add cli/ to the table and remove it from the not-yet list.

## E2 — no operator documentation for the CLI at all (MEDIUM, docs)
Ref: docs/ contains github-apps.md and roadmap.md; nothing documents installing
or running dracla. The only usage text is argparse --help and design 6.9, which
describes six commands that do not exist (C3).
Impact: an adopter following the design will try commands that fail.
Follow-up: a docs/cli.md covering the real surface, with the uvx invocation, the
required arguments and why each is required (recipient, privacy policy,
retention), and what to do after install.

## E3 — idempotency is claimed in a docstring, not demonstrated (LOW, docs/tests)
Ref: provision.py:5-8 and roadmap R5 both assert re-runnability. No test asserts
it (D1), and B2 identifies a reuse path that breaks it.
Follow-up: prove it with a test rather than asserting it in prose.

## E4 — failure leaves no recovery guidance in the output (MEDIUM, operability)
Ref: main.py:138-148 prints "error: {msg}" plus an optional hint.
Impact: a mid-install failure — after repos exist, before seeding — tells the
user what failed but not what state the org is now in, nor that re-running is
safe. B1 shows a raw traceback in exactly that window.
Follow-up: on failure, print what was created and that re-running resumes.

## E5 — no docs for running the CLI from source (LOW, docs)
Ref: cli/ has no README; core/README.md documents core only.
Tests set PYTHONPATH themselves; a contributor has to read the test file to
learn how to invoke the CLI before it is installed.
Follow-up: one usage block in README or cli/README.md.

## F1 — the DR-033 org-permission warning does not block (HIGH, security)
Ref: provision.py:149-158, main.py:72-73
The check exists and fires correctly (verified: it fired on the real `dracla`
org, which grants members 'read'). But it is printed and then install proceeds
to create the repos and write config anyway.
REQ-SEC-2 exempts DraCLA from encrypting signer fields ON THE BASIS THAT the
private repository is a sufficient access boundary. When the org default is
read, that basis does not hold, and install nonetheless produces a records repo
every org member can read.
Impact: the design's central privacy assumption is silently false for a large
class of orgs — the exact class the check was written to detect.
Follow-up: make a non-'none' base permission fail unless --i-accept-org-read is
passed, or have install restrict the two repos explicitly after creating them
(design section 9 says "restrict both to the intended readers explicitly",
which is not implemented).

## F2 — install never verifies the created repos are private (MEDIUM, security)
Ref: provision.py:87-117
repo_is_private is only consulted for repos that ALREADY exist. After creating
with "private": True, nothing re-reads to confirm. Org policy can override
creation settings.
Follow-up: read back and assert private after creation; fail loudly otherwise.

## F3 — _token() is invoked three times per install (LOW, security)
Ref: main.py:70, 81, 100
Each call may shell out to `gh auth token`, so the token crosses a process
boundary up to three times per run and appears in three subprocess buffers.
Follow-up: resolve once and pass it down.

## F4 — GitHub error bodies are surfaced to the user unfiltered (LOW, security)
Ref: github.py:44 (body[:300]) -> provision.py:114 -> main.py:143
Error text from the API is printed verbatim. GitHub does not echo credentials in
error bodies, so this is low, but the CLI has no scrubbing layer and the same
path will later carry richer responses.
Follow-up: keep bodies out of user-facing text, or allowlist fields.

## F5 — repo descriptions embed the slug into public-ish metadata (INFO)
Ref: provision.py:125-128
Descriptions say "Contains signer data" and name the project. Repos are private,
so this is not exposure today; worth remembering if visibility ever changes.
