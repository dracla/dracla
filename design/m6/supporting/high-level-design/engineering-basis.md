# M6 architecture engineering basis

Supporting evidence for the [architecture](../../high-level-design.md), not a
second specification or an implementation claim. Inspection used Sapling head
`ec45c63ad01c197330702bbaefb2c5935333e688`. Completed M1/M3 source and plan bytes
remain unchanged. The pre-correction requirements' general/DBB round3 reports
and ten-node authority closure remain historical evidence. The exact-copy
correction requires current affected review and dependency closure; those
earlier stamps do not approve changed bytes.

## Existing primitives and real gaps

| Source | Existing reuse | Missing owned integration |
|---|---|---|
| `core/dracla/provisioning.py` | Pure `InstallInput`, exact role planning, `InstallationVerifier` and `VerifiedInstallation`; execution deliberately blocked. | Real current provenance verifier and ordered I/O coordinator. A ready dry run is not an installer. |
| `core/dracla/administration.py`, `github_admin.py` | Scoped typed authority, private creation, branch rename, sealed Actions-secret delivery and workflow dispatch with ambiguous result categories. | Contents initial README, exact seeding/readback and installation/proof orchestration; keep broad local admin separate from hosted App authority. |
| `core/dracla/cli/app.py`, `config.py`, `release.py` | Closed install grammar, actual dependency/policy preflight, verify/reconcile/export composition and non-echoing recovery prompt. | Execute installation, fixed restore command, selected local deployment profile and safe private handoff. No existing rotate/restore handler is implied. |
| `core/dracla/records/history.py` | Full origin/key/history replay, strict bootstrap and final current-binding checks. `_bootstrap` presently equates historical IDs with live transport IDs. | Explicit historical-origin/current distinction and tightly constructed recovery admission. Existing strict reader rejects a copied old arrangement under new IDs. |
| `core/dracla/records/reconcile.py` | `StoredPreconditions`, actual immutable observations, full publication/repair. Ordinary Connect/external evidence intentionally refuses without its owning provider. | Healthy source verification and the explicit new activation/rebind's own retry under successor transport; imported pending work never resumes as part of restore. No blanket historical fallback or replacement engine. |
| `core/dracla/records/github.py`, `credentials.py` | Numeric protected execution ID before keys, fixed control purposes, scoped immutable/conditional transport and cleanup of process-observed tokens. This is explicitly not unknown-token incident containment. | M4/M5 protected bootstrap adapters plus M6 recovery purpose/config/current successor integration; M4 `m4/13` owns the planned all-token incident barrier and M6 composes installed/local recovery proof and live drivers. |
| Python and TS conformance modules | Strict v1 events, artifact identities/AAD, replay, operation packages, coverage/derived generation contracts and shared authoring corpus. | Prospective schema2 rebind and closed dispatch/generation/replay vectors in both implementations, counted once in M6. |
| `api/wrangler.toml` | A2 benchmark worker only. | Production deployment assets for the reviewed M4/M5 topology and actual self-hosted acceptance. Do not label the bench config a deployment. |

The reviewed M4 plan owns the common Worker/HTTP/SQLite harness, route/gate and
writer foundations. M5 owns bootstrap wrapping, installed proofs, initial Connect
acquisition and protected actual Python integration. They remain future
prerequisites here. Their costs do not become M6 foundation costs again.

Actual tokenizer-based existing-source anchors retained in the campaign are
247 administration,585 GitHub admin,221 provisioning,143 CLI app,119 config,
127 release,375 credentials,380 history,656 append and381 reconcile nonblank
non-comment-only physical lines. Docstrings count physically. These are reuse
measurements, not proposed new delivered LOC. The plan must estimate actual
changed responsibilities and executable integration cases rather than charge
these complete modules again. Shipped config/instructions count as production;
test helpers/config/generators/live drivers count as tests. Designs and static
data are excluded.

## Primary feasibility evidence and limits

The prior M6 provider investigation checked GitHub's owner-mediated App manifest
conversion, state/expiry, empty-repository Contents initialization and branch
rename/readback. It did not establish live literal-loopback registration acceptance.
The plan must retain a real-account acceptance gate or settle it from primary
implementation evidence; OAuth callback documentation alone is insufficient.
Never substitute hosted custody of the transport private key or invent a broad
admin-token fallback to conceal that gap.

[GitHub backup guidance](https://docs.github.com/en/repositories/archiving-a-github-repository/backing-up-a-repository)
and [mirror duplication guidance](https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository)
support preserving repository history/refs into new repositories. M6 reuses
that operator transport with exact private/empty-target and imported-ref
verification. It does not build another Git object-copy engine or imply that
repository import restores GitHub account settings/secrets/installations.

[GitHub's repository Actions policy API](https://docs.github.com/en/rest/actions/permissions#set-github-actions-permissions-for-a-repository)
supports administrator disable/readback. [Push-triggered workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push)
can use imported code. The supported mirror procedure therefore verifies a
deny before any control ref push, excludes inherited secrets/runners, installs
and audits only current protected eligible code, and constrains reenabling.
An after-import disabled observation cannot prove earlier execution was safe.
Require actual ordered HTTP/live-driver negatives for malicious push/schedule/
dispatch content, old eligible refs, inherited resources, lost replies and a
policy that cannot be disabled. Policy denial blocks; no broader service grant,
local self-authenticating receipt or history deletion is a fallback.

Current `InstallationCredentials.close()` explicitly handles only tokens this
process observed. M4's reviewed `m4/13` plans unknown-token minting-cutoff and
permanent-invalidation/lifetime-margin evidence. That planned prerequisite is
not implemented by M3 cleanup. M6 must own the actual installer/recovery wiring
and live proof; missing or uncertain cutoff/invalidation/expiry/current binding
keeps routes closed. Correcting the former implemented-status claim is a
representation fix, not a runtime containment fix. The runtime integration and
live acceptance remain unperformed requirements, not silently deferred scope.

Existing M4/M5 architecture bases own platform/protocol research for production
Workers, static assets/origins, service bindings, App consent and runtime limits.
Reference those sources rather than repeat investigations or infer installed
behavior from documentation. No authenticated account, secret, hosted or live
capacity operation ran during authoring.

## Alternatives and direction check

Use the existing planner/admin seam and one verified coordinator. A second
progress database, hosted provisioning service or generic workflow interpreter
would add authority and recovery obligations without meeting a missing locked
requirement. Current repository evidence remains the source of resumption proof.

Keep initial bootstrap limited to verified keys/manifests/idle guards. Building a
full unconnected projection would need a new M1 format and wider runtime changes;
the owner approved first-event Connect materialization instead.

For new-ID restore, keep one append-only transition and a narrowly typed
origin/current recovery context over the existing engine. Rewriting genesis,
using aliases as canonical truth, permitting arbitrary old-ID authorization or
starting fresh history loses the approved legal/history/recovery guarantees.
A completely separate recovery writer duplicates the most sensitive protocol.
The plan must expose actual integration cost and denial tests for this added
context. Exact mirror import preserves broken application state and missing refs;
it neither runs the engine nor repairs the source. Explicit activation checks an
already consistent idle source before writes and may resume only its own new
rebind operation, not work from the snapshot. This removes the unused prospective
old-operation continuation fields/path; all six source heads remain OIDs.
During copy/health checks, new targets stay unbound while source routes remain
unchanged. After health/current authority and confirmation, reuse M4's conditional
stage/pending gate order and revalidate heads before secrets/jobs/rebind writes.
Pre-event failure conditionally restores only that exact generation; accepted
activation stays pending through completion, with newer quarantine taking priority.
If implementation demands a general bypass or another writer, return
that material change instead of silently broadening the approved extension.

The approved one local deployment-profile selector addresses the locked
self-hosted targeting requirement while retaining the existing command shapes.
The owner explicitly approved its actual public behavior on4November2026;
the earlier generic self-hosting approval alone did not settle that selector.
The profile is explicit local trust configuration, never self-authenticating
remote discovery. No new credential grant or runtime store follows.

## Finite work and evidence

The detailed plan must cover all18 requirements and their parent journeys,
including exact broken/incomplete copies and write-free activation denial,
healthy-source one/all-role replacement, exact companions, prepared/appending/
landed retries of the new activation only, snapshot/source substitutions,
mixed schema/AAD/generation denial,
read/admin/sign/revoke/export after restore, newer quarantine, write-free retry,
credential retirement and security-cutoff migration. Count actual integration
and live-driver code, not only unit handlers. Actual published release, adopter
pins, GitHub policy/consent, protected key-bearing execution, service proofs and
Cloudflare capacity remain separate execution/production gates.
