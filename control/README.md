# Control operation, recovery and artifact changes

`reconcile.yml` is the protected control workflow template. The bootstrap and
`verify_release.py` authenticate explicit executable selections before project
secrets reach the installed package. Neither a workflow output flag nor the
downloaded package's own declarations replace that verification. Deployment,
secret provisioning and authentic release/hosted acceptance remain separate
gates; the source template is not an installed control repository.

The operator guide is [GitHub Apps](../docs/github-apps.md). The concrete local
commands and their secret inputs are in [CLI and administration](../docs/cli.md).
The contracts are HLD §§6.10.2, 8.1.2, 9.1 and M3 LLD §§3.1, 5, 7–8.

## Preserve a complete backup

1. Mirror the complete records, coverage and control repositories, including
   full commit history and all branches. Do not substitute a working-directory
   archive or just the default branch. Retain canonical events, all key history,
   operational state and private derived/enforcement state.
2. Record the snapshot time, each source repository's numeric ID and every
   branch name/head OID atomically with that snapshot. Store the observation
   with the corresponding mirror. Verify that every recorded commit exists.
   Use the operator's independent repository access for this step; the data App
   must continue to exclude control.
3. Store the adopter recovery wrapping key in a separate safe location. Preserve
   the generations needed to unwrap every retained records and coverage key.
   Ordinary repository readers must not receive recovery or live credentials
   in the backup.
4. Retain the protected workflow, exact execution profile, bootstrap image and
   verified wheel/lock/evidence set needed for the selected release. Credentials
   needed to resume a live deployment stay in their separate secret stores.

This is the existing operator mirror procedure, not a new DraCLA backup command,
wire format or append log. A manifest detects incomplete/mismatched restoration;
it cannot detect an administrator who controls and alters both data and backups.

## Restore, authenticate and recover

1. Restore all three repositories' complete histories and recorded refs from
   one matching backup. Keep hosted writers and routes unavailable while the
   authorized recovery procedure runs. A local command is not authority to
   disable or re-enable those services.
2. Independently compare every restored source ID and branch/head OID with the
   saved observation. Check every required commit, including ancestors. Stop
   before keys on a missing repository/ref/commit or mismatched identity/head.
   An incomplete restore must not become a new baseline.
3. If a repository was replaced, retain both its original and replacement ID
   for administrator-authorized rebind. Do not edit authenticated bootstrap
   evidence or silently substitute a new command/configuration ID. Automatic
   trust transfer is not supported by M3.
4. Verify the exact protected release and dependency artifacts externally before
   supplying any App, control-wrapping or recovery secret. Use only the resulting
   same verified installed environment. The control workflow verifies the App
   assignment and excludes control before wrapping-key access; local operator
   mode remains a separate explicit maintenance path.
5. Run the documented `verify` command using the protected project/repository
   identities and the private recovery prompt. It authenticates bootstrap,
   actual key commitments, activation ancestry and complete canonical replay.
   Invalid or missing historical keys, wrong IDs and corrupt history stop the
   run. Recovery-key possession does not authorize plaintext export.
6. For a retained prepared/appending/terminal operation, run the existing
   `reconcile` command. It uses the durable frozen package, normal append/CAS
   rules and authenticated state to finish forward. Verify all coverage/private
   projection classes and repeat reconciliation to check idempotence. Preserve
   every existing canonical/key commit; a pending operation may append its own
   validated event, but recovery never force-updates or repairs canonical data.
7. Treat `route-unavailable-proof-required` and `check-confirmation-required`
   as blocked recovery states. Idle projection reconstruction needs M4's
   independently authenticated route-unavailable repair integration. A success
   reservation needs M4's exact publication confirmation. An operator assertion,
   timeout, fixture callback or successful local replay cannot supply either.
8. Complete and verify replacement wrapping paths, credentials, registry/App
   rebinds, hosted routing and the enforcer sweep through their owning M4/M5/M6
   integrations before declaring the deployment recovered. M3 tests do not
   complete those steps. Export only when explicitly requested and currently
   authorized by the canonical reader-source union.

After an App-key incident, apply HLD §8.1.2's all-token containment barrier
across every assignment before final restoration. A working replacement key or
successful known-token revocation does not prove unknown issued tokens inactive.
Compromise of a key-bearing job also invokes the relevant data-key procedure.

## Explicit upgrade and rollback

1. Retain the currently verified profile, bootstrap digest, wheel, complete
   runtime/build locks and original standard evidence before changing pins.
2. Review and select the exact replacement version, source numeric identity,
   source/workflow/builder commits, bootstrap/trust-root digests, wheel filename
   and hash, and runtime/build lock hashes in protected control configuration.
   Records/coverage content cannot choose any executable input.
3. Repeat the existing external build/publish verification and finite dependency
   closure checks. Unsupported evidence, missing inputs, different same-version
   wheel bytes or altered locks fail; do not resolve another dependency set.
4. Install only the verified wheels offline into a fresh protected environment.
   Repeat the wheel-derived installed-file/environment checks at the secret
   handoff. Never repair a failed check by trusting installed `RECORD`, an old
   workflow flag or the package's self-report.
5. Run verification and reconciliation against current authenticated repository
   state. Compare source identities and canonical evidence, and check a repeat
   performs no additional mutation. Do not restore an old event/key head or
   undo a valid canonical transition to make the package work.
6. For rollback, explicitly reselect the retained older pins/artifacts and repeat
   the same gate and current-history checks. A retained version is not exempt
   from verification or guaranteed to understand newer canonical history.
   Failed verification/compatibility keeps the job stopped before secret use.

## What the current exercises establish

`core/tests/test_records_6.py` stores inert fixture repository objects separately
from recovery material, checks the all-repository mirror observation, restores
prepared/landed operations and invokes the real authenticated engines. It checks
canonical-prefix preservation, all-projection verification, write-free repeats,
numeric-ID/key rejection and the explicit missing-M4 repair gate.

The installed test builds this candidate's real code into two synthetic package
versions and reinstalls the retained first wheel for rollback. Each isolated
process proves every imported `dracla` module comes from that selected installed
wheel. It carries the encrypted fixture forward and compares canonical/key
evidence across the selections. It uses the test interpreter's dependencies;
it is not a closed production bootstrap environment or a compatibility test of
an authentic older published release. Separate existing M3/5 producer/installer
validation covers the locked offline environment boundary.

The protected-selection test calls the existing release verifier again for
upgrade and rollback using explicit synthetic publisher/crypto responses. These
responses do not authenticate a real publisher. Authentic DraCLA publication,
published bootstrap/adopter pins, hosted workflow execution, live App/CAS/token/
key containment and M4/M5/M6 assembled recovery remain open production gates.
