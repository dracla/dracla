# M1-11 release-profile evidence

The installed format-1 profile is
`core/dracla/conformance/release-profile-v1.json`. Its numeric limits constrain
prepared cells, bounded calls and private derived data. Coverage has no size
limit. A private class exceeding its limit fails closed while canonical
acceptance, revocation and reader withdrawal remain available.

| Limit | Installed value | Evidence and rationale |
|---|---:|---|
| Whole prepared cell | 1,048,576 bytes | Finite complete-cell budget for the existing M1-9 boundary; profile tests exercise limit−1, limit and limit+1. |
| Index shard ciphertext | 65,536 bytes | The concentrated 128-subject fixture uses 32,237 bytes in one shard. |
| Status-detail shard ciphertext | 262,144 bytes | The same fixture uses 40,429 bytes in one status shard. Private source provenance can grow independently; overflow remains explicit. |
| Reader-authority shard ciphertext | 262,144 bytes | A source with 512 current members and 2,048 retained cursor entries uses 143,884 bytes. |
| Derived-state ciphertext | 32,768 bytes | All 96 digest entries and 32 standing exemption rules use 13,810 bytes. |
| Members per reader source | 512 | The concentrated reader fixture reaches this limit; membership boundary tests reject the next entry. |
| Retained reader cursor entries per source | 2,048 | The same fixture reaches the cumulative churn limit independently of current membership; entries are never silently pruned. |
| Continuous exemption rules | 32 | The state fixture contains 32 complete standing-rule records. |
| Continuous reader rules | 10 | Fixed by HLD §6.6; nine, ten and eleven rules are tested. |
| Bulk affected shards per operation | 32 | Conservative finite admission budget; future writers must fan out service invocations under the separate request budget. |
| Mutation retries | 3 | Finite retry admission preserves the explicit unsettled outcome; every boundary is tested. |
| Subrequests per invocation | 49 | The locked cold path admits 39 base subrequests plus ten continuous reader rules (49); the release-profile cross-limit test accepts 49 and rejects 50. HLD §9.2 remains the deployment capacity model. |

The size measurements use actual M1-2 AES-GCM ciphertext, including its
16-byte authentication tag. Envelope base64 expansion and metadata are not
ciphertext bytes. The state size is its exact canonical plaintext length plus
that tag; assembly never encrypts or regenerates a shard to compute its digest.
The deterministic nonce and key belong exclusively to the test fixture.

These are schema-valid local fixture measurements. Limits are simultaneous
constraints, so independently saturating every source or accepting arbitrarily
long provenance strings is not promised to fit one shard. Admission and class
overflow checks still apply. Hosted CPU, network fan-out and the real-account
release envelope remain the existing later-milestone acceptance work.

Reproduce with:

`PYTHONPATH=core .venv/bin/python -m unittest core/tests/test_conformance_release_profile.py core/tests/test_conformance_derived.py -q`

`TestReleaseProfile.test_request_budget_includes_locked_reader_cold_path` fixes
the 39 + 10 request-budget boundary and rejection at 50.
`TestDerived.test_installed_profile_capacity_fixture` fixes the measurements;
the profile and derived tests exercise exact numeric boundaries, generation
mismatch, missing bulk shards, wrong envelope contexts and digest corruption.
`test_acceptance_and_revocation_complete_past_largest_private_shard_limit`
uses a deliberately smaller private profile to prove the asymmetry without
placing any rejecting cap on coverage.

The read API carries project, resolved-events OID, subject and agreement in
`DerivedReadRow`, outside persisted shard bytes. `resolve_read_status` takes a
validated coverage observation as its active-agreement context and requires its
source OID to match those resolved events. Its explicit marker/fence pair must
belong to that same coverage observation. Canonical materialization generations
are authenticated inputs to assembly and validation; the reference fold never
invents them from potentially unavailable writer-observation history.

The bounded read path carries the authenticated derived state and one selected
private class of plaintext/envelope shards through `DerivedReadProjection`.
`CoverageReadContext` carries exactly `source.enc.json`,
`agreements/active.enc.json`, `inflight.enc.json`, and
`decision-fence.enc.json`. Selected shard generation, path, project, digest,
size, row, source, and state checks reuse the complete validators without
requiring unrelated private shards or coverage user shards. Complete
materialization and 96-shard assembly remain the authoring and publication
contracts.
