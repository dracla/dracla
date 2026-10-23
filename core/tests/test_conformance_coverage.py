"""Coverage plaintext goldens, replay equivalence and fail-closed mutations."""

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from dracla.conformance import (
    CoverageError, CoverageProjection, ContributorTupleDecision, OverrideGrant,
    ReplayState, base64url_encode, canonical_json, coverage_delta, coverage_shard,
    decode_decision_fence, decode_inflight_marker, evaluate_subject,
    materialize_coverage, override_key, replay_events, validate_coverage_projection,
)
from core.tests import test_conformance_replay as replay_fixtures

from core.tests.corpus_consumption import CLAIMS


VECTORS = Path(__file__).resolve().parents[2] / "conformance" / "vectors" / "coverage-v1.json"


class TestCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = json.loads(VECTORS.read_text())
        replay_fixtures.TestCanonicalReplay.setUpClass()

    def files(self, *, active=True, basis=None, exempt=False):
        files = copy.deepcopy(self.v["empty_files"])
        if active:
            files["agreements/active.enc.json"] = copy.deepcopy(self.v["active"])
        if basis:
            files["users/07.enc.json"]["7"] = {
                "agreements": {"agreement-1": copy.deepcopy(self.v[basis])}, "overrides": {}}
        if exempt:
            files["exemptions.enc.json"]["7"] = {"active": True}
        return files

    def projection(self, **kwargs):
        return CoverageProjection(self.v["project_id"], self.files(**kwargs))

    def pair(self, fence="idle", marker="empty", *, subjects=None):
        f = copy.deepcopy(self.v["operation_states"]["fences"][fence])
        m = copy.deepcopy(self.v["operation_states"]["markers"][marker])
        if fence == "idle":
            f["generation"] = 0
        if subjects is not None:
            f.update(subjects=subjects, project_wide=not subjects)
            for entry in m["ops"].values():
                entry.update(subjects=subjects, project_wide=not subjects)
        return decode_inflight_marker(canonical_json(m)), decode_decision_fence(canonical_json(f))

    def state(self, records):
        result = replay_events("project-1", replay_fixtures.BASE, records)
        self.assertTrue(result.valid, result.error)
        return result.state

    def materialize(self, state, pair=None):
        return materialize_coverage(state, pair or self.pair(), canonical_oid=state.current_head_oid,
                                    built_at="2026-01-01T00:00:00Z", dracla_version="test-1")

    def test_complete_operation_state_input_goldens(self):
        from dracla.conformance.operations import decode_decision_fence, decode_inflight_marker
        for field, decoder in (("fences", decode_decision_fence), ("markers", decode_inflight_marker)):
            decoded = {key: decoder(canonical_json(value)).to_dict()
                       for key, value in self.v["operation_states"][field].items()}
            self.assertEqual(decoded, self.v["operation_states"][field])
            CLAIMS.case("coverage-v1.json", "operation_states", field)

    def test_independent_empty_projection_and_all_shard_boundaries(self):
        state = ReplayState("project-1", "b" * 40, "b" * 40, project_state="active")
        actual = self.materialize(state)
        self.assertEqual(actual.to_dict(), self.v["empty_files"])
        self.assertEqual(actual.plaintext_files(), {k: canonical_json(v) for k, v in self.v["empty_files"].items()})
        self.assertEqual(len(actual.plaintext_files()), 37)
        for case in self.v["shard_cases"]:
            self.assertEqual(coverage_shard(case["user"], shard_count=32), case["expected"])
            CLAIMS.case('coverage-v1.json', 'shard_cases', case)
        self.assertEqual(coverage_shard(2**53 - 1, shard_count=32), 31)
        for value in [True, 0, -1, 2**53, "7", None]:
            with self.assertRaises(CoverageError):
                coverage_shard(value, shard_count=32)
        for count in [True, 0, 16, 64, "32"]:
            with self.assertRaises(CoverageError):
                coverage_shard(7, shard_count=count)
        CLAIMS.equal("coverage-v1.json", "empty_files", {k: json.loads(v) for k, v in actual.plaintext_files().items()})

    def test_fixed_effective_decisions_and_currency_restore_without_shard_changes(self):
        for case in self.v["evaluation_cases"]:
            with self.subTest(case=case["name"]):
                d = evaluate_subject(self.projection(basis=case["basis"], exempt=case["exempt"]), 7, "agreement-1")
                self.assertEqual([d.decision, d.reason_code], case["expected"])
            CLAIMS.case('coverage-v1.json', 'evaluation_cases', case)
        before = self.projection(basis="signed")
        for case in self.v["currency_cases"]:
            files = before.to_dict()
            files["agreements/active.enc.json"].update({k: v for k, v in case.items() if k != "expected"})
            after = CoverageProjection("project-1", files)
            d = evaluate_subject(after, 7, "agreement-1")
            self.assertEqual([d.decision, d.reason_code], case["expected"])
            self.assertEqual(coverage_delta(before, after).shards, ())
            self.assertEqual(files["users/07.enc.json"], before.to_dict()["users/07.enc.json"])
            CLAIMS.case('coverage-v1.json', 'currency_cases', case)
        self.assertEqual(coverage_delta(before, before).files, ())
        self.assertEqual(evaluate_subject(self.projection(active=False), 7, "agreement-1").reason_code, "not_signed")
        CLAIMS.value('coverage-v1.json', 'project_id', 'active', 'signed', 'revoked', 'unresolved')

    def test_combined_basis_precedence_and_fail_closed_overlays(self):
        for case in self.v["combined_basis_cases"]:
            with self.subTest(case=case["name"]):
                files = self.files(basis=case["basis"], exempt=case["exempt"])
                files["agreements/active.enc.json"].update(case["active"])
                decision = evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
                self.assertEqual([decision.decision, decision.reason_code], case["expected"])
            CLAIMS.case('coverage-v1.json', 'combined_basis_cases', case)

        signed_exempt = self.projection(basis="signed", exempt=True)
        files = signed_exempt.to_dict()
        files["source.enc.json"].update(project_state="succeeded", successor_project_id="project-2")
        decision = evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
        self.assertEqual([decision.decision, decision.reason_code], ["uncovered", None])

        marker, fence = self.pair("mutation", "open", subjects=[7])
        files = signed_exempt.to_dict()
        files.update({"inflight.enc.json": marker.to_dict(), "decision-fence.enc.json": fence.to_dict()})
        decision = evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
        self.assertEqual([decision.decision, decision.reason_code], ["uncovered", "indeterminate"])

        helper = replay_fixtures.TestCanonicalReplay()
        records, _, _ = helper.active_records(nonce=9300)
        unresolved = replace(
            self.state(records),
            unresolved={((7, "agreement-1"), self.v["active"]["activation_event_id"])},
        )
        files = self.materialize(unresolved).to_dict()
        files["exemptions.enc.json"]["7"] = {"active": True}
        decision = evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
        self.assertEqual([decision.decision, decision.reason_code], ["uncovered", "indeterminate"])

    def test_version_sets_use_canonical_json_order_and_materialize_replay_state(self):
        event_id = self.v["active"]["activation_event_id"]
        for case in self.v["version_ordering_cases"]:
            with self.subTest(case=case["name"]):
                values = case["canonical_values"]
                self.assertEqual(
                    [canonical_json(version).decode("ascii") for version in values],
                    case["canonical_json"],
                )
                files = self.files(active=True)
                active = files["agreements/active.enc.json"]
                active[case["set"]] = values
                active["active_version"] = case["active_version"]
                if case["set"] == "retired_versions":
                    active["accepted_versions"] = ["1"]
                projection = CoverageProjection("project-1", files)
                self.assertEqual(projection.to_dict()["agreements/active.enc.json"][case["set"]], values)

                reversed_files = copy.deepcopy(files)
                reversed_files["agreements/active.enc.json"][case["set"]] = case["reversed_values"]
                with self.assertRaises(CoverageError):
                    CoverageProjection("project-1", reversed_files)

                duplicate_files = copy.deepcopy(files)
                duplicate_files["agreements/active.enc.json"][case["set"]] = [values[0], values[0]]
                with self.assertRaises(CoverageError):
                    CoverageProjection("project-1", duplicate_files)

                state_kwargs = {
                    "agreement_id": "agreement-1",
                    "active_version": case["active_version"],
                    "accepted_versions": tuple(values) if case["set"] == "accepted_versions" else ("1",),
                    "retired_versions": tuple(values) if case["set"] == "retired_versions" else (),
                    "activation_event_id": event_id,
                }
                materialized = self.materialize(ReplayState(
                    "project-1", "b" * 40, "b" * 40, project_state="active", **state_kwargs))
                self.assertEqual(
                    materialized.to_dict()["agreements/active.enc.json"][case["set"]],
                    values,
                )
            CLAIMS.case('coverage-v1.json', 'version_ordering_cases', case)

    def test_replay_activation_acceptance_revocation_resigning_and_source_advancement(self):
        helper = replay_fixtures.TestCanonicalReplay()
        records = []
        helper.append(records, "project_connected", 9000)
        empty = self.materialize(self.state(records))
        self.assertIsNone(empty.to_dict()["agreements/active.enc.json"]["agreement_id"])
        publication = helper.append(records, "agreement_published", 9001)
        published = self.materialize(self.state(records))
        self.assertEqual(coverage_delta(empty, published).files, ("source.enc.json",))
        helper.append(records, "agreement_activated", 9002, **{"payload.published_event_id": publication.event_id})
        active = self.materialize(self.state(records))
        self.assertEqual(coverage_delta(published, active).files, ("agreements/active.enc.json", "source.enc.json"))
        helper.append(records, "acceptance", 9003)
        accepted = self.materialize(self.state(records))
        self.assertEqual(accepted.to_dict()["users/07.enc.json"]["7"]["agreements"]["agreement-1"], self.v["signed"])
        self.assertEqual(coverage_delta(active, accepted).shards, (7,))
        self.assertEqual(evaluate_subject(accepted, 7, "agreement-1").decision, "covered")
        helper.append(records, "revocation", 9004)
        revoked = self.materialize(self.state(records))
        self.assertEqual(evaluate_subject(revoked, 7, "agreement-1").reason_code, "revoked")
        helper.append(records, "acceptance", 9005)
        resigned = self.materialize(self.state(records))
        self.assertEqual(evaluate_subject(resigned, 7, "agreement-1").reason_code, "signed")
        self.assertEqual(resigned.to_dict()["users/07.enc.json"], accepted.to_dict()["users/07.enc.json"])
        helper.append(records, "records_reader_authorized", 9006)
        reader = self.materialize(self.state(records))
        self.assertEqual(coverage_delta(resigned, reader).files, ("source.enc.json",))
        self.assertNotIn("reader_authority", str(reader.to_dict()))

    def test_exemption_union_materialization_and_source_only_reader_changes(self):
        helper = replay_fixtures.TestCanonicalReplay()
        records = []
        helper.append(records, "project_connected", 9100)
        before = self.materialize(self.state(records))
        first = helper.exemption_event(9101)
        records.append(helper.record(first, records[-1].commit_oid, len(records) + 1))
        one = self.materialize(self.state(records))
        second = helper.exemption_event(9102, "individual")
        records.append(helper.record(second, records[-1].commit_oid, len(records) + 1))
        two = self.materialize(self.state(records))
        self.assertEqual(one.to_dict()["exemptions.enc.json"], {"7": {"active": True}})
        self.assertEqual(two.to_dict()["exemptions.enc.json"], one.to_dict()["exemptions.enc.json"])
        self.assertEqual(evaluate_subject(two, 7, "agreement-1").reason_code, "exempt")
        self.assertEqual(coverage_delta(before, one).shards, ())
        self.assertNotIn("contract", str(two.to_dict()))
        state = self.state(records)
        remaining = {k: v for k, v in state.exemption_source_records.items() if v.source_event_id != first.event_id}
        reduced = self.materialize(replace(state, exemption_source_records=remaining))
        self.assertEqual(reduced.to_dict()["exemptions.enc.json"], two.to_dict()["exemptions.enc.json"])
        none = self.materialize(replace(state, exemption_source_records={}))
        self.assertEqual(evaluate_subject(none, 7, "agreement-1").reason_code, "not_signed")

    def test_actual_canonical_currency_restore_keeps_signature_rows_and_revocation_cutoff(self):
        helper = replay_fixtures.TestCanonicalReplay()
        records, _, activation = helper.active_records(nonce=9300)
        helper.append(records, "acceptance", 9303)
        signed = self.materialize(self.state(records))
        publication = helper.second_publication(records, 9304)
        helper.append(records, "agreement_activated", 9305, **{
            "target.version": "2", "payload.published_event_id": publication.event_id,
            "payload.supersedes_coverage": False, "payload.accepted_versions": ["1", "2"]})
        preserved = self.materialize(self.state(records))
        self.assertEqual(evaluate_subject(preserved, 7, "agreement-1").reason_code, "signed")
        self.assertEqual(coverage_delta(signed, preserved).shards, ())
        helper.append(records, "agreement_activated", 9306, **{
            "target.version": "2", "payload.published_event_id": publication.event_id,
            "payload.supersedes_coverage": True, "payload.accepted_versions": ["2"]})
        retired = self.materialize(self.state(records))
        self.assertEqual(evaluate_subject(retired, 7, "agreement-1").reason_code, "version_not_active")
        self.assertEqual(coverage_delta(preserved, retired).shards, ())
        helper.append(records, "agreement_activation_restored", 9307, **{
            "target.activation_event_id": activation.event_id, "payload.accepted_versions": ["1"]})
        restored = self.materialize(self.state(records))
        self.assertEqual(evaluate_subject(restored, 7, "agreement-1").reason_code, "signed")
        self.assertEqual(coverage_delta(retired, restored).shards, ())
        helper.append(records, "revocation", 9308)
        revoked = self.materialize(self.state(records))
        self.assertEqual(evaluate_subject(revoked, 7, "agreement-1").reason_code, "revoked")
        helper.append(records, "project_succeeded", 9309)
        succeeded = self.materialize(self.state(records))
        self.assertIsNotNone(evaluate_subject(succeeded, 7, "agreement-1").successor_project_id)

    def test_all_shards_pack_every_subject_and_compare_logical_deltas(self):
        decisions = {}
        for user in range(1, 65):
            d = ContributorTupleDecision(user, "project-1", "agreement-1", "recipient-1", "covered",
                                         self.v["active"]["activation_event_id"], "1", "sha256:" + "a" * 64)
            decisions[d.tuple_key] = d
        state = ReplayState("project-1", "b" * 40, "b" * 40, project_state="active",
                            recipient={"recipient_id": "recipient-1"}, tuple_decisions=decisions)
        full = self.materialize(state)
        empty = self.materialize(replace(state, tuple_decisions={}))
        self.assertEqual(coverage_delta(empty, full).shards, tuple(range(32)))
        for user in range(1, 65):
            row = full.to_dict()[f"users/{user % 32:02d}.enc.json"][str(user)]
            self.assertEqual(row["agreements"]["agreement-1"], self.v["signed"])
        self.assertEqual(coverage_delta(full, empty).shards, tuple(range(32)))

    def test_marker_fence_windows_scope_and_lifecycle_precede_coverage(self):
        state = ReplayState("project-1", "b" * 40, "b" * 40, project_state="active")
        for subjects in [[], [7], [8]]:
            for marker in ["empty", "open"]:
                projection = self.materialize(state, self.pair("mutation", marker, subjects=subjects))
                expected = "not_signed" if subjects == [8] else "indeterminate"
                self.assertEqual(evaluate_subject(projection, 7, "agreement-1").reason_code, expected)
        self.assertEqual(evaluate_subject(self.materialize(state, self.pair("success")), 7, "agreement-1").reason_code, "not_signed")
        files = self.files(basis="signed", exempt=True)
        marker, fence = self.pair("mutation", "open", subjects=[7])
        files.update({"inflight.enc.json": marker.to_dict(), "decision-fence.enc.json": fence.to_dict()})
        self.assertEqual(evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1").reason_code, "indeterminate")
        files["source.enc.json"].update(project_state="succeeded", successor_project_id="project-2")
        decision = evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
        self.assertEqual(decision.decision, "uncovered")
        self.assertEqual(decision.successor_project_id, "project-2")
        self.assertIsNone(decision.reason_code)

    def test_override_exact_tuple_materializes_without_private_reason(self):
        event_id = base64url_encode(bytes([2]) * 32)
        grant = OverrideGrant(event_id, 31, 5, "c" * 40,
                              ({"github_user_id": 7, "login_snapshot": "alice"},),
                              "private-reason", "private-instrument")
        state = ReplayState("project-1", "b" * 40, "b" * 40, project_state="active", override_grants={event_id: grant})
        p = self.materialize(state)
        context = {"repository_id": 31, "pull_request_number": 5, "tree_oid": "c" * 40}
        d = evaluate_subject(p, 7, "agreement-1", context)
        self.assertTrue(d.overridden)
        self.assertEqual(d.decision, "covered")
        self.assertIsNone(d.reason_code)
        for field, value in [("repository_id", 32), ("pull_request_number", 6), ("tree_oid", "d" * 40)]:
            self.assertEqual(evaluate_subject(p, 7, "agreement-1", {**context, field: value}).decision, "uncovered")
        self.assertEqual(evaluate_subject(p, 8, "agreement-1", context).decision, "uncovered")
        self.assertNotIn("private-", str(p.to_dict()))
        removed = self.materialize(replace(state, override_grants={event_id: replace(grant, withdrawal_event_id="withdrawal", withdrawal_reason="withdrawn")}))
        self.assertEqual(evaluate_subject(removed, 7, "agreement-1", context).decision, "uncovered")
        with self.assertRaises(CoverageError):
            self.materialize(replace(state, override_grants={event_id: grant, "duplicate": grant}))

    def test_projection_context_is_deeply_immutable_and_source_bound(self):
        files = self.files(basis="signed")
        p = CoverageProjection("project-1", files)
        files["users/07.enc.json"].clear()
        exported = p.to_dict()
        exported["users/07.enc.json"].clear()
        self.assertEqual(evaluate_subject(p, 7, "agreement-1").decision, "covered")
        with self.assertRaises(FrozenInstanceError):
            p.project_id = "other"
        with self.assertRaises(TypeError):
            p._files["source.enc.json"]["canonical_sha"] = "c" * 40
        validate_coverage_projection(p, expected_project_id="project-1", expected_canonical_oid="b" * 40)
        for kwargs in [{"expected_project_id": "other"}, {"expected_project_id": "project-1", "expected_canonical_oid": "c" * 40}]:
            with self.assertRaises(CoverageError):
                validate_coverage_projection(p, **kwargs)
        with self.assertRaises(CoverageError):
            coverage_delta(p, CoverageProjection("other", self.files()))
        with self.assertRaises(CoverageError):
            evaluate_subject(p, 7, "another-agreement")

    def test_closed_schema_mutations_never_pass_a_covered_row(self):
        base = self.files(basis="signed", exempt=True)
        objects = [[], ["source.enc.json"], ["agreements/active.enc.json"], ["exemptions.enc.json", "7"],
                   ["users/07.enc.json", "7"], ["users/07.enc.json", "7", "agreements", "agreement-1"]]
        def target(value, path):
            for k in path:
                value = value[k]
            return value
        for path in objects:
            for field in list(target(base, path)):
                with self.subTest(path=path, missing=field):
                    files = copy.deepcopy(base)
                    del target(files, path)[field]
                    with self.assertRaises(CoverageError):
                        CoverageProjection("project-1", files)
            files = copy.deepcopy(base)
            target(files, path)["private_legal_name"] = "forbidden"
            with self.assertRaises(CoverageError):
                CoverageProjection("project-1", files)
        mutations = [
            (["source.enc.json", "canonical_sha"], "wrong"),
            (["source.enc.json", "built_at"], "never"),
            (["source.enc.json", "dracla_version"], ""),
            (["source.enc.json", "project_state"], "unconnected"),
            (["source.enc.json", "successor_project_id"], "other"),
            (["agreements/active.enc.json", "projection_format"], True),
            (["agreements/active.enc.json", "shard_count"], 64),
            (["agreements/active.enc.json", "agreement_id"], None),
            (["agreements/active.enc.json", "activation_event_id"], "wrong"),
            (["agreements/active.enc.json", "active_version"], "2"),
            (["agreements/active.enc.json", "accepted_versions"], []),
            (["agreements/active.enc.json", "accepted_versions"], ["1", "1"]),
            (["agreements/active.enc.json", "accepted_versions"], ["2", "1"]),
            (["agreements/active.enc.json", "accepted_versions"], [None]),
            (["agreements/active.enc.json", "retired_versions"], ["1"]),
            (["agreements/active.enc.json", "retired_versions"], {}),
            (["exemptions.enc.json"], []),
            (["exemptions.enc.json", "7", "active"], False),
            (["users/07.enc.json"], []),
            (["users/07.enc.json", "7", "agreements"], []),
            (["users/07.enc.json", "7", "overrides"], []),
            (["users/07.enc.json", "7", "agreements", "agreement-1", "decision"], "uncovered"),
            (["users/07.enc.json", "7", "agreements", "agreement-1", "reason_code"], "private-reason"),
            (["users/07.enc.json", "7", "agreements", "agreement-1", "digest"], None),
        ]
        for path, value in mutations:
            with self.subTest(path=path, value=value):
                files = copy.deepcopy(base)
                target(files, path[:-1])[path[-1]] = value
                with self.assertRaises(CoverageError):
                    CoverageProjection("project-1", files)
        for key in ["0", "07", "-1", "٧", "9007199254740992", "9" * 200]:
            files = copy.deepcopy(base)
            files["exemptions.enc.json"] = {key: {"active": True}}
            with self.assertRaises(CoverageError):
                CoverageProjection("project-1", files)
        files = copy.deepcopy(base)
        files["users/06.enc.json"]["7"] = files["users/07.enc.json"].pop("7")
        with self.assertRaises(CoverageError):
            CoverageProjection("project-1", files)

    def test_operation_mismatch_and_override_corruption_are_fatal(self):
        for fence in ["idle", "success"]:
            files = self.files(basis="signed")
            marker, f = self.pair(fence, "open")
            files.update({"inflight.enc.json": marker.to_dict(), "decision-fence.enc.json": f.to_dict()})
            with self.assertRaises(CoverageError):
                CoverageProjection("project-1", files)
        for field, value in [("operation_sha256", "sha256:" + "f" * 64), ("subjects", [8]), ("project_wide", False)]:
            files = self.files(basis="signed")
            marker, fence = self.pair("mutation", "open")
            m = marker.to_dict()
            next(iter(m["ops"].values()))[field] = value
            files.update({"inflight.enc.json": m, "decision-fence.enc.json": fence.to_dict()})
            with self.assertRaises(CoverageError):
                CoverageProjection("project-1", files)
        entry = {"repository_id": 31, "pull_request_number": 5, "subject_user_id": 7,
                 "tree_oid": "c" * 40, "grant_event_id": base64url_encode(bytes([2]) * 32), "active": True}
        key = override_key(repository_id=31, pull_request_number=5, subject_user_id=7, tree_oid="c" * 40)
        for field, value in [("active", False), ("active", 1), ("subject_user_id", 8), ("repository_id", True),
                             ("tree_oid", "bad"), ("grant_event_id", "bad"), ("legal_name", "private")]:
            files = self.files(basis="signed")
            files["users/07.enc.json"]["7"]["overrides"] = {key: {**entry, field: value}}
            with self.assertRaises(CoverageError):
                CoverageProjection("project-1", files)
        files = self.files(basis="signed")
        files["users/07.enc.json"]["7"]["overrides"] = {"wrong-key": entry}
        with self.assertRaises(CoverageError):
            CoverageProjection("project-1", files)

    def test_unresolved_replay_is_not_overridden_by_exemption_or_a_signature(self):
        helper = replay_fixtures.TestCanonicalReplay()
        records, _, _ = helper.active_records(nonce=9200)
        event = helper.append(records, "acceptance", 9203)
        state = self.state(records)
        unresolved = replace(state, unresolved={((7, "agreement-1"), event.event_id)})
        projection = self.materialize(unresolved)
        self.assertEqual(projection.to_dict()["users/07.enc.json"]["7"]["agreements"]["agreement-1"], self.v["unresolved"])
        self.assertEqual(evaluate_subject(projection, 7, "agreement-1").reason_code, "indeterminate")
        self.assertEqual(evaluate_subject(projection, 8, "agreement-1").reason_code, "not_signed")
        for malformed in [frozenset({"wrong"}), frozenset({(7, "event")}), frozenset({((7,), "event")})]:
            with self.assertRaises(CoverageError):
                self.materialize(replace(state, unresolved=malformed))

    def test_invalid_public_inputs_and_inconsistent_bases_fail_closed(self):
        state = ReplayState("project-1", "b" * 40, "b" * 40, project_state="active")
        kwargs = dict(canonical_oid="b" * 40, built_at="2026-01-01T00:00:00Z", dracla_version="test-1")
        for candidate, pair, arguments in [
                ({}, self.pair(), kwargs),
                (state, self.pair(), {**kwargs, "canonical_oid": "c" * 40}),
                (state, [], kwargs), (state, (self.pair()[0],), kwargs),
                (state, tuple(reversed(self.pair())), kwargs)]:
            with self.assertRaises(CoverageError):
                materialize_coverage(candidate, pair, **arguments)
        with self.assertRaises(CoverageError):
            self.materialize(ReplayState("project-1", "b" * 40, "b" * 40))
        with self.assertRaises(CoverageError):
            CoverageProjection("project-1", {"unsafe": float("inf")})
        with self.assertRaises(CoverageError):
            CoverageProjection("project-1", {"non-json": object()})
        p = self.projection()
        for invalid in [None, {}, "projection"]:
            with self.assertRaises(CoverageError):
                evaluate_subject(invalid, 7, "agreement-1")
            with self.assertRaises(CoverageError):
                coverage_delta(p, invalid)
            with self.assertRaises(CoverageError):
                validate_coverage_projection(invalid, expected_project_id="project-1")
        for context in [{}, {"repository_id": 31, "pull_request_number": 1, "tree_oid": "wrong"}]:
            with self.assertRaises(ValueError):
                evaluate_subject(p, 7, "agreement-1", context)
        files = self.files(active=False)
        files["agreements/active.enc.json"]["accepted_versions"] = ["1"]
        with self.assertRaises(CoverageError):
            CoverageProjection("project-1", files)
        files = self.files()
        files["source.enc.json"].update(project_state="succeeded", successor_project_id="project-1")
        with self.assertRaises(CoverageError):
            evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
        for value in ["covered", "uncovered"]:
            files = self.files(basis="revoked")
            row = files["users/07.enc.json"]["7"]["agreements"]["agreement-1"]
            row.update(decision=value, version="1")
            with self.assertRaises(CoverageError):
                CoverageProjection("project-1", files)
        decision = ContributorTupleDecision(7, "other", "agreement-1", "recipient-1", "uncovered", "event")
        with self.assertRaises(CoverageError):
            self.materialize(replace(state, tuple_decisions={decision.tuple_key: decision}))


if __name__ == "__main__":
    unittest.main()
