"""Executable M1-6 canonical replay vectors and state-machine evidence."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import MappingProxyType

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    ActiveAgreement,
    AgreementActivation,
    AgreementPublication,
    CanonicalEventRecord,
    ContributorTupleDecision,
    ProjectLifecycle,
    ReplayCorruptionError,
    ReplayError,
    ReplayResult,
    ReplayState,
    active_agreement,
    apply_event,
    base64url_encode,
    current_configuration,
    derive_event_identity,
    effective_contributor_tuple_decision,
    initial_replay_state,
    latest_contributor_tuple_decision,
    project_lifecycle,
    replay_events,
    validate_event,
)


EVENTS = Path(__file__).parent / "vectors" / "events-v1.json"
REPLAY = Path(__file__).parent / "vectors" / "replay-v1.json"
BASE = "b" * 40


class TestCanonicalReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        corpus = json.loads(EVENTS.read_text(encoding="utf-8"))
        cls.rows = {row["type"]: row for row in corpus["events"]}
        cls.vector = json.loads(REPLAY.read_text(encoding="utf-8"))

    def event(self, event_type, nonce, parent=None, **changes):
        value = copy.deepcopy(self.rows[event_type])
        value["operation_nonce"] = base64url_encode(int(nonce).to_bytes(16, "big"))
        if event_type in {"acceptance", "revocation"}:
            value["confirmed_canonical_oid"] = parent
        for path, replacement in changes.items():
            target = value
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = copy.deepcopy(replacement)
        return self.validate(value)

    def validate(self, value):
        identity = derive_event_identity(
            value["project_id"],
            value["operation_nonce"],
            value["actor"],
            value["type"],
            value["target"],
            value["payload"],
            value["confirmed_canonical_oid"],
        )
        value.update(
            event_id=identity.event_id,
            idempotency_key=identity.idempotency_key,
            operation_sha256=identity.operation_sha256,
        )
        return validate_event(value)

    def record(self, event, parent, commit_number):
        commit = f"{commit_number:040x}"
        return CanonicalEventRecord(event, commit, parent)

    def append(self, records, event_type, nonce, **changes):
        parent = records[-1].commit_oid if records else BASE
        event_parent = parent if event_type in {"acceptance", "revocation"} else None
        event = self.event(event_type, nonce, event_parent, **changes)
        records.append(self.record(event, parent, len(records) + 1))
        return event

    def active_records(self, *, nonce=10):
        records = []
        self.append(records, "project_connected", nonce)
        publication = self.append(records, "agreement_published", nonce + 1)
        activation = self.append(
            records,
            "agreement_activated",
            nonce + 2,
            **{"payload.published_event_id": publication.event_id},
        )
        return records, publication, activation

    def second_publication(self, records, nonce, version="2"):
        from dracla.conformance.artifacts import segment

        parent = records[-1].commit_oid
        value = copy.deepcopy(self.rows["agreement_published"])
        value["operation_nonce"] = base64url_encode(int(nonce).to_bytes(16, "big"))
        value["target"]["version"] = version
        value["payload"]["snapshot_content_path"] = (
            f"agreements/{segment('agreement-1')}/{segment(version)}.md"
        )
        value["payload"]["snapshot_metadata_path"] = (
            f"agreements/{segment('agreement-1')}/{segment(version)}.meta.json"
        )
        publication = self.validate(value)
        records.append(self.record(publication, parent, len(records) + 1))
        return publication

    def owner_transfer_event(self, nonce=30):
        value = copy.deepcopy(self.rows["project_repository_owner_changed"])
        value["operation_nonce"] = base64url_encode(int(nonce).to_bytes(16, "big"))
        value["target"]["prior_repository_owner"] = copy.deepcopy(
            self.rows["project_connected"]["payload"]["repository_owner"]
        )
        value["payload"]["repository_ids"] = copy.deepcopy(
            self.rows["project_connected"]["payload"]["repository_ids"]
        )
        for item in value["authorizations"]:
            if item["operation"].endswith("records_repository"):
                item["resource_id"] = 11
            elif item["operation"].endswith("coverage_repository"):
                item["resource_id"] = 12
            elif item["operation"].endswith("control_repository"):
                item["resource_id"] = 13
        return self.validate(value)

    def vector_records(self, case_name):
        records = []
        if case_name == "empty":
            return records
        self.append(records, "project_connected", 100)
        if case_name == "connection":
            return records
        if case_name == "config-and-keyring":
            self.append(records, "config_updated", 101)
            self.append(records, "keyring_activated", 102, **{"payload.generation": 2})
            return records
        publication = self.append(records, "agreement_published", 101)
        self.append(
            records,
            "agreement_activated",
            102,
            **{"payload.published_event_id": publication.event_id},
        )
        if case_name in {"connect-publish-activate", "timestamps"}:
            return records
        if case_name == "accepted-version-reactivation":
            publication_two = self.second_publication(records, 103)
            self.append(
                records,
                "agreement_activated",
                104,
                **{
                    "target.version": "2",
                    "payload.published_event_id": publication_two.event_id,
                    "payload.accepted_versions": ["1", "2"],
                },
            )
            self.append(
                records,
                "agreement_activated",
                105,
                **{
                    "target.version": "1",
                    "payload.published_event_id": publication.event_id,
                    "payload.accepted_versions": ["1", "2"],
                },
            )
            return records
        if case_name == "tuple-cutoff-resign-correction":
            self.append(records, "acceptance", 103)
            self.append(records, "revocation", 104)
            fresh_acceptance = self.append(records, "acceptance", 105)
            self.append(records, "acceptance", 106, **{"payload.supersedes": fresh_acceptance.event_id})
            return records
        if case_name == "tuple-isolation":
            self.append(records, "acceptance", 103)
            self.append(
                records,
                "acceptance",
                104,
                **{
                    "actor.github_user_id": 8,
                    "target.coverage_tuple.github_user_id": 8,
                },
            )
            return records
        if case_name == "activation-modes-restore":
            publication_two = self.second_publication(records, 103)
            activation_two = self.append(
                records,
                "agreement_activated",
                104,
                **{
                    "target.version": "2",
                    "payload.published_event_id": publication_two.event_id,
                    "payload.supersedes_coverage": True,
                    "payload.accepted_versions": ["2"],
                },
            )
            publication_three = self.second_publication(records, 105, version="3")
            self.append(
                records,
                "agreement_activated",
                106,
                **{
                    "target.version": "3",
                    "payload.published_event_id": publication_three.event_id,
                    "payload.accepted_versions": ["2", "3"],
                },
            )
            self.append(
                records,
                "agreement_activation_restored",
                107,
                **{
                    "target.activation_event_id": activation_two.event_id,
                    "payload.accepted_versions": ["2"],
                },
            )
            return records
        if case_name == "owner-transfer-successor-maintenance":
            records = [records[0]]
            owner = self.owner_transfer_event(103)
            records.append(self.record(owner, records[-1].commit_oid, 2))
            publication = self.append(records, "agreement_published", 104)
            self.append(records, "agreement_activated", 105, **{"payload.published_event_id": publication.event_id})
            self.append(records, "acceptance", 106)
            self.append(records, "project_succeeded", 107)
            self.append(records, "keyring_activated", 108, **{"payload.generation": 2})
            self.append(records, "revocation", 109)
            return records
        raise AssertionError(f"unknown vector case {case_name}")

    def test_vector_cases_execute_positive_assertions(self):
        for case in self.vector["valid_cases"]:
            with self.subTest(case=case["name"]):
                records = self.vector_records(case["name"])
                self.assertEqual([record.event.type for record in records], case["record_types"])
                result = replay_events(case["project_id"], self.vector["base_commit_oid"], records)
                self.assertTrue(result.valid, result.error)
                repeat = replay_events(case["project_id"], self.vector["base_commit_oid"], records)
                self.assertEqual(result.to_dict(), repeat.to_dict())
                state = result.state
                self.assertEqual(state.project_state, case["expected_project_state"])
                self.assertEqual(state.to_dict()["unresolved"], case["expected_unresolved"])
                version = case.get("expected_active_version")
                if version is None:
                    self.assertIsNone(active_agreement(state))
                else:
                    current = active_agreement(state)
                    self.assertEqual(current.active_version, version)
                    self.assertEqual(list(current.accepted_versions), case["expected_accepted_versions"])
                    self.assertEqual(list(current.retired_versions), case.get("expected_retired_versions", []))
                if "expected_keyring_generation" in case:
                    self.assertEqual(state.keyring_generation, case["expected_keyring_generation"])
                    self.assertEqual(current_configuration(state), state.configuration)
                if "expected_successor_project_id" in case:
                    self.assertEqual(state.repository_owner["github_account_id"], 20)
                    self.assertEqual(project_lifecycle(state).successor_project_id, case["expected_successor_project_id"])
                if "expected_latest_decision" in case:
                    key = records[3].event.target["coverage_tuple"]
                    self.assertEqual(latest_contributor_tuple_decision(state, key).decision, case["expected_latest_decision"])

    def test_negative_vector_cases_execute_corruption_assertions(self):
        builders = {
            "wrong-project": self.negative_wrong_project,
            "broken-ancestry": self.negative_broken_ancestry,
            "duplicate-event-id": self.negative_duplicate_event,
            "idempotency-fingerprint-conflict": self.negative_idempotency_conflict,
            "duplicate-commit": self.negative_duplicate_commit,
            "base-commit-reuse": self.negative_base_commit_reuse,
            "activation-before-publication": self.negative_activation_before_publication,
            "inactive-signing": self.negative_inactive_signing,
            "wrong-recipient": self.negative_wrong_recipient,
            "wrong-agreement": self.negative_wrong_agreement,
            "acceptance-before-connection": self.negative_acceptance_before_connection,
            "invalid-supersession": self.negative_invalid_supersession,
            "non-current-confirmed": self.negative_non_current_confirmed,
            "illegal-post-success": self.negative_illegal_post_success,
            "conflicting-successor": self.negative_conflicting_successor,
            "ordinary-retired-revival": self.negative_retired_revival,
            "restore-missing-target": self.negative_restore_missing,
            "restore-cross-project": self.negative_restore_cross_project,
            "restore-cross-agreement": self.negative_restore_cross_agreement,
            "restore-non-activation": self.negative_restore_non_activation,
            "restore-set-mismatch": self.negative_restore_set_mismatch,
            "m1-7-out-of-scope": self.negative_m17,
        }
        self.assertEqual({case["name"] for case in self.vector["negative_cases"]}, set(builders))
        for case in self.vector["negative_cases"]:
            with self.subTest(case=case["name"]):
                result = builders[case["name"]]()
                self.assertTrue(result.corrupted, case["name"])
                self.assertIsNone(result.state)
                self.assertIsNotNone(result.error)
                self.assertIn(case["failure"], result.reason)

    def negative_result(self, records, project_id="project-1"):
        return replay_events(project_id, BASE, records)

    def negative_wrong_project(self):
        event = self.event("project_connected", 200, **{"project_id": "other-project"})
        return self.negative_result([self.record(event, BASE, 1)])

    def negative_broken_ancestry(self):
        event = self.event("project_connected", 201)
        return self.negative_result([self.record(event, "c" * 40, 1)])

    def negative_duplicate_event(self):
        event = self.event("project_connected", 202)
        record = self.record(event, BASE, 1)
        return self.negative_result([record, self.record(event, record.commit_oid, 2)])

    def negative_idempotency_conflict(self):
        first = self.event("project_connected", 203)
        second_value = copy.deepcopy(self.rows["project_connected"])
        second_value["operation_nonce"] = first.operation_nonce
        second_value["payload"]["project_slug"] = "different-project"
        second = self.validate(second_value)
        first_record = self.record(first, BASE, 1)
        return self.negative_result([first_record, self.record(second, first_record.commit_oid, 2)])

    def negative_duplicate_commit(self):
        first = self.event("project_connected", 204)
        second = self.event("config_updated", 205)
        third = self.event("config_updated", 206)
        first_record = self.record(first, BASE, 1)
        second_record = self.record(second, first_record.commit_oid, 2)
        # The third record continues ancestry but reuses the first commit OID.
        # This is distinct from a self-parenting commit, which the model rejects
        # at construction time.
        duplicate = CanonicalEventRecord(third, first_record.commit_oid, second_record.commit_oid)
        return self.negative_result([first_record, second_record, duplicate])

    def negative_base_commit_reuse(self):
        first = self.event("project_connected", 420)
        second = self.event("config_updated", 421)
        first_record = self.record(first, BASE, 1)
        reused_base = CanonicalEventRecord(second, BASE, first_record.commit_oid)
        return self.negative_result([first_record, reused_base])

    def negative_activation_before_publication(self):
        records = []
        self.append(records, "project_connected", 206)
        activation = self.event("agreement_activated", 207, **{"payload.published_event_id": "A" * 43})
        records.append(self.record(activation, records[-1].commit_oid, 2))
        return self.negative_result(records)

    def negative_inactive_signing(self):
        records, _, _ = self.active_records(nonce=208)
        publication_two = self.second_publication(records, 211)
        acceptance = self.event(
            "acceptance", 212, records[-1].commit_oid,
            **{"target.version": "2", "target.digest": publication_two.payload["digest"]},
        )
        records.append(self.record(acceptance, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_wrong_recipient(self):
        records, _, _ = self.active_records(nonce=213)
        acceptance = self.event(
            "acceptance", 216, records[-1].commit_oid,
            **{
                "target.recipient.recipient_id": "recipient-2",
                "target.coverage_tuple.recipient_id": "recipient-2",
            },
        )
        records.append(self.record(acceptance, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_wrong_agreement(self):
        records, _, _ = self.active_records(nonce=217)
        acceptance = self.event(
            "acceptance", 220, records[-1].commit_oid,
            **{"target.coverage_tuple.agreement_id": "agreement-2"},
        )
        records.append(self.record(acceptance, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_acceptance_before_connection(self):
        acceptance = self.event("acceptance", 221, BASE)
        return self.negative_result([self.record(acceptance, BASE, 1)])

    def negative_invalid_supersession(self):
        records, _, _ = self.active_records(nonce=222)
        self.append(records, "acceptance", 225)
        second = self.event("acceptance", 226, records[-1].commit_oid, **{"payload.supersedes": "A" * 43})
        records.append(self.record(second, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_non_current_confirmed(self):
        records, _, _ = self.active_records(nonce=227)
        acceptance = self.event("acceptance", 230, BASE)
        records.append(self.record(acceptance, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_illegal_post_success(self):
        records, _, _ = self.active_records(nonce=231)
        self.append(records, "project_succeeded", 234)
        self.append(records, "config_updated", 235)
        return self.negative_result(records)

    def negative_conflicting_successor(self):
        records, _, _ = self.active_records(nonce=236)
        self.append(records, "project_succeeded", 239)
        second = self.event("project_succeeded", 240, **{"target.successor_project_id": "another-successor"})
        records.append(self.record(second, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_retired_revival(self):
        records, _, _ = self.active_records(nonce=241)
        publication_two = self.second_publication(records, 244)
        self.append(
            records,
            "agreement_activated",
            245,
            **{
                "target.version": "2",
                "payload.published_event_id": publication_two.event_id,
                "payload.supersedes_coverage": True,
                "payload.accepted_versions": ["2"],
            },
        )
        publication_one = records[1].event
        self.append(
            records,
            "agreement_activated",
            246,
            **{
                "payload.published_event_id": publication_one.event_id,
                "payload.accepted_versions": ["1"],
            },
        )
        return self.negative_result(records)

    def restore_records(self, nonce=247):
        records, _, activation = self.active_records(nonce=nonce)
        publication_two = self.second_publication(records, nonce + 3)
        activation_two = self.append(
            records,
            "agreement_activated",
            nonce + 4,
            **{
                "target.version": "2",
                "payload.published_event_id": publication_two.event_id,
                "payload.supersedes_coverage": True,
                "payload.accepted_versions": ["2"],
            },
        )
        return records, activation, activation_two

    def negative_restore_missing(self):
        records, _, _ = self.restore_records()
        self.append(records, "agreement_activation_restored", 252, **{"target.activation_event_id": "A" * 43})
        return self.negative_result(records)

    def negative_restore_cross_project(self):
        records, activation, _ = self.restore_records(253)
        value = copy.deepcopy(self.rows["agreement_activation_restored"])
        value["operation_nonce"] = base64url_encode((257).to_bytes(16, "big"))
        value["target"]["activation_event_id"] = activation.event_id
        value["project_id"] = "other-project"
        restored = self.validate(value)
        records.append(self.record(restored, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_restore_cross_agreement(self):
        records, activation, _ = self.restore_records(258)
        restored = self.event(
            "agreement_activation_restored", 263,
            **{"target.agreement_id": "agreement-2", "target.activation_event_id": activation.event_id},
        )
        records.append(self.record(restored, records[-1].commit_oid, len(records) + 1))
        return self.negative_result(records)

    def negative_restore_non_activation(self):
        records, _, _ = self.restore_records(264)
        publication_two = records[-2].event
        self.append(records, "agreement_activation_restored", 269, **{"target.activation_event_id": publication_two.event_id, "payload.accepted_versions": ["2"]})
        return self.negative_result(records)

    def negative_restore_set_mismatch(self):
        records, activation, _ = self.restore_records(270)
        self.append(
            records,
            "agreement_activation_restored",
            275,
            **{"target.activation_event_id": activation.event_id, "payload.accepted_versions": ["2"]},
        )
        return self.negative_result(records)

    def negative_m17(self):
        event = self.event("enforcement_scope_requested", 276)
        return self.negative_result([self.record(event, BASE, 1)])

    def test_timestamp_does_not_order_records(self):
        records, _, _ = self.active_records(nonce=277)
        value = records[0].event.to_dict()
        value["recorded_at"] = "2099-01-01T00:00:00Z"
        later = self.validate(value)
        records[0] = self.record(later, BASE, 1)
        result = self.negative_result(records)
        self.assertTrue(result.valid, result.error)

    def test_query_helpers_models_and_serialization_are_immutable(self):
        empty = initial_replay_state("project-1", BASE)
        self.assertEqual(project_lifecycle(empty).state, "unconnected")
        self.assertIsNone(current_configuration(empty))
        self.assertIsNone(active_agreement(empty))
        self.assertEqual(empty.to_dict()["unresolved"], [])
        with self.assertRaises(FrozenInstanceError):
            empty.current_head_oid = "a" * 40

        records, _, _ = self.active_records(nonce=278)
        result = replay_events("project-1", BASE, records)
        state = result.state
        self.assertIsInstance(state.recipient, MappingProxyType)
        self.assertIsInstance(state.publications, MappingProxyType)
        with self.assertRaises(TypeError):
            state.recipient["recipient_id"] = "other"
        with self.assertRaises(FrozenInstanceError):
            state.configuration = None
        active = active_agreement(state)
        self.assertIsInstance(active, ActiveAgreement)
        self.assertEqual(active["active_version"], "1")
        with self.assertRaises(FrozenInstanceError):
            active.active_version = "2"
        publication = next(iter(state.publications.values()))
        self.assertIsInstance(publication, AgreementPublication)
        self.assertIsInstance(publication.to_dict(), dict)
        activation = next(iter(state.activations.values()))
        self.assertIsInstance(activation, AgreementActivation)
        self.assertEqual(result.state.to_dict()["project_id"], "project-1")
        self.assertEqual(result.to_dict()["state"], result.state.to_dict())
        self.assertTrue(result.to_dict()["valid"])
        self.assertEqual(result.last_event_identity, records[-1].event.event_id)
        with self.assertRaises(FrozenInstanceError):
            result.state = None

    def test_direct_unresolved_representation_is_deterministic(self):
        values = {
            ((8, "agreement-1"), "z" * 43),
            ((7, "agreement-1"), "a" * 43),
        }
        first = ReplayState("project-1", BASE, BASE, unresolved=values)
        second = ReplayState("project-1", BASE, BASE, unresolved=set(reversed(tuple(values))))
        self.assertEqual(first.to_dict()["unresolved"], second.to_dict()["unresolved"])
        self.assertEqual(first.unresolved, frozenset(values))

    def test_model_and_input_validation_boundaries(self):
        with self.assertRaises(ReplayError):
            initial_replay_state("project-1", "not-an-oid")
        with self.assertRaises(ReplayError):
            CanonicalEventRecord("not-an-event", BASE, "a" * 40)
        event = self.event("project_connected", 279)
        with self.assertRaises(ReplayError):
            CanonicalEventRecord(event, BASE, BASE)
        with self.assertRaises(ReplayError):
            replay_events("project-1", BASE, "not-records")
        with self.assertRaises(ReplayError):
            apply_event("not-state", CanonicalEventRecord(event, "1" * 40, BASE))
        with self.assertRaises(ReplayError):
            ProjectLifecycle("project-1", "invalid")
        with self.assertRaises(ReplayError):
            ProjectLifecycle("project-1", "unconnected", "successor")
        with self.assertRaises(ReplayError):
            ProjectLifecycle("project-1", "succeeded")
        with self.assertRaises(ReplayError):
            ContributorTupleDecision(7, "project-1", "a", "r", "invalid", "e")
        with self.assertRaises(ReplayError):
            ContributorTupleDecision(7, "project-1", "a", "r", "covered", "e")
        with self.assertRaises(ReplayError):
            ContributorTupleDecision(7, "project-1", "a", "r", "uncovered", "e", version="1")
        with self.assertRaises(ReplayError):
            ActiveAgreement("a", "1", (), (), "e", False)

    def test_effective_query_applies_version_cutoff(self):
        records, _, _ = self.active_records(nonce=280)
        acceptance = self.append(records, "acceptance", 283)
        publication_two = self.second_publication(records, 284)
        self.append(
            records,
            "agreement_activated",
            285,
            **{
                "target.version": "2",
                "payload.published_event_id": publication_two.event_id,
                "payload.supersedes_coverage": True,
                "payload.accepted_versions": ["2"],
            },
        )
        result = self.negative_result(records)
        self.assertTrue(result.valid, result.error)
        key = acceptance.target["coverage_tuple"]
        latest = latest_contributor_tuple_decision(result.state, key)
        effective = effective_contributor_tuple_decision(result.state, key)
        self.assertEqual(latest.decision, "covered")
        self.assertEqual(effective.decision, "uncovered")
        self.assertIsNone(effective.version)

        fresh = self.append(
            records,
            "acceptance",
            286,
            **{"target.version": "2"},
        )
        resigned = replay_events("project-1", BASE, records)
        self.assertTrue(resigned.valid, resigned.error)
        latest = latest_contributor_tuple_decision(resigned.state, key)
        effective = effective_contributor_tuple_decision(resigned.state, key)
        self.assertEqual(latest.event_id, fresh.event_id)
        self.assertEqual(effective.decision, "covered")

    def test_additional_transition_and_query_boundaries(self):
        """Exercise the closed-state negative edges and every query shape."""
        records, publication, activation = self.active_records(nonce=290)
        state = self.negative_result(records).state

        # Public model aliases are read-only projections of immutable models.
        record = records[0]
        self.assertIs(record.validated_event, record.event)
        self.assertEqual(record.event_id, record.event.event_id)
        self.assertEqual(record.to_dict()["commit_oid"], record.commit_oid)
        self.assertEqual(state.head_oid, records[-1].commit_oid)
        self.assertEqual(state.events_head_oid, records[-1].commit_oid)
        self.assertEqual(state.lifecycle.state, "active")
        self.assertEqual(state.current_configuration, state.configuration)
        self.assertEqual(state.active_agreement_id, "agreement-1")
        self.assertEqual(state.accepted_version_set, ("1",))
        self.assertEqual(state.retired_version_set, ())
        self.assertEqual(state.published_agreements, state.publications)
        self.assertEqual(state.latest_decisions, state.tuple_decisions)
        self.assertEqual(state.currency_transition_event_id, activation.event_id)
        self.assertEqual(state.last_event_identity, activation.event_id)
        self.assertEqual(state.event_ids, tuple(state.event_records))
        self.assertEqual(len(state.idempotency_keys), len(state.event_records))

        decision = ContributorTupleDecision(7, "project-1", "agreement-1", "recipient-1", "covered", "e", "1", "sha256:" + "a" * 64)
        self.assertTrue(decision.is_covered)
        self.assertEqual(decision.tuple_key, (7, "agreement-1", "recipient-1"))
        self.assertEqual(decision["decision"], "covered")
        self.assertEqual(decision.to_dict()["version"], "1")
        lifecycle = project_lifecycle(state)
        self.assertEqual(lifecycle["state"], "active")
        self.assertEqual(lifecycle.to_dict()["project_id"], "project-1")
        agreement = active_agreement(state)
        self.assertEqual(agreement.version, "1")
        self.assertEqual(agreement["agreement_id"], "agreement-1")
        self.assertEqual(agreement.to_dict()["accepted_versions"], ["1"])
        result = self.negative_result(records)
        self.assertTrue(result.ok)
        self.assertTrue(result.is_valid)
        self.assertFalse(result.is_corrupt)
        self.assertIsNone(result.reason)
        self.assertIsNone(result.corruption_reason)
        corrupt = ReplayResult(None, ReplayCorruptionError("bad"), "event", "c" * 40)
        self.assertFalse(corrupt.valid)
        self.assertTrue(corrupt.corrupted)
        self.assertTrue(corrupt.is_corrupt)
        self.assertEqual(corrupt.error.args, ("bad",))
        self.assertEqual(corrupt.reason, "bad")
        self.assertEqual(corrupt.corruption_reason, "bad")
        self.assertEqual(corrupt.last_event_identity, "event")
        self.assertEqual(corrupt.to_dict(), {
            "valid": False,
            "corrupted": True,
            "state": None,
            "reason": "bad",
            "last_event_id": "event",
            "last_commit_oid": "c" * 40,
        })

        # Cover recursive freezing/thawing and immutable unresolved mapping
        # representation without making unresolved part of a valid M1 fold.
        direct = ReplayState(
            "project-1", BASE, BASE,
            recipient={"recipient_id": "r", "values": [1], "set": {2}},
            unresolved={("subject", "agreement-1"): "event"},
        )
        self.assertEqual(direct.to_dict()["unresolved"], [[["subject", "agreement-1"], "event"]])
        self.assertEqual(direct.to_dict()["recipient"]["values"], [1])
        self.assertEqual(direct.to_dict()["recipient"]["set"], [2])
        self.assertEqual(direct.unresolved, frozenset({(("subject", "agreement-1"), "event")}))

        nested = {"value": 1}
        tuple_state = ReplayState(
            "project-1",
            BASE,
            BASE,
            recipient={"nested": (nested,)},
        )
        nested["value"] = 2
        self.assertEqual(tuple_state.recipient["nested"][0]["value"], 1)
        with self.assertRaises(TypeError):
            tuple_state.recipient["nested"][0]["value"] = 3

        with self.assertRaises(ReplayError):
            ActiveAgreement("agreement-1", "1", ("1",), ("1",), "e", False)
        with self.assertRaises(ReplayError):
            AgreementActivation("e", "a", "1", "p", False, ("1", "1"))
        with self.assertRaises(ReplayError):
            AgreementActivation("e", "a", "1", "p", False, ("2", "1"))
        with self.assertRaises(ReplayError):
            ReplayState("project-1", BASE, BASE, project_state="invalid")
        with self.assertRaises(ReplayError):
            ReplayState("project-1", BASE, BASE, event_records={record.event_id: record})
        with self.assertRaises(ReplayError):
            ReplayState("project-1", BASE, BASE, project_state="succeeded")
        with self.assertRaises(ReplayError):
            ReplayState("project-1", BASE, BASE, accepted_versions=("1",), retired_versions=("1",))
        with self.assertRaises(ReplayError):
            ReplayState("project-1", BASE, BASE, publications=[])

        # Invalid canonical events and non-record inputs are corruption, while
        # malformed public arguments remain programmer errors.
        invalid = replace(record.event, operation_sha256="sha256:" + "f" * 64)
        invalid_result = self.negative_result([CanonicalEventRecord(invalid, "1" * 40, BASE)])
        self.assertIn("invalid event", invalid_result.reason)
        malformed = replace(record.event, authorizations=(object(),))
        malformed_result = self.negative_result(
            [CanonicalEventRecord(malformed, "2" * 40, BASE)]
        )
        self.assertIn("invalid event", malformed_result.reason)
        with self.assertRaises(ReplayError):
            apply_event(state, object())
        with self.assertRaises(ReplayError):
            initial_replay_state("", BASE)

        # Connection and lifecycle closure guards.
        duplicate_records = list(records)
        self.append(duplicate_records, "project_connected", 400)
        self.assertIn("genesis", self.negative_result(duplicate_records).reason)
        self.assertIn("successor", self.negative_result([self.record(self.event("project_connected", 292, **{"payload.successor_of": "project-1"}), BASE, 1)]).reason)
        owner = self.owner_transfer_event(293)
        owner_value = owner.to_dict()
        owner_value["target"]["prior_repository_owner"]["github_account_id"] = 999
        owner_bad = self.validate(owner_value)
        owner_records = [records[0], self.record(owner_bad, records[0].commit_oid, 2)]
        self.assertIn("current owner", self.negative_result(owner_records).reason)
        owner_value = owner.to_dict()
        owner_value["payload"]["project_slug"] = "other-slug"
        owner_bad = self.validate(owner_value)
        self.assertIn("project slug", self.negative_result([records[0], self.record(owner_bad, records[0].commit_oid, 2)]).reason)
        owner_value = owner.to_dict()
        owner_value["payload"]["repository_ids"]["records"] = 99
        for item in owner_value["authorizations"]:
            if item["operation"].endswith("records_repository"):
                item["resource_id"] = 99
        owner_bad = self.validate(owner_value)
        self.assertIn("repository set", self.negative_result([records[0], self.record(owner_bad, records[0].commit_oid, 2)]).reason)
        succeeded = self.event("project_succeeded", 294)
        succeeded_state = replace(state, successor_project_id="existing-successor")
        with self.assertRaises(ReplayCorruptionError) as closure_error:
            apply_event(succeeded_state, self.record(succeeded, state.current_head_oid, 99))
        self.assertIn("successor closure", str(closure_error.exception))

        closed_records, closed_publication, _ = self.active_records(nonce=430)
        self.append(closed_records, "project_succeeded", 433)
        closed_parent = closed_records[-1].commit_oid
        forbidden = (
            self.event("config_updated", 434),
            self.event("agreement_published", 435),
            self.event(
                "agreement_activated",
                436,
                **{"payload.published_event_id": closed_publication.event_id},
            ),
            self.event("acceptance", 437, closed_parent),
            self.owner_transfer_event(438),
        )
        for offset, event in enumerate(forbidden, start=1):
            with self.subTest(post_success_type=event.type):
                result = self.negative_result(
                    closed_records
                    + [self.record(event, closed_parent, len(closed_records) + offset)]
                )
                self.assertIn("forbidden after project success", result.reason)

        # Keyring and repository authorization bindings.
        keyring = self.event("keyring_activated", 295, BASE)
        self.assertIn("connection", self.negative_result([self.record(keyring, BASE, 1)]).reason)
        connected = self.event("project_connected", 296)
        connection_record = self.record(connected, BASE, 1)
        stale = self.event("keyring_activated", 297, connection_record.commit_oid, **{"payload.generation": 2})
        stale_record = self.record(stale, connection_record.commit_oid, 2)
        stale_again = self.event("keyring_activated", 298, stale_record.commit_oid, **{"payload.generation": 2})
        self.assertIn("does not advance", self.negative_result([connection_record, stale_record, self.record(stale_again, stale_record.commit_oid, 3)]).reason)
        key_event = self.event("keyring_activated", 299, connection_record.commit_oid, **{"payload.generation": 2})
        mismatched_key_state = replace(
            self.negative_result([connection_record, self.record(key_event, connection_record.commit_oid, 2)]).state,
            repository_ids={"records": 99, "coverage": 12, "control": 13},
        )
        key_event_two = self.event("keyring_activated", 317, mismatched_key_state.current_head_oid, **{"payload.generation": 3})
        with self.assertRaises(ReplayCorruptionError) as key_error:
            apply_event(mismatched_key_state, self.record(key_event_two, mismatched_key_state.current_head_oid, 3))
        self.assertIn("authorization set", str(key_error.exception))
        bad_auth = self.event("config_updated", 300, connection_record.commit_oid)
        mismatched_auth_state = replace(
            self.negative_result([connection_record]).state,
            repository_ids={"records": 99, "coverage": 12, "control": 13},
        )
        with self.assertRaises(ReplayCorruptionError) as auth_error:
            apply_event(mismatched_auth_state, self.record(bad_auth, mismatched_auth_state.current_head_oid, 2))
        self.assertIn("authorization", str(auth_error.exception))

        # Publication/activation exactness, including one agreement and one
        # immutable recipient.
        from dracla.conformance.artifacts import segment

        second_agreement = self.event(
            "agreement_published", 301,
            **{
                "target.agreement_id": "agreement-2",
                "payload.snapshot_content_path": f"agreements/{segment('agreement-2')}/{segment('1')}.md",
                "payload.snapshot_metadata_path": f"agreements/{segment('agreement-2')}/{segment('1')}.meta.json",
            },
        )
        self.assertIn("second agreement", self.negative_result(records[:2] + [self.record(second_agreement, records[1].commit_oid, 3)]).reason)
        wrong_recipient_publication = self.event("agreement_published", 302, **{"payload.recipient.legal_name": "Wrong Recipient"})
        self.assertIn("legal recipient", self.negative_result([records[0], self.record(wrong_recipient_publication, records[0].commit_oid, 2)]).reason)
        duplicate_publication = self.event("agreement_published", 303)
        self.assertIn("published more than once", self.negative_result(records[:2] + [self.record(duplicate_publication, records[1].commit_oid, 3)]).reason)
        bad_set_activation = self.event("agreement_activated", 305, **{"payload.published_event_id": publication.event_id, "payload.accepted_versions": ["2"]})
        self.assertIn("exact transition", self.negative_result(records[:2] + [self.record(bad_set_activation, records[1].commit_oid, 3)]).reason)

        # Acceptance/revocation history and configuration checks.
        acceptance = self.event("acceptance", 306, records[-1].commit_oid)
        no_config_state = replace(state, configuration=None)
        self.assertIn("configuration", str(self._apply_or_result(no_config_state, acceptance, records[-1].commit_oid, 4)))
        bad_digest = self.event("acceptance", 307, records[-1].commit_oid, **{"target.digest": "sha256:" + "b" * 64})
        self.assertIn("published agreement", self.negative_result(records + [self.record(bad_digest, records[-1].commit_oid, 4)]).reason)
        bad_fields = self.event("acceptance", 308, records[-1].commit_oid, **{"payload.fields": {}})
        self.assertIn("fields", self.negative_result(records + [self.record(bad_fields, records[-1].commit_oid, 4)]).reason)
        bad_labels = self.event("acceptance", 309, records[-1].commit_oid, **{"payload.confirmations": [{"label": "Other", "checked": True}]})
        self.assertIn("confirmations", self.negative_result(records + [self.record(bad_labels, records[-1].commit_oid, 4)]).reason)
        first_acceptance = self.append(records, "acceptance", 310)
        duplicate_acceptance = self.event("acceptance", 311, records[-1].commit_oid)
        self.assertIn("correction link", self.negative_result(records + [self.record(duplicate_acceptance, records[-1].commit_oid, len(records) + 1)]).reason)

        revoke_before = self.event("revocation", 312, BASE)
        self.assertIn("connection", self.negative_result([self.record(revoke_before, BASE, 1)]).reason)
        bad_revoke = self.event("revocation", 313, records[-1].commit_oid, **{"target.coverage_tuple.recipient_id": "recipient-2"})
        self.assertIn("legal recipient", self.negative_result(records + [self.record(bad_revoke, records[-1].commit_oid, len(records) + 1)]).reason)
        no_prior = self.event(
            "revocation", 314, records[-1].commit_oid,
            **{"actor.github_user_id": 8, "target.coverage_tuple.github_user_id": 8},
        )
        self.assertIn("prior", self.negative_result(records + [self.record(no_prior, records[-1].commit_oid, len(records) + 1)]).reason)
        revoke = self.append(records, "revocation", 315)
        duplicate_revoke = self.event("revocation", 316, records[-1].commit_oid)
        self.assertIn("duplicate revocation", self.negative_result(records + [self.record(duplicate_revoke, records[-1].commit_oid, len(records) + 1)]).reason)

        # Query coercion accepts canonical mappings, models, tuples and the
        # compact scalar form, while rejecting incomplete requests.
        key = (7, "agreement-1", "recipient-1")
        self.assertIsNone(latest_contributor_tuple_decision(state, key))
        self.assertIsNone(latest_contributor_tuple_decision(state, {"github_user_id": 7, "agreement_id": "agreement-1", "recipient_id": "recipient-1"}))
        self.assertIsNone(latest_contributor_tuple_decision(state, decision))
        self.assertIsNone(latest_contributor_tuple_decision(state, [7, "agreement-1", "recipient-1"]))
        self.assertIsNone(latest_contributor_tuple_decision(state, 7, "agreement-1", "recipient-1"))
        with self.assertRaises(ReplayError):
            latest_contributor_tuple_decision(state)
        with self.assertRaises(ReplayError):
            latest_contributor_tuple_decision(state, "bad")
        with self.assertRaises(ReplayError):
            latest_contributor_tuple_decision(
                state,
                {
                    "github_user_id": 7,
                    "project_id": "other-project",
                    "agreement_id": "agreement-1",
                    "recipient_id": "recipient-1",
                },
            )
        with self.assertRaises(ReplayError):
            latest_contributor_tuple_decision(
                state,
                ContributorTupleDecision(
                    7,
                    "other-project",
                    "agreement-1",
                    "recipient-1",
                    "uncovered",
                    "e",
                ),
            )
        self.assertIsNone(effective_contributor_tuple_decision(state, key))

    def _apply_or_result(self, state, event, parent, number):
        try:
            apply_event(state, self.record(event, parent, number))
        except ReplayCorruptionError as error:
            return str(error)
        return "valid"


if __name__ == "__main__":
    unittest.main()
