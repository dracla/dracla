"""Revision-14 closed event model and identity contract tests."""

from __future__ import annotations

import base64
import copy
import json
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    AuthorizationEvidence,
    EVENT_TYPES,
    EventValidationError,
    canonical_json,
    parse_event_jcs,
    validate_authorizations,
    validate_event,
)
from dracla.conformance import events as event_module  # noqa: E402


VECTORS = Path(__file__).parent / "vectors" / "events-v1.json"


class TestEventModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.rows = {row["type"]: row for row in cls.corpus["events"]}

    def test_vector_covers_closed_registry_and_recomputes_every_identity(self):
        self.assertEqual(set(self.rows), EVENT_TYPES)
        self.assertEqual(len(self.rows), 28)
        for value in self.rows.values():
            with self.subTest(event_type=value["type"]):
                event = validate_event(value, expected_project_id=value["project_id"])
                self.assertEqual(event.to_dict(), value)
                self.assertEqual(event.canonical_bytes, canonical_json(value))
                parsed = parse_event_jcs(event.canonical_bytes, expected_path=event.path)
                self.assertEqual(parsed, event)


    def test_models_and_nested_event_values_are_immutable(self):
        event = validate_event(self.rows["project_connected"])
        with self.assertRaises(FrozenInstanceError):
            event.project_id = "other"
        with self.assertRaises(TypeError):
            event.payload["project_slug"] = "other"
        with self.assertRaises(TypeError):
            event.payload["repository_ids"]["records"] = 99
        self.assertEqual(event.payload["project_slug"], "project-one")


    def test_revocation_rejects_actor_not_bound_to_coverage_subject(self):
        from dracla.conformance import derive_event_identity

        value = copy.deepcopy(self.rows["revocation"])
        value["actor"]["github_user_id"] = 999
        identity = derive_event_identity(value["project_id"], value["operation_nonce"], value["actor"], value["type"], value["target"], value["payload"], value["confirmed_canonical_oid"])
        value.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        with self.assertRaises(EventValidationError):
            validate_event(value)


    def test_expected_project_and_path_and_canonical_boundaries(self):
        value = copy.deepcopy(self.rows["revocation"])
        event = validate_event(value)
        with self.assertRaises(EventValidationError):
            validate_event(value, expected_project_id="other")
        with self.assertRaises(EventValidationError):
            validate_event(value, expected_path="events/aa/bb/not-an-event.enc.json")
        with self.assertRaises(EventValidationError):
            parse_event_jcs(event.canonical_bytes + b" ")
        with self.assertRaises(EventValidationError):
            parse_event_jcs(b'{"schema_version":1,"schema_version":1}')


    def test_representative_closed_schema_and_relation_negatives(self):
        cases = []
        value = copy.deepcopy(self.rows["config_updated"])
        value["payload"]["unexpected"] = True
        cases.append(value)
        value = copy.deepcopy(self.rows["project_connected"])
        value["payload"]["bootstrap"]["repository_ids"]["records"] = 99
        cases.append(value)
        value = copy.deepcopy(self.rows["override"])
        value["target"]["pull_request_number"] = 0
        cases.append(value)
        value = copy.deepcopy(self.rows["retry_requested"])
        value["target"]["check_kind"] = "unknown"
        cases.append(value)
        value = copy.deepcopy(self.rows["exemption_materialized"])
        value["payload"]["membership_evidence"]["github_user_id"] = 8
        cases.append(value)
        value = copy.deepcopy(self.rows["records_reader_snapshot_authorized"])
        value["target"]["subjects"].append(copy.deepcopy(value["target"]["subjects"][0]))
        cases.append(value)
        value = copy.deepcopy(self.rows["acceptance"])
        value["confirmed_canonical_oid"] = None
        cases.append(value)
        for case in cases:
            with self.subTest(event_type=case["type"]), self.assertRaises(EventValidationError):
                validate_event(case)


    def test_restore_event_rejects_non_exact_shape_and_authorization(self):
        for section, field in (
            ("target", "agreement_id"),
            ("target", "activation_event_id"),
            ("payload", "accepted_versions"),
            ("payload", "reason"),
        ):
            value = copy.deepcopy(self.rows["agreement_activation_restored"])
            del value[section][field]
            with self.subTest(section=section, missing=field), self.assertRaises(EventValidationError):
                validate_event(value)

        for section in ("target", "payload"):
            value = copy.deepcopy(self.rows["agreement_activation_restored"])
            value[section]["unexpected"] = True
            with self.subTest(section=section, extra=True), self.assertRaises(EventValidationError):
                validate_event(value)

        value = copy.deepcopy(self.rows["agreement_activation_restored"])
        value["authorizations"][0]["operation"] = "agreement_activate"
        with self.assertRaises(EventValidationError):
            validate_event(value)


    def test_checked_in_negative_vectors_are_executed(self):
        names = [case["name"] for case in self.corpus["negative_examples"]]
        self.assertEqual(
            set(names),
            {
                "unknown_event_type",
                "missing_top_level_member",
                "extra_top_level_member",
                "wrong_actor_kind",
                "missing_confirmed_head",
                "unsafe_repository_id",
                "extra_payload_member",
                "duplicate_subject",
                "wrong_snapshot_path",
                "wrong_authorization_pair",
                "unordered_scope_set",
                "identity_mismatch",
                "reserved_entity_authorized",
                "reserved_entity_deauthorized",
            },
        )
        self.assertEqual(len(names), len(set(names)))
        for case in self.corpus["negative_examples"]:
            with self.subTest(name=case["name"]), self.assertRaises(EventValidationError):
                validate_event(case["input"])


    def test_absolute_https_urls_reject_ambiguous_authority_and_escapes(self):
        for value in (
            "https://exa mple.test/path",
            "https://example.test/%ZZ",
            r"https://example.test/foo\bar",
            "https://example.test/\npath",
            "https://",
            "https://:443/path",
            "https://[bad]/path",
            "https://example.test:bad/path",
            "https://example.test:65536/path",
            "https://example.test:/path",
        ):
            with self.subTest(value=value), self.assertRaises(EventValidationError):
                event_module._url(value, "url")
        for value in ("https://example.test", "https://example.test/path%20ok", "https://example.test:443/path?x=1#fragment"):
            with self.subTest(value=value):
                self.assertEqual(event_module._url(value, "url"), value)


    def test_reachable_scalar_and_nested_validation_errors(self):
        bad = lambda function, *args: self.assertRaises(EventValidationError, function, *args)
        bad(event_module._object, None, "object")
        bad(event_module._object, {"bad": object()}, "object")
        bad(event_module._string, None, "string")
        bad(event_module._ascii_token, "é", "token")
        self.assertEqual(event_module._ascii_token("token", "token"), "token")
        bad(event_module._positive, 0, "id")
        bad(event_module._nonnegative, -1, "generation")
        bad(event_module._oid, "A" * 40, "oid")
        bad(event_module._digest, "sha256:" + "A" * 64, "digest")
        bad(event_module._timestamp, "2026-99-29T00:00:00Z", "timestamp")
        bad(event_module._timestamp, "bad", "timestamp")
        bad(event_module._event_id, 1, "event_id")
        bad(event_module._event_id, "bad", "event_id")
        bad(event_module._url, "http://example.test", "url")
        self.assertEqual(event_module._thaw(event_module._freeze({"x": [1]})), {"x": [1]})

        models = (
            event_module.CoverageTuple(1, "p", "a", "r"),
            event_module.Recipient("r", "R"),
            event_module.RepositoryOwner(1, "owner"),
            event_module.Subject(1, "user"),
            event_module.Team(1, 2, "team"),
            event_module.MembershipEvidence(1, 2, 1, "member", "2026-08-29T00:00:00Z", None, None),
            event_module.RepositoryIds(1, 2, 3),
            event_module.CurrentKids("r", "c"),
            event_module.ConfigurationField("name", "Name", "text"),
        )
        for model in models:
            self.assertIsInstance(model.to_dict(), dict)
        configuration = event_module.ProjectConfiguration("https://example.test", "retain", "correct", (models[-1],), ("agree",))
        self.assertIsInstance(configuration.to_dict(), dict)
        bootstrap = event_module.Bootstrap("install", "a" * 40, "sha256:" + "a" * 64, "b" * 40, event_module.RepositoryIds(1, 2, 3), event_module.CurrentKids("r", "c"))
        self.assertIsInstance(bootstrap.to_dict(), dict)
        self.assertIsInstance(event_module.ScopeSelector("repository", 1, "owner", "repo").to_dict(), dict)
        self.assertIsInstance(event_module.ScopeSelector("organization", 1, "org").to_dict(), dict)

        bad(event_module._parse_coverage, {})
        bad(event_module._parse_recipient, {})
        bad(event_module._parse_owner, {})
        bad(event_module._parse_subject, {})
        bad(event_module._parse_team, {})
        bad(event_module._parse_membership, {"organization_id": 1, "team_id": 2, "github_user_id": 1, "state": "member", "checked_at": "2026-08-29T00:00:00Z", "etag": "", "github_request_id": None})
        bad(event_module._parse_membership, {"organization_id": 1, "team_id": 2, "github_user_id": 1, "state": "unknown", "checked_at": "2026-08-29T00:00:00Z", "etag": None, "github_request_id": None})
        bad(event_module._parse_repo_ids, {"records": 1, "coverage": 1, "control": 3})
        bad(event_module._parse_kids, {})
        bad(event_module._parse_configuration, {"privacy_policy_url": "https://example.test", "retention_statement": "r", "correction_procedure": "c", "required_fields": {}, "confirmation_labels": []})
        bad(event_module._parse_configuration, {"privacy_policy_url": "https://example.test", "retention_statement": "r", "correction_procedure": "c", "required_fields": [], "confirmation_labels": {}})
        configuration_bad = copy.deepcopy(self.rows["project_connected"]["payload"]["project_configuration"])
        configuration_bad["required_fields"][0]["name"] = "not safe"
        bad(event_module._parse_configuration, configuration_bad)
        configuration_bad = copy.deepcopy(self.rows["project_connected"]["payload"]["project_configuration"])
        configuration_bad["required_fields"][0]["required"] = False
        bad(event_module._parse_configuration, configuration_bad)
        configuration_bad = copy.deepcopy(self.rows["project_connected"]["payload"]["project_configuration"])
        configuration_bad["required_fields"].append(copy.deepcopy(configuration_bad["required_fields"][0]))
        bad(event_module._parse_configuration, configuration_bad)
        configuration_bad = copy.deepcopy(self.rows["project_connected"]["payload"]["project_configuration"])
        configuration_bad["confirmation_labels"].append("I agree")
        bad(event_module._parse_configuration, configuration_bad)
        bad(event_module._parse_scope, {}, "scope")
        bad(event_module._parse_scope, [1], "scope")
        selector = self.rows["enforcement_scope_requested"]["payload"]["desired_scope"][0]
        bad(event_module._parse_scope, [selector, selector], "scope")
        bad(event_module._parse_scope, [{"kind": "unknown"}], "scope")
        bad(event_module._parse_scope, [{"kind": "repository", "repository_id": 1, "owner_snapshot": "z", "name_snapshot": "z"}, selector], "scope")
        bad(event_module._parse_subjects, [], "subjects")
        subject = self.rows["override"]["payload"]["subjects"][0]
        bad(event_module._parse_subjects, [subject, subject], "subjects")
        bad(event_module._parse_subjects, [{"github_user_id": 8, "login_snapshot": "z"}, subject], "subjects")
        bad(event_module._parse_actor, [], "revocation")
        bad(event_module._parse_actor, {}, "revocation")
        bad(event_module._parse_actor, {"kind": "automation", "principal": "worker-portal"}, "revocation")
        bad(event_module._parse_auth_structure, "not-an-array", "override")
        bad(event_module._parse_auth_structure, [], "override")
        bad(event_module._parse_auth_structure, [{"x": 1}], "acceptance")
        valid_auth = self.rows["override"]["authorizations"][0]
        parsed_auth = AuthorizationEvidence(**valid_auth)
        self.assertEqual(event_module._parse_auth_structure([parsed_auth], "override"), (parsed_auth,))
        bad(event_module._parse_auth_structure, [1], "override")
        auth = self.rows["override"]["authorizations"][0]
        bad(event_module._parse_auth_structure, [auth, auth], "override")
        keyring_auth = self.rows["keyring_activated"]["authorizations"]
        bad(event_module._parse_auth_structure, list(reversed(keyring_auth)), "keyring_activated")
        malformed_keyring_auth = AuthorizationEvidence(**keyring_auth[0])
        object.__setattr__(malformed_keyring_auth, "operation", "not-keyring")
        bad(event_module._parse_auth_structure, [malformed_keyring_auth], "keyring_activated")


    def test_optional_shapes_and_all_event_specific_rejection_branches(self):
        def invalid(event_type, path, value):
            row = copy.deepcopy(self.rows[event_type])
            target = row["target"]
            payload = row["payload"]
            (target if path[0] == "target" else payload)[path[1]] = value
            with self.assertRaises(EventValidationError):
                validate_event(row)
        invalid("acceptance", ("payload", "confirmations"), {})
        invalid("acceptance", ("payload", "fields"), [])
        invalid("acceptance", ("payload", "confirmations"), [{"label": "I agree", "checked": False}])
        invalid("acceptance", ("payload", "supersedes"), "bad")
        invalid("revocation", ("payload", "effect"), "bad")
        invalid("agreement_activated", ("payload", "supersedes_coverage"), 1)
        invalid("agreement_activated", ("payload", "accepted_versions"), [])
        invalid("agreement_activation_restored", ("target", "activation_event_id"), "bad")
        invalid("agreement_activation_restored", ("payload", "accepted_versions"), [])
        invalid("agreement_activation_restored", ("payload", "accepted_versions"), ["2", "1"])
        invalid("agreement_activation_restored", ("payload", "accepted_versions"), ["1", "1"])
        invalid("agreement_activation_restored", ("payload", "accepted_versions"), ["1", 2])
        invalid("agreement_activation_restored", ("payload", "accepted_versions"), "1")
        invalid("agreement_activation_restored", ("payload", "reason"), "")
        invalid("agreement_activation_restored", ("payload", "reason"), 1)
        invalid("project_connected", ("payload", "project_slug"), "Bad")
        invalid("project_repository_owner_changed", ("payload", "project_slug"), "Bad")
        invalid("override", ("payload", "instrument_ref"), 1)
        invalid("override_withdrawn", ("payload", "instrument_ref"), 1)
        invalid("retry_requested", ("target", "check_identity"), "bad")
        retry = copy.deepcopy(self.rows["retry_requested"])
        retry["target"]["check_kind"] = "merge_group"
        retry["target"]["check_identity"] = "a" * 40
        retry["operation_nonce"] = "bad"
        with self.assertRaises(EventValidationError):
            validate_event(retry)
        invalid("exemption", ("payload", "source_kind"), "bad")
        invalid("exemption", ("payload", "basis"), 1)
        individual = copy.deepcopy(self.rows["exemption"])
        individual["payload"] = {"source_kind": "individual", "basis": "basis", "instrument_ref": "ref"}
        individual["authorizations"][0]["operation"] = "exemption_individual_add"
        from dracla.conformance import derive_event_identity
        identity = derive_event_identity(individual["project_id"], individual["operation_nonce"], individual["actor"], individual["type"], individual["target"], individual["payload"], individual["confirmed_canonical_oid"])
        individual.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        self.assertEqual(validate_event(individual).type, "exemption")
        invalid("exemption_materialized", ("payload", "result"), "bad")
        membership_mismatch = copy.deepcopy(self.rows["exemption_materialized"])
        membership_mismatch["payload"]["membership_evidence"]["state"] = "not_member"
        with self.assertRaises(EventValidationError):
            validate_event(membership_mismatch)
        invalid("records_reader_materialized", ("payload", "prior_materialization_event_id"), "bad")


    def test_optional_valid_event_shapes_and_nonce_domains(self):
        from dracla.conformance import derive_automation_nonce, derive_event_identity, derive_github_retry_nonce

        acceptance = copy.deepcopy(self.rows["acceptance"])
        acceptance["payload"]["supersedes"] = acceptance["event_id"]
        identity = derive_event_identity(acceptance["project_id"], acceptance["operation_nonce"], acceptance["actor"], acceptance["type"], acceptance["target"], acceptance["payload"], acceptance["confirmed_canonical_oid"])
        acceptance.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        self.assertEqual(validate_event(acceptance).type, "acceptance")

        connected = copy.deepcopy(self.rows["project_connected"])
        connected["payload"]["successor_of"] = "previous-project"
        identity = derive_event_identity(connected["project_id"], connected["operation_nonce"], connected["actor"], connected["type"], connected["target"], connected["payload"], connected["confirmed_canonical_oid"])
        connected.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        self.assertEqual(validate_event(connected).type, "project_connected")

        retry = copy.deepcopy(self.rows["retry_requested"])
        retry["target"]["check_kind"] = "merge_group"
        retry["target"]["check_identity"] = "a" * 40
        retry["payload"]["github_delivery_id"] = None
        retry["operation_nonce"] = derive_github_retry_nonce(11, "merge_group", "a" * 40, None)
        identity = derive_event_identity(retry["project_id"], retry["operation_nonce"], retry["actor"], retry["type"], retry["target"], retry["payload"], retry["confirmed_canonical_oid"])
        retry.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        self.assertEqual(validate_event(retry).type, "retry_requested")

        materialized = copy.deepcopy(self.rows["exemption_materialized"])
        materialized["payload"]["prior_materialization_event_id"] = materialized["event_id"]
        materialized["operation_nonce"] = derive_automation_nonce(materialized["target"]["rule_event_id"], 7, "add", materialized["event_id"])
        identity = derive_event_identity(materialized["project_id"], materialized["operation_nonce"], materialized["actor"], materialized["type"], materialized["target"], materialized["payload"], materialized["confirmed_canonical_oid"])
        materialized.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        self.assertEqual(validate_event(materialized).type, "exemption_materialized")

        automation_wrong_nonce = copy.deepcopy(self.rows["exemption_materialized"])
        automation_wrong_nonce["operation_nonce"] = derive_automation_nonce(
            automation_wrong_nonce["target"]["rule_event_id"], 7, "withdraw", None,
        )
        identity = derive_event_identity(
            automation_wrong_nonce["project_id"], automation_wrong_nonce["operation_nonce"],
            automation_wrong_nonce["actor"], automation_wrong_nonce["type"],
            automation_wrong_nonce["target"], automation_wrong_nonce["payload"],
            automation_wrong_nonce["confirmed_canonical_oid"],
        )
        automation_wrong_nonce.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        with self.assertRaises(EventValidationError):
            validate_event(automation_wrong_nonce)

        scope_wrong_nonce = copy.deepcopy(self.rows["enforcement_scope_activated"])
        scope_wrong_nonce["operation_nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
        identity = derive_event_identity(
            scope_wrong_nonce["project_id"], scope_wrong_nonce["operation_nonce"],
            scope_wrong_nonce["actor"], scope_wrong_nonce["type"],
            scope_wrong_nonce["target"], scope_wrong_nonce["payload"],
            scope_wrong_nonce["confirmed_canonical_oid"],
        )
        scope_wrong_nonce.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        with self.assertRaises(EventValidationError):
            validate_event(scope_wrong_nonce)

        retry_wrong_nonce = copy.deepcopy(self.rows["retry_requested"])
        retry_wrong_nonce["operation_nonce"] = "AgICAgICAgICAgICAgICAg"
        identity = derive_event_identity(
            retry_wrong_nonce["project_id"], retry_wrong_nonce["operation_nonce"],
            retry_wrong_nonce["actor"], retry_wrong_nonce["type"],
            retry_wrong_nonce["target"], retry_wrong_nonce["payload"],
            retry_wrong_nonce["confirmed_canonical_oid"],
        )
        retry_wrong_nonce.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        with self.assertRaises(EventValidationError):
            validate_event(retry_wrong_nonce)

    def test_top_level_and_cross_field_fail_closed_boundaries(self):
        from dracla.conformance import derive_event_identity

        def invalid_top_level(event_type, field, value):
            row = copy.deepcopy(self.rows[event_type])
            row[field] = value
            with self.assertRaises(EventValidationError):
                validate_event(row)

        invalid_top_level("config_updated", "schema_version", 2)
        invalid_top_level("config_updated", "idempotency_key", "bad")
        invalid_top_level("config_updated", "confirmed_canonical_oid", "a" * 40)

        event = validate_event(self.rows["config_updated"])
        self.assertEqual(validate_event(event), event)
        self.assertEqual(event.event_path, event.path)

        def reidentify(row):
            identity = derive_event_identity(
                row["project_id"], row["operation_nonce"], row["actor"], row["type"],
                row["target"], row["payload"], row["confirmed_canonical_oid"],
            )
            row.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
            return row

        acceptance = copy.deepcopy(self.rows["acceptance"])
        acceptance["target"]["coverage_tuple"]["project_id"] = "other-project"
        with self.assertRaises(EventValidationError):
            validate_event(reidentify(acceptance))

        connected = copy.deepcopy(self.rows["project_connected"])
        connected["payload"]["bootstrap"]["repository_ids"]["records"] = 99
        with self.assertRaises(EventValidationError):
            validate_event(reidentify(connected))

        owner_change = copy.deepcopy(self.rows["project_repository_owner_changed"])
        owner_change["payload"]["new_repository_owner"] = owner_change["target"]["prior_repository_owner"]
        for authorization in owner_change["authorizations"]:
            if authorization["operation"] == "project_repository_owner_change_owner":
                authorization["resource_id"] = owner_change["payload"]["new_repository_owner"]["github_account_id"]
        with self.assertRaises(EventValidationError):
            validate_event(reidentify(owner_change))

        same_owner_id = copy.deepcopy(self.rows["project_repository_owner_changed"])
        same_owner_id["payload"]["new_repository_owner"] = {
            **same_owner_id["target"]["prior_repository_owner"],
            "login_snapshot": "renamed-owner",
        }
        for authorization in same_owner_id["authorizations"]:
            if authorization["operation"] == "project_repository_owner_change_owner":
                authorization["resource_id"] = same_owner_id["payload"]["new_repository_owner"]["github_account_id"]
        with self.assertRaisesRegex(EventValidationError, "different owner"):
            validate_event(reidentify(same_owner_id))

    def test_schema_version_requires_exact_builtin_integer_one(self):
        for schema_version in (True, 1.0):
            value = copy.deepcopy(self.rows["config_updated"])
            value["schema_version"] = schema_version
            with self.subTest(schema_version=schema_version), self.assertRaisesRegex(
                EventValidationError, "schema_version is not supported"
            ):
                validate_event(value)

        value = copy.deepcopy(self.rows["config_updated"])
        value["schema_version"] = 1
        self.assertEqual(validate_event(value).schema_version, 1)

    def test_scope_abandonment_reason_code_is_nonempty_string(self):
        from dracla.conformance import derive_event_identity

        def reidentify(row):
            identity = derive_event_identity(
                row["project_id"], row["operation_nonce"], row["actor"], row["type"],
                row["target"], row["payload"], row["confirmed_canonical_oid"],
            )
            row.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
            return row

        accepted = copy.deepcopy(self.rows["enforcement_scope_abandoned"])
        accepted["payload"]["reason_code"] = "理由"
        self.assertEqual(validate_event(reidentify(accepted)).payload["reason_code"], "理由")
        for value in ("", 7, None):
            rejected = copy.deepcopy(self.rows["enforcement_scope_abandoned"])
            rejected["payload"]["reason_code"] = value
            with self.subTest(value=value), self.assertRaises(EventValidationError):
                validate_event(reidentify(rejected))

    def test_unexpected_identity_errors_are_wrapped(self):
        with patch.object(event_module, "derive_event_identity", side_effect=ValueError("unexpected identity failure")):
            with self.assertRaises(EventValidationError):
                validate_event(self.rows["config_updated"])


    def test_checked_in_authorization_and_jcs_vectors(self):
        expected_authorization_ids = {
            "scope_repository_bind", "scope_repository_widen", "scope_repository_narrow", "scope_repository_remove",
            "scope_organization_bind", "scope_organization_widen", "scope_organization_narrow", "scope_organization_remove",
            "actor_github_administrative", "actor_automation_materialization",
        }
        self.assertEqual({case["id"] for case in self.corpus["authorization_cases"]}, expected_authorization_ids)
        self.assertEqual(len(self.corpus["authorization_cases"]), len(expected_authorization_ids))
        for case in self.corpus["authorization_cases"]:
            with self.subTest(category="authorization", case=case["id"]):
                if case.get("category") == "scope":
                    kind = case["resource_kind"]
                    resource_id = 41 if kind == "organization" else 31
                    operation = case["operation"]
                    action = operation.rsplit("_", 1)[-1]
                    selector = lambda resource, snapshot: {
                        "kind": kind,
                        ("organization_id" if kind == "organization" else "repository_id"): resource,
                        ("login_snapshot" if kind == "organization" else "owner_snapshot"): snapshot,
                        **({} if kind == "organization" else {"name_snapshot": "repo" if resource == 31 else "repo2"}),
                    }
                    if action == "bind":
                        prior, desired = [], [selector(resource_id, "snapshot")]
                    elif action == "widen":
                        prior, desired = [selector(resource_id, "snapshot")], [selector(resource_id, "snapshot"), selector(resource_id + 1, "snapshot2")]
                        resource_id += 1
                    elif action == "narrow":
                        prior, desired = [selector(resource_id, "snapshot"), selector(resource_id + 1, "snapshot2")], [selector(resource_id, "snapshot")]
                        resource_id += 1
                    else:
                        prior, desired = [selector(resource_id, "snapshot")], []
                    row = {
                        "operation": operation, "resource_kind": kind, "resource_id": resource_id,
                        "required_authority": "organization_owner" if kind == "organization" else "contributing_repository_admin",
                        "observed_authority": "admin", "authorized": True,
                        "checked_at": "2026-08-29T00:00:00Z", "github_request_id": None,
                    }
                    validate_authorizations(
                        "enforcement_scope_requested",
                        {"change_id": "oracle"},
                        {"prior_scope": prior, "desired_scope": desired, "prior_registry_generation": 0},
                        {"kind": case["actor_kind"], "github_user_id": 7, "login_snapshot": "admin"},
                        [row],
                    )
                else:
                    event = validate_event(self.rows[case["event_type"]])
                    self.assertEqual(event.actor["kind"], case["actor_kind"])
                self.assertEqual(case["expect"], "accept")

        expected_jcs_ids = {"invalid_utf8", "noncanonical_whitespace", "duplicate_key", "unsafe_number"}
        self.assertEqual({case["id"] for case in self.corpus["jcs_negative_cases"]}, expected_jcs_ids)
        self.assertEqual(len(self.corpus["jcs_negative_cases"]), len(expected_jcs_ids))
        for case in self.corpus["jcs_negative_cases"]:
            raw = base64.urlsafe_b64decode(case["bytes_b64"] + "===")
            with self.subTest(category="jcs", case=case["id"]), self.assertRaises(EventValidationError):
                parse_event_jcs(raw)
            self.assertEqual(case["expect"], "reject")
