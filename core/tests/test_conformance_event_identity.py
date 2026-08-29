"""Revision-13 event identity and authorization vocabulary contract tests."""

from __future__ import annotations

import inspect
import json
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    AUTHORIZATION_TABLE,
    AuthorizationEvidence,
    AuthorizationValidationError,
    EventIdentity,
    EventIdentityError,
    base64url_encode,
    canonical_json,
    derive_automation_nonce,
    derive_event_identity,
    derive_github_retry_nonce,
    derive_scope_terminal_nonce,
    event_path,
    new_operation_nonce,
    stable_actor_identity,
    validate_authorizations,
)

IDENTITY_VECTORS = Path(__file__).parent / "vectors" / "event-identities-v1.json"
AUTHORIZATION_VECTORS = Path(__file__).parent / "vectors" / "authorization-vocabulary-v1.json"


class TestEventIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(IDENTITY_VECTORS.read_text(encoding="utf-8"))

    def test_independent_identity_vector_is_exact(self):
        vector = self.vectors["event_identity"]
        self.assertEqual(self.vectors["schema_version"], 1)
        identity = derive_event_identity(
            vector["project_id"],
            vector["operation_nonce"],
            vector["actor"],
            vector["event_type"],
            vector["target"],
            vector["payload"],
            vector["confirmed_canonical_oid"],
        )
        self.assertEqual(identity.idempotency_key, vector["idempotency_key"])
        self.assertEqual(identity.operation_sha256, vector["operation_sha256"])
        self.assertEqual(identity.event_id, vector["event_id"])
        self.assertEqual(identity.path, vector["event_path"])
        self.assertEqual(identity.event_path, vector["event_path"])
        self.assertEqual(event_path(identity.event_id), vector["event_path"])
        self.assertFalse(hasattr(identity, "project_id"))

    def test_scope_terminal_identity_vectors_are_pairwise_distinct(self):
        identities = []
        activation_vector = None
        activation_identity = None
        for vector in self.vectors["scope_terminal_identity_variants"]:
            if vector["name"] in {"activation", "abandonment"}:
                derived_nonce = derive_scope_terminal_nonce(
                    vector["payload"]["request_event_id"], vector["event_type"]
                )
                self.assertEqual(derived_nonce, vector["operation_nonce"])
            if vector["name"] == "activation":
                activation_vector = vector
            identity = derive_event_identity(
                vector["project_id"],
                vector["operation_nonce"],
                vector["actor"],
                vector["event_type"],
                vector["target"],
                vector["payload"],
                vector["confirmed_canonical_oid"],
            )
            self.assertEqual(identity.operation_nonce, vector["operation_nonce"])
            self.assertEqual(identity.idempotency_key, vector["idempotency_key"])
            self.assertEqual(identity.operation_sha256, vector["operation_sha256"])
            self.assertEqual(identity.event_id, vector["event_id"])
            self.assertEqual(identity.path, vector["event_path"])
            identities.append(identity)
            if vector["name"] == "activation":
                activation_identity = identity
        self.assertEqual(len({identity.idempotency_key for identity in identities}), 3)
        self.assertEqual(len({identity.event_id for identity in identities}), 3)
        self.assertIsNotNone(activation_vector)
        self.assertIsNotNone(activation_identity)
        conflict = derive_event_identity(
            activation_vector["project_id"], activation_vector["operation_nonce"],
            activation_vector["actor"], activation_vector["event_type"],
            activation_vector["target"], {"request_event_id": "different"},
            activation_vector["confirmed_canonical_oid"],
        )
        # The deterministic child key/path identify the same attempted outcome;
        # a changed fingerprint is the conflict a writer/replay layer rejects.
        self.assertEqual(conflict.idempotency_key, activation_identity.idempotency_key)
        self.assertEqual(conflict.event_id, activation_identity.event_id)
        self.assertNotEqual(conflict.operation_sha256, activation_identity.operation_sha256)

    def test_identity_api_rejects_caller_supplied_key_or_event_id(self):
        vector = self.vectors["scope_terminal_identity_variants"][1]
        kwargs = {
            "project_id": vector["project_id"],
            "operation_nonce": vector["operation_nonce"],
            "actor": vector["actor"],
            "event_type": vector["event_type"],
            "target": vector["target"],
            "payload": vector["payload"],
            "confirmed_canonical_oid": vector["confirmed_canonical_oid"],
        }
        for name in ("idempotency_key", "event_id"):
            with self.subTest(name=name), self.assertRaises(TypeError):
                derive_event_identity(**kwargs, **{name: "caller-supplied"})
        # The child nonce is derived from the request and terminal type, not
        # independently supplied by the identity model.
        self.assertNotIn("idempotency_key", inspect.signature(derive_event_identity).parameters)
        self.assertNotIn("event_id", inspect.signature(derive_event_identity).parameters)

    def test_identity_requires_closed_event_type_without_target_payload_schema(self):
        vector = self.vectors["event_identity"]
        for event_type in ("unknown_event", "", "évenť"):
            with self.subTest(event_type=event_type), self.assertRaises(EventIdentityError):
                derive_event_identity(
                    vector["project_id"],
                    vector["operation_nonce"],
                    vector["actor"],
                    event_type,
                    {"arbitrary": [1, True]},
                    {"still": {"arbitrary": None}},
                    None,
                )
        # M1-4 checks only that these are objects; M1-5 owns their schemas.
        derive_event_identity(
            vector["project_id"], vector["operation_nonce"], vector["actor"],
            "acceptance", {"future_target": 1}, {"future_payload": ["x"]}, None,
        )

    def test_vector_negative_examples_reject_at_the_identity_boundary(self):
        cases = self.vectors["negative_examples"]
        expected_names = frozenset(
            {
                "unknown_event_type",
                "non_ascii_event_token",
                "unsafe_operation_nonce",
                "malformed_actor",
                "malformed_target",
                "malformed_payload",
                "unsafe_confirmed_oid",
                "caller_supplied_idempotency_key",
                "caller_supplied_event_id",
            }
        )
        self.assertEqual(len(cases), len(expected_names))
        self.assertEqual({case["name"] for case in cases}, expected_names)
        for case in cases:
            arguments = {
                key: case[key]
                for key in (
                    "project_id", "operation_nonce", "actor", "event_type",
                    "target", "payload", "confirmed_canonical_oid",
                )
            }
            with self.subTest(case=case["name"]):
                if "unexpected_kwargs" in case:
                    with self.assertRaises(TypeError):
                        derive_event_identity(**arguments, **case["unexpected_kwargs"])
                else:
                    with self.assertRaises(EventIdentityError):
                        derive_event_identity(**arguments)

    def test_vector_lists_the_complete_closed_event_type_set(self):
        vector = self.vectors["event_identity"]
        common_input = self.vectors["event_identity_common_input"]
        expected_vectors = self.vectors["event_identity_vectors"]
        self.assertEqual(set(self.vectors["event_types_v1"]), set(expected_vectors))
        self.assertEqual(len(expected_vectors), 27)
        automation_types = {"exemption_materialized", "records_reader_materialized"}
        self.assertEqual(
            {
                event_type
                for event_type, expected in expected_vectors.items()
                if expected["actor"]["kind"] == "automation"
            },
            automation_types,
        )
        self.assertEqual(
            {
                event_type
                for event_type, expected in expected_vectors.items()
                if expected["actor"]["kind"] == "github"
            },
            set(self.vectors["event_types_v1"]) - automation_types,
        )
        for event_type in self.vectors["event_types_v1"]:
            expected = expected_vectors[event_type]
            with self.subTest(event_type=event_type):
                identity = derive_event_identity(
                    common_input["project_id"], expected["operation_nonce"], expected["actor"],
                    event_type, common_input["target"], common_input["payload"],
                    expected["confirmed_canonical_oid"],
                )
                self.assertEqual(identity.operation_nonce, expected["operation_nonce"])
                self.assertEqual(identity.idempotency_key, expected["idempotency_key"])
                self.assertEqual(identity.operation_sha256, expected["operation_sha256"])
                self.assertEqual(identity.event_id, expected["event_id"])
                self.assertEqual(identity.path, expected["event_path"])

    def test_identity_and_actor_input_boundaries(self):
        vector = self.vectors["event_identity"]
        actor = vector["actor"]
        with self.assertRaises(EventIdentityError):
            stable_actor_identity(None)
        for bad_actor in (
            {"kind": "github", "github_user_id": 0, "login_snapshot": "x"},
            {"kind": "github", "github_user_id": 1, "login_snapshot": ""},
            {"kind": "github", "github_user_id": 1, "login_snapshot": "x", "extra": 1},
            {"kind": "automation", "principal": "other"},
        ):
            with self.subTest(actor=bad_actor), self.assertRaises(EventIdentityError):
                stable_actor_identity(bad_actor)
        with self.assertRaises(EventIdentityError):
            derive_event_identity("", vector["operation_nonce"], actor, "acceptance", {}, {}, None)
        with self.assertRaises(EventIdentityError):
            derive_event_identity("project-alpha", vector["operation_nonce"], actor, "acceptance", [], {}, None)
        with self.assertRaises(EventIdentityError):
            derive_event_identity("project-alpha", vector["operation_nonce"], actor, "acceptance", {"x": {1}}, {}, None)
        with self.assertRaises(EventIdentityError):
            derive_event_identity("project-alpha", vector["operation_nonce"], actor, "acceptance", {}, [], None)
        with self.assertRaises(EventIdentityError):
            derive_event_identity("project-alpha", vector["operation_nonce"], actor, "acceptance", {}, {"x": {1}}, None)
        with self.assertRaises(EventIdentityError):
            derive_event_identity("project-alpha", vector["operation_nonce"], actor, "acceptance", {}, {}, "not-an-oid")
        with self.assertRaises(EventIdentityError):
            EventIdentity(
                vector["operation_nonce"], vector["idempotency_key"], "bad", vector["event_id"], vector["event_path"]
            )
        with self.assertRaises(EventIdentityError):
            EventIdentity(
                "bad", vector["idempotency_key"], vector["operation_sha256"], vector["event_id"], vector["event_path"]
            )
        with self.assertRaises(EventIdentityError):
            EventIdentity(
                vector["operation_nonce"], vector["idempotency_key"], vector["operation_sha256"], "bad", vector["event_path"]
            )

    def test_stable_actor_identity_excludes_login_snapshot(self):
        for vector in self.vectors["actors"]:
            self.assertEqual(stable_actor_identity(vector["actor"]), vector["stable"])
        actor = self.vectors["actors"][0]["actor"]
        changed = {**actor, "login_snapshot": "renamed"}
        first = derive_event_identity("project-alpha", self.vectors["random_nonce"]["operation_nonce"], actor, "acceptance", {}, {}, None)
        second = derive_event_identity("project-alpha", self.vectors["random_nonce"]["operation_nonce"], changed, "acceptance", {}, {}, None)
        self.assertEqual(first, second)

    def test_random_and_deterministic_nonce_vectors_are_exact(self):
        random = self.vectors["random_nonce"]
        with patch("dracla.conformance.event_identity.secrets.token_bytes", return_value=bytes.fromhex(random["bytes_hex"])) as token_bytes:
            self.assertEqual(new_operation_nonce(), random["operation_nonce"])
        token_bytes.assert_called_once_with(16)

        automation = self.vectors["automation_nonce"]
        self.assertEqual(
            derive_automation_nonce(
                automation["rule_event_id"],
                automation["subject_user_id"],
                automation["result"],
                automation["prior_materialization_event_id"],
            ),
            automation["nonce"],
        )
        retry = self.vectors["github_retry_nonce"]
        self.assertEqual(
            derive_github_retry_nonce(
                retry["repository_id"],
                retry["check_kind"],
                retry["check_identity"],
                retry["github_delivery_id"],
            ),
            retry["nonce"],
        )
        terminals = self.vectors["scope_terminal_nonces"]
        self.assertEqual(
            derive_scope_terminal_nonce(terminals["request_event_id"], "enforcement_scope_activated"),
            terminals["activation"],
        )
        self.assertEqual(
            derive_scope_terminal_nonce(terminals["request_event_id"], "enforcement_scope_abandoned"),
            terminals["abandonment"],
        )
        self.assertNotEqual(terminals["activation"], terminals["abandonment"])

        for vector in self.vectors["deterministic_nonce_variants"]:
            with self.subTest(domain=vector["domain"], nonce=vector["nonce"]):
                if vector["domain"] == "automation":
                    actual = derive_automation_nonce(
                        vector["rule_event_id"], vector["subject_user_id"], vector["result"],
                        vector["prior_materialization_event_id"],
                    )
                elif vector["domain"] == "github_retry":
                    actual = derive_github_retry_nonce(
                        vector["repository_id"], vector["check_kind"], vector["check_identity"],
                        vector["github_delivery_id"],
                    )
                else:
                    actual = derive_scope_terminal_nonce(
                        vector["request_event_id"], vector["terminal_type"]
                    )
                self.assertEqual(actual, vector["nonce"])

    def test_scope_terminal_nonce_rejects_injected_child_digest_collision(self):
        class CollidingDigest:
            calls = 0

            def digest(self):
                self.calls += 1
                return b"\x00" * 16 + bytes([self.calls]) * 16

        with patch(
            "dracla.conformance.event_identity.hashlib.sha256",
            return_value=CollidingDigest(),
        ) as sha256:
            with self.assertRaises(EventIdentityError):
                derive_scope_terminal_nonce("request-event-1", "enforcement_scope_activated")
        self.assertEqual(sha256.call_count, 2)

    def test_nonce_and_event_boundaries_fail_closed(self):
        for bad in ("", "AAECAwQFBgcICQoLDA0ODw=", "short", bytes(16)):
            with self.subTest(bad=bad), self.assertRaises(EventIdentityError):
                derive_event_identity("project-alpha", bad, self.vectors["actors"][0]["actor"], "acceptance", {}, {}, None)
        for bad in ("", "not-an-event-id", "a" * 43 + "="):
            with self.subTest(bad=bad), self.assertRaises(EventIdentityError):
                event_path(bad)
        with self.assertRaises(EventIdentityError):
            with patch("dracla.conformance.event_identity.secrets.token_bytes", return_value=b"short"):
                new_operation_nonce()
        with self.assertRaises(EventIdentityError):
            with patch("dracla.conformance.event_identity.secrets.token_bytes", return_value="not-bytes"):
                new_operation_nonce()
        invalid_nonce_args = (
            ("", 1, "add", None),
            ("rule", 0, "add", None),
            ("rule", 1, "other", None),
            ("rule", 1, "add", ""),
        )
        for args in invalid_nonce_args:
            with self.subTest(args=args), self.assertRaises(EventIdentityError):
                derive_automation_nonce(*args)
        with self.assertRaises(EventIdentityError):
            derive_github_retry_nonce(1, "pull_request", 0, None)
        with self.assertRaises(EventIdentityError):
            derive_github_retry_nonce(1, "merge_group", "short", None)
        with self.assertRaises(EventIdentityError):
            derive_scope_terminal_nonce("request", "enforcement_scope_requested")
        with self.assertRaises(EventIdentityError):
            derive_github_retry_nonce(1, "other", 1, None)
        with self.assertRaises(EventIdentityError):
            derive_github_retry_nonce(1, "pull_request", 0, None)
        with self.assertRaises(EventIdentityError):
            derive_github_retry_nonce(1, "merge_group", "not-an-oid", None)
        with self.assertRaises(EventIdentityError):
            derive_github_retry_nonce(1, "pull_request", 1, "")

    def test_changed_payload_reuses_key_but_changes_operation_fingerprint(self):
        vector = self.vectors["event_identity"]
        first = derive_event_identity(
            vector["project_id"], vector["operation_nonce"], vector["actor"], vector["event_type"],
            vector["target"], self.vectors["changed_payload"]["original_payload"], vector["confirmed_canonical_oid"],
        )
        changed = derive_event_identity(
            vector["project_id"], vector["operation_nonce"], vector["actor"], vector["event_type"],
            vector["target"], self.vectors["changed_payload"]["changed_payload"], vector["confirmed_canonical_oid"],
        )
        self.assertEqual(first.idempotency_key, changed.idempotency_key)
        self.assertEqual(first.event_id, changed.event_id)
        self.assertNotEqual(first.operation_sha256, changed.operation_sha256)

    def test_models_are_immutable_and_identity_relation_is_checked(self):
        vector = self.vectors["event_identity"]
        identity = derive_event_identity(
            vector["project_id"], vector["operation_nonce"], vector["actor"], vector["event_type"],
            vector["target"], vector["payload"], vector["confirmed_canonical_oid"],
        )
        with self.assertRaises(FrozenInstanceError):
            identity.event_id = "changed"
        with self.assertRaises(EventIdentityError):
            EventIdentity(
                identity.operation_nonce, identity.idempotency_key,
                identity.operation_sha256, identity.event_id, "events/AA/AA/bad.enc.json",
            )


def _evidence(operation, resource_kind, resource_id, authority, *, request_id=None):
    return AuthorizationEvidence(
        operation=operation,
        resource_kind=resource_kind,
        resource_id=resource_id,
        required_authority=authority,
        observed_authority="observed",
        authorized=True,
        checked_at="2026-08-29T00:00:00Z",
        github_request_id=request_id,
    )


class TestAuthorizationVocabulary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(AUTHORIZATION_VECTORS.read_text(encoding="utf-8"))
        cls.actor = {"kind": "github", "github_user_id": 7, "login_snapshot": "admin"}
        cls.target = {}
        cls.payload = {}

    def test_vector_contains_every_literal_operation_pair(self):
        self.assertEqual(self.vectors["schema_version"], 1)
        expected = {(operation, kind, authority) for _event, operation, kind, authority in AUTHORIZATION_TABLE}
        actual = {tuple(row) for row in self.vectors["operation_rows"]}
        self.assertEqual(actual, expected)
        for operation, kind, authority in actual:
            item = _evidence(operation, kind, 101, authority)
            self.assertEqual(item.operation, operation)
        for operation, kind, authority in self.vectors["pair_rejections"]:
            with self.subTest(operation=operation):
                with self.assertRaises(AuthorizationValidationError):
                    AuthorizationEvidence(operation, kind, 101, authority, "observed", True, self.vectors["timestamp"], None)

    def test_authorization_model_rejects_malformed_evidence_and_timestamps(self):
        valid = {
            "operation": "agreement_publish",
            "resource_kind": "repository",
            "resource_id": 5,
            "required_authority": "records_repository_admin",
            "observed_authority": "ok",
            "authorized": True,
            "checked_at": self.vectors["timestamp"],
            "github_request_id": None,
        }
        with self.assertRaises(AuthorizationValidationError):
            AuthorizationEvidence("unknown", "repository", 5, "records_repository_admin", "ok", True, valid["checked_at"], None)
        with self.assertRaises(AuthorizationValidationError):
            AuthorizationEvidence("agreement_publish", "organization", 5, "records_repository_admin", "ok", True, valid["checked_at"], None)
        with self.assertRaises(AuthorizationValidationError):
            AuthorizationEvidence("agreement_publish", "repository", 0, "records_repository_admin", "ok", True, valid["checked_at"], None)
        with self.assertRaises(AuthorizationValidationError):
            AuthorizationEvidence("agreement_publish", "repository", 5, "records_repository_admin", "", True, valid["checked_at"], None)
        with self.assertRaises(AuthorizationValidationError):
            AuthorizationEvidence("agreement_publish", "repository", 5, "records_repository_admin", "ok", False, valid["checked_at"], None)
        for checked_at in ("not-a-timestamp", "2026-02-30T00:00:00Z"):
            with self.subTest(checked_at=checked_at), self.assertRaises(AuthorizationValidationError):
                AuthorizationEvidence(**{**valid, "checked_at": checked_at})
        with self.assertRaises(AuthorizationValidationError):
            AuthorizationEvidence(**{**valid, "github_request_id": ""})

    def test_authorization_container_and_object_boundaries(self):
        item = _evidence("agreement_publish", "repository", 5, "records_repository_admin")
        for authorizations in (None, "not-a-sequence", b"not-a-sequence"):
            with self.subTest(authorizations=authorizations), self.assertRaises(AuthorizationValidationError):
                validate_authorizations("agreement_published", {}, {}, self.actor, authorizations)
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, ["not-an-object"])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, [{**item.to_dict(), "extra": 1}])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, [{key: value for key, value in item.to_dict().items() if key != "operation"}])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", [], {}, self.actor, [item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {"bad": {1}}, self.actor, [item])
        # Evidence instances are accepted as already-validated immutable rows.
        self.assertEqual(validate_authorizations("agreement_published", {}, {}, self.actor, [item]), (item,))

    def test_vector_negative_examples_reject_at_the_authorization_boundary(self):
        self.assertNotIn("negative_cases", self.vectors)
        cases = self.vectors["negative_examples"]
        expected_names = frozenset(
            {
                "missing_authorization",
                "extra_authorization",
                "duplicate_authorization",
                "mismatched_target_resource",
                "unknown_event_type",
                "unknown_operation",
                "wrong_operation_pair",
                "actor_variant_violation",
                "unsafe_authorization_id",
                "unordered_authorization",
                "malformed_authorization_member",
                "authorization_missing_field",
                "authorization_extra_field",
                "authorization_false_result",
                "authorization_bad_timestamp",
                "authorization_bad_request_id",
                "missing_scope_payload",
                "scope_selector_extra_field",
                "scope_selector_unknown_kind",
                "scope_selector_unsafe_id",
                "scope_selector_duplicate",
                "scope_selector_unordered",
                "scope_wrong_pair",
                "scope_wrong_resource",
                "key_activation_missing_context",
                "key_activation_empty_context",
                "key_activation_incomplete_context",
                "key_activation_extra_context",
                "key_activation_duplicate_context",
                "key_activation_unsafe_context",
                "key_activation_wrong_evidence_set",
                "key_activation_wrong_pair",
                "non_keyring_affected_context",
                "key_activation_context_not_sequence",
                "key_activation_context_unsafe_large_id",
            }
        )
        self.assertEqual(len(cases), len(expected_names))
        self.assertEqual({case["name"] for case in cases}, expected_names)
        for case in cases:
            with self.subTest(case=case["name"]), self.assertRaises(AuthorizationValidationError):
                kwargs = {
                    "affected_repository_ids": case["affected_repository_ids"]
                } if "affected_repository_ids" in case else {}
                validate_authorizations(
                    case["event_type"], case["target"], case["payload"],
                    case["actor"], case["authorizations"], **kwargs,
                )

    def test_empty_authorization_actor_rules(self):
        for event_type in ("acceptance", "revocation"):
            self.assertEqual(validate_authorizations(event_type, {}, {}, self.actor, []), ())
        automation = {"kind": "automation", "principal": "worker-portal"}
        for event_type in ("exemption_materialized", "records_reader_materialized"):
            self.assertEqual(validate_authorizations(event_type, {}, {}, automation, []), ())
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("acceptance", {}, {}, automation, [])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("exemption_materialized", {}, {}, self.actor, [])

    def test_connection_requires_exact_seven_rows_bound_to_payload(self):
        payload = {
            "repository_owner": {"github_account_id": 10, "login_snapshot": "owner"},
            "repository_ids": {"records": 11, "coverage": 12, "control": 13},
        }
        rows = {
            "project_connect_owner": ("account", 10, "repository_owner_control"),
            "project_connect_records_repository": ("repository", 11, "project_repository_admin"),
            "project_connect_coverage_repository": ("repository", 12, "project_repository_admin"),
            "project_connect_control_repository": ("repository", 13, "project_repository_admin"),
            "project_connect_records_app": ("installation", 21, "records_app_binding"),
            "project_connect_enforcer_app": ("installation", 22, "enforcer_app_binding"),
            "project_connect_trigger_app": ("installation", 23, "trigger_app_binding"),
        }
        values = [_evidence(operation, kind, resource_id, authority) for operation, (kind, resource_id, authority) in rows.items()]
        values.sort(key=lambda item: item.canonical_bytes)
        result = validate_authorizations("project_connected", {}, payload, self.actor, values)
        self.assertEqual(tuple(item.operation for item in result), tuple(item.operation for item in values))
        for bad in (values[:-1], values + [values[0]], values[:1] + list(reversed(values[1:]))):
            with self.subTest(count=len(bad)), self.assertRaises(AuthorizationValidationError):
                validate_authorizations("project_connected", {}, payload, self.actor, bad)
        wrong = list(values)
        wrong[0] = _evidence("project_connect_records_repository", "repository", 999, "project_repository_admin")
        wrong.sort(key=lambda item: item.canonical_bytes)
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("project_connected", {}, payload, self.actor, wrong)

    def test_vector_connection_and_owner_transfer_cases_are_exact(self):
        for case in self.vectors["connection_cases"]:
            values = [
                _evidence(operation, kind, resource_id, authority)
                for operation, kind, resource_id, authority in case["rows"]
            ]
            with self.subTest(event_type=case["event_type"]):
                result = validate_authorizations(
                    case["event_type"], {}, case["payload"], self.actor, values
                )
                self.assertEqual(
                    [item.to_dict()["operation"] for item in result],
                    [row[0] for row in case["rows"]],
                )

    def test_connection_rows_reject_every_missing_or_mismatched_relation(self):
        case = self.vectors["connection_cases"][0]

        def values(rows):
            evidence = [_evidence(operation, kind, resource_id, authority) for operation, kind, resource_id, authority in rows]
            evidence.sort(key=lambda item: item.canonical_bytes)
            return evidence

        base = case["rows"]
        payload = case["payload"]
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, payload, self.actor, values(base[:-1]))
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, payload, self.actor, values(base + [base[0]]))
        duplicate_operation = list(base)
        duplicate_operation[-1] = [base[0][0], base[0][1], 999, base[0][3]]
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, payload, self.actor, values(duplicate_operation))
        missing_owner = {**payload}
        missing_owner.pop("repository_owner")
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, missing_owner, self.actor, values(base))
        missing_repositories = {**payload}
        missing_repositories.pop("repository_ids")
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, missing_repositories, self.actor, values(base))
        wrong_owner = {**payload, "repository_owner": {"github_account_id": 99, "login_snapshot": "owner"}}
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, wrong_owner, self.actor, values(base))
        wrong_repository = {**payload, "repository_ids": {"records": 999, "coverage": 12, "control": 13}}
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, wrong_repository, self.actor, values(base))
        duplicate_repositories = {**payload, "repository_ids": {"records": 11, "coverage": 11, "control": 13}}
        duplicate_repository_rows = list(base)
        duplicate_repository_rows[1] = [base[1][0], base[1][1], 11, base[1][3]]
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, duplicate_repositories, self.actor, values(duplicate_repository_rows))
        duplicate_apps = list(base)
        duplicate_apps[4] = [base[4][0], base[4][1], 22, base[4][3]]
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, payload, self.actor, values(duplicate_apps))

    def test_owner_transfer_uses_new_owner_payload_relation(self):
        case = self.vectors["connection_cases"][1]
        rows = [_evidence(operation, kind, resource_id, authority) for operation, kind, resource_id, authority in case["rows"]]
        self.assertEqual(len(validate_authorizations(case["event_type"], {}, case["payload"], self.actor, rows)), 7)
        wrong = {**case["payload"], "new_repository_owner": {"github_account_id": 21, "login_snapshot": "new-owner"}}
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(case["event_type"], {}, wrong, self.actor, rows)

    def test_scope_alternatives_bind_widen_narrow_remove_and_organization(self):
        def selector(kind, resource_id):
            if kind == "repository":
                return {"kind": kind, "repository_id": resource_id, "owner_snapshot": "owner", "name_snapshot": f"repo-{resource_id}"}
            return {"kind": kind, "organization_id": resource_id, "login_snapshot": f"org-{resource_id}"}

        cases = (
            ("enforcement_scope_repository_bind", [], [selector("repository", 31)]),
            ("enforcement_scope_repository_widen", [selector("repository", 31)], [selector("repository", 31), selector("repository", 32)]),
            ("enforcement_scope_repository_narrow", [selector("repository", 31), selector("repository", 32)], [selector("repository", 31)]),
            ("enforcement_scope_repository_remove", [selector("repository", 31)], []),
            ("enforcement_scope_organization_bind", [], [selector("organization", 41)]),
            ("enforcement_scope_organization_widen", [selector("organization", 41)], [selector("organization", 41), selector("organization", 42)]),
            ("enforcement_scope_organization_narrow", [selector("organization", 41), selector("organization", 42)], [selector("organization", 41)]),
            ("enforcement_scope_organization_remove", [selector("organization", 41)], []),
        )
        for operation, prior, desired in cases:
            kind = "organization" if "organization" in operation else "repository"
            authority = "organization_owner" if kind == "organization" else "contributing_repository_admin"
            identity_key = "organization_id" if kind == "organization" else "repository_id"
            if operation.endswith("_bind"):
                changed = desired
            elif operation.endswith("_widen"):
                changed = [item for item in desired if item not in prior]
            else:
                changed = [item for item in prior if item not in desired]
            resource_id = changed[0][identity_key]
            item = _evidence(operation, kind, resource_id, authority)
            with self.subTest(operation=operation):
                ordered = [item]
                self.assertEqual(
                    validate_authorizations(
                        "enforcement_scope_requested", {"change_id": "change"},
                        {"prior_scope": prior, "desired_scope": desired}, self.actor, ordered,
                    ),
                    (item,),
                )

    def test_scope_activation_and_abandonment_keep_one_literal_relation(self):
        selector = {"kind": "repository", "repository_id": 55, "owner_snapshot": "owner", "name_snapshot": "repo"}
        item = _evidence("enforcement_scope_repository_bind", "repository", 55, "contributing_repository_admin")
        self.assertEqual(
            validate_authorizations("enforcement_scope_activated", {"change_id": "c"}, {"desired_scope": [selector]}, self.actor, [item]),
            (item,),
        )
        self.assertEqual(
            validate_authorizations("enforcement_scope_abandoned", {"change_id": "c"}, {"reason_code": "operator_cancelled"}, self.actor, [item]),
            (item,),
        )

    def test_scope_rejects_malformed_sets_and_non_atomic_transitions(self):
        selector = {"kind": "repository", "repository_id": 55, "owner_snapshot": "owner", "name_snapshot": "repo"}
        selector_two = {"kind": "repository", "repository_id": 56, "owner_snapshot": "owner", "name_snapshot": "repo-2"}
        item = _evidence("enforcement_scope_repository_bind", "repository", 55, "contributing_repository_admin")
        base_target = {"change_id": "c"}

        malformed_sets = (
            ({"prior_scope": {}, "desired_scope": [selector]}, "bad prior type"),
            ({"prior_scope": ["not-an-object"], "desired_scope": [selector]}, "bad selector type"),
            ({"prior_scope": [{**selector, "extra": 1}], "desired_scope": [selector]}, "repo extra field"),
            ({"prior_scope": [{"kind": "organization", "organization_id": 1, "login_snapshot": "org", "extra": 1}], "desired_scope": []}, "org extra field"),
            ({"prior_scope": [{"kind": "other", "id": 1}], "desired_scope": []}, "unknown selector kind"),
            ({"prior_scope": [{**selector, "repository_id": 0}], "desired_scope": []}, "unsafe selector ID"),
            ({"prior_scope": [{**selector, "owner_snapshot": ""}], "desired_scope": []}, "empty snapshot"),
            ({"prior_scope": [{**selector, "owner_snapshot": 1}], "desired_scope": []}, "non-string snapshot"),
            ({"prior_scope": [selector, selector], "desired_scope": []}, "duplicate selector"),
            ({"prior_scope": [selector_two, selector], "desired_scope": []}, "unordered selectors"),
        )
        for payload, label in malformed_sets:
            with self.subTest(label=label), self.assertRaises(AuthorizationValidationError):
                validate_authorizations("enforcement_scope_requested", base_target, payload, self.actor, [item])

        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"desired_scope": [selector]}, self.actor, [item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": []}, self.actor, [item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": [], "desired_scope": [selector]}, self.actor, [])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": [], "desired_scope": [selector]}, self.actor, [item, _evidence("enforcement_scope_repository_widen", "repository", 55, "contributing_repository_admin")])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": [], "desired_scope": [selector]}, self.actor, [_evidence("agreement_publish", "repository", 5, "records_repository_admin")])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": [selector], "desired_scope": [selector, selector_two, {**selector_two, "repository_id": 57}]}, self.actor, [item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": [], "desired_scope": [selector, selector_two]}, self.actor, [item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_requested", base_target, {"prior_scope": [selector], "desired_scope": [selector, selector_two]}, self.actor, [_evidence("enforcement_scope_repository_widen", "repository", 999, "contributing_repository_admin")])

        activation_payload = {"desired_scope": [selector]}
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_activated", base_target, activation_payload, self.actor, [_evidence("enforcement_scope_repository_bind", "repository", 999, "contributing_repository_admin")])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("enforcement_scope_activated", base_target, {}, self.actor, [item])

    def test_scope_actor_and_authorization_shape_rules(self):
        selector = {"kind": "organization", "organization_id": 41, "login_snapshot": "org"}
        item = _evidence("enforcement_scope_organization_bind", "organization", 41, "organization_owner")
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "enforcement_scope_requested", {"change_id": "c"}, {"prior_scope": [], "desired_scope": [selector]},
                {"kind": "automation", "principal": "worker-portal"}, [item],
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "enforcement_scope_requested", {"change_id": "c"}, {"prior_scope": [], "desired_scope": [selector]},
                self.actor, [_evidence("enforcement_scope_repository_bind", "repository", 41, "contributing_repository_admin")],
            )

    def test_every_fixed_event_row_and_target_repository_relation(self):
        fixed = {
            "project_succeeded": ("project_succeed", "repository", "records_repository_admin"),
            "agreement_published": ("agreement_publish", "repository", "records_repository_admin"),
            "agreement_activated": ("agreement_activate", "repository", "records_repository_admin"),
            "config_updated": ("project_config_update", "repository", "records_repository_admin"),
            "exemption_snapshot": ("exemption_snapshot_add", "repository", "records_repository_admin"),
            "exemption_source_withdrawn": ("exemption_source_withdraw", "repository", "records_repository_admin"),
            "exemption_rule_configured": ("exemption_rule_configure", "repository", "records_repository_admin"),
            "exemption_rule_withdrawn": ("exemption_rule_withdraw", "repository", "records_repository_admin"),
            "records_reader_authorized": ("records_reader_individual_add", "repository", "records_repository_admin"),
            "records_reader_snapshot_authorized": ("records_reader_snapshot_add", "repository", "records_repository_admin"),
            "records_reader_withdrawn": ("records_reader_source_withdraw", "repository", "records_repository_admin"),
            "records_reader_rule_configured": ("records_reader_rule_configure", "repository", "records_repository_admin"),
            "records_reader_rule_withdrawn": ("records_reader_rule_withdraw", "repository", "records_repository_admin"),
            "override_withdrawn": ("override_withdraw", "repository", "contributing_repository_maintain"),
        }
        for event_type, row in fixed.items():
            item = _evidence(row[0], row[1], 99, row[2])
            with self.subTest(event_type=event_type):
                self.assertEqual(validate_authorizations(event_type, {}, {}, self.actor, [item]), (item,))
        for event_type, row in (("override", ("override_grant", "repository", "contributing_repository_maintain")), ("retry_requested", ("retry_request", "repository", "contributing_repository_write"))):
            item = _evidence(row[0], row[1], 99, row[2])
            self.assertEqual(validate_authorizations(event_type, {"repository_id": 99}, {}, self.actor, [item]), (item,))
            with self.assertRaises(AuthorizationValidationError):
                validate_authorizations(event_type, {"repository_id": 100}, {}, self.actor, [item])

    def test_key_activation_requires_one_row_per_affected_repository(self):
        values = [_evidence("keyring_activate", "repository", resource_id, "project_repository_admin") for resource_id in (11, 12, 13)]
        values.sort(key=lambda item: item.canonical_bytes)
        affected_repository_ids = (11, 12, 13)
        self.assertEqual(
            validate_authorizations(
                "keyring_activated", {}, {}, self.actor, values,
                affected_repository_ids=affected_repository_ids,
            ),
            tuple(values),
        )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "keyring_activated", {}, {}, self.actor, [],
                affected_repository_ids=affected_repository_ids,
            )
        wrong = list(values)
        wrong[0] = _evidence("keyring_activate", "repository", 11, "project_repository_admin", request_id="different")
        # Different request IDs do not change row identity; duplicate resource IDs do.
        wrong[1] = _evidence("keyring_activate", "repository", 11, "project_repository_admin")
        wrong.sort(key=lambda item: item.canonical_bytes)
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "keyring_activated", {}, {}, self.actor, wrong,
                affected_repository_ids=affected_repository_ids,
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "keyring_activated", {}, {}, self.actor,
                [_evidence("agreement_publish", "repository", 11, "records_repository_admin")],
                affected_repository_ids=(11,),
            )

    def test_vector_key_activation_case_covers_multiple_repositories(self):
        case = self.vectors["key_activation_cases"][0]
        values = [
            _evidence(operation, kind, resource_id, authority)
            for operation, kind, resource_id, authority in case["rows"]
        ]
        self.assertEqual(
            validate_authorizations(
                case["event_type"], {}, {}, self.actor, values,
                affected_repository_ids=case["affected_repository_ids"],
            ),
            tuple(values),
        )

    def test_vector_scope_cases_cover_every_repository_and_organization_alternative(self):
        def expected_selector(case):
            operation = case["operation"]
            kind = "organization" if "organization" in operation else "repository"
            key = "organization_id" if kind == "organization" else "repository_id"
            if operation.endswith("_bind"):
                resource_id = case["desired_scope"][0][key]
            elif operation.endswith("_widen"):
                resource_id = case["desired_scope"][-1][key]
            else:
                resource_id = case["prior_scope"][-1][key]
            authority = "organization_owner" if kind == "organization" else "contributing_repository_admin"
            return kind, resource_id, authority

        for case in self.vectors["scope_cases"]:
            kind, resource_id, authority = expected_selector(case)
            item = _evidence(case["operation"], kind, resource_id, authority)
            with self.subTest(operation=case["operation"]):
                self.assertEqual(
                    validate_authorizations(
                        "enforcement_scope_requested",
                        {"change_id": "change"},
                        {"prior_scope": case["prior_scope"], "desired_scope": case["desired_scope"]},
                        self.actor,
                        [item],
                    ),
                    (item,),
                )

    def test_authorization_schema_order_duplicate_and_unknown_rejections(self):
        item = _evidence("agreement_publish", "repository", 5, "records_repository_admin")
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, [item, item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, [item, _evidence("agreement_activate", "repository", 5, "records_repository_admin")])
        reversed_items = [
            _evidence("agreement_publish", "repository", 5, "records_repository_admin"),
            _evidence("project_config_update", "repository", 5, "records_repository_admin"),
        ]
        # config_updated is not the agreement-publish action, so this is a
        # cross-row failure independent of order.
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, reversed_items)
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("unknown_event", {}, {}, self.actor, [])
        malformed = {"operation": "agreement_publish", "resource_kind": "repository", "resource_id": 5, "required_authority": "records_repository_admin", "observed_authority": "ok", "authorized": False, "checked_at": "2026-08-29T00:00:00Z", "github_request_id": None}
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, [malformed])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("agreement_published", {}, {}, self.actor, [{**item.to_dict(), "extra": 1}])

    def test_exemption_variants_fixed_rows_and_target_relations(self):
        for source_kind, operation in (("bot", "exemption_bot_add"), ("individual", "exemption_individual_add")):
            item = _evidence(operation, "repository", 5, "records_repository_admin")
            self.assertEqual(
                validate_authorizations("exemption", {}, {"source_kind": source_kind}, self.actor, [item]),
                (item,),
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "exemption", {}, {"source_kind": "unknown"}, self.actor,
                [_evidence("exemption_bot_add", "repository", 5, "records_repository_admin")],
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "exemption", {}, {"source_kind": "bot"}, self.actor,
                [_evidence("exemption_individual_add", "repository", 5, "records_repository_admin")],
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "override", {}, {}, self.actor,
                [_evidence("override_grant", "repository", 5, "contributing_repository_maintain")],
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "retry_requested", {"repository_id": 0}, {}, self.actor,
                [_evidence("retry_request", "repository", 5, "contributing_repository_write")],
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "override", {"repository_id": 5}, {}, self.actor,
                [_evidence("retry_request", "repository", 5, "contributing_repository_write")],
            )
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "exemption", {}, {"source_kind": "bot"},
                {"kind": "automation", "principal": "worker-portal"},
                [_evidence("exemption_bot_add", "repository", 5, "records_repository_admin")],
            )

    def test_no_authorization_events_reject_nonempty_evidence(self):
        item = _evidence("agreement_publish", "repository", 5, "records_repository_admin")
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations("acceptance", {}, {}, self.actor, [item])
        with self.assertRaises(AuthorizationValidationError):
            validate_authorizations(
                "exemption_materialized", {}, {}, {"kind": "automation", "principal": "worker-portal"}, [item]
            )


if __name__ == "__main__":
    unittest.main()
