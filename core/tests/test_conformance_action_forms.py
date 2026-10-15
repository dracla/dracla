"""HLD §5.4 byte, authentication, context and immutable-effect conformance."""

import base64
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))

from dracla.conformance import (  # noqa: E402
    ActionForm, ActionFormContext, ActionFormError, CanonicalEventRecord,
    EVENT_TYPES, VerifiedActionForm, canonical_json, current_configuration,
    derive_event_identity, encode_action_form, form_action_spec, replay_events,
    validate_event, validate_terminal_noop, verify_action_form,
)
from dracla.conformance import action_forms as module  # noqa: E402


VECTORS = Path(__file__).parent / "vectors"


class TestActionForms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads((VECTORS / "action-form-v1.json").read_text())
        cls.events = {row["type"]: row for row in json.loads((VECTORS / "events-v1.json").read_text())["events"]}
        cls.keys = {row["kid"]: bytes.fromhex(row["key_hex"]) for row in cls.corpus["keys"]}
        cls.key = next(iter(cls.keys.values()))

    def _context(self, payload, **changes):
        values = {name: payload[name] for name in (
            "session_jti", "github_user_id", "project_id", "type",
            "operation_nonce", "confirmed_canonical_oid", "operation_sha256",
        )}
        values.update(self.corpus["context"])
        values.update(changes)
        return ActionFormContext(**values)

    def _signed_bytes(self, data, key=None):
        tag = hmac.new(key or self.key, b"dracla-action-form-v1\0" + data, hashlib.sha256).digest()
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
        return b64(data) + "." + b64(tag)

    def _signed(self, value, key=None):
        return self._signed_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), key)

    def _payload(self):
        return copy.deepcopy(self.corpus["golden"]["form"])

    def _verify(self, payload, **context_changes):
        return verify_action_form(self._signed(payload), keys=self.keys, context=self._context(payload, **context_changes))

    def _bind_operation(self, payload, operation):
        head = payload["confirmed_canonical_oid"] if payload["type"] in {"acceptance", "revocation"} else None
        payload["operation_sha256"] = derive_event_identity(
            payload["project_id"], payload["operation_nonce"],
            {"kind": "github", "github_user_id": payload["github_user_id"], "login_snapshot": "changed-login"},
            payload["type"], operation["target"], operation["payload"], head,
        ).operation_sha256

    def _prove(self, payload, terminal, operation, **changes):
        expected = {"expected_project_id": payload["project_id"], "expected_confirmed_oid": payload["confirmed_canonical_oid"]}
        expected.update(changes)
        validate_terminal_noop(self._verify(payload, confirmed_canonical_oid=self.corpus["later_head"]), terminal, operation, **expected)

    def _event_identity(self, event):
        identity = derive_event_identity(
            event["project_id"], event["operation_nonce"], event["actor"], event["type"],
            event["target"], event["payload"], event["confirmed_canonical_oid"],
        )
        event.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        return event

    def test_independent_fixed_jcs_tag_and_one_dot_token(self):
        golden = self.corpus["golden"]
        payload = golden["form"]
        self.assertEqual(canonical_json(payload), golden["payload_jcs"].encode())
        self.assertEqual(encode_action_form(payload, key=self.key), golden["token"])
        self.assertEqual(encode_action_form(ActionForm(**payload), key=self.key), golden["token"])
        left, right = golden["token"].split(".")
        self.assertNotIn("=", left + right)
        self.assertEqual(base64.urlsafe_b64decode(right + "="), bytes.fromhex(golden["tag_hex"]))
        verified = verify_action_form(golden["token"], keys=self.keys, context=self._context(payload))
        self.assertIsInstance(verified, VerifiedActionForm)
        self.assertEqual(verified.form.to_dict(), payload)
        self.assertTrue(verified.preparable)
        self.assertFalse(verified.is_noop)
        with self.assertRaises(FrozenInstanceError):
            verified.form.type = "override"
        with self.assertRaises(ActionFormError):
            VerifiedActionForm(None)

    def test_verified_result_requires_authentication_factory(self):
        payload = self._payload()
        for terminal in (None, self.events["config_updated"]["event_id"]):
            with self.subTest(terminal=terminal):
                payload["terminal_noop_event_id"] = terminal
                form = ActionForm(**payload)
                with self.assertRaises(ActionFormError):
                    VerifiedActionForm(form)
                with self.assertRaises(ActionFormError):
                    VerifiedActionForm(form, _verified=object())
                verified = self._verify(payload)
                self.assertEqual(verified.form, form)
                self.assertEqual(verified.preparable, terminal is None)
                with self.assertRaises(ActionFormError):
                    replace(verified, form=form)
                with self.assertRaises(FrozenInstanceError):
                    verified.form = form

    def test_closed_registry_has_every_table_row_and_no_internal_action(self):
        expected = EVENT_TYPES - {"enforcement_scope_activated", "enforcement_scope_abandoned", "exemption_materialized", "records_reader_materialized"}
        self.assertEqual({row["type"] for row in self.corpus["actions"]}, expected)
        self.assertEqual(len(expected), 24)
        for row in self.corpus["actions"]:
            spec = form_action_spec(row["type"])
            self.assertEqual((spec.action_type, spec.write_type, spec.terminal_types), (row["type"], row["write_type"], tuple(row["terminal_types"])))
        for name in list(EVENT_TYPES - expected) + ["unknown", "", None, [], True]:
            with self.subTest(name=name), self.assertRaises(ActionFormError):
                form_action_spec(name)

    def test_active_and_explicitly_eligible_predecessor_keys(self):
        for kid, key in self.keys.items():
            payload = self._payload()
            payload["kid"] = kid
            token = encode_action_form(payload, key=key)
            self.assertEqual(verify_action_form(token, keys=self.keys, context=self._context(payload)).form.kid, kid)
            remaining = {k: v for k, v in self.keys.items() if k != kid}
            with self.assertRaises(ActionFormError):
                verify_action_form(token, keys=remaining, context=self._context(payload))
            with self.assertRaises(ActionFormError):
                verify_action_form(token, keys={kid: b"wrong-secret"}, context=self._context(payload))

    def test_malformed_token_encodings(self):
        token = self.corpus["golden"]["token"]
        left, right = token.split(".")
        cases = [None, 1, [], "", left, ".", token + ".", token + ".x", left + "=." + right, left + "." + right + "=", left + ".AA", "!." + right, left + ".!", " " + token]
        for value in cases:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ActionFormError):
                verify_action_form(value, keys=self.keys, context=self._context(self._payload()))

    def test_noncanonical_and_malformed_payload_bytes(self):
        payload = self._payload()
        canonical = canonical_json(payload)
        candidates = [json.dumps(payload, indent=2).encode(), canonical + b"\n", b"\xff", b"{", b"null", b"[]", b'{"v":1,"v":1}']
        for value in candidates:
            with self.subTest(size=len(value)), self.assertRaises(ActionFormError):
                verify_action_form(self._signed_bytes(value), keys=self.keys, context=self._context(payload))

    def test_closed_payload_field_and_scalar_rejections(self):
        cases = [None, [], {}, dict(self._payload(), extra=True)]
        mutations = {
            "v": [True, 2, "1"], "algorithm": ["none", "HS512", []],
            "kid": ["", "AA", "S0tLS0tLS0tLS0tLS0tLSw="],
            "session_jti": ["", 17], "github_user_id": [True, 0, -1, 1.5, 2**53],
            "project_id": ["", None], "type": ["exemption_materialized", "other", []],
            "operation_nonce": ["AA", "", "="], "confirmed_canonical_oid": [None, "A" * 40, "d" * 39],
            "operation_sha256": ["0" * 64, "sha256:" + "A" * 64],
            "terminal_noop_event_id": ["", "AA", True],
            "issued_at": ["2026-02-30T12:00:00Z", "2026-01-02T12:00:00+00:00", "2026-01-02T12:00:00.000Z"],
            "expires_at": ["2026-01-02T11:59:59Z", "2026-01-02T19:55:01Z"],
        }
        for name, values in mutations.items():
            for value in values:
                payload = self._payload()
                payload[name] = value
                cases.append(payload)
        missing = self._payload()
        del missing["terminal_noop_event_id"]
        cases.append(missing)
        for value in cases:
            with self.subTest(shape=type(value).__name__), self.assertRaises(ActionFormError):
                encode_action_form(value, key=self.key)
            with self.assertRaises(ActionFormError):
                verify_action_form(self._signed(value), keys=self.keys, context=self._context(self._payload()))

    def test_retry_has_no_terminal_noop_alternative(self):
        payload = self._payload()
        payload.update(type="retry_requested", terminal_noop_event_id=self.events["retry_requested"]["event_id"])
        with self.assertRaises(ActionFormError):
            encode_action_form(payload, key=self.key)

    def test_bad_keys_and_untyped_context(self):
        payload = self._payload()
        for key in [b"", "secret", bytearray(b"secret"), None]:
            with self.subTest(key_type=type(key).__name__), self.assertRaises(ActionFormError):
                encode_action_form(payload, key=key)
            with self.assertRaises(ActionFormError):
                verify_action_form(self._signed(payload), keys={payload["kid"]: key}, context=self._context(payload))
        for keys in [None, [], {}]:
            with self.assertRaises(ActionFormError):
                verify_action_form(self._signed(payload), keys=keys, context=self._context(payload))
        with self.assertRaises(ActionFormError):
            verify_action_form(self._signed(payload), keys=self.keys, context={})

    def test_constant_time_tag_comparison_for_valid_and_wrong_tags(self):
        compare = hmac.compare_digest
        payload = self._payload()
        token = self._signed(payload)
        left, right = token.split(".")
        raw = bytearray(base64.urlsafe_b64decode(right + "="))
        raw[0] ^= 1
        wrong = left + "." + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        with patch.object(module.hmac, "compare_digest", wraps=compare) as compared:
            self._verify(payload)
            self.assertEqual(compared.call_count, 1)
            with self.assertRaises(ActionFormError):
                verify_action_form(wrong, keys=self.keys, context=self._context(payload))
            self.assertEqual(compared.call_count, 2)
            self.assertTrue(all(len(arg) == 32 for arg in compared.call_args.args))

    def test_every_request_binding_must_match(self):
        payload = self._payload()
        changes = {"session_jti": "other-session", "github_user_id": 20, "project_id": "other-project", "type": "override", "operation_nonce": "Q0NDQ0NDQ0NDQ0NDQ0NDQw", "operation_sha256": "sha256:" + "1" * 64}
        for name, value in changes.items():
            with self.subTest(name=name), self.assertRaises(ActionFormError):
                self._verify(payload, **{name: value})
        for change in [{"current_time": "invalid"}, {"session_expires_at": None}, {"session_jti": ""}, {"github_user_id": True}, {"project_id": ""}, {"type": "internal"}, {"operation_nonce": "AA"}, {"confirmed_canonical_oid": "bad"}, {"operation_sha256": "bad"}]:
            with self.subTest(change=next(iter(change))), self.assertRaises(ActionFormError):
                self._context(payload, **change)

    def test_absolute_expiry_and_parent_session_boundaries(self):
        payload = self._payload()
        self._verify(payload, current_time=payload["issued_at"], session_expires_at=payload["expires_at"])
        self._verify(payload, current_time="2026-01-02T19:54:59Z")
        for changes in [{"current_time": "2026-01-02T11:59:59Z"}, {"current_time": payload["expires_at"]}, {"current_time": "2026-01-02T20:00:00Z"}, {"session_expires_at": "2026-01-02T19:54:59Z"}]:
            with self.subTest(changes=changes), self.assertRaises(ActionFormError):
                self._verify(payload, **changes)
        empty = dict(payload, expires_at=payload["issued_at"])
        encode_action_form(empty, key=self.key)
        with self.assertRaises(ActionFormError):
            self._verify(empty)

    def test_every_non_noop_form_requires_exact_current_head(self):
        for row in self.corpus["actions"]:
            payload = self._payload()
            payload["type"] = row["type"]
            event = self.events[row["type"]]
            operation = {"target": event["target"], "payload": event["payload"]}
            if row["type"] in {"acceptance", "revocation"}:
                payload["github_user_id"] = event["target"]["coverage_tuple"]["github_user_id"]
            if row["type"] == "retry_requested":
                payload["operation_nonce"] = event["operation_nonce"]
            self._bind_operation(payload, operation)
            verified = self._verify(payload)
            self.assertTrue(verified.preparable)
            with self.subTest(action=row["type"]), self.assertRaises(ActionFormError):
                self._verify(payload, confirmed_canonical_oid=self.corpus["later_head"])
        self._verify(dict(self._payload(), confirmed_canonical_oid="d" * 64))

    def test_every_terminal_alternative_is_stable_after_head_advances(self):
        covered = set()
        for case in self.corpus["terminal_noops"]:
            payload = case["form"]
            terminal = self.events[case["terminal_fixture_type"]]
            with self.subTest(case=case["id"]):
                self.assertEqual(encode_action_form(payload, key=self.key), case["token"])
                verified = verify_action_form(case["token"], keys=self.keys, context=self._context(payload, confirmed_canonical_oid=self.corpus["later_head"]))
                self.assertTrue(verified.is_noop)
                self.assertFalse(verified.preparable)
                self._prove(payload, terminal, case["operation"])
                self._prove(payload, validate_event(terminal), case["operation"])
                self._prove(payload, canonical_json(terminal), case["operation"])
                covered.add((payload["type"], terminal["type"]))
        expected = {(row["type"], terminal) for row in self.corpus["actions"] for terminal in row["terminal_types"]}
        self.assertEqual(covered, expected)
        self.assertEqual(len(covered), 24)

    def test_admin_digest_uses_event_null_head_and_contributors_use_form_head(self):
        for case in self.corpus["terminal_noops"]:
            payload = copy.deepcopy(case["form"])
            original = payload["operation_sha256"]
            self._bind_operation(payload, case["operation"])
            self.assertEqual(payload["operation_sha256"], original)
            wrong_head = None if payload["type"] in {"acceptance", "revocation"} else payload["confirmed_canonical_oid"]
            payload["operation_sha256"] = derive_event_identity(payload["project_id"], payload["operation_nonce"], {"kind": "github", "github_user_id": payload["github_user_id"], "login_snapshot": "other"}, payload["type"], case["operation"]["target"], case["operation"]["payload"], wrong_head).operation_sha256
            with self.subTest(action=payload["type"]), self.assertRaises(ActionFormError):
                self._prove(payload, self.events[case["terminal_fixture_type"]], case["operation"])

    def test_terminal_requires_verified_noop_and_exact_read_context(self):
        case = self.corpus["terminal_noops"][0]
        for value in [case["form"], ActionForm(**case["form"]), self._verify(self._payload()), None]:
            with self.assertRaises(ActionFormError):
                validate_terminal_noop(value, self.events[case["terminal_fixture_type"]], case["operation"], expected_project_id=case["form"]["project_id"], expected_confirmed_oid=case["form"]["confirmed_canonical_oid"])
        for changes in [{"expected_project_id": "other-project"}, {"expected_confirmed_oid": "e" * 40}]:
            with self.assertRaises(ActionFormError):
                self._prove(case["form"], self.events[case["terminal_fixture_type"]], case["operation"], **changes)

    def test_terminal_event_must_be_complete_valid_and_at_bound_path(self):
        case = next(c for c in self.corpus["terminal_noops"] if c["action_type"] == "config_updated")
        terminal = copy.deepcopy(self.events["config_updated"])
        bad = [{}, dict(terminal, extra=True), dict(terminal, operation_sha256="sha256:" + "0" * 64), json.dumps(terminal, indent=2).encode()]
        wrong_project = copy.deepcopy(terminal)
        wrong_project["project_id"] = "other-project"
        bad.append(self._event_identity(wrong_project))
        wrong_nonce = copy.deepcopy(terminal)
        wrong_nonce["operation_nonce"] = "Q0NDQ0NDQ0NDQ0NDQ0NDQw"
        bad.append(self._event_identity(wrong_nonce))
        for event in bad:
            with self.assertRaises(ActionFormError):
                self._prove(case["form"], event, case["operation"])
        payload = copy.deepcopy(case["form"])
        event = self.events["agreement_published"]
        payload["terminal_noop_event_id"] = event["event_id"]
        with self.assertRaises(ActionFormError):
            self._prove(payload, event, case["operation"])

    def test_submitted_operation_must_be_closed_valid_and_digest_bound(self):
        case = next(c for c in self.corpus["terminal_noops"] if c["action_type"] == "config_updated")
        wrong = copy.deepcopy(case["operation"])
        wrong["payload"]["project_configuration"]["retention_statement"] = "Changed desired effect."
        bad = [None, {}, dict(case["operation"], extra=True), {"target": {"extra": 1}, "payload": {}}, wrong]
        for operation in bad:
            with self.assertRaises(ActionFormError):
                self._prove(case["form"], self.events["config_updated"], operation)
        payload = copy.deepcopy(case["form"])
        self._bind_operation(payload, wrong)
        with self.assertRaises(ActionFormError):
            self._prove(payload, self.events["config_updated"], wrong)

    def test_contributor_operation_must_match_actor_project_and_recipient(self):
        for action in ["acceptance", "revocation"]:
            case = next(c for c in self.corpus["terminal_noops"] if c["action_type"] == action)
            changes = [("github_user_id", 999), ("project_id", "other-project")]
            if action == "acceptance":
                changes.append(("recipient_id", "other-recipient"))
            for field, value in changes:
                operation = copy.deepcopy(case["operation"])
                operation["target"]["coverage_tuple"][field] = value
                payload = copy.deepcopy(case["form"])
                self._bind_operation(payload, operation)
                with self.subTest(action=action, field=field), self.assertRaises(ActionFormError):
                    self._prove(payload, self.events[action], operation)

    def test_scope_noop_compares_repeated_desired_scope_without_request_read(self):
        case = next(c for c in self.corpus["terminal_noops"] if c["action_type"] == "enforcement_scope_requested")
        operation = copy.deepcopy(case["operation"])
        operation["target"]["change_id"] = "new-request-that-was-never-appended"
        payload = copy.deepcopy(case["form"])
        self._bind_operation(payload, operation)
        self._prove(payload, self.events["enforcement_scope_activated"], operation)
        other = copy.deepcopy(operation)
        other["payload"]["desired_scope"] = copy.deepcopy(operation["payload"]["prior_scope"])
        self.assertNotEqual(other["payload"]["desired_scope"], operation["payload"]["desired_scope"])
        self._bind_operation(payload, other)
        with self.assertRaises(ActionFormError):
            self._prove(payload, self.events["enforcement_scope_activated"], other)
        payload["terminal_noop_event_id"] = self.events["enforcement_scope_abandoned"]["event_id"]
        with self.assertRaises(ActionFormError):
            self._prove(payload, self.events["enforcement_scope_abandoned"], other)

    def test_restore_alternatives_require_named_target_and_exact_set_not_reason(self):
        cases = [c for c in self.corpus["terminal_noops"] if c["action_type"] == "agreement_activation_restored"]
        for case in cases:
            terminal = self.events[case["terminal_fixture_type"]]
            operation = copy.deepcopy(case["operation"])
            operation["payload"]["reason"] = "Another audit reason."
            payload = copy.deepcopy(case["form"])
            self._bind_operation(payload, operation)
            self._prove(payload, terminal, operation)
            for part, field, value in [("target", "agreement_id", "different-agreement"), ("target", "activation_event_id", "A" * 43), ("payload", "accepted_versions", ["different-version"])]:
                wrong = copy.deepcopy(operation)
                wrong[part][field] = value
                self._bind_operation(payload, wrong)
                with self.subTest(terminal=terminal["type"], field=field), self.assertRaises(ActionFormError):
                    self._prove(payload, terminal, wrong)

    def test_old_config_noop_survives_actual_later_replay_state_change(self):
        connection = validate_event(self.events["project_connected"])
        original_raw = copy.deepcopy(self.events["config_updated"])
        original_raw["payload"]["project_configuration"]["retention_statement"] = "Configuration at form issuance."
        original = validate_event(self._event_identity(original_raw))
        changed = copy.deepcopy(self.events["config_updated"])
        changed["operation_nonce"] = "cHBwcHBwcHBwcHBwcHBwcA"
        changed["payload"]["project_configuration"]["retention_statement"] = "Changed after form issuance."
        later = validate_event(self._event_identity(changed))
        records = [CanonicalEventRecord(connection, "1" * 40, "b" * 40), CanonicalEventRecord(original, "2" * 40, "1" * 40), CanonicalEventRecord(later, "3" * 40, "2" * 40)]
        result = replay_events(connection.project_id, "b" * 40, records)
        self.assertTrue(result.valid, result.error)
        self.assertEqual(current_configuration(result.state)["retention_statement"], "Changed after form issuance.")
        case = next(c for c in self.corpus["terminal_noops"] if c["action_type"] == "config_updated")
        operation = {"target": original.to_dict()["target"], "payload": original.to_dict()["payload"]}
        payload = dict(case["form"], confirmed_canonical_oid="2" * 40)
        self._bind_operation(payload, operation)
        verified = self._verify(payload, confirmed_canonical_oid="3" * 40)
        validate_terminal_noop(verified, original, operation, expected_project_id=payload["project_id"], expected_confirmed_oid="2" * 40)
        self.assertFalse(verified.preparable)
        self.assertNotEqual(current_configuration(result.state)["retention_statement"], operation["payload"]["project_configuration"]["retention_statement"])


if __name__ == "__main__":
    unittest.main()
