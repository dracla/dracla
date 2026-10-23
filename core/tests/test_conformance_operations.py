"""Closed operation states, independent wire vectors, and persisted crash tuples."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from enum import Enum
from pathlib import Path

from dracla.conformance import (
    DecisionFence, InFlightMarker, OperationConflict, OperationCorruption,
    PreparedOperation, PreparedOperationReference, acquire_mutation_fence,
    append_claim, authoritative_check_identity, base64url_decode, base64url_encode,
    canonical_json, claim_append, clear_prepared_operation, close_inflight_marker,
    decode_decision_fence, decode_inflight_marker, decode_prepared_operation,
    encode_decision_fence, encode_inflight_marker, encode_prepared_operation,
    open_inflight_marker, prepare_operation, release_mutation_fence, release_success,
    reserve_success, terminal_operation, validate_operation_cross_bindings, validate_event,
)

from core.tests.corpus_consumption import CLAIMS


VECTORS = Path(__file__).resolve().parents[2] / "conformance" / "vectors" / "operation-state-v1.json"
ERRORS = (OperationConflict, OperationCorruption)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class TestOperationStates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(VECTORS.read_text())
        cls.limit = cls.corpus["profile"]["max_prepared_operation_bytes"]
        cls.project = cls.corpus["project_id"]
        cls.head = cls.corpus["cells"]["prepared"]["prepared_events_head"]
        cls.event = validate_event(json.loads(base64url_decode(cls.corpus["cells"]["prepared"]["event_jcs_b64"])))
        cls.owner = dict(operation_id=cls.event.idempotency_key, operation_sha256=cls.event.operation_sha256)
        cls.preconditions = [{
            "name": "generations-absence", "artifact_kind": "materialization-generations",
            "repository_role": "records", "branch": "events",
            "path": "config/materialization-generations.enc.json", "binding_mode": "events-head",
            "binding": {"mode": "events-head", "events_head": cls.head}, "value": None,
        }]

    def decode(self, value, **changes):
        args = dict(expected_project_id=self.project, max_prepared_operation_bytes=self.limit,
                    preconditions=self.preconditions)
        args.update(changes)
        return decode_prepared_operation(wire(value), **args)

    def cell(self, name):
        return self.decode(self.corpus["cells"][name])

    def fence(self, name):
        return decode_decision_fence(canonical_json(self.corpus["fences"][name]))

    def marker(self, name):
        return decode_inflight_marker(canonical_json(self.corpus["markers"][name]))

    def ref(self, **changes):
        args = dict(commit_oid="d" * 40, blob_sha="e" * 40, cell=self.cell("prepared"))
        args.update(changes)
        return PreparedOperationReference(**args)

    def event_fixture(self, event_type):
        from core.tests import test_conformance_event_artifacts as fixtures
        from dracla.conformance import SideArtifact, derive_event_identity, required_side_artifacts

        fixtures.TestSideArtifactPackages.setUpClass()
        fixture = fixtures.TestSideArtifactPackages()
        row = copy.deepcopy(fixture.rows[event_type])
        if event_type in ("override", "exemption_snapshot"):
            container = row["payload"] if event_type == "override" else row["target"]
            container["subjects"].append({"github_user_id": 9, "login_snapshot": "second"})
            identity = derive_event_identity(row["project_id"], row["operation_nonce"], row["actor"],
                event_type, row["target"], row["payload"], row["confirmed_canonical_oid"])
            row.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key,
                       operation_sha256=identity.operation_sha256)
        event = validate_event(row)
        head = event.confirmed_canonical_oid or self.head
        prior = {name: event.event_id
                 for name in ("derived_index", "status_detail", "reader_authority")}
        preconditions = fixture._preconditions(event, head, {"prior-generations": prior})
        package = []
        for artifact in required_side_artifacts(event, preconditions=preconditions, expected_head=head):
            self.assertEqual(artifact.kind, "materialization_generations")
            generations = {name: event.event_id if name in artifact.affected_classes else value
                           for name, value in prior.items()}
            package.append(SideArtifact(artifact.kind, artifact.path,
                canonical_json({"generations_version": 1, **generations})))
        cell = prepare_operation(self.cell("idle"), event, package,
            expected_project_id=self.project, expected_events_head=head,
            preconditions=preconditions, max_prepared_operation_bytes=self.limit)
        return cell, PreparedOperationReference("d" * 40, "e" * 40, cell)

    def bindings(self, fence=None, marker=None, reference=None):
        return dict(fence=fence if fence is not None else self.fence("mutation"),
                    marker=marker if marker is not None else self.marker("open"),
                    prepared_reference=reference if reference is not None else self.ref())

    def prepare(self, cell, **changes):
        args = dict(expected_project_id=self.project, expected_events_head=self.head,
                    preconditions=self.preconditions, max_prepared_operation_bytes=self.limit)
        args.update(changes)
        return prepare_operation(cell, self.event, self.corpus["cells"]["prepared"]["side_artifacts"], **args)

    def claim(self, cell, **changes):
        args = dict(**self.owner, **self.bindings(), append_head=self.head,
                    max_prepared_operation_bytes=self.limit)
        args.update(changes)
        return claim_append(cell, **args)

    def terminal(self, cell, result="semantic_noop", **changes):
        args = dict(**self.owner, **self.bindings(marker=self.marker("empty") if result == "landed" else None),
                    result=result, observed_events_head="c" * 40,
                    canonical_commit="c" * 40 if result == "landed" else None,
                    projection_verified=result == "landed", readback_verified=result == "landed")
        args.update(changes)
        return terminal_operation(cell, **args)

    def release(self, cell, **changes):
        args = dict(fence=self.fence("mutation"), expected_mutation=self.fence("mutation"),
                    cell=cell, marker=self.marker("empty"), prepared_reference=self.ref(),
                    projection_verified=True, readback_verified=True)
        args.update(changes)
        return release_mutation_fence(**args)

    def clear(self, cell, **changes):
        args = dict(expected_terminal=self.cell("landed"), mutation_fence=self.fence("mutation"),
                    released_fence=self.fence("released"), marker=self.marker("empty"), prepared_reference=self.ref())
        args.update(changes)
        return clear_prepared_operation(cell, **args)

    def test_independent_domain_hash_and_wire_goldens(self):
        for name, function in (("append_claim", append_claim), ("check_identity", authoritative_check_identity)):
            with self.subTest(name=name):
                vector = self.corpus[name]
                self.assertEqual(canonical_json(vector["input"]), vector["jcs"].encode())
                self.assertEqual(function(**vector["input"]), vector["expected"])
        for name, obj in self.corpus["cells"].items():
            with self.subTest(cell=name):
                self.assertEqual(encode_prepared_operation(self.decode(obj), max_prepared_operation_bytes=self.limit), canonical_json(obj))
            CLAIMS.case('operation-state-v1.json', 'cells', name)
        for mapping, decoder, encoder in (("fences", decode_decision_fence, encode_decision_fence),
                                          ("markers", decode_inflight_marker, encode_inflight_marker)):
            for name, obj in self.corpus[mapping].items():
                with self.subTest(mapping=mapping, name=name):
                    self.assertEqual(encoder(decoder(wire(obj))), canonical_json(obj))
                CLAIMS.case('operation-state-v1.json', mapping, name)
        CLAIMS.value('operation-state-v1.json', 'profile', 'project_id', 'append_claim', 'check_identity')

    def test_prepare_and_all_state_retries_preserve_exact_package(self):
        prepared = self.prepare(self.cell("idle"))
        self.assertEqual(prepared, self.cell("prepared"))
        for name in ("prepared", "appending", "landed", "semantic_noop", "conflict"):
            cell = self.cell(name)
            self.assertIs(self.prepare(cell), cell)
        changed = self.corpus["cells"]["prepared"] | {"prepared_events_head": "a" * 40}
        other = self.decode(changed, preconditions=[self.preconditions[0] | {"binding": {"mode": "events-head", "events_head": "a" * 40}}])
        with self.assertRaises(OperationConflict):
            self.prepare(other)
        other = self.cell("conflict").to_dict() | {"operation_id": base64url_encode(b"x" * 32)}
        with self.assertRaises(OperationConflict):
            self.prepare(self.decode(other))

    def test_exact_append_right_and_revalidated_head_replacement(self):
        prepared, appending = self.cell("prepared"), self.cell("appending")
        self.assertEqual(self.claim(prepared), appending)
        self.assertIs(self.claim(appending), appending)
        with self.assertRaises(OperationConflict):
            self.claim(appending, append_head="a" * 40)
        next_claim = self.claim(appending, append_head="a" * 40,
                                expected_append_claim=appending.to_dict()["append_claim"])
        self.assertEqual(next_claim.to_dict()["append_claim"], append_claim(**self.owner, append_head="a" * 40))
        self.assertEqual(next_claim.to_dict()["event_jcs_b64"], prepared.to_dict()["event_jcs_b64"])
        self.assertEqual(next_claim.generation, prepared.generation)
        for name in ("semantic_noop", "conflict", "landed", "idle"):
            with self.subTest(state=name), self.assertRaises(ERRORS):
                self.claim(self.cell(name))
        for changes in (dict(operation_id=base64url_encode(b"x" * 32)),
                        dict(operation_sha256="sha256:" + "a" * 64),
                        dict(marker=self.marker("empty")), dict(fence=self.fence("idle")),
                        dict(prepared_reference=self.ref(blob_sha="a" * 40))):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                self.claim(prepared, **changes)

    def test_terminal_cas_race_defeats_delayed_claim_and_appending_repairs_forward(self):
        for result in ("semantic_noop", "conflict"):
            terminal = self.terminal(self.cell("prepared"), result)
            self.assertEqual(terminal, self.cell(result))
            self.assertEqual(self.decode(json.loads(encode_prepared_operation(terminal, max_prepared_operation_bytes=self.limit))), terminal)
            self.assertIs(self.terminal(terminal, result), terminal)
            with self.assertRaises(ERRORS):
                self.claim(terminal)
            with self.assertRaises(OperationConflict):
                self.terminal(self.cell("appending"), result)
        landed = self.terminal(self.cell("appending"), "landed")
        self.assertEqual(landed, self.cell("landed"))
        self.assertEqual(self.decode(json.loads(encode_prepared_operation(landed, max_prepared_operation_bytes=self.limit))), landed)
        self.assertIs(self.terminal(landed, "landed"), landed)
        for cell, result in (("prepared", "landed"), ("landed", "conflict"), ("idle", "conflict")):
            with self.subTest(cell=cell, result=result), self.assertRaises(ERRORS):
                self.terminal(self.cell(cell), result)
        for changes in (dict(marker=self.marker("open")), dict(projection_verified=False),
                        dict(readback_verified=False), dict(projection_verified=1)):
            with self.subTest(changes=changes), self.assertRaises(OperationConflict):
                self.terminal(self.cell("appending"), "landed", **changes)
        for changes in (dict(marker=self.marker("empty")), dict(canonical_commit="a" * 40),
                        dict(result="unknown"), dict(operation_id=base64url_encode(b"x" * 32))):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                self.terminal(self.cell("prepared"), **changes)
        with self.assertRaises(OperationConflict):
            self.terminal(landed, "landed", observed_events_head="a" * 40)

    def test_terminal_rejects_noncanonical_string_results(self):
        class Result(str, Enum):
            LANDED = "landed"
            SEMANTIC_NOOP = "semantic_noop"
            CONFLICT = "conflict"

        for cell_name, result in (("appending", Result.LANDED),
                                  ("prepared", Result.SEMANTIC_NOOP),
                                  ("prepared", Result.CONFLICT)):
            with self.subTest(result=result), self.assertRaises(OperationCorruption):
                self.terminal(self.cell(cell_name), result)

    def test_fence_and_success_compete_and_only_matching_owner_can_release(self):
        idle, prepared = self.fence("idle"), self.cell("prepared")
        mutation = acquire_mutation_fence(idle, prepared, self.ref(), subjects=[], project_wide=True)
        self.assertEqual(mutation, self.fence("mutation"))
        self.assertIs(acquire_mutation_fence(mutation, self.cell("appending"), self.ref(), subjects=[], project_wide=True), mutation)
        success = reserve_success(idle, self.marker("empty"), check_identity=self.corpus["check_identity"]["expected"], projection_commit=self.head)
        self.assertEqual(success, self.fence("success"))
        self.assertIs(reserve_success(success, self.marker("empty"), **{k: success.to_dict()[k] for k in ("check_identity", "projection_commit")}), success)
        with self.assertRaises(OperationConflict):
            acquire_mutation_fence(success, prepared, self.ref(), subjects=[], project_wide=True)
        with self.assertRaises(OperationConflict):
            reserve_success(mutation, self.marker("open"), check_identity=self.corpus["check_identity"]["expected"], projection_commit=self.head)
        with self.assertRaises(OperationConflict):
            reserve_success(success, self.marker("empty"), check_identity=base64url_encode(b"x" * 32), projection_commit=self.head)
        for state in (idle, mutation, self.fence("released")):
            if state.state == "idle" and state.generation == 7:
                continue
            with self.assertRaises(OperationConflict):
                release_success(state, success, completion_verified=False)
        released = release_success(success, success, completion_verified=True)
        self.assertEqual(released, self.fence("released"))
        self.assertIs(release_success(released, success, completion_verified=True), released)
        with self.assertRaises(OperationConflict):
            release_success(mutation, success, completion_verified=True)
        with self.assertRaises(OperationConflict):
            release_success(idle, idle, completion_verified=True)
        with self.assertRaises(OperationConflict):
            acquire_mutation_fence(idle, self.cell("appending"), self.ref(), subjects=[], project_wide=True)
        # Success consumes the complete coverage-side operational observation.
        # Both a first reservation and an identical retry reject an orphan marker.
        for fence in (idle, success):
            with self.subTest(fence=fence.state), self.assertRaises(ERRORS):
                reserve_success(fence, marker=self.marker("open"),
                                check_identity=self.corpus["check_identity"]["expected"],
                                projection_commit=self.head)
        for marker in (None, {}, self.cell("idle")):
            with self.subTest(marker=marker), self.assertRaises(OperationCorruption):
                reserve_success(idle, marker=marker,
                                check_identity=self.corpus["check_identity"]["expected"],
                                projection_commit=self.head)

    def test_marker_scope_and_first_started_at_are_preserved_without_expiry(self):
        for subjects, wide in (([], True),):
            fence = acquire_mutation_fence(self.fence("idle"), self.cell("prepared"), self.ref(), subjects=subjects, project_wide=wide)
            opened = open_inflight_marker(self.marker("empty"), fence, cell=self.cell("prepared"), prepared_reference=self.ref(), started_at="1900-01-01T00:00:00Z")
            self.assertIs(open_inflight_marker(opened, fence, cell=self.cell("appending"), prepared_reference=self.ref(), started_at="2099-12-31T23:59:59Z"), opened)
            self.assertEqual(opened.to_dict()["ops"][self.event.idempotency_key]["started_at"], "1900-01-01T00:00:00Z")
            validate_operation_cross_bindings(self.cell("appending"), fence, opened, prepared_reference=self.ref())
            with self.assertRaises(OperationConflict):
                close_inflight_marker(opened, fence, cell=self.cell("prepared"), prepared_reference=self.ref())
            with self.assertRaises(OperationConflict):
                close_inflight_marker(opened, fence, cell=self.cell("appending"), prepared_reference=self.ref())
            closed = close_inflight_marker(opened, fence, cell=self.cell("appending"), prepared_reference=self.ref(), projection_verified=True)
            self.assertEqual(closed, self.marker("empty"))
            self.assertIs(close_inflight_marker(closed, fence, cell=self.cell("landed"), prepared_reference=self.ref()), closed)
            with self.assertRaises(OperationConflict):
                open_inflight_marker(closed, fence, cell=self.cell("landed"), prepared_reference=self.ref(), started_at="2099-12-31T23:59:59Z")
        with self.assertRaises(ERRORS):
            open_inflight_marker(self.marker("open"), self.fence("idle"), cell=self.cell("prepared"), prepared_reference=self.ref(), started_at="2099-01-01T00:00:00Z")
        for event_type, subjects, wide in (
            ("acceptance", [7], False), ("revocation", [7], False),
            ("override", [7, 9], False), ("exemption_snapshot", [7, 9], False),
            ("records_reader_authorized", [7], False),
            ("agreement_activated", [], True), ("agreement_activation_restored", [], True),
            ("override_withdrawn", [], True), ("exemption_rule_withdrawn", [], True),
        ):
            with self.subTest(event_type=event_type):
                cell, reference = self.event_fixture(event_type)
                fence = acquire_mutation_fence(self.fence("idle"), cell, reference,
                    subjects=subjects, project_wide=wide)
                opened = open_inflight_marker(self.marker("empty"), fence, cell=cell,
                    prepared_reference=reference, started_at="1900-01-01T00:00:00Z")
                self.assertIs(open_inflight_marker(opened, fence, cell=cell,
                    prepared_reference=reference, started_at="2099-01-01T00:00:00Z"), opened)
                validate_operation_cross_bindings(cell, fence, opened, prepared_reference=reference)
                for wrong_subjects, wrong_wide in (([8], False), ([7], False), ([], True)):
                    if (wrong_subjects, wrong_wide) == (subjects, wide):
                        continue
                    with self.assertRaises(OperationCorruption):
                        acquire_mutation_fence(self.fence("idle"), cell, reference,
                            subjects=wrong_subjects, project_wide=wrong_wide)
                    wrong_fence = decode_decision_fence(canonical_json(fence.to_dict() |
                        {"subjects": wrong_subjects, "project_wide": wrong_wide}))
                    wrong_marker = decode_inflight_marker(canonical_json({"ops": {
                        cell.to_dict()["operation_id"]: {"operation_sha256": cell.to_dict()["operation_sha256"],
                            "subjects": wrong_subjects, "project_wide": wrong_wide,
                            "started_at": "1900-01-01T00:00:00Z"}}}))
                    with self.assertRaises(OperationCorruption):
                        validate_operation_cross_bindings(cell, wrong_fence, wrong_marker,
                            prepared_reference=reference)

    def test_terminal_release_then_readback_then_clear_only_exact_owner(self):
        for result in ("landed", "semantic_noop", "conflict"):
            terminal = self.cell(result)
            released = self.release(terminal, projection_verified=result == "landed")
            self.assertEqual(released, self.fence("released"))
            self.assertIs(self.release(terminal, fence=released), released)
            cleared = self.clear(terminal, expected_terminal=terminal)
            self.assertEqual(cleared, self.cell("idle"))
            self.assertIs(self.clear(cleared, expected_terminal=terminal), cleared)
        for changes in (dict(marker=self.marker("open")), dict(readback_verified=False),
                        dict(projection_verified=False), dict(projection_verified=1),
                        dict(fence=self.fence("success")), dict(expected_mutation=self.fence("idle")),
                        dict(prepared_reference=self.ref(commit_oid="a" * 40))):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                self.release(self.cell("landed"), **changes)
        with self.assertRaises(OperationConflict):
            self.release(self.cell("prepared"))
        for changes in (dict(marker=self.marker("open")), dict(released_fence=self.fence("idle")),
                        dict(released_fence=self.fence("success")), dict(mutation_fence=self.fence("idle")),
                        dict(expected_terminal=self.cell("prepared"))):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                self.clear(self.cell("landed"), **changes)
        with self.assertRaises(OperationConflict):
            self.clear(self.cell("conflict"))
        wrong_idle = self.decode({"state": "idle", "generation": 5})
        with self.assertRaises(OperationConflict):
            self.clear(wrong_idle)

    def test_every_persisted_crash_tuple_has_exact_legal_next_transitions(self):
        for vector in self.corpus["crashes"]:
            cell, fence, marker = self.cell(vector["cell"]), self.fence(vector["fence"]), self.marker(vector["marker"])
            binding = self.bindings(fence, marker)
            validate_operation_cross_bindings(cell, fence, marker, prepared_reference=self.ref())
            actions = {
                "prepare": lambda: self.prepare(cell),
                "acquire": lambda: acquire_mutation_fence(fence, cell, self.ref(), subjects=[], project_wide=True),
                "reserve": lambda: reserve_success(fence, marker, check_identity=self.corpus["check_identity"]["expected"], projection_commit=self.head),
                "open": lambda: open_inflight_marker(marker, fence, cell=cell, prepared_reference=self.ref(), started_at="2099-01-01T00:00:00Z"),
                "claim": lambda: self.claim(cell, **binding),
                "noop": lambda: self.terminal(cell, "semantic_noop", **binding),
                "conflict": lambda: self.terminal(cell, "conflict", **binding),
                "landed": lambda: self.terminal(cell, "landed", **binding),
                "close": lambda: close_inflight_marker(marker, fence, cell=cell, prepared_reference=self.ref()),
                "close_projected": lambda: close_inflight_marker(marker, fence, cell=cell, prepared_reference=self.ref(), projection_verified=True),
                "release": lambda: self.release(cell, fence=fence, marker=marker),
                "clear": lambda: self.clear(cell, released_fence=fence, marker=marker),
                "release_success": lambda: release_success(fence, self.fence("success"), completion_verified=True),
            }
            accepted = []
            for name, action in actions.items():
                try:
                    action()
                except ERRORS:
                    continue
                accepted.append(name)
            expected = set(vector["allowed"])
            with self.subTest(crash=vector["id"]):
                self.assertEqual(set(accepted), expected)
            CLAIMS.case('operation-state-v1.json', 'crashes', vector)

    def test_closed_state_schemas_reject_missing_extra_and_invalid_scalars(self):
        for mapping, decoder in (("cells", self.decode),
                                 ("fences", lambda obj: decode_decision_fence(wire(obj))),
                                 ("markers", lambda obj: decode_inflight_marker(wire(obj)))):
            for name, obj in self.corpus[mapping].items():
                for key in obj:
                    changed = copy.deepcopy(obj)
                    del changed[key]
                    with self.subTest(mapping=mapping, name=name, missing=key), self.assertRaises(OperationCorruption):
                        decoder(changed)
                with self.subTest(mapping=mapping, name=name, extra=True), self.assertRaises(OperationCorruption):
                    decoder(obj | {"unknown": None})
                if "generation" in obj:
                    for value in (-1, True, 1.0, "4", None, 2**53):
                        with self.subTest(mapping=mapping, name=name, generation=value), self.assertRaises(OperationCorruption):
                            decoder(obj | {"generation": value})
                    for value in ("unknown", {}, [], 1, None):
                        with self.subTest(mapping=mapping, name=name, state=value), self.assertRaises(OperationCorruption):
                            decoder(obj | {"state": value})
                CLAIMS.case('operation-state-v1.json', mapping, name)
        for decoder in (decode_decision_fence, decode_inflight_marker,
                        lambda data: decode_prepared_operation(data, expected_project_id=self.project, max_prepared_operation_bytes=self.limit)):
            for raw in (b'[]', b'null', b' {"state":"idle","generation":0}', b'\xff',
                        b'{"ops":{},"ops":{}}', b'{'):
                with self.subTest(decoder=decoder, raw=raw), self.assertRaises(OperationCorruption):
                    decoder(raw)
        for changes in (dict(operation_id="bad"), dict(operation_sha256="bad"), dict(event_id="bad"),
                        dict(result="unknown"), dict(canonical_commit=None), dict(observed_events_head="BAD")):
            with self.subTest(changes=changes), self.assertRaises(OperationCorruption):
                self.decode(self.corpus["cells"]["landed"] | changes)
        with self.assertRaises(OperationCorruption):
            self.decode(self.corpus["cells"]["conflict"] | {"canonical_commit": "a" * 40})
        with self.assertRaises(OperationCorruption):
            decode_decision_fence(canonical_json(self.corpus["fences"]["success"] | {"check_identity": "bad"}))

    def test_frozen_package_rejects_any_identity_byte_membership_or_head_change(self):
        original = self.corpus["cells"]["prepared"]
        for changes in (dict(operation_id=base64url_encode(b"x" * 32)),
                        dict(operation_sha256="sha256:" + "a" * 64), dict(event_id=base64url_encode(b"x" * 32)),
                        dict(event_jcs_b64="bad="), dict(prepared_events_head="a" * 40),
                        dict(side_artifacts={}), dict(side_artifacts=[])):
            with self.subTest(changes=changes), self.assertRaises(OperationCorruption):
                self.decode(original | changes)
        for change in ("reverse", "duplicate", "missing", "extra", "digest", "bytes", "path", "kind", "field", "raw"):
            changed = copy.deepcopy(original)
            package = changed["side_artifacts"]
            if change == "reverse":
                package.reverse()
            elif change == "duplicate":
                package.append(package[0])
            elif change == "missing":
                package.pop()
            elif change == "extra":
                package.append(package[0] | {"path": "extra.enc.json"})
            elif change == "field":
                package[0]["extra"] = 1
            elif change == "raw":
                package[0]["bytes"] = package[0].pop("bytes_b64")
            else:
                field = {"digest": "sha256", "bytes": "bytes_b64", "path": "path", "kind": "kind"}[change]
                package[0][field] = {"digest": "sha256:" + "a" * 64, "bytes": base64url_encode(b"changed"), "path": "wrong.enc.json", "kind": "project_config"}[change]
            with self.subTest(change=change), self.assertRaises(OperationCorruption):
                self.decode(changed)
        with self.assertRaises(OperationCorruption):
            self.decode(original, expected_project_id="wrong")
        with self.assertRaises(OperationCorruption):
            self.decode(original, preconditions=None)
        wrong_claim = self.corpus["cells"]["appending"] | {"append_claim": base64url_encode(b"x" * 32)}
        with self.assertRaises(OperationCorruption):
            self.decode(wrong_claim)
        for changes in (dict(event={}), dict(side_artifacts={} )):
            args = dict(cell=self.cell("idle"), event=self.event, side_artifacts=original["side_artifacts"],
                        expected_project_id=self.project, expected_events_head=self.head,
                        preconditions=self.preconditions, max_prepared_operation_bytes=self.limit)
            args.update(changes)
            with self.assertRaises(OperationCorruption):
                prepare_operation(**args)

    def test_cross_binding_rejects_all_stale_owners_references_packages_and_scopes(self):
        prepared, mutation, opened = self.cell("prepared"), self.fence("mutation"), self.marker("open")
        # The frozen project_connected event affects the whole project.
        with self.assertRaises(OperationCorruption):
            acquire_mutation_fence(self.fence("idle"), prepared, self.ref(),
                                   subjects=[7], project_wide=False)
        for field, value in (("operation_id", base64url_encode(b"x" * 32)),
                             ("operation_sha256", "sha256:" + "a" * 64),
                             ("prepared_commit_oid", "a" * 40), ("prepared_blob_sha", "a" * 40),
                             ("prepared_generation", 5), ("subjects", [8]), ("project_wide", False)):
            obj = mutation.to_dict() | {field: value}
            if field == "project_wide":
                obj["subjects"] = [7]
            elif field == "subjects":
                obj["project_wide"] = False
            changed = decode_decision_fence(canonical_json(obj))
            with self.subTest(field=field), self.assertRaises(OperationCorruption):
                validate_operation_cross_bindings(prepared, changed, opened, prepared_reference=self.ref())
        for cell in (self.cell("idle"), self.decode(self.corpus["cells"]["landed"] | {"event_id": base64url_encode(b"x" * 32)}),
                     self.decode(self.corpus["cells"]["prepared"] | {"generation": 5})):
            with self.assertRaises(OperationCorruption):
                validate_operation_cross_bindings(cell, mutation, opened, prepared_reference=self.ref())
        other_head = self.corpus["cells"]["prepared"] | {"prepared_events_head": "a" * 40}
        other = self.decode(other_head, preconditions=[self.preconditions[0] | {"binding": {"mode": "events-head", "events_head": "a" * 40}}])
        with self.assertRaises(OperationCorruption):
            validate_operation_cross_bindings(other, mutation, opened, prepared_reference=self.ref())
        with self.assertRaises(OperationCorruption):
            validate_operation_cross_bindings(prepared, mutation, opened)
        for fence in (self.fence("idle"), self.fence("success")):
            for cell, marker in ((prepared, opened), (self.cell("appending"), self.marker("empty"))):
                with self.assertRaises(OperationCorruption):
                    validate_operation_cross_bindings(cell, fence, marker)
        for changes in (dict(commit_oid="bad"), dict(blob_sha="bad"), dict(cell=self.cell("appending")), dict(cell={})):
            with self.assertRaises(OperationCorruption):
                self.ref(**changes)

    def test_marker_rejects_second_entry_wrong_owner_and_malformed_scope(self):
        for subjects, wide in (([], False), ([7], True), ([9, 7], False), ([7, 7], False),
                               ([True], False), ([0], False), ([-1], False), ([2**53], False), ("7", False), ([7], 0)):
            fence = self.corpus["fences"]["mutation"] | {"subjects": subjects, "project_wide": wide}
            marker = copy.deepcopy(self.corpus["markers"]["open"])
            marker["ops"][self.event.idempotency_key].update(subjects=subjects, project_wide=wide)
            for decoder, obj in ((decode_decision_fence, fence), (decode_inflight_marker, marker)):
                with self.subTest(subjects=subjects, wide=wide), self.assertRaises(OperationCorruption):
                    decoder(wire(obj))
        opened = copy.deepcopy(self.corpus["markers"]["open"])
        entry = opened["ops"][self.event.idempotency_key]
        other = base64url_encode(b"x" * 32)
        for obj in ({"ops": {other: entry, **opened["ops"]}}, {"ops": []},
                    {"ops": {"bad": entry}}, {"ops": {other: entry | {"unknown": None}}},
                    {"ops": {other: entry | {"started_at": "old"}}},
                    {"ops": {other: entry | {"operation_sha256": "bad"}}}):
            with self.assertRaises(OperationCorruption):
                decode_inflight_marker(canonical_json(obj))
        other_marker = decode_inflight_marker(canonical_json({"ops": {other: entry}}))
        for function in (lambda: open_inflight_marker(other_marker, self.fence("mutation"), cell=self.cell("prepared"), prepared_reference=self.ref(), started_at="2099-01-01T00:00:00Z"),
                         lambda: close_inflight_marker(other_marker, self.fence("mutation"), cell=self.cell("landed"), prepared_reference=self.ref())):
            with self.assertRaises(ERRORS):
                function()

    def test_explicit_profile_bounds_complete_bytes_including_append_overhead(self):
        raw = canonical_json(self.corpus["cells"]["prepared"])
        self.assertEqual(self.decode(self.corpus["cells"]["prepared"], max_prepared_operation_bytes=len(raw)), self.cell("prepared"))
        with self.assertRaises(OperationCorruption):
            self.decode(self.corpus["cells"]["prepared"], max_prepared_operation_bytes=len(raw) - 1)
        with self.assertRaises(OperationCorruption):
            self.prepare(self.cell("idle"), max_prepared_operation_bytes=len(raw))
        with self.assertRaises(OperationCorruption):
            self.claim(self.cell("prepared"), max_prepared_operation_bytes=len(raw))
        with self.assertRaises(OperationCorruption):
            encode_prepared_operation(self.cell("prepared"), max_prepared_operation_bytes=len(raw) - 1)
        for raw in (None, {}, "{}", bytearray(b"{}")):
            with self.assertRaises(OperationCorruption):
                decode_prepared_operation(raw, expected_project_id=self.project, max_prepared_operation_bytes=self.limit)
        for limit in (True, 0, -1, "16384", None, 2**53):
            with self.subTest(limit=limit), self.assertRaises(OperationCorruption):
                self.decode(self.corpus["cells"]["prepared"], max_prepared_operation_bytes=limit)
        for function in (lambda: append_claim(**(self.owner | {"operation_id": "bad"}), append_head=self.head),
                         lambda: authoritative_check_identity(True, self.head, 9, "delivery"),
                         lambda: authoritative_check_identity(12, "BAD", 9, "delivery"),
                         lambda: authoritative_check_identity(12, self.head, 0, "delivery"),
                         lambda: authoritative_check_identity(12, self.head, 9, "")):
            with self.assertRaises(OperationCorruption):
                function()
        fence = decode_decision_fence(canonical_json({"state": "success_reserved", "generation": 2**53 - 1,
                                                      "check_identity": self.corpus["check_identity"]["expected"], "projection_commit": self.head}))
        with self.assertRaises(OperationCorruption):
            release_success(fence, fence, completion_verified=True)

    def test_public_states_are_factory_only_and_deeply_immutable(self):
        for cls, value in ((PreparedOperation, self.cell("prepared")), (DecisionFence, self.fence("mutation")),
                           (InFlightMarker, self.marker("open"))):
            for factory in (lambda: cls(value.to_dict()), lambda: cls(value.to_dict(), _factory=object()), lambda: replace(value)):
                with self.subTest(cls=cls), self.assertRaises((OperationCorruption, TypeError)):
                    factory()
            with self.assertRaises((FrozenInstanceError, TypeError, AttributeError)):
                value._value = {}
            with self.assertRaises(TypeError):
                value._value["extra"] = None
            with self.assertRaises((FrozenInstanceError, TypeError, AttributeError)):
                value.extra = 1
            changed = value.to_dict()
            changed.clear()
            self.assertTrue(value.to_dict())
        with self.assertRaises(TypeError):
            self.cell("prepared")._value["side_artifacts"][0]["path"] = "evil"
        with self.assertRaises(TypeError):
            self.fence("mutation")._value["subjects"][0] = 10
        with self.assertRaises(OperationCorruption):
            encode_decision_fence(self.cell("idle"))
        with self.assertRaises(OperationCorruption):
            encode_inflight_marker({})
        with self.assertRaises(OperationCorruption):
            acquire_mutation_fence(self.fence("idle"), self.cell("prepared"), None, subjects=[7], project_wide=False)
        with self.assertRaises(OperationConflict):
            acquire_mutation_fence(self.fence("idle"), self.cell("landed"), self.ref(), subjects=[7], project_wide=False)

    def test_transition_proposals_keep_typed_corruption_errors(self):
        for index, call in enumerate((
            lambda: self.prepare(self.cell("idle"), expected_events_head={1, 2}),
            lambda: acquire_mutation_fence(self.fence("idle"), self.cell("prepared"), self.ref(),
                                           subjects=[2**53], project_wide=False),
            lambda: acquire_mutation_fence(self.fence("idle"), self.cell("prepared"), self.ref(),
                                           subjects=[{1, 2}], project_wide=False),
            lambda: reserve_success(self.fence("idle"), self.marker("empty"),
                                    check_identity=self.corpus["check_identity"]["expected"],
                                    projection_commit={1, 2}),
            lambda: reserve_success(self.fence("idle"), self.marker("empty"), check_identity={1, 2},
                                    projection_commit=self.head),
        )):
            with self.subTest(proposal=index), self.assertRaises(OperationCorruption):
                call()
