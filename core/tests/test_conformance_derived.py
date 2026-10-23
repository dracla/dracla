"""Independent derived schemas, actual replay lifecycles and fail-closed reads."""

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from dracla.conformance import (
    CoverageProjection, CoverageReadContext, DerivedClassOverflow, DerivedError, DerivedPlaintext,
    DerivedProjection, DerivedReadProjection, DerivedReadRow, ReleaseProfile, ReleaseProfileError,
    assemble_derived_projection, base64url_encode, canonical_json, derived_delta,
    encrypt_artifact, evaluate_subject, load_release_profile, materialize_coverage,
    materialize_derived, reader_authority_shard, reader_source_for_subject, replay_events, resolve_artifact_identity,
    resolve_read_status, resolve_selected_read_status, validate_derived_projection, validate_materialization_generations,
    validate_project_configuration,
)
from core.tests import test_conformance_coverage as coverage_fixtures
from core.tests import test_conformance_replay as replay_fixtures

from core.tests.corpus_consumption import CLAIMS

BASE = replay_fixtures.BASE


class TestDerived(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = json.loads((Path(__file__).resolve().parents[2] / "conformance/vectors/derived-v1.json").read_text())
        replay_fixtures.TestCanonicalReplay.setUpClass()
        coverage_fixtures.TestCoverage.setUpClass()

    def setUp(self):
        self.f = replay_fixtures.TestCanonicalReplay()
        self.cf = coverage_fixtures.TestCoverage()
        self.profile = load_release_profile()

    @staticmethod
    def fixed_bytes(value):
        """Decode literal byte chunks from the shared wire-golden corpus."""
        if type(value) is list:
            value = "".join(value)
        return bytes.fromhex(value)

    def state(self, records):
        result = replay_events("project-1", BASE, records)
        self.assertTrue(result.valid, result.error)
        return result.state

    def materialize(self, records, profile=None):
        return materialize_derived(self.state(records), profile=profile or self.profile)

    def connected(self):
        records = []
        self.f.append(records, "project_connected", 1000)
        return records

    def rebuild(self, plain, *, files=None, rules=None, profile=None):
        value = plain.to_dict()
        return DerivedPlaintext(plain.project_id, plain.canonical_oid,
            files=value["files"] if files is None else files,
            standing_rules=value["standing_rules"] if rules is None else rules,
            configuration=value["configuration"], profile=profile or self.profile)

    def encrypted(self, plain):
        with patch("dracla.conformance.envelope.secrets.token_bytes", return_value=bytes(12)):
            return {path: encrypt_artifact(raw, project_id=plain.project_id,
                identity=resolve_artifact_identity("records", "derived", path),
                kid=b"k" * 16, key=b"k" * 32) for path, raw in plain.plaintext_files().items()}

    def generations(self, event_id=None):
        return {"generations_version": 1, **{name: event_id or self.v["event_id"]
            for name in ("derived_index", "status_detail", "reader_authority")}}

    def assembled(self, plain, *, profile=None, generations=None, encrypted=None):
        return assemble_derived_projection(plain, canonical_oid=plain.canonical_oid,
            generations=generations or self.generations(),
            encrypted_shards=encrypted or self.encrypted(plain), profile=profile or self.profile)

    def bounded(self, records, derived_class, shard=7, *, generation=None,
                state=None, selected_files=None, selected_envelopes=None):
        plain = self.materialize(records)
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        path = f"derived/{ {'derived_index': 'index', 'status_detail': 'status-detail', 'reader_authority': 'reader-authority'}[derived_class] }/{shard:02d}.enc.json"
        return DerivedReadProjection("project-1", plain.canonical_oid,
            state=projection.state_dict(),
            selected_files={path: plain.to_dict()["files"][path]} if selected_files is None else selected_files,
            selected_envelopes={path: encrypted[path]} if selected_envelopes is None else selected_envelopes,
            generation=generation or self.generations()[derived_class], profile=self.profile)

    def bounded_coverage(self, state, pair=None):
        pair = pair or self.cf.pair()
        full = materialize_coverage(state, pair, canonical_oid=state.current_head_oid,
                                    built_at=self.v["recorded_at"], dracla_version="test")
        files = full.to_dict()
        return CoverageReadContext("project-1", {
            name: files[name] for name in ("source.enc.json", "agreements/active.enc.json",
                                           "inflight.enc.json", "decision-fence.enc.json")})

    def facts(self, kind="none", version=None):
        return {"version": version, "accepted_at": self.v["recorded_at"] if kind == "acceptance" else None,
            "revoked_at": self.v["recorded_at"] if kind == "revocation" else None,
            "basis": {"kind": kind, "event_id": None if kind == "none" else self.v["event_id"]}}

    def detail(self, kind="none", version=None, *, exempt=False):
        source = {"source_kind": "individual", **copy.deepcopy(self.v["source_kinds"]["individual"]), "sequence": 0}
        return {"login_snapshot": None, "login_as_of": None,
            "agreements": {"agreement-1": self.facts(kind, version)},
            "exemption_sources": {self.v["event_id"]: source} if exempt else {},
            "exemption_sequence_next": int(exempt), "materialization_cursor": {}}

    def index(self, detail):
        return {key: copy.deepcopy(detail[key]) for key in ("login_snapshot", "login_as_of", "agreements")} | {
            "exempt": bool(detail["exemption_sources"])}

    def read(self, detail, *, coverage=None, pair=None, oid=None, scope=None):
        pair = pair or self.cf.pair()
        if coverage is None:
            files = self.cf.files()
            files["agreements/active.enc.json"] = copy.deepcopy(self.v["active_agreement"])
            files["inflight.enc.json"], files["decision-fence.enc.json"] = (v.to_dict() for v in pair)
            coverage = CoverageProjection("project-1", files)
        row = DerivedReadRow("project-1", oid or BASE, 7, "agreement-1", detail)
        return resolve_read_status(row, coverage, scope or [], pair)

    def test_empty_closed_shards_and_canonical_configuration(self):
        records = self.connected()
        plain = self.materialize(records)
        self.assertEqual(plain.to_dict()["files"], self.v["empty_shards"])
        self.assertEqual(len(plain.plaintext_files()), 96)
        self.assertEqual(set(plain.plaintext_files().values()), {b"{}"})
        self.assertEqual(plain.to_dict()["standing_rules"], {})
        self.assertEqual(canonical_json(plain.to_dict()["configuration"]),
                         canonical_json(records[0].event.to_dict()["payload"]["project_configuration"]))
        validate_project_configuration(plain.to_dict()["configuration"])
        validate_materialization_generations(self.generations(records[0].event_id))
        with self.assertRaises(FrozenInstanceError):
            plain.canonical_oid = "a" * 40
        value = plain.to_dict()
        value["files"]["derived/index/00.enc.json"]["32"] = {}
        self.assertEqual(plain.to_dict()["files"], self.v["empty_shards"])
        CLAIMS.equal("derived-v1.json", "empty_shards", plain.to_dict()["files"])

    def test_all_fixed_status_reason_and_generic_mapping_vectors(self):
        for case in self.v["cases"]:
            with self.subTest(case=case["name"]):
                detail = self.detail(case["kind"], case["version"], exempt=case["exempt"])
                actual = self.read(detail)
                index = self.read(self.index(detail))
                self.assertEqual((actual.status, actual.reason_code, actual.coverage_reason_code),
                    (case["status"], case["reason"], case["generic"]))
                self.assertEqual((index.status, index.reason_code), (actual.status, actual.reason_code))
                self.assertEqual(actual.version, case["version"])
                if case["kind"] in {"none", "unresolved"}:
                    self.assertIsNone(actual.accepted_at)
                    self.assertIsNone(actual.revoked_at)
                if case["kind"] == "revocation":
                    self.assertIsNone(actual.version)
                    self.assertIsNone(actual.accepted_at)
                files = self.cf.files(basis={"acceptance": "signed", "revocation": "revoked",
                    "unresolved": "unresolved", "none": None}[case["kind"]], exempt=case["exempt"])
                files["agreements/active.enc.json"] = copy.deepcopy(self.v["active_agreement"])
                if case["kind"] == "acceptance":
                    files["users/07.enc.json"]["7"]["agreements"]["agreement-1"]["version"] = case["version"]
                covered = evaluate_subject(CoverageProjection("project-1", files), 7, "agreement-1")
                self.assertEqual((actual.coverage_decision, actual.coverage_reason_code),
                                 (covered.decision, covered.reason_code))
            CLAIMS.case('derived-v1.json', 'cases', case)
        CLAIMS.value('derived-v1.json', 'active_agreement', 'recorded_at', 'event_id')

    def test_index_only_exemption_and_synthesized_agreement_row(self):
        detail = self.detail(exempt=True)
        detail["agreements"] = {}
        for record in [detail, self.index(detail)]:
            result = self.read(record)
            self.assertEqual((result.status, result.reason_code), ("exempt", "exempt_source_active"))
            self.assertIsNone(result.version)
        detail["exemption_sources"] = {}
        result = self.read(detail)
        self.assertEqual((result.reason_code, result.event_id), ("no_acceptance_recorded", None))

    def test_operational_overlay_scope_windows_and_complete_facts(self):
        for case in self.v["cases"]:
            detail = self.detail(case["kind"], case["version"], exempt=case["exempt"])
            original = copy.deepcopy(detail)
            for fence, marker in [("mutation", "empty"), ("mutation", "open")]:
                for subjects, covered in [([7], True), ([8], False), ([], True)]:
                    pair = self.cf.pair(fence, marker, subjects=subjects)
                    result = self.read(detail, pair=pair)
                    self.assertEqual(result.status, "indeterminate" if covered else case["status"])
                    self.assertEqual(result.reason_code, "operation_in_flight" if covered else case["reason"])
                    index = self.read(self.index(detail), pair=pair)
                    self.assertEqual((index.status, index.reason_code), (result.status, result.reason_code))
            for fence in ["idle", "success"]:
                result = self.read(detail, pair=self.cf.pair(fence, "empty"))
                self.assertEqual((result.status, result.reason_code), (case["status"], case["reason"]))
            self.assertEqual(detail, original)
            CLAIMS.case('derived-v1.json', 'cases', case)

    def test_read_rejects_rolled_back_coverage_and_every_operation_mismatch(self):
        detail = self.detail("acceptance", "1")
        with self.assertRaises(DerivedError):
            self.read(detail, oid="a" * 40)
        for bad_pair in [None, (), [], (None, None), self.cf.pair() + self.cf.pair()]:
            row = DerivedReadRow("project-1", BASE, 7, "agreement-1", detail)
            with self.assertRaises(DerivedError):
                resolve_read_status(row, self.cf.projection(), [], bad_pair)
        pair = self.cf.pair("mutation", "open")
        row = DerivedReadRow("project-1", BASE, 7, "agreement-1", detail)
        with self.assertRaises(DerivedError):
            resolve_read_status(row, self.cf.projection(), [], pair)
        with self.assertRaises(DerivedError):
            resolve_read_status(row, None, [], self.cf.pair())
        with self.assertRaises(DerivedError):
            resolve_read_status({}, self.cf.projection(), [], self.cf.pair())

    def test_effective_scope_is_read_input_not_persisted(self):
        scope = [{"kind": "repository", "repository_id": 1,
                  "owner_snapshot": "owner", "name_snapshot": "repository"}]
        detail = self.detail("acceptance", "1")
        result = self.read(detail, scope=scope)
        self.assertEqual(result.enforcement_scope[0].to_dict(), scope[0])
        self.assertNotIn("enforcement_scope", detail)
        with self.assertRaises(DerivedError):
            self.read(detail, scope=[{"kind": "unknown"}])

    def test_actual_acceptance_revocation_resigning_and_currency_restore(self):
        records, publication, activation = self.f.active_records(nonce=1100)
        first = self.f.append(records, "acceptance", 1110)
        plain = self.materialize(records)
        row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(row["agreements"]["agreement-1"]["basis"], {"kind": "acceptance", "event_id": first.event_id})
        self.assertEqual(row["login_snapshot"], first.actor["login_snapshot"])
        second_publication = self.f.second_publication(records, 1111)
        self.f.append(records, "agreement_activated", 1112, **{
            "target.version": "2", "payload.published_event_id": second_publication.event_id,
            "payload.supersedes_coverage": True, "payload.accepted_versions": ["2"]})
        after = self.materialize(records)
        self.assertEqual(derived_delta(plain, after).files, ())
        current = self.state(records)
        coverage = materialize_coverage(current, self.cf.pair(), canonical_oid=current.current_head_oid,
                                       built_at=self.v["recorded_at"], dracla_version="test")
        self.assertEqual(self.read(row, coverage=coverage, oid=current.current_head_oid).status, "superseded")
        self.f.append(records, "agreement_activation_restored", 1113, **{
            "target.agreement_id": "agreement-1", "target.activation_event_id": activation.event_id,
            "payload.accepted_versions": ["1"]})
        restored = self.materialize(records)
        self.assertEqual(derived_delta(after, restored).files, ())
        current = self.state(records)
        coverage = materialize_coverage(current, self.cf.pair(), canonical_oid=current.current_head_oid,
                                       built_at=self.v["recorded_at"], dracla_version="test")
        self.assertEqual(self.read(row, coverage=coverage, oid=current.current_head_oid).status, "current")
        self.f.append(records, "revocation", 1114)
        revoked = self.materialize(records).to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertIsNone(revoked["agreements"]["agreement-1"]["accepted_at"])
        self.assertIsNone(revoked["agreements"]["agreement-1"]["version"])

    def test_admin_subject_login_snapshot_and_reader_only_event_do_not_rewrite_index(self):
        records = self.connected()
        self.f.append(records, "exemption", 1201, **{"actor.github_user_id": 99,
            "actor.login_snapshot": "administrator", "target.subject.login_snapshot": "recorded-subject"})
        before = self.materialize(records)
        row = before.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(row["login_snapshot"], "recorded-subject")
        self.assertEqual(row["agreements"], {})
        self.assertNotIn("99", before.to_dict()["files"]["derived/status-detail/03.enc.json"])
        self.f.append(records, "records_reader_authorized", 1202, **{
            "target.subject.login_snapshot": "later-reader-login",
            "actor.github_user_id": 7, "actor.login_snapshot": "later-actor-login",
            "recorded_at": "2027-01-01T00:00:00Z"})
        after = self.materialize(records)
        self.assertEqual(derived_delta(before, after).classes, ("reader_authority",))
        self.assertEqual(after.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"], row)

    def test_subject_set_logins_and_canonical_ancestry_not_timestamp(self):
        records = self.connected()
        source = self.f.append(records, "exemption_snapshot", 1210, **{
            "actor.github_user_id": 99, "target.subjects": [
                {"github_user_id": 7, "login_snapshot": "first-seven"},
                {"github_user_id": 8, "login_snapshot": "first-eight"}],
            "recorded_at": "2027-01-01T00:00:00Z"})
        self.f.append(records, "exemption_source_withdrawn", 1211, **{
            "target.source_event_id": source.event_id,
            "target.subject": {"github_user_id": 7, "login_snapshot": "ancestry-wins"},
            "actor.github_user_id": 99, "recorded_at": "2025-01-01T00:00:00Z"})
        state = self.state(records)
        state = replace(state, event_records=dict(reversed(list(state.event_records.items()))))
        values = materialize_derived(state, profile=self.profile).to_dict()["files"]
        self.assertEqual(values["derived/status-detail/07.enc.json"]["7"]["login_snapshot"], "ancestry-wins")
        self.assertEqual(values["derived/status-detail/07.enc.json"]["7"]["login_as_of"], "2025-01-01T00:00:00Z")
        self.assertEqual(values["derived/status-detail/08.enc.json"]["8"]["login_snapshot"], "first-eight")

    def test_digest_table_complete_exact_envelope_binding_and_immutable_projection(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        state = projection.state_dict()
        self.assertEqual(set(state), {"state_version", "generations", "shard_digests", "standing_rules", "shard_count", "profile"})
        for name, prefix in [("derived_index", "index"), ("status_detail", "status-detail"), ("reader_authority", "reader-authority")]:
            self.assertEqual(set(state["shard_digests"][name]), {f"{i:02d}" for i in range(32)})
            for token, digest in state["shard_digests"][name].items():
                self.assertEqual(digest, "sha256:" + hashlib.sha256(encrypted[f"derived/{prefix}/{token}.enc.json"]).hexdigest())
        validate_derived_projection(projection, generations=self.generations(), encrypted_shards=encrypted, profile=self.profile)
        self.assertEqual(len(projection.plaintext_files()), 97)
        self.assertEqual(derived_delta(projection, projection).files, ())
        with self.assertRaises(FrozenInstanceError):
            projection.plaintext = plain
        state["state_version"] = 99
        self.assertEqual(projection.state_dict()["state_version"], 1)

    def test_stale_generations_partial_fanout_and_digest_corruption_fail_closed(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        newer = dict(self.generations(), status_detail="B" * 42 + "A")
        with self.assertRaises(DerivedError):
            validate_derived_projection(projection, generations=newer, encrypted_shards=encrypted, profile=self.profile)
        for path in ["derived/index/00.enc.json", "derived/status-detail/31.enc.json", "derived/reader-authority/00.enc.json"]:
            partial = dict(encrypted)
            del partial[path]
            with self.assertRaises(DerivedError):
                self.assembled(plain, encrypted=partial)
        corrupt = dict(encrypted)
        path = "derived/index/00.enc.json"
        value = json.loads(corrupt[path])
        value["ciphertext"] = base64url_encode(b"x" * 18)
        corrupt[path] = canonical_json(value)
        with self.assertRaises(DerivedError):
            validate_derived_projection(projection, generations=self.generations(), encrypted_shards=corrupt, profile=self.profile)
        for changed in [dict(projection.state_dict(), unexpected=True), dict(projection.state_dict(), shard_count=16),
                        dict(projection.state_dict(), state_version=True)]:
            with self.assertRaises(DerivedError):
                DerivedProjection(plain, changed)

    def test_malformed_envelope_metadata_encoding_profile_and_state_size(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        path = "derived/index/00.enc.json"
        for field, bad in [("project_id", "other-project"), ("artifact_kind", "coverage-shard"),
                           ("logical_id", "derived:derived/index/01.enc.json"), ("schema_version", True),
                           ("kid", "x"), ("nonce", "x"), ("ciphertext", "x"), ("ciphertext", "")]:
            value = json.loads(encrypted[path])
            value[field] = bad
            with self.subTest(field=field), self.assertRaises(DerivedError):
                self.assembled(plain, encrypted={**encrypted, path: canonical_json(value)})
        for raw in [b"{}", b"[]", b"not-json", "not-bytes"]:
            with self.assertRaises(DerivedError):
                self.assembled(plain, encrypted={**encrypted, path: raw})
        profile = ReleaseProfile({**self.profile.to_dict(), "max_state_ciphertext_bytes": 1})
        with self.assertRaises(DerivedClassOverflow) as error:
            self.assembled(plain, encrypted=encrypted, profile=profile)
        self.assertEqual(error.exception.derived_class, "state")
        with self.assertRaises(DerivedError):
            assemble_derived_projection(plain, canonical_oid="a" * 40,
                generations=self.generations(), encrypted_shards=encrypted, profile=self.profile)

    def test_closed_fact_schemas_and_privacy_never_accept_extra_members(self):
        plain = self.materialize(self.connected())
        detail = self.detail("acceptance", "1")
        for name in ["legal_name", "email", "signer", "raw_evidence", "status", "reason_code"]:
            with self.assertRaises(DerivedError):
                DerivedReadRow("project-1", BASE, 7, "agreement-1", {**detail, name: "secret"})
            facts = copy.deepcopy(detail)
            facts["agreements"]["agreement-1"][name] = "secret"
            with self.assertRaises(DerivedError):
                DerivedReadRow("project-1", BASE, 7, "agreement-1", facts)
        for key in detail:
            invalid = copy.deepcopy(detail)
            del invalid[key]
            with self.assertRaises(DerivedError):
                DerivedReadRow("project-1", BASE, 7, "agreement-1", invalid)
        for field, value in [("login_as_of", self.v["recorded_at"]), ("exemption_sequence_next", True),
                              ("agreements", []), ("materialization_cursor", [])]:
            with self.assertRaises(DerivedError):
                DerivedReadRow("project-1", BASE, 7, "agreement-1", {**detail, field: value})
        for bad in [[], "bad", True]:
            with self.assertRaises(DerivedError):
                self.rebuild(plain, files=bad)

    def test_all_subject_shard_boundaries_and_wrong_shard_rejection(self):
        plain = self.materialize(self.connected())
        files = plain.to_dict()["files"]
        for user in range(1, 65):
            row = self.detail()
            files[f"derived/status-detail/{user % 32:02d}.enc.json"][str(user)] = row
            files[f"derived/index/{user % 32:02d}.enc.json"][str(user)] = self.index(row)
        valid = self.rebuild(plain, files=files)
        self.assertEqual(len([p for p, raw in valid.plaintext_files().items() if raw != b"{}"]), 64)
        wrong = copy.deepcopy(files)
        wrong["derived/index/00.enc.json"]["7"] = self.index(self.detail())
        with self.assertRaises(DerivedError):
            self.rebuild(plain, files=wrong)
        for user in ["0", "07", "+7", "9007199254740992", "x"]:
            invalid = copy.deepcopy(files)
            invalid["derived/index/07.enc.json"][user] = self.index(self.detail())
            with self.assertRaises(DerivedError):
                self.rebuild(plain, files=invalid)

    def test_exemption_source_kind_goldens_null_patterns_and_sequences(self):
        for kind, golden in self.v["source_kinds"].items():
            detail = self.detail(exempt=True)
            source = {"source_kind": kind, **copy.deepcopy(golden), "sequence": 0}
            detail["exemption_sources"] = {self.v["event_id"]: source}
            if kind == "continuous_team":
                detail["materialization_cursor"] = {self.v["event_id"]: "B" * 42 + "A"}
            self.assertEqual(self.read(detail).reason_code, "exempt_source_active")
            for field in source:
                bad = copy.deepcopy(detail)
                del bad["exemption_sources"][self.v["event_id"]][field]
                with self.assertRaises(DerivedError):
                    self.read(bad)
            CLAIMS.case('derived-v1.json', 'source_kinds', kind)
        for basis in [None, "basis"]:
            for instrument in [None, "instrument"]:
                row = self.detail(exempt=True)
                row["exemption_sources"][self.v["event_id"]].update(
                    source_kind="bot", basis=basis, instrument_ref=instrument)
                self.assertEqual(self.read(row).status, "exempt")
        for field, bad in [("team", self.v["source_kinds"]["snapshot"]["team"]),
                           ("basis", None), ("rule_event_id", self.v["event_id"]), ("sequence", 1)]:
            row = self.detail(exempt=True)
            row["exemption_sources"][self.v["event_id"]][field] = bad
            with self.assertRaises(DerivedError):
                self.read(row)

    def test_nonempty_index_and_status_detail_wire_goldens(self):
        goldens = self.v["wire_goldens"]["status_rows"]
        self.assertEqual({item["name"] for item in goldens},
                         {case["name"] for case in self.v["cases"]})
        cases = {case["name"]: case for case in self.v["cases"]}
        for golden in goldens:
            case = cases[golden["name"]]
            with self.subTest(case=golden["name"]):
                base = self.materialize(self.connected())
                detail = self.detail(case["kind"], case["version"], exempt=case["exempt"])
                files = base.to_dict()["files"]
                files["derived/status-detail/07.enc.json"]["7"] = detail
                files["derived/index/07.enc.json"]["7"] = self.index(detail)
                plain = self.rebuild(base, files=files)
                actual = plain.plaintext_files()
                self.assertEqual(actual["derived/status-detail/07.enc.json"],
                                 self.fixed_bytes(golden["status_detail_bytes_hex"]))
                self.assertEqual(actual["derived/index/07.enc.json"],
                                 self.fixed_bytes(golden["index_bytes_hex"]))
        CLAIMS.case("derived-v1.json", "wire_goldens", 'status_rows')

    def test_canonical_prepublication_exemption_and_withdrawal_wire_goldens(self):
        golden = self.v["wire_goldens"]["pre_agreement_exemption"]
        inputs = golden["inputs"]
        records = []
        self.f.append(records, "project_connected", inputs["connected_nonce"])
        source = self.f.exemption_event(inputs["exemption_nonce"], inputs["source_kind"])
        self.assertEqual(source.event_id, golden["source_event_id"])
        records.append(self.f.record(source, records[-1].commit_oid, len(records) + 1))
        exempted = self.materialize(records)
        for path, expected in golden["stages"]["exempted"].items():
            self.assertEqual(exempted.plaintext_files()[path], self.fixed_bytes(expected))
        exempted_row = exempted.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(exempted_row["agreements"], {})
        self.assertEqual(self.read(exempted_row).reason_code, golden["expected"]["exempted_reason"])

        withdrawal = self.f.event("exemption_source_withdrawn", inputs["withdrawal_nonce"], **{
            "target.source_event_id": source.event_id,
            "target.subject": dict(source.target["subject"]),
        })
        records.append(self.f.record(withdrawal, records[-1].commit_oid, len(records) + 1))
        withdrawn = self.materialize(records)
        for path, expected in golden["stages"]["withdrawn"].items():
            self.assertEqual(withdrawn.plaintext_files()[path], self.fixed_bytes(expected))
        withdrawn_row = withdrawn.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(withdrawn_row["agreements"], {})
        result = self.read(withdrawn_row)
        self.assertEqual(result.reason_code, golden["expected"]["withdrawn_reason"])
        self.assertIsNone(result.event_id)
        CLAIMS.case("derived-v1.json", "wire_goldens", 'pre_agreement_exemption')

    def test_canonical_signature_acceptance_and_revocation_wire_goldens(self):
        golden = self.v["wire_goldens"]["canonical_signature"]
        inputs = golden["inputs"]
        records, _, _ = self.f.active_records(nonce=inputs["active_nonce"])
        acceptance = self.f.append(records, "acceptance", inputs["acceptance_nonce"])
        self.assertEqual(acceptance.event_id, golden["acceptance_event_id"])
        accepted = self.materialize(records)
        for path, expected in golden["stages"]["accepted"].items():
            self.assertEqual(accepted.plaintext_files()[path], self.fixed_bytes(expected))
        accepted_row = accepted.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(self.read(accepted_row).reason_code, golden["expected"]["accepted_reason"])

        revocation = self.f.append(records, "revocation", inputs["revocation_nonce"])
        self.assertEqual(revocation.event_id, golden["revocation_event_id"])
        revoked = self.materialize(records)
        for path, expected in golden["stages"]["revoked"].items():
            self.assertEqual(revoked.plaintext_files()[path], self.fixed_bytes(expected))
        revoked_row = revoked.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(self.read(revoked_row).reason_code, golden["expected"]["revoked_reason"])
        CLAIMS.case("derived-v1.json", "wire_goldens", 'canonical_signature')

    def test_canonical_recorded_exemption_wire_golden(self):
        golden = self.v["wire_goldens"]["canonical_recorded_exemption"]
        inputs = golden["inputs"]
        records, _, _ = self.f.active_records(nonce=inputs["active_nonce"])
        source = self.f.exemption_event(inputs["exemption_nonce"], inputs["source_kind"])
        self.assertEqual(source.event_id, golden["source_event_id"])
        records.append(self.f.record(source, records[-1].commit_oid, len(records) + 1))
        plain = self.materialize(records)
        for path, expected in golden["stage"].items():
            self.assertEqual(plain.plaintext_files()[path], self.fixed_bytes(expected))
        row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(self.read(row).reason_code, golden["expected_reason"])
        CLAIMS.case("derived-v1.json", "wire_goldens", 'canonical_recorded_exemption')

    def test_canonical_reader_authoring_wire_goldens(self):
        golden = self.v["wire_goldens"]["canonical_readers"]
        inputs = golden["inputs"]
        records = []
        self.f.append(records, "project_connected", inputs["connected_nonce"])
        individual = self.f.append(records, "records_reader_authorized", inputs["individual_nonce"])
        snapshot = self.f.append(records, "records_reader_snapshot_authorized", inputs["snapshot_nonce"])
        rule = self.f.append(records, "records_reader_rule_configured", inputs["continuous_rule_nonce"])
        addition = self.f.reader_materialization_event(rule, "add", None)
        records.append(self.f.record(addition, records[-1].commit_oid, len(records) + 1))
        self.assertEqual({"individual": individual.event_id, "snapshot": snapshot.event_id,
                          "continuous_team": rule.event_id, "continuous_add": addition.event_id},
                         golden["source_event_ids"])
        plain = self.materialize(records)
        actual = plain.plaintext_files()
        for path, expected in golden["files"].items():
            self.assertEqual(actual[path], self.fixed_bytes(expected))
        CLAIMS.case("derived-v1.json", "wire_goldens", 'canonical_readers')

    def test_canonical_assembled_state_with_standing_rule_wire_golden(self):
        golden = self.v["wire_goldens"]["canonical_assembled_state"]
        inputs = golden["inputs"]
        records = []
        self.f.append(records, "project_connected", inputs["connected_nonce"])
        rule = self.f.append(records, "exemption_rule_configured", inputs["standing_rule_nonce"])
        self.assertEqual(rule.event_id, golden["rule_event_id"])
        plain = self.materialize(records)
        self.assertEqual(plain.to_dict()["standing_rules"], {
            golden["rule_event_id"]: golden["standing_rule"]
        })
        fixture = golden["fixture"]
        encrypted = {}
        with patch("dracla.conformance.envelope.secrets.token_bytes",
                   return_value=bytes.fromhex(fixture["nonce_hex"])):
            for path, raw in plain.plaintext_files().items():
                encrypted[path] = encrypt_artifact(
                    raw,
                    project_id=fixture["project_id"],
                    identity=resolve_artifact_identity("records", "derived", path),
                    kid=bytes.fromhex(fixture["kid_hex"]),
                    key=bytes.fromhex(fixture["key_hex"]),
                )
        projection = self.assembled(
            plain,
            generations={"generations_version": 1, **golden["generations"]},
            encrypted=encrypted,
        )
        expected = self.fixed_bytes(golden["bytes_hex"])
        self.assertEqual(projection.plaintext_files()["derived/state.enc.json"], expected)
        state = json.loads(expected)
        self.assertEqual(state["standing_rules"], {
            golden["rule_event_id"]: golden["standing_rule"]
        })
        self.assertEqual({name: len(tokens) for name, tokens in state["shard_digests"].items()},
                         golden["digest_token_counts"])
        CLAIMS.case("derived-v1.json", "wire_goldens", 'canonical_assembled_state')

    def test_exemption_source_kind_wire_goldens_cover_null_patterns(self):
        goldens = self.v["wire_goldens"]["exemption_source_rows"]
        self.assertEqual({item["name"] for item in goldens}, set(self.v["source_kinds"]))
        for golden in goldens:
            with self.subTest(kind=golden["name"]):
                base = self.materialize(self.connected())
                detail = self.detail(exempt=True)
                source = {
                    "source_kind": golden["name"],
                    **copy.deepcopy(self.v["source_kinds"][golden["name"]]),
                    "sequence": 0,
                }
                detail["exemption_sources"][self.v["event_id"]] = source
                rules = {}
                if golden["name"] == "continuous_team":
                    detail["materialization_cursor"] = {
                        self.v["event_id"]: "B" * 42 + "A"
                    }
                    rules[self.v["event_id"]] = {
                        key: copy.deepcopy(source[key])
                        for key in ("team", "basis", "instrument_ref")
                    }
                files = base.to_dict()["files"]
                files["derived/status-detail/07.enc.json"]["7"] = detail
                files["derived/index/07.enc.json"]["7"] = self.index(detail)
                plain = self.rebuild(base, files=files, rules=rules)
                actual = plain.plaintext_files()
                self.assertEqual(actual["derived/status-detail/07.enc.json"],
                                 self.fixed_bytes(golden["status_detail_bytes_hex"]))
                self.assertEqual(actual["derived/index/07.enc.json"],
                                 self.fixed_bytes(golden["index_bytes_hex"]))
        CLAIMS.case("derived-v1.json", "wire_goldens", 'exemption_source_rows')

    def test_reader_authority_wire_goldens_cover_all_reader_kinds(self):
        goldens = self.v["wire_goldens"]["reader_authority"]
        self.assertEqual({item["name"] for item in goldens},
                         {"individual", "snapshot", "continuous_team"})
        for golden in goldens:
            with self.subTest(kind=golden["name"]):
                path_number = int(golden["path"].split("/")[-1].split(".")[0])
                self.assertEqual(reader_authority_shard(golden["source_id"]), path_number)
                base = self.materialize(self.connected())
                files = base.to_dict()["files"]
                files[golden["path"]][golden["source_id"]] = copy.deepcopy(golden["row"])
                plain = self.rebuild(base, files=files)
                self.assertEqual(plain.plaintext_files()[golden["path"]],
                                 self.fixed_bytes(golden["bytes_hex"]))
        CLAIMS.case("derived-v1.json", "wire_goldens", 'reader_authority')

    def test_assembled_state_wire_golden_carries_all_digest_tokens(self):
        golden = self.v["wire_goldens"]["assembled_state"]
        fixture = golden["fixture"]
        plain = self.materialize(self.connected())
        self.assertEqual(plain.project_id, fixture["project_id"])
        self.assertEqual(plain.canonical_oid, fixture["canonical_oid"])
        encrypted = {}
        with patch("dracla.conformance.envelope.secrets.token_bytes",
                   return_value=bytes.fromhex(fixture["nonce_hex"])):
            for path, raw in plain.plaintext_files().items():
                encrypted[path] = encrypt_artifact(
                    raw,
                    project_id=fixture["project_id"],
                    identity=resolve_artifact_identity("records", "derived", path),
                    kid=bytes.fromhex(fixture["kid_hex"]),
                    key=bytes.fromhex(fixture["key_hex"]),
                )
        projection = self.assembled(
            plain,
            generations={"generations_version": 1, **golden["generations"]},
            encrypted=encrypted,
        )
        expected = self.fixed_bytes(golden["bytes_hex"])
        self.assertEqual(projection.plaintext_files()["derived/state.enc.json"], expected)
        state = json.loads(expected)
        self.assertEqual(set(state), {"state_version", "generations", "shard_digests",
                                      "standing_rules", "shard_count", "profile"})
        self.assertEqual(set(state["shard_digests"]),
                         {"derived_index", "status_detail", "reader_authority"})
        for digests in state["shard_digests"].values():
            self.assertEqual(set(digests), {f"{i:02d}" for i in range(32)})
        CLAIMS.case("derived-v1.json", "wire_goldens", 'assembled_state')

    def test_standing_rule_empty_membership_and_withdrawal_only_change_detail(self):
        records = self.connected()
        self.f.append(records, "exemption", 1301)
        before = self.materialize(records)
        rule = self.f.append(records, "exemption_rule_configured", 1302)
        configured = self.materialize(records)
        self.assertEqual(derived_delta(before, configured).files, ("derived/state.enc.json",))
        self.assertEqual(set(configured.to_dict()["standing_rules"]), {rule.event_id})
        add = self.f.exemption_materialization_event(rule, "add", None)
        records.append(self.f.record(add, records[-1].commit_oid, len(records) + 1))
        added = self.materialize(records)
        self.f.append(records, "exemption_rule_withdrawn", 1303, **{"target.rule_event_id": rule.event_id})
        withdrawn = self.materialize(records)
        self.assertEqual(withdrawn.to_dict()["standing_rules"], {})
        self.assertEqual(derived_delta(added, withdrawn).classes, ("status_detail",))
        row = withdrawn.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(row["materialization_cursor"], {})
        self.assertTrue(row["exemption_sources"])

    def test_last_rule_withdrawal_changes_index_and_keeps_unsigned_provenance_null(self):
        records = self.connected()
        rule = self.f.append(records, "exemption_rule_configured", 1310)
        add = self.f.exemption_materialization_event(rule, "add", None)
        records.append(self.f.record(add, records[-1].commit_oid, len(records) + 1))
        before = self.materialize(records)
        self.f.append(records, "exemption_rule_withdrawn", 1311, **{"target.rule_event_id": rule.event_id})
        after = self.materialize(records)
        self.assertEqual(derived_delta(before, after).classes, ("derived_index", "status_detail"))
        row = after.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(row["agreements"], {})
        self.assertFalse(row["exemption_sources"])
        result = self.read(row)
        self.assertEqual((result.reason_code, result.event_id), ("no_acceptance_recorded", None))

    def test_exemption_add_withdraw_add_keeps_sequence_and_materialization_cursor(self):
        records = self.connected()
        rule = self.f.append(records, "exemption_rule_configured", 1320)
        prior = None
        ids = []
        for result in ["add", "withdraw", "add"]:
            event = self.f.exemption_materialization_event(rule, result, prior)
            records.append(self.f.record(event, records[-1].commit_oid, len(records) + 1))
            plain = self.materialize(records)
            row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
            self.assertEqual(row["materialization_cursor"][rule.event_id], event.event_id)
            self.assertEqual(row["exemption_sequence_next"], 1 if len(ids) < 2 else 2)
            self.assertEqual(bool(row["exemption_sources"]), result == "add")
            if result == "add":
                self.assertEqual(row["exemption_sources"][rule.event_id]["sequence"], 0 if not ids else 1)
            ids.append(event.event_id)
            prior = event.event_id
        self.assertEqual(len(set(ids)), 3)

    def test_multiple_sources_choose_latest_sequence_without_destroying_revocation(self):
        records, _, _ = self.f.active_records(nonce=1330)
        self.f.append(records, "acceptance", 1333)
        self.f.append(records, "revocation", 1334)
        first = self.f.append(records, "exemption", 1335)
        second = self.f.exemption_event(1336, "bot")
        records.append(self.f.record(second, records[-1].commit_oid, len(records) + 1))
        plain = self.materialize(records)
        row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(self.read(row).event_id, second.event_id)
        self.f.append(records, "exemption_source_withdrawn", 1337, **{
            "target.source_event_id": second.event_id, "target.subject": first.to_dict()["target"]["subject"]})
        row = self.materialize(records).to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(self.read(row).event_id, first.event_id)
        self.f.append(records, "exemption_source_withdrawn", 1338, **{
            "target.source_event_id": first.event_id, "target.subject": first.to_dict()["target"]["subject"]})
        row = self.materialize(records).to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        self.assertEqual(self.read(row).reason_code, "revoked_by_contributor")
        self.assertIsNone(row["agreements"]["agreement-1"]["accepted_at"])

    def test_reader_snapshot_withdrawals_preserve_siblings_and_remove_last_source(self):
        records = self.connected()
        source = self.f.append(records, "records_reader_snapshot_authorized", 1401, **{
            "target.subjects": [{"github_user_id": 7, "login_snapshot": "seven"},
                                {"github_user_id": 8, "login_snapshot": "eight"}]})
        path = f"derived/reader-authority/{reader_authority_shard(source.event_id):02d}.enc.json"
        for user in [7, 8]:
            before = self.materialize(records)
            self.f.append(records, "records_reader_withdrawn", 1400 + user, **{
                "target.source_event_id": source.event_id,
                "target.subject": {"github_user_id": user, "login_snapshot": "renamed"}})
            after = self.materialize(records)
            self.assertEqual(derived_delta(before, after).files, (path, "derived/state.enc.json"))
            values = after.to_dict()["files"][path]
            if user == 7:
                self.assertEqual(set(values[source.event_id]["subjects"]), {"8"})
                self.assertEqual(values[source.event_id]["team"], source.to_dict()["payload"]["team"])
            else:
                self.assertNotIn(source.event_id, values)

    def test_reader_continuous_cursor_survives_empty_membership_and_rename(self):
        records = self.connected()
        rule = self.f.append(records, "records_reader_rule_configured", 1410)
        path = f"derived/reader-authority/{reader_authority_shard(rule.event_id):02d}.enc.json"
        configured = self.materialize(records).to_dict()["files"][path][rule.event_id]
        self.assertEqual(configured["subjects"], {})
        prior = None
        ids = []
        for result in ["add", "withdraw", "add"]:
            event = self.f.reader_materialization_event(rule, result, prior)
            records.append(self.f.record(event, records[-1].commit_oid, len(records) + 1))
            source = self.materialize(records).to_dict()["files"][path][rule.event_id]
            self.assertEqual(source["team"], configured["team"])
            self.assertEqual(source["materialization_cursor"]["7"], event.event_id)
            self.assertEqual(bool(source["subjects"]), result == "add")
            ids.append(event.event_id)
            prior = event.event_id
        self.assertEqual(len(set(ids)), 3)
        self.f.append(records, "records_reader_rule_withdrawn", 1411, **{"target.rule_event_id": rule.event_id})
        self.assertNotIn(rule.event_id, self.materialize(records).to_dict()["files"][path])

    def selected_shard(self, plain, path, values):
        """Bind supplied plaintext to a matching encrypted shard and state digest."""
        with patch("dracla.conformance.envelope.secrets.token_bytes", return_value=bytes(12)):
            envelope = encrypt_artifact(canonical_json(values), project_id=plain.project_id,
                identity=resolve_artifact_identity("records", "derived", path),
                kid=b"k" * 16, key=b"k" * 32)
        state = self.assembled(plain).state_dict()
        derived_class = "status_detail" if "/status-detail/" in path else "reader_authority"
        state["shard_digests"][derived_class][path.rsplit("/", 1)[1][:2]] = (
            "sha256:" + hashlib.sha256(envelope).hexdigest())
        return DerivedReadProjection(plain.project_id, plain.canonical_oid, state=state,
            selected_files={path: values}, selected_envelopes={path: envelope},
            generation=self.generations()[derived_class], profile=self.profile)

    def test_continuous_exemption_provenance_matches_standing_rule(self):
        records = self.connected()
        rule = self.f.append(records, "exemption_rule_configured", 2050)
        event = self.f.exemption_materialization_event(rule, "add", None)
        records.append(self.f.record(event, records[-1].commit_oid, len(records) + 1))
        plain = self.materialize(records)
        path = "derived/status-detail/07.enc.json"
        self.selected_shard(plain, path, plain.to_dict()["files"][path])
        for field in ("team", "basis", "instrument_ref"):
            with self.subTest(field=field):
                files = plain.to_dict()["files"]
                source = files[path]["7"]["exemption_sources"][rule.event_id]
                if field == "team":
                    source[field]["team_id"] += 1
                else:
                    source[field] += "-different"
                for boundary in ("full", "selected"):
                    with self.subTest(boundary=boundary), self.assertRaisesRegex(
                            DerivedError, "disagrees with its standing rule"):
                        if boundary == "full":
                            self.rebuild(plain, files=files)
                        else:
                            self.selected_shard(plain, path, files[path])

    def test_departed_reader_cursor_rejects_its_source_rule_id(self):
        records = self.connected()
        rule = self.f.append(records, "records_reader_rule_configured", 2060)
        prior = None
        for result in ("add", "withdraw"):
            event = self.f.reader_materialization_event(rule, result, prior)
            records.append(self.f.record(event, records[-1].commit_oid, len(records) + 1))
            prior = event.event_id
        plain = self.materialize(records)
        path = f"derived/reader-authority/{reader_authority_shard(rule.event_id):02d}.enc.json"
        files = plain.to_dict()["files"]
        source = files[path][rule.event_id]
        self.assertEqual(source["subjects"], {})
        self.assertEqual(source["materialization_cursor"]["7"], prior)
        self.selected_shard(plain, path, files[path])
        source["materialization_cursor"]["7"] = rule.event_id
        for boundary in ("full", "selected"):
            with self.subTest(boundary=boundary), self.assertRaisesRegex(
                    DerivedError, "not its source rule"):
                if boundary == "full":
                    self.rebuild(plain, files=files)
                else:
                    self.selected_shard(plain, path, files[path])

    def test_exemption_cursor_rejects_rule_id_with_or_without_membership(self):
        records = self.connected()
        rule = self.f.append(records, "exemption_rule_configured", 2065)
        prior = None
        path = "derived/status-detail/07.enc.json"
        for result in ("add", "withdraw"):
            event = self.f.exemption_materialization_event(rule, result, prior)
            records.append(self.f.record(event, records[-1].commit_oid, len(records) + 1))
            prior = event.event_id
            plain = self.materialize(records)
            files = plain.to_dict()["files"]
            row = files[path]["7"]
            self.assertEqual(bool(row["exemption_sources"]), result == "add")
            self.assertEqual(row["materialization_cursor"][rule.event_id], event.event_id)
            self.selected_shard(plain, path, files[path])
            row["materialization_cursor"][rule.event_id] = rule.event_id
            for boundary in ("full", "selected", "read-row"):
                with self.subTest(result=result, boundary=boundary), self.assertRaisesRegex(
                        DerivedError, "exemption cursor must name a materialization"):
                    if boundary == "full":
                        self.rebuild(plain, files=files)
                    elif boundary == "selected":
                        self.selected_shard(plain, path, files[path])
                    else:
                        self.read(row, oid=plain.canonical_oid)

    def test_succeeded_project_reads_fail_closed_before_status_selection(self):
        for event_type in ("acceptance", "exemption"):
            records, _, _ = self.f.active_records(nonce=2070)
            self.f.append(records, event_type, 2073)
            self.f.append(records, "project_succeeded", 2074)
            state = self.state(records)
            plain = materialize_derived(state, profile=self.profile)
            detail = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
            for pair in (self.cf.pair(), self.cf.pair("mutation", "open"),
                         self.cf.pair("success", "empty")):
                full = materialize_coverage(state, pair, canonical_oid=state.current_head_oid,
                    built_at=self.v["recorded_at"], dracla_version="test")
                decision = evaluate_subject(full, 7, "agreement-1")
                self.assertEqual(decision.decision, "uncovered")
                self.assertEqual(decision.successor_project_id, state.successor_project_id)
                bounded = self.bounded_coverage(state, pair)
                for coverage in (full, bounded):
                    for row in (detail, self.index(detail)):
                        with self.subTest(event_type=event_type, coverage=type(coverage).__name__,
                                          fence=pair[1].to_dict()["state"], detail="exemption_sources" in row):
                            with self.assertRaisesRegex(DerivedError, "project has been succeeded"):
                                self.read(row, coverage=coverage, pair=pair, oid=state.current_head_oid)

    def test_unresolved_replay_is_durable_and_never_replaced_by_exemption(self):
        records, _, _ = self.f.active_records(nonce=1420)
        event = self.f.append(records, "acceptance", 1423)
        state = replace(self.state(records), unresolved=frozenset({((7, "agreement-1"), event.event_id)}))
        plain = materialize_derived(state, profile=self.profile)
        row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        expected = self.facts("unresolved")
        expected["basis"]["event_id"] = event.event_id
        self.assertEqual(row["agreements"]["agreement-1"], expected)
        self.assertEqual(self.read(row).reason_code, "replay_unresolved")
        for pair in [self.cf.pair(), self.cf.pair("success")]:
            self.assertEqual(self.read(row, pair=pair).reason_code, "replay_unresolved")

    def test_reader_sources_and_cumulative_cursor_limit_boundaries(self):
        plain = self.materialize(self.connected())
        source_id = self.v["event_id"]
        path = f"derived/reader-authority/{reader_authority_shard(source_id):02d}.enc.json"
        profile = ReleaseProfile({**self.profile.to_dict(), "max_reader_source_members": 3,
                                  "max_reader_cursor_entries": 4})
        for count in [2, 3, 4]:
            files = plain.to_dict()["files"]
            files[path][source_id] = {"kind": "snapshot", "team": self.v["source_kinds"]["snapshot"]["team"],
                "materialization_cursor": {}, "subjects": {str(i): {"added_event_id": source_id} for i in range(1, count + 1)}}
            if count <= 3:
                self.rebuild(plain, files=files, profile=profile)
            else:
                with self.assertRaises(ReleaseProfileError):
                    self.rebuild(plain, files=files, profile=profile)
        for count in [3, 4, 5]:
            files = plain.to_dict()["files"]
            files[path][source_id] = {"kind": "continuous_team", "team": self.v["source_kinds"]["snapshot"]["team"],
                "materialization_cursor": {str(i): "B" * 42 + "A" for i in range(1, count + 1)}, "subjects": {}}
            if count <= 4:
                self.rebuild(plain, files=files, profile=profile)
            else:
                with self.assertRaises(ReleaseProfileError):
                    self.rebuild(plain, files=files, profile=profile)

    def test_rule_count_limits_and_source_shard_distribution(self):
        plain = self.materialize(self.connected())
        profile = ReleaseProfile({**self.profile.to_dict(), "max_continuous_exemption_rules": 3})
        team = self.v["source_kinds"]["snapshot"]["team"]
        for count in [2, 3, 4]:
            rules = {base64url_encode(hashlib.sha256(str(i).encode()).digest()):
                {"team": team, "basis": "basis", "instrument_ref": "instrument"} for i in range(count)}
            if count <= 3:
                self.rebuild(plain, rules=rules, profile=profile)
            else:
                with self.assertRaises(ReleaseProfileError):
                    self.rebuild(plain, rules=rules, profile=profile)
        for count in [9, 10, 11]:
            files = plain.to_dict()["files"]
            for i in range(count):
                key = base64url_encode(hashlib.sha256(str(i).encode()).digest())
                path = f"derived/reader-authority/{reader_authority_shard(key):02d}.enc.json"
                files[path][key] = {"kind": "continuous_team", "team": team,
                    "materialization_cursor": {}, "subjects": {}}
            if count <= 10:
                self.rebuild(plain, files=files)
            else:
                with self.assertRaises(ReleaseProfileError):
                    self.rebuild(plain, files=files)
        cases = self.v["source_shards"]
        self.assertEqual({case["shard"] for case in cases}, set(range(32)))
        additions = [case for case in cases if "sha256" in case]
        self.assertEqual(len(additions), 6)
        self.assertEqual({case["shard"] for case in additions}, {0, 3, 14, 24, 26, 29})
        for case in cases:
            self.assertEqual(reader_authority_shard(case["source_id"]), case["shard"])
            CLAIMS.case("derived-v1.json", "source_shards", case)
        for case in additions:
            digest = hashlib.sha256(case["source_id"].encode("utf-8")).hexdigest()
            self.assertEqual(digest, case["sha256"])
            self.assertEqual(int(digest[:2], 16) >> 3, case["shard"])

        files = plain.to_dict()["files"]
        for case in additions:
            path = f"derived/reader-authority/{case['shard']:02d}.enc.json"
            files[path][case["source_id"]] = {
                "kind": "individual", "team": None, "materialization_cursor": {},
                "subjects": {"7": {"added_event_id": case["source_id"]}},
            }
            self.assertEqual(set(files[path]), {case["source_id"]})
        self.rebuild(plain, files=files)

    def test_envelope_size_and_small_state_exact_boundaries(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        state_ciphertext_size = len(projection.plaintext_files()["derived/state.enc.json"]) + 16
        for delta in [-1, 0, 1]:
            profile = ReleaseProfile({**self.profile.to_dict(), "max_state_ciphertext_bytes": state_ciphertext_size + delta})
            if delta < 0:
                with self.assertRaises(DerivedClassOverflow):
                    self.assembled(plain, encrypted=encrypted, profile=profile)
            else:
                self.assembled(plain, encrypted=encrypted, profile=profile)
        # Canonical empty-object ciphertext is exactly two plaintext bytes plus a16-byte tag.
        for name in ["derived_index", "status_detail", "reader_authority"]:
            for limit in [17, 18, 19]:
                values = self.profile.to_dict()
                values["max_shard_ciphertext_bytes"][name] = limit
                profile = ReleaseProfile(values)
                if limit < 18:
                    with self.assertRaises(DerivedClassOverflow) as error:
                        self.assembled(plain, encrypted=encrypted, profile=profile)
                    self.assertEqual(error.exception.derived_class, name)
                else:
                    self.assembled(plain, encrypted=encrypted, profile=profile)

    def test_acceptance_and_revocation_complete_past_largest_private_shard_limit(self):
        records, _, _ = self.f.active_records(nonce=1500)
        for i in range(8):
            self.f.append(records, "acceptance", 1510 + i, **{
                "actor.github_user_id": 7 + 32 * i, "target.coverage_tuple.github_user_id": 7 + 32 * i})
        values = self.profile.to_dict()
        values["max_shard_ciphertext_bytes"] = {name: 512 for name in values["max_shard_ciphertext_bytes"]}
        profile = ReleaseProfile(values)
        for revoke in [False, True]:
            if revoke:
                self.f.append(records, "revocation", 1520)
            state = self.state(records)
            coverage = materialize_coverage(state, self.cf.pair(), canonical_oid=state.current_head_oid,
                built_at=self.v["recorded_at"], dracla_version="test")
            self.assertGreater(len(coverage.plaintext_files()["users/07.enc.json"]), 512)
            self.assertEqual(evaluate_subject(coverage, 7, "agreement-1").reason_code, "revoked" if revoke else "signed")
            plaintext = materialize_derived(state, profile=profile)
            with self.assertRaises(DerivedClassOverflow) as error:
                self.assembled(plaintext, profile=profile)
            self.assertIn(error.exception.derived_class, {"derived_index", "status_detail"})
            self.assertEqual(state.current_head_oid, records[-1].commit_oid)

    def test_reader_source_projection_is_subject_bound_and_keeps_snapshot_team_private(self):
        records = self.connected()
        individual = self.f.append(records, "records_reader_authorized", 1601)
        snapshot = self.f.append(records, "records_reader_snapshot_authorized", 1602)
        rule = self.f.append(records, "records_reader_rule_configured", 1603)
        event = self.f.reader_materialization_event(rule, "add", None)
        records.append(self.f.record(event, records[-1].commit_oid, len(records) + 1))
        plain = self.materialize(records)
        for source in [individual, snapshot, rule]:
            result = reader_source_for_subject(plain, source.event_id, 7)
            continuous = source is rule
            self.assertEqual(set(result), {"source_id", "kind", "organization_id", "team_id"})
            self.assertEqual(result["organization_id"], rule.target["team"]["organization_id"] if continuous else None)
            self.assertEqual(result["team_id"], rule.target["team"]["team_id"] if continuous else None)
            with self.assertRaises(DerivedError):
                reader_source_for_subject(plain, source.event_id, 999)
        with self.assertRaises(DerivedError):
            reader_source_for_subject(plain, self.v["event_id"], 7)
        with self.assertRaises(DerivedError):
            reader_source_for_subject(None, rule.event_id, 7)
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        validate_derived_projection(projection, generations=self.generations(),
            encrypted_shards=encrypted, profile=self.profile)

    def test_signature_basis_null_patterns_and_closed_generation_configuration(self):
        for kind, changes in [("none", {"version": "1"}), ("acceptance", {"revoked_at": self.v["recorded_at"]}),
                              ("revocation", {"accepted_at": self.v["recorded_at"]}),
                              ("unresolved", {"version": "1"})]:
            row = self.detail(kind, "1" if kind == "acceptance" else None)
            row["agreements"]["agreement-1"].update(changes)
            with self.assertRaises(DerivedError):
                self.read(row)
        for kind in ["unknown", [], None, 1]:
            row = self.detail()
            row["agreements"]["agreement-1"]["basis"]["kind"] = kind
            with self.assertRaises(DerivedError):
                self.read(row)
        index = self.index(self.detail())
        index["exempt"] = 1
        with self.assertRaises(DerivedError):
            self.read(index)
        for invalid in [dict(self.generations(), generations_version=True),
                        dict(self.generations(), generations_version=2),
                        dict(self.generations(), unknown=self.v["event_id"]),
                        dict(self.generations(), reader_authority=None)]:
            with self.assertRaises(DerivedError):
                validate_materialization_generations(invalid)
        config = self.materialize(self.connected()).to_dict()["configuration"]
        with self.assertRaises(DerivedError):
            validate_project_configuration({**config, "unknown": True})

    def test_source_schema_and_counter_corruption_is_fatal(self):
        for bad in ["unknown", None, []]:
            row = self.detail(exempt=True)
            row["exemption_sources"][self.v["event_id"]]["source_kind"] = bad
            with self.assertRaises(DerivedError):
                self.read(row)
        row = self.detail(exempt=True)
        row["exemption_sources"]["B" * 42 + "A"] = copy.deepcopy(row["exemption_sources"][self.v["event_id"]])
        with self.assertRaises(DerivedError):
            self.read(row)
        row = self.detail(exempt=True)
        row["exemption_sources"][self.v["event_id"]].update(source_kind="continuous_team",
            team=self.v["source_kinds"]["snapshot"]["team"], rule_event_id="B" * 42 + "A")
        with self.assertRaises(DerivedError):
            self.read(row)

    def test_reader_source_closed_kind_membership_and_cursor_rejections(self):
        plain = self.materialize(self.connected())
        key, other = self.v["event_id"], "B" * 42 + "A"
        path = f"derived/reader-authority/{reader_authority_shard(key):02d}.enc.json"
        base = {"kind": "individual", "team": None, "subjects": {"7": {"added_event_id": key}}, "materialization_cursor": {}}
        invalids = [dict(base, kind=[]), dict(base, kind="unknown"), dict(base, team=self.v["source_kinds"]["snapshot"]["team"]),
            dict(base, subjects=[]), dict(base, subjects={}), dict(base, materialization_cursor={"7": other}),
            dict(base, subjects={"7": {"added_event_id": other}}),
            dict(base, kind="snapshot", team=self.v["source_kinds"]["snapshot"]["team"], subjects={}),
            dict(base, kind="continuous_team", team=self.v["source_kinds"]["snapshot"]["team"]),
            dict(base, kind="continuous_team", team=self.v["source_kinds"]["snapshot"]["team"], materialization_cursor={"7": other})]
        for source in invalids:
            files = plain.to_dict()["files"]
            files[path][key] = source
            with self.assertRaises(DerivedError):
                self.rebuild(plain, files=files)
        for field in base:
            files = plain.to_dict()["files"]
            source = copy.deepcopy(base)
            del source[field]
            files[path][key] = source
            with self.assertRaises(DerivedError):
                self.rebuild(plain, files=files)
        files = plain.to_dict()["files"]
        files[f"derived/reader-authority/{(reader_authority_shard(key) + 1) % 32:02d}.enc.json"][key] = base
        with self.assertRaises(DerivedError):
            self.rebuild(plain, files=files)

    def test_index_detail_disagreement_and_unreachable_rules_fail_closed(self):
        plain = self.materialize(self.connected())
        detail = self.detail()
        files = plain.to_dict()["files"]
        files["derived/status-detail/07.enc.json"]["7"] = detail
        with self.assertRaises(DerivedError):
            self.rebuild(plain, files=files)
        files["derived/index/07.enc.json"]["7"] = dict(self.index(detail), exempt=True)
        with self.assertRaises(DerivedError):
            self.rebuild(plain, files=files)
        key = self.v["event_id"]
        for cursor, source, rules in [(True, False, {}), (False, True, {}),
                (False, True, {key: {k: self.v["source_kinds"]["continuous_team"][k]
                                    for k in ("team", "basis", "instrument_ref")}})]:
            row = self.detail(exempt=source)
            if source:
                row["exemption_sources"][key] = {"source_kind": "continuous_team",
                    **self.v["source_kinds"]["continuous_team"], "sequence": 0}
            if cursor:
                row["materialization_cursor"] = {key: "B" * 42 + "A"}
            files = plain.to_dict()["files"]
            files["derived/status-detail/07.enc.json"]["7"] = row
            files["derived/index/07.enc.json"]["7"] = self.index(row)
            with self.assertRaises(DerivedError):
                self.rebuild(plain, files=files, rules=rules)
        with self.assertRaises(DerivedError):
            self.rebuild(plain, rules=[])
        files = plain.to_dict()["files"]
        files["derived/index/00.enc.json"] = []
        with self.assertRaises(DerivedError):
            self.rebuild(plain, files=files)

    def test_public_type_source_and_ancestry_boundaries(self):
        records = self.connected()
        plain = self.materialize(records)
        for state in [None, [], self.state([])]:
            with self.assertRaises(DerivedError):
                materialize_derived(state, profile=self.profile)
        with self.assertRaises(DerivedError):
            materialize_derived(self.state(records), profile=None)
        state = replace(self.state(records), event_records={}, current_head_oid=BASE)
        with self.assertRaises(DerivedError):
            materialize_derived(state, profile=self.profile)
        state = replace(self.state(records), current_head_oid="a" * 40)
        with self.assertRaises(DerivedError):
            materialize_derived(state, profile=self.profile)
        record = records[0]
        for extra in [replace(record, commit_oid="a" * 40), record]:
            state = replace(self.state(records), event_records={record.event_id: record, "extra": extra})
            with self.assertRaises(DerivedError):
                materialize_derived(state, profile=self.profile)
        for bad in [object(), {"not-json": object()}]:
            with self.assertRaises(DerivedError):
                self.rebuild(plain, files=bad)
        for function in [lambda: DerivedProjection(None, {}),
                         lambda: assemble_derived_projection(None, canonical_oid=BASE, generations={}, encrypted_shards={}, profile=self.profile),
                         lambda: validate_derived_projection(None, generations=self.generations(), encrypted_shards={}, profile=self.profile),
                         lambda: derived_delta(None, plain), lambda: derived_delta(plain, self.assembled(plain))]:
            with self.assertRaises(DerivedError):
                function()
        other = DerivedPlaintext("other-project", plain.canonical_oid, files=plain.to_dict()["files"],
            configuration=plain.to_dict()["configuration"], standing_rules={}, profile=self.profile)
        with self.assertRaises(DerivedError):
            derived_delta(plain, other)

    def test_stored_state_profile_and_digest_encodings_are_closed(self):
        plain = self.materialize(self.connected())
        projection = self.assembled(plain)
        for mutate in [lambda s: s["profile"].update(max_continuous_reader_rules=9),
                       lambda s: s["profile"]["max_shard_ciphertext_bytes"].update(coverage=1),
                       lambda s: s["shard_digests"]["derived_index"].update({"00": "a" * 64}),
                       lambda s: s["shard_digests"]["derived_index"].pop("31"),
                       lambda s: s.update(standing_rules={self.v["event_id"]: {}})]:
            state = projection.state_dict()
            mutate(state)
            with self.assertRaises(DerivedError):
                DerivedProjection(plain, state)

    def test_full_release_profile_contract_claim_follows_schema_assertions(self):
        from core.tests.test_conformance_release_profile import TestReleaseProfile

        checks = TestReleaseProfile()
        for name in (
            "test_checked_in_numeric_profile_and_canonical_roundtrip",
            "test_every_root_member_is_required_and_unknowns_are_rejected",
            "test_invalid_scalar_profiles_and_fixed_values",
            "test_coverage_cap_and_misclassified_limits_are_unrepresentable",
        ):
            checks.setUp()
            getattr(checks, name)()
        CLAIMS.contract("closed_schemas", "release-profile")

    def test_replay_basis_and_source_context_cannot_be_substituted(self):
        records, _, _ = self.f.active_records(nonce=1700)
        self.f.append(records, "acceptance", 1703)
        state = self.state(records)
        key, decision = next(iter(state.tuple_decisions.items()))
        for decisions in [{(8, key[1], key[2]): decision},
                          {key: replace(decision, event_id=self.v["event_id"])}]:
            with self.assertRaises(DerivedError):
                materialize_derived(replace(state, tuple_decisions=decisions), profile=self.profile)
        with self.assertRaises(DerivedError):
            materialize_derived(replace(state, unresolved=frozenset({(7, "agreement-1")})), profile=self.profile)
        source = self.f.append(records, "records_reader_authorized", 1704)
        state = self.state(records)
        value = state.reader_source_records[source.event_id]
        with self.assertRaises(DerivedError):
            materialize_derived(replace(state, reader_source_records={self.v["event_id"]: value}), profile=self.profile)
        row = DerivedReadRow("project-1", BASE, 7, "different-agreement", self.detail())
        with self.assertRaises(DerivedError):
            resolve_read_status(row, self.cf.projection(), [], self.cf.pair())

    def test_unobserved_unresolved_subject_login_stays_explicit_null(self):
        records = self.connected()
        state = replace(self.state(records), unresolved=frozenset({((8, "agreement-1"), records[0].event_id)}))
        plain = materialize_derived(state, profile=self.profile)
        row = plain.to_dict()["files"]["derived/status-detail/08.enc.json"]["8"]
        self.assertIsNone(row["login_snapshot"])
        self.assertIsNone(row["login_as_of"])

    def test_installed_profile_capacity_fixture(self):
        plain = self.materialize(self.connected())
        files = plain.to_dict()["files"]
        for i in range(128):
            user = 7 + 32 * i
            row = self.detail("acceptance", "1")
            files["derived/status-detail/07.enc.json"][str(user)] = row
            files["derived/index/07.enc.json"][str(user)] = self.index(row)
        key, added = self.v["event_id"], "B" * 42 + "A"
        team = self.v["source_kinds"]["snapshot"]["team"]
        path = f"derived/reader-authority/{reader_authority_shard(key):02d}.enc.json"
        files[path][key] = {"kind": "continuous_team", "team": team,
            "subjects": {str(i): {"added_event_id": added} for i in range(1, 513)},
            "materialization_cursor": {str(i): added for i in range(1, 2049)}}
        rules = {base64url_encode(hashlib.sha256(str(i).encode()).digest()):
            {"team": team, "basis": "capacity fixture", "instrument_ref": "fixture-v1"} for i in range(32)}
        plain = self.rebuild(plain, files=files, rules=rules)
        projection = self.assembled(plain)
        from dracla.conformance import base64url_decode
        encrypted = self.encrypted(plain)
        for prefix, expected in [("index", 32237), ("status-detail", 40429), ("reader-authority", 143884)]:
            sizes = [len(base64url_decode(json.loads(raw)["ciphertext"]))
                     for path, raw in encrypted.items() if path.startswith("derived/" + prefix + "/")]
            self.assertEqual(max(sizes), expected)
        self.assertEqual(len(projection.plaintext_files()["derived/state.enc.json"]) + 16, 13810)

    def test_reader_withdrawal_stays_available_while_private_profile_is_exceeded(self):
        records = self.connected()
        source = self.f.append(records, "records_reader_snapshot_authorized", 1801, **{
            "target.subjects": [{"github_user_id": i, "login_snapshot": str(i)} for i in [7, 8, 9]]})
        small = ReleaseProfile({**self.profile.to_dict(), "max_reader_source_members": 1})
        for user, remaining in [(7, 2), (8, 1), (9, 0)]:
            self.f.append(records, "records_reader_withdrawn", 1800 + user, **{
                "target.source_event_id": source.event_id,
                "target.subject": {"github_user_id": user, "login_snapshot": "observed"}})
            state = self.state(records)
            coverage = materialize_coverage(state, self.cf.pair(), canonical_oid=state.current_head_oid,
                built_at=self.v["recorded_at"], dracla_version="test")
            self.assertEqual(coverage.to_dict()["source.enc.json"]["canonical_sha"], records[-1].commit_oid)
            if remaining > 1:
                with self.assertRaises(ReleaseProfileError):
                    materialize_derived(state, profile=small)
            else:
                plain = materialize_derived(state, profile=small)
                path = f"derived/reader-authority/{reader_authority_shard(source.event_id):02d}.enc.json"
                sources = plain.to_dict()["files"][path]
                self.assertEqual(len(sources[source.event_id]["subjects"]) if sources else 0, remaining)

    def test_stale_reader_generation_does_not_invalidate_current_index_or_status_class(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        generations = dict(self.generations(), reader_authority="B" * 42 + "A")
        for path in ["derived/index/00.enc.json", "derived/status-detail/31.enc.json"]:
            validate_derived_projection(projection, generations=generations,
                encrypted_shards={path: encrypted[path]}, profile=self.profile)
        path = "derived/reader-authority/00.enc.json"
        with self.assertRaises(DerivedError):
            validate_derived_projection(projection, generations=generations,
                encrypted_shards={path: encrypted[path]}, profile=self.profile)
        for selected in [{}, {"unknown": b"{}"}, []]:
            with self.assertRaises(DerivedError):
                validate_derived_projection(projection, generations=self.generations(),
                    encrypted_shards=selected, profile=self.profile)

    def test_selected_read_rejects_profile_state_size_and_shard_size_drift(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        path = "derived/index/00.enc.json"
        selected = {path: encrypted[path]}
        for changes in [{"max_reader_source_members": 1}, {"max_state_ciphertext_bytes": 1}]:
            profile = ReleaseProfile({**self.profile.to_dict(), **changes})
            with self.assertRaises((DerivedError, DerivedClassOverflow)):
                validate_derived_projection(projection, generations=self.generations(),
                    encrypted_shards=selected, profile=profile)
        values = self.profile.to_dict()
        values["max_shard_ciphertext_bytes"]["derived_index"] = 17
        profile = ReleaseProfile(values)
        state = projection.state_dict()
        state["profile"]["max_shard_ciphertext_bytes"]["derived_index"] = 17
        stale = DerivedProjection(plain, state)
        with self.assertRaises(DerivedClassOverflow) as error:
            validate_derived_projection(stale, generations=self.generations(),
                encrypted_shards=selected, profile=profile)
        self.assertEqual(error.exception.derived_class, "derived_index")

    def test_bounded_selected_status_and_index_reads_use_only_selected_class(self):
        records, _, _ = self.f.active_records(nonce=1960)
        self.f.append(records, "acceptance", 1963)
        state = self.state(records)
        status = self.bounded(records, "status_detail")
        context = self.bounded_coverage(state)
        status_result = resolve_selected_read_status(
            status, subject=7, agreement_id="agreement-1", coverage=context,
            effective_scope=[], operation_state=self.cf.pair())
        self.assertEqual((status_result.status, status_result.reason_code),
                         ("current", "accepted_current_version"))
        self.assertEqual(set(status.selected_files()), {self.v["bounded_read"]["status_path"]})

        index = self.bounded(records, "derived_index")
        index_result = resolve_selected_read_status(
            index, subject=7, agreement_id="agreement-1", coverage=context,
            effective_scope=[], operation_state=self.cf.pair())
        self.assertEqual((index_result.status, index_result.reason_code),
                         ("current", "accepted_current_version"))
        self.assertEqual(set(index.selected_files()), {self.v["bounded_read"]["index_path"]})

    def test_bounded_reader_lookup_uses_only_reader_authority(self):
        records = self.connected()
        source = self.f.append(records, "records_reader_authorized", 1971)
        state = self.state(records)
        reader = self.bounded(records, "reader_authority",
                              shard=reader_authority_shard(source.event_id))
        self.assertEqual(reader.selected_class, "reader_authority")
        self.assertEqual(set(reader.selected_files()),
                         {self.v["bounded_read"]["reader_path"]})
        self.assertEqual(reader_source_for_subject(reader, source.event_id, 7), {
            "source_id": source.event_id, "kind": "individual",
            "organization_id": None, "team_id": None})
        with self.assertRaises(DerivedError):
            reader_source_for_subject(reader, source.event_id, 8)
        self.assertEqual(self.bounded_coverage(state).project_id, "project-1")
        CLAIMS.value('derived-v1.json', 'bounded_read')

    def test_bounded_reader_rule_count_matches_complete_profile_across_selected_shards(self):
        plain = self.materialize(self.connected())
        encrypted = self.encrypted(plain)
        assembled = self.assembled(plain, encrypted=encrypted)
        team = self.v["source_kinds"]["snapshot"]["team"]
        source_rows = {}
        for i in range(11):
            source_id = base64url_encode(hashlib.sha256(f"bounded-reader-{i}".encode()).digest())
            source_rows[source_id] = {"kind": "continuous_team", "team": team,
                                      "materialization_cursor": {}, "subjects": {}}
        nonempty_paths = {
            f"derived/reader-authority/{reader_authority_shard(source_id):02d}.enc.json"
            for source_id in source_rows
        }
        self.assertGreater(len(nonempty_paths), 1)
        for all_shards in [False, True]:
            for count in [9, 10, 11]:
                files = {path: {} for path in (
                    [f"derived/reader-authority/{i:02d}.enc.json" for i in range(32)]
                    if all_shards else sorted(nonempty_paths))}
                for source_id, row in list(source_rows.items())[:count]:
                    path = f"derived/reader-authority/{reader_authority_shard(source_id):02d}.enc.json"
                    files[path][source_id] = row
                envelopes = {}
                with patch("dracla.conformance.envelope.secrets.token_bytes", return_value=bytes(12)):
                    for path, values in files.items():
                        envelopes[path] = encrypt_artifact(
                            canonical_json(values), project_id="project-1",
                            identity=resolve_artifact_identity("records", "derived", path),
                            kid=b"k" * 16, key=b"k" * 32)
                state = assembled.state_dict()
                for path, raw in envelopes.items():
                    token = path.rsplit("/", 1)[1][:2]
                    state["shard_digests"]["reader_authority"][token] = (
                        "sha256:" + hashlib.sha256(raw).hexdigest())
                kwargs = dict(project_id="project-1", canonical_oid=plain.canonical_oid,
                              state=state, selected_files=files, selected_envelopes=envelopes,
                              generation=self.generations()["reader_authority"], profile=self.profile)
                if count <= 10:
                    DerivedReadProjection(**kwargs)
                else:
                    with self.assertRaises(ReleaseProfileError):
                        DerivedReadProjection(**kwargs)

    def test_bounded_read_rejects_selected_integrity_currency_and_operation_drift(self):
        records, _, _ = self.f.active_records(nonce=1980)
        self.f.append(records, "acceptance", 1983)
        plain = self.materialize(records)
        encrypted = self.encrypted(plain)
        projection = self.assembled(plain, encrypted=encrypted)
        fixture = self.v["bounded_read"]
        path = fixture["status_path"]
        selected = {path: plain.to_dict()["files"][path]}
        envelopes = {path: encrypted[path]}
        kwargs = dict(project_id="project-1", canonical_oid=plain.canonical_oid,
                      state=projection.state_dict(), selected_files=selected,
                      selected_envelopes=envelopes,
                      generation=self.generations()["status_detail"], profile=self.profile)
        DerivedReadProjection(**kwargs)
        with self.assertRaises(DerivedError):
            DerivedReadProjection(**{**kwargs, "generation": "B" * 42 + "A"})
        wrong_path = fixture["index_path"]
        with self.assertRaises(DerivedError):
            DerivedReadProjection(**{**kwargs, "selected_files": {wrong_path: selected[path]},
                                     "selected_envelopes": {wrong_path: envelopes[path]}})
        with self.assertRaises(DerivedError):
            DerivedReadProjection(**{**kwargs, "selected_envelopes": {path: b"{}"}})

        state = self.state(records)
        good_context = self.bounded_coverage(state)
        wrong_head = good_context.to_dict()
        wrong_head["source.enc.json"]["canonical_sha"] = "a" * 40
        with self.assertRaises(DerivedError):
            resolve_selected_read_status(
                DerivedReadProjection(**kwargs), subject=7, agreement_id="agreement-1",
                coverage=CoverageReadContext("project-1", wrong_head),
                effective_scope=[], operation_state=self.cf.pair())
        active = good_context.to_dict()
        active["agreements/active.enc.json"]["accepted_versions"] = []
        with self.assertRaises(DerivedError):
            CoverageReadContext("project-1", active)
        bad_pair = self.cf.pair("mutation", "empty", subjects=[7])
        bad_context = self.bounded_coverage(state, bad_pair)
        with self.assertRaises(DerivedError):
            resolve_selected_read_status(
                DerivedReadProjection(**kwargs), subject=7, agreement_id="agreement-1",
                coverage=bad_context, effective_scope=[], operation_state=self.cf.pair())

    def test_correction_chain_keeps_one_latest_row_without_superseded_status(self):
        records = self.f.vector_records("tuple-cutoff-resign-correction")
        state = self.state(records)
        plain = materialize_derived(state, profile=self.profile)
        row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        decision = next(d for d in state.tuple_decisions.values() if d.github_user_id == 7)
        self.assertEqual(set(row["agreements"]), {decision.agreement_id})
        self.assertEqual(row["agreements"][decision.agreement_id]["basis"]["event_id"], decision.event_id)
        coverage = materialize_coverage(state, self.cf.pair(), canonical_oid=state.current_head_oid,
            built_at=self.v["recorded_at"], dracla_version="test")
        self.assertEqual(self.read(row, coverage=coverage, oid=state.current_head_oid).status, "current")
        for raw in plain.plaintext_files().values():
            for forbidden in [b'"legal_name"', b'"email"', b'"signer"', b'"raw_evidence"']:
                self.assertNotIn(forbidden, raw)

    def test_completed_mutation_serves_terminal_status_without_second_derived_write(self):
        records, _, _ = self.f.active_records(nonce=1900)
        self.f.append(records, "acceptance", 1903)
        state = self.state(records)
        plain = materialize_derived(state, profile=self.profile)
        before = plain.plaintext_files()
        row = plain.to_dict()["files"]["derived/status-detail/07.enc.json"]["7"]
        for pair, reason in [(self.cf.pair("mutation", "empty"), "operation_in_flight"),
                             (self.cf.pair("mutation", "open"), "operation_in_flight"),
                             (self.cf.pair(), "accepted_current_version")]:
            coverage = materialize_coverage(state, pair, canonical_oid=state.current_head_oid,
                built_at=self.v["recorded_at"], dracla_version="test")
            self.assertEqual(self.read(row, coverage=coverage, oid=state.current_head_oid, pair=pair).reason_code, reason)
            self.assertEqual(plain.plaintext_files(), before)
