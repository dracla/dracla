"""Shared corpus relocation, reproducibility, reference and mutation gates."""

import copy
import hashlib
import json
import os
import runpy
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from dracla.conformance import (
    CanonicalEventRecord, canonical_json, validate_event, replay_events,
    materialize_coverage, materialize_derived, decode_inflight_marker,
    decode_decision_fence, load_release_profile, base64url_decode,
    DerivedError, DerivedPlaintext, assemble_derived_projection,
    DerivedReadProjection, validate_derived_projection, encrypt_artifact,
    resolve_artifact_identity,
)
from dracla.conformance import coverage, events, operations, vectors

from core.tests.corpus_consumption import CLAIMS

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / "conformance/vectors"


class TestSharedVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = vectors.generate()
        cls.manifest = json.loads(cls.generated["manifest.json"])
        cls.transitions = json.loads(cls.generated["incremental-v1.json"])

    def test_original_eleven_files_preserve_exact_pre_relocation_bytes(self):
        original = json.loads((ROOT / "conformance/authoring/relocation-v1.json").read_bytes())
        self.assertEqual(len(original["sha256"]), 11)
        self.assertFalse((ROOT / "core/tests/vectors").exists())
        for name, digest in original["sha256"].items():
            with self.subTest(file=name):
                self.assertEqual("sha256:" + hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest(), digest)
                self.assertEqual(self.generated[name], (DIRECTORY / name).read_bytes())

    def test_manifest_files_versions_owners_and_case_registries_agree(self):
        expected = set(self.manifest["files"]) | {"manifest.json"}
        self.assertEqual(expected, {p.name for p in DIRECTORY.iterdir()})
        owners = set()
        for name, row in self.manifest["files"].items():
            with self.subTest(file=name):
                self.assertEqual(row["contract_version"], 1)
                raw = (DIRECTORY / name).read_bytes()
                self.assertEqual(row["sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
                self.assertTrue(row["authoring_slices"])
                owners.update(row["authoring_slices"])
                self.assertTrue(row["cases"])
                self.assertEqual(len(row["cases"]), len(set(row["cases"])))
                value = json.loads(raw)
                for field, data in value.items():
                    self.assertIn(field, row["cases"])
                    if isinstance(data, list):
                        labels = [item.get("id", item.get("name", str(i)))
                                  if isinstance(item, dict) else str(i)
                                  for i, item in enumerate(data)]
                        self.assertTrue(all(f"{field}/{label}" in row["cases"] for label in labels))
        self.assertEqual(owners, {f"M1-{i}" for i in range(1, 13)})

    def test_regeneration_is_deterministic_and_never_reads_output(self):
        self.assertEqual(self.generated, vectors.generate())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "conformance/authoring", root / "conformance/authoring")
            self.assertEqual(vectors.generate(root), self.generated)

    def test_history_authors_are_loaded_from_selected_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "conformance/authoring", root / "conformance/authoring")
            author = root / "conformance/authoring/histories.py"
            with author.open("a") as stream:
                stream.write('\nraise RuntimeError("selected-root-history-probe")\n')
            with self.assertRaisesRegex(RuntimeError, "selected-root-history-probe"):
                vectors.generate(root)
            for name in ("build.py", "transitions.py"):
                with self.subTest(author=name):
                    with self.assertRaisesRegex(RuntimeError, "selected-root-history-probe"):
                        runpy.run_path(str(root / "conformance/authoring" / name))
            # Loading an alternate tree must not poison the original imports.
            self.assertEqual(vectors.generate(), self.generated)

    def test_generator_cli_works_outside_repository_root(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        result = subprocess.run(
            [sys.executable, "-m", "dracla.conformance.vectors", "--check"],
            cwd=ROOT / "core", env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_transition_corpus_covers_every_post_genesis_event(self):
        rows = json.loads(self.generated["events-v1.json"])["events"]
        expected = {row["type"] for row in rows} - {"project_connected"}
        actual = {case["input"]["record"]["event"]["type"]
                  for case in self.transitions["cases"]}
        self.assertEqual(actual, expected)
        for event_type in ("enforcement_scope_abandoned", "retry_requested"):
            case = next(case for case in self.transitions["cases"]
                        if case["input"]["record"]["event"]["type"] == event_type)
            with self.subTest(event_type=event_type):
                self.assertNotEqual(case["before"]["canonical_oid"],
                                    case["after"]["canonical_oid"])
                self.assertEqual(case["after"]["canonical_oid"],
                                 case["input"]["record"]["commit_oid"])
                self.assertEqual(case["after"]["coverage"]["source.enc.json"]["canonical_sha"],
                                 case["after"]["canonical_oid"])

    def test_check_rejects_changed_missing_extra_vector_and_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "conformance/authoring", root / "conformance/authoring")
            target = root / "conformance/vectors"
            target.mkdir()
            for name, raw in self.generated.items():
                (target / name).write_bytes(raw)
            self.assertEqual(vectors.check(root), ())
            name = "coverage-v1.json"
            (target / name).write_bytes(self.generated[name] + b" ")
            self.assertIn(name, vectors.check(root))
            (target / name).unlink()
            self.assertIn(name, vectors.check(root))
            (target / name).write_bytes(self.generated[name])
            (target / "orphan.json").write_text("{}")
            self.assertIn("orphan.json", vectors.check(root))
            (target / "orphan.json").unlink()
            manifest = copy.deepcopy(self.manifest)
            manifest["files"][name]["cases"].pop()
            (target / "manifest.json").write_text(json.dumps(manifest))
            self.assertIn("manifest.json", vectors.check(root))

    def test_changed_implementation_cannot_pass_generator_check(self):
        original = coverage.coverage_shard
        with patch.object(coverage, "coverage_shard", side_effect=lambda user, **kw: (original(user, **kw) + 1) % 32):
            # The independent expected shard values do not change with this
            # mutation. Generation must either differ or reject its new output.
            try:
                changed = vectors.check()
            except ValueError:
                return
            self.assertIn("coverage-v1.json", changed)

    def test_currency_and_combined_basis_mutations_cannot_pass_generator_check(self):
        original = coverage.evaluate_subject

        def currency_mutation(projection, subject, agreement_id):
            result = original(projection, subject, agreement_id)
            active = projection.to_dict()["agreements/active.enc.json"]
            if active["active_version"] == "2":
                return replace(result, decision="covered", reason_code="signed")
            return result

        with patch.object(coverage, "evaluate_subject", side_effect=currency_mutation):
            try:
                changed = vectors.check()
            except ValueError:
                changed = ("coverage-v1.json",)
            self.assertIn("coverage-v1.json", changed)

        def precedence_mutation(projection, subject, agreement_id):
            result = original(projection, subject, agreement_id)
            exemptions = projection.to_dict()["exemptions.enc.json"]
            if result.reason_code == "signed" and exemptions.get("7", {}).get("active") is True:
                return replace(result, reason_code="exempt")
            return result

        with patch.object(coverage, "evaluate_subject", side_effect=precedence_mutation):
            try:
                changed = vectors.check()
            except ValueError:
                changed = ("coverage-v1.json",)
            self.assertIn("coverage-v1.json", changed)

        # Remove only the combined-basis author loop in a temporary checkout.
        # The signed-plus-exempt mutation must still drift that checkout,
        # proving the regression is independent of currency_cases.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "conformance/authoring", root / "conformance/authoring")
            shutil.copytree(ROOT / "conformance/vectors", root / "conformance/vectors")
            source = (root / "conformance/authoring/build.py").read_text()
            start = source.index("    # Combined-basis cases exercise")
            end = source.index("    for row in value['version_ordering_cases']:", start)
            (root / "conformance/authoring/build.py").write_text(source[:start] + source[end:])
            with patch.object(coverage, "evaluate_subject", side_effect=precedence_mutation):
                try:
                    changed = vectors.check(root)
                except ValueError:
                    changed = ("coverage-v1.json",)
            self.assertEqual(changed, ())
            with self.assertRaises(AssertionError):
                self.assertIn("coverage-v1.json", changed)

    def test_operation_crash_expectations_follow_transition_authors(self):
        def reject_success_reservation(*args, **kwargs):
            raise operations.OperationConflict("mutation probe")

        with patch.object(operations, "reserve_success",
                          side_effect=reject_success_reservation) as mutated:
            try:
                changed = vectors.check()
            except (ValueError, operations.OperationConflict, operations.OperationCorruption):
                changed = ("operation-state-v1.json",)
        self.assertGreater(mutated.call_count, 0)
        self.assertIn("operation-state-v1.json", changed)

        # Remove only the crash recomputation from a temporary author checkout.
        # The same mutation must then leave stale checked-in crash results
        # apparently clean, proving the committed probe is the regression gate.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "conformance/authoring", root / "conformance/authoring")
            shutil.copytree(ROOT / "conformance/vectors", root / "conformance/vectors")
            source = (root / "conformance/authoring/build.py").read_text()
            start = source.index("    # Crash expectations are derived")
            end = source.index("\ndef coverage_vectors", start)
            (root / "conformance/authoring/build.py").write_text(source[:start] + source[end:])
            with patch.object(operations, "reserve_success",
                              side_effect=reject_success_reservation):
                changed = vectors.check(root)
            self.assertEqual(changed, ())
            with self.assertRaises(AssertionError):
                self.assertIn("operation-state-v1.json", changed)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires Unix filesystem entry fixtures")
    def test_check_rejects_nested_orphan_and_nonregular_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "conformance/vectors"
            target.mkdir(parents=True)
            for name, raw in self.generated.items():
                (target / name).write_bytes(raw)
            with patch.object(vectors, "generate", return_value=self.generated):
                nested = target / "nested"
                nested.mkdir()
                (nested / "orphan.json").write_text("{}")
                with self.subTest(kind="nested orphan"):
                    self.assertIn("nested", vectors.check(root))
                shutil.rmtree(nested)
                name = "coverage-v1.json"
                original = root / "same-bytes.json"
                original.write_bytes(self.generated[name])
                (target / name).unlink()
                (target / name).symlink_to(original)
                with self.subTest(kind="same bytes through symlink"):
                    self.assertIn(name, vectors.check(root))
                (target / name).unlink()
                (target / name).write_bytes(self.generated[name])
                os.mkfifo(target / "pipe.json")
                with self.subTest(kind="nonregular entry"):
                    self.assertIn("pipe.json", vectors.check(root))

    def test_invalid_authoring_registry_and_nonce_variant_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "conformance/authoring"
            shutil.copytree(ROOT / "conformance/authoring", source)
            path = source / "authorization-vocabulary-v1.json"
            original = path.read_bytes()
            value = json.loads(original)
            value["operation_rows"].pop()
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "authorization registry changed"):
                vectors.generate(root)
            path.write_bytes(original)
            path = source / "event-identities-v1.json"
            value = json.loads(path.read_bytes())
            value["deterministic_nonce_variants"][0]["domain"] = "unknown"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "unknown deterministic nonce"):
                vectors.generate(root)

    def test_duplicate_case_and_broken_reference_history_cannot_be_emitted(self):
        from conformance.authoring import build, transitions
        with self.assertRaisesRegex(ValueError, "duplicate corpus case"):
            build.case_registry({"cases": [{"id": "same"}, {"id": "same"}]})
        value = json.loads((DIRECTORY / "events-v1.json").read_bytes())
        event = validate_event(next(row for row in value["events"] if row["type"] == "project_connected"))
        broken = CanonicalEventRecord(event, "c" * 40, "a" * 40)
        with self.assertRaisesRegex(ValueError, "invalid reference history"):
            transitions.state_for([broken])

    @staticmethod
    def records(values):
        return [CanonicalEventRecord(validate_event(row["event"]), row["commit_oid"], row["parent_oid"])
                for row in values]

    def reference(self, records, operation, metadata):
        result = replay_events("project-1", self.transitions["base_commit_oid"], records)
        self.assertTrue(result.valid, result.error)
        state = result.state
        pair = (decode_inflight_marker(canonical_json(operation[0])),
                decode_decision_fence(canonical_json(operation[1])))
        public = materialize_coverage(state, pair, canonical_oid=state.current_head_oid,
            built_at=metadata["built_at"], dracla_version=metadata["dracla_version"])
        private = materialize_derived(state, profile=load_release_profile())
        return public.to_dict(), private.to_dict()

    def test_every_incremental_triple_equals_two_full_reference_materializations(self):
        self.assertGreater(len(self.transitions["cases"]), 100)
        for case in self.transitions["cases"]:
            with self.subTest(case=case["id"]):
                records = self.records(case["history"])
                operation = case["input"]["operation_state"]
                before = self.reference(records, operation, case["input"])
                after = self.reference(records + self.records([case["input"]["record"]]), operation, case["input"])
                self.assertEqual(before, (case["before"]["coverage"], case["before"]["derived"]))
                self.assertEqual(after, (case["after"]["coverage"], case["after"]["derived"]))
            CLAIMS.case('incremental-v1.json', 'cases', case)
        CLAIMS.value('incremental-v1.json', 'project_id')

    def _publication_material(self, case, side):
        """Recreate source-test envelopes from a compact publication recipe."""
        publication = case["publication"]
        evidence = publication[side]
        value = case[side]
        profile = load_release_profile()
        private = DerivedPlaintext(
            self.transitions["project_id"], evidence["canonical_oid"],
            files=value["derived"]["files"],
            configuration=value["derived"]["configuration"],
            standing_rules=value["derived"]["standing_rules"], profile=profile)
        crypto = publication["crypto"]
        with patch("dracla.conformance.envelope.secrets.token_bytes",
                   return_value=bytes.fromhex(crypto["nonce_hex"])):
            encrypted = {
                path: encrypt_artifact(
                    raw, project_id=private.project_id,
                    identity=resolve_artifact_identity("records", "derived", path),
                    kid=bytes.fromhex(crypto["kid_hex"]),
                    key=bytes.fromhex(crypto["key_hex"]),
                )
                for path, raw in private.plaintext_files().items()
            }
        projection = assemble_derived_projection(
            private, canonical_oid=evidence["canonical_oid"],
            generations=evidence["generations"], encrypted_shards=encrypted,
            profile=profile)
        self.assertEqual(
            projection.plaintext_files()["derived/state.enc.json"],
            base64url_decode(evidence["state_bytes_b64"]),
        )
        self.assertEqual(json.loads(base64url_decode(evidence["state_bytes_b64"]))["shard_digests"],
                         evidence["envelope_digests"])
        validate_derived_projection(
            projection, generations=evidence["generations"],
            encrypted_shards=encrypted, profile=profile)
        return private, encrypted

    def test_ordinary_publication_generations_follow_canonical_event_author(self):
        for case in self.transitions["cases"]:
            before = case["before"]["generations"]
            after = case["after"]["generations"]
            event = case["input"]["record"]["event"]
            event_id = event["event_id"]
            affected = set(events._AFFECTED_CLASSES.get(event["type"], ()))
            if event["type"] in {"exemption_rule_withdrawn", "records_reader_withdrawn",
                                  "records_reader_rule_withdrawn"}:
                continue
            for name in ("derived_index", "status_detail", "reader_authority"):
                expected = event_id if name in affected else before[name]
                self.assertEqual(after[name], expected, case["id"])
            if "publication" in case:
                self.assertEqual(case["publication"]["before"]["generations"], before)
                self.assertEqual(case["publication"]["after"]["generations"], after)
            CLAIMS.case('incremental-v1.json', 'cases', case)

        union = next(case for case in self.transitions["cases"]
                      if case["id"] == "exemption-source-union/02/exemption")
        self.assertNotIn("derived/index/07.enc.json", union["changed"]["derived"])
        self.assertEqual(union["before"]["derived"]["files"]["derived/index/07.enc.json"],
                         union["after"]["derived"]["files"]["derived/index/07.enc.json"])
        self.assertEqual(union["after"]["generations"]["derived_index"],
                         union["input"]["record"]["event"]["event_id"])
        private, envelopes = self._publication_material(union, "after")
        assembled = assemble_derived_projection(
            private, canonical_oid=union["publication"]["after"]["canonical_oid"],
            generations=union["after"]["generations"], encrypted_shards=envelopes,
            profile=load_release_profile())
        index_path = "derived/index/07.enc.json"
        DerivedReadProjection(
            self.transitions["project_id"], union["publication"]["after"]["canonical_oid"],
            state=assembled.state_dict(),
            selected_files={index_path: private.to_dict()["files"][index_path]},
            selected_envelopes={index_path: envelopes[index_path]},
            generation=union["after"]["generations"]["derived_index"],
            profile=load_release_profile())

        no_op = next(case for case in self.transitions["cases"]
                     if case["id"] == "all-reader-shards/35/records_reader_withdrawn")
        self.assertEqual(no_op["before"]["generations"]["reader_authority"],
                         no_op["after"]["generations"]["reader_authority"])
        self.assertEqual(no_op["changed"]["coverage"], ["source.enc.json"])

    def test_every_derived_publication_has_complete_state_and_digest_bindings(self):
        published = 0
        for case in self.transitions["cases"]:
            if not case["changed"]["derived"]:
                self.assertNotIn("publication", case)
                continue
            with self.subTest(case=case["id"]):
                before, before_envelopes = self._publication_material(case, "before")
                after, after_envelopes = self._publication_material(case, "after")
                publication = case["publication"]
                unchanged = set(publication["unchanged_shards"])
                self.assertTrue(unchanged <= set(before_envelopes))
                for path in unchanged:
                    self.assertEqual(before_envelopes[path], after_envelopes[path])
                self.assertTrue(set(case["changed"]["derived"]) & {"derived/state.enc.json"})
                self.assertFalse(unchanged & set(case["changed"]["derived"]))
                self.assertEqual(before.project_id, after.project_id)
                published += 1
            CLAIMS.case('incremental-v1.json', 'cases', case)
        self.assertEqual(published, 93)

    def test_stale_reader_skip_repair_and_partial_bulk_publication_fail_closed(self):
        stale, bulk = self.transitions["publication_cases"]
        self.assertEqual(stale["input"]["skip_reason"], "reader_authority_generation_is_stale")
        withdrawal = stale["input"]["record"]
        self.assertEqual(stale["after"]["canonical_source_advanced"], withdrawal["commit_oid"])
        self.assertEqual(stale["before"]["reader_generation"],
                         stale["history"][-1]["event"]["event_id"])
        self.assertNotEqual(stale["before"]["reader_generation"],
                            stale["repair"]["generations"]["reader_authority"])
        self.assertNotEqual(stale["read_assertions"]["stale_reader_generation"],
                            stale["read_assertions"]["repaired_reader_generation"])
        stale_pub = stale["stale_private"]
        stale_private = DerivedPlaintext(
            self.transitions["project_id"], stale_pub["canonical_oid"],
            files=stale_pub["plaintext"]["files"],
            configuration=stale_pub["plaintext"]["configuration"],
            standing_rules=stale_pub["plaintext"]["standing_rules"],
            profile=load_release_profile())
        crypto = stale_pub["crypto"]
        with patch("dracla.conformance.envelope.secrets.token_bytes",
                   return_value=bytes.fromhex(crypto["nonce_hex"])):
            stale_envelopes = {
                path: encrypt_artifact(
                    raw, project_id=stale_private.project_id,
                    identity=resolve_artifact_identity("records", "derived", path),
                    kid=bytes.fromhex(crypto["kid_hex"]), key=bytes.fromhex(crypto["key_hex"]),
                ) for path, raw in stale_private.plaintext_files().items()
            }
        stale_projection = assemble_derived_projection(
            stale_private, canonical_oid=stale_pub["canonical_oid"],
            generations=stale_pub["generations"], encrypted_shards=stale_envelopes,
            profile=load_release_profile())
        stale_state_raw = stale_projection.plaintext_files()["derived/state.enc.json"]
        self.assertEqual(stale_state_raw, base64url_decode(stale_pub["state_bytes_b64"]))
        self.assertEqual(json.loads(stale_state_raw)["shard_digests"], stale_pub["envelope_digests"])
        with self.assertRaises(DerivedError):
            validate_derived_projection(
                stale_projection, generations=stale["repair"]["generations"],
                encrypted_shards=stale_envelopes, profile=load_release_profile())
        reader_path = next(path for path, value in stale_private.to_dict()["files"].items()
                           if path.startswith("derived/reader-authority/") and value)
        with self.assertRaises(DerivedError):
            DerivedReadProjection(
                self.transitions["project_id"], stale_pub["canonical_oid"],
                state=stale_projection.state_dict(),
                selected_files={reader_path: stale_private.to_dict()["files"][reader_path]},
                selected_envelopes={reader_path: stale_envelopes[reader_path]},
                generation=stale["repair"]["generations"]["reader_authority"],
                profile=load_release_profile())

        repair_pub = stale["repair"]
        repair_private = DerivedPlaintext(
            self.transitions["project_id"], repair_pub["canonical_oid"],
            files=repair_pub["plaintext"]["files"],
            configuration=repair_pub["plaintext"]["configuration"],
            standing_rules=repair_pub["plaintext"]["standing_rules"],
            profile=load_release_profile())
        repair_crypto = repair_pub["crypto"]
        with patch("dracla.conformance.envelope.secrets.token_bytes",
                   return_value=bytes.fromhex(repair_crypto["nonce_hex"])):
            repair_envelopes = {
                path: encrypt_artifact(
                    raw, project_id=repair_private.project_id,
                    identity=resolve_artifact_identity("records", "derived", path),
                    kid=bytes.fromhex(repair_crypto["kid_hex"]),
                    key=bytes.fromhex(repair_crypto["key_hex"]),
                ) for path, raw in repair_private.plaintext_files().items()
            }
        repair_projection = assemble_derived_projection(
            repair_private, canonical_oid=repair_pub["canonical_oid"],
            generations=repair_pub["generations"],
            encrypted_shards=repair_envelopes, profile=load_release_profile())
        repair_state_raw = repair_projection.plaintext_files()["derived/state.enc.json"]
        self.assertEqual(repair_state_raw, base64url_decode(repair_pub["state_bytes_b64"]))
        self.assertEqual(json.loads(repair_state_raw)["shard_digests"], repair_pub["envelope_digests"])
        validate_derived_projection(
            repair_projection, generations=repair_pub["generations"],
            encrypted_shards=repair_envelopes, profile=load_release_profile())
        repair_reader_path = next(
            path for path, value in repair_private.to_dict()["files"].items()
            if path.startswith("derived/reader-authority/") and value)
        DerivedReadProjection(
            self.transitions["project_id"], repair_pub["canonical_oid"],
            state=repair_projection.state_dict(),
            selected_files={repair_reader_path: repair_private.to_dict()["files"][repair_reader_path]},
            selected_envelopes={repair_reader_path: repair_envelopes[repair_reader_path]},
            generation=repair_pub["generations"]["reader_authority"],
            profile=load_release_profile())

        missing = bulk["partial_publication"]["missing_shards"]
        plain = DerivedPlaintext(
            self.transitions["project_id"], bulk["publication"]["after"]["canonical_oid"],
            files=bulk["after"]["derived"]["files"],
            configuration=bulk["after"]["derived"]["configuration"],
            standing_rules=bulk["after"]["derived"]["standing_rules"],
            profile=load_release_profile())
        crypto = bulk["publication"]["crypto"]
        with patch("dracla.conformance.envelope.secrets.token_bytes",
                   return_value=bytes.fromhex(crypto["nonce_hex"])):
            envelopes = {
                path: encrypt_artifact(
                    raw, project_id=plain.project_id,
                    identity=resolve_artifact_identity("records", "derived", path),
                    kid=bytes.fromhex(crypto["kid_hex"]), key=bytes.fromhex(crypto["key_hex"]),
                ) for path, raw in plain.plaintext_files().items()
            }
        for path in missing:
            del envelopes[path]
        with self.assertRaises(DerivedError):
            assemble_derived_projection(
                plain, canonical_oid=plain.canonical_oid,
                generations=bulk["publication"]["after"]["generations"],
                encrypted_shards=envelopes, profile=load_release_profile())
        self.assertEqual(
            bulk["partial_publication"]["published_generation"],
            bulk["publication"]["before"]["generations"]["reader_authority"],
        )
        CLAIMS.case("incremental-v1.json", "publication_cases", stale)
        CLAIMS.case("incremental-v1.json", "publication_cases", bulk)

    def test_all_shards_source_unions_reader_source_advance_and_operational_windows(self):
        subject_shards, reader_shards = set(), set()
        union_sizes = set()
        for case in self.transitions["cases"]:
            if case["id"].startswith("all-subject-shards/") and case["input"]["record"]["event"]["type"] == "acceptance":
                subject_shards.update(path for path in case["changed"]["coverage"] if path.startswith("users/"))
            if case["id"].startswith("all-reader-shards/"):
                reader_shards.update(path for path in case["changed"]["derived"] if path.startswith("derived/reader-authority/"))
                self.assertEqual(case["changed"]["coverage"], ["source.enc.json"])
            if case["id"].startswith("exemption-source-union/"):
                union_sizes.update(len(values) for values in case["input"]["prior_exemption_union"].values())
            CLAIMS.case('incremental-v1.json', 'cases', case)
        self.assertEqual(subject_shards, {f"users/{i:02d}.enc.json" for i in range(32)})
        self.assertEqual(reader_shards, {f"derived/reader-authority/{i:02d}.enc.json" for i in range(32)})
        self.assertTrue({0, 1, 2}.issubset(union_sizes))
        self.assertEqual(len(self.transitions["operational_cases"]), 8)
        for case in self.transitions["operational_cases"]:
            with self.subTest(case=case["id"]):
                after = self.reference(self.records(case["history"]), case["input"]["operation_state"], case["input"])
                self.assertEqual(after, (case["after"]["coverage"], case["after"]["derived"]))
                self.assertEqual(case["before"]["derived"], case["after"]["derived"])
            CLAIMS.case('incremental-v1.json', 'operational_cases', case)

    def test_cli_check_passes_for_complete_checked_in_corpus(self):
        result = subprocess.run([sys.executable, "-m", "dracla.conformance.vectors", "--check"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_generation_check_failure_and_missing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(vectors, "source_root", return_value=root), \
                 patch.object(vectors, "generate", return_value={"fixture.json": b"{}\n"}):
                self.assertEqual(vectors.main([]), 0)
                self.assertEqual((root / "conformance/vectors/fixture.json").read_bytes(), b"{}\n")
            with patch.object(vectors, "source_root", return_value=root), \
                 patch.object(vectors, "check", return_value=("fixture.json",)), \
                 patch("sys.stderr"):
                self.assertEqual(vectors.main(["--check"]), 1)
            with patch.object(vectors, "__file__", str(root / "core/dracla/conformance/vectors.py")):
                with self.assertRaisesRegex(ValueError, "source checkout"):
                    vectors.source_root()
                with patch("sys.stderr"):
                    self.assertEqual(vectors.main([]), 1)

    def test_every_read_overlay_matches_current_author_for_index_and_detail(self):
        from dataclasses import asdict
        from dracla.conformance import CoverageProjection, DerivedReadRow, resolve_read_status
        self.assertEqual(len(self.transitions["read_cases"]), 88)
        for case in self.transitions["read_cases"]:
            with self.subTest(case=case["id"]):
                pair = (decode_inflight_marker(canonical_json(case["operation_state"][0])),
                        decode_decision_fence(canonical_json(case["operation_state"][1])))
                projection = CoverageProjection("project-1", case["coverage"])
                row = DerivedReadRow("project-1", case["canonical_oid"], case["subject"],
                                     case["agreement_id"], case["row"])
                resolved = asdict(resolve_read_status(row, projection, case["effective_scope"], pair))
                resolved["enforcement_scope"] = list(resolved["enforcement_scope"])
                self.assertEqual(resolved, case["expected"])
                detail = case["row"]
                index = {k: detail[k] for k in ("login_snapshot", "login_as_of", "agreements")}
                index["exempt"] = bool(detail["exemption_sources"])
                index_row = DerivedReadRow("project-1", case["canonical_oid"], case["subject"],
                                           case["agreement_id"], index)
                served = resolve_read_status(index_row, projection, case["effective_scope"], pair)
                self.assertEqual((served.status, served.reason_code),
                                 (resolved["status"], resolved["reason_code"]))
            CLAIMS.case('incremental-v1.json', 'read_cases', case)
