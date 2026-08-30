"""Side-artifact byte and package contract tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    CanonicalShaBinding,
    CrossProjectBinding,
    EventValidationError,
    EventsHeadBinding,
    GenerationBinding,
    PreconditionEvidence,
    PreconditionValidationError,
    RegistryGenerationBinding,
    SideArtifact,
    SideArtifactRequirement,
    SideArtifactValidationError,
    canonical_json,
    required_preconditions,
    required_side_artifacts,
    validate_event,
    validate_side_artifact_package,
)
from dracla.conformance import events as event_module  # noqa: E402


VECTORS = Path(__file__).parent / "vectors" / "events-v1.json"
HEAD = "b" * 40


class TestSideArtifactPackages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.rows = {row["type"]: row for row in cls.corpus["events"]}

    def _evidence(self, event, requirement, value):
        if requirement.binding_mode == "events-head":
            binding = EventsHeadBinding(requirement.expected_head)
        elif requirement.binding_mode == "generation":
            binding = GenerationBinding(requirement.expected_head, event.event_id, event.event_id)
        elif requirement.binding_mode == "canonical-sha":
            binding = CanonicalShaBinding(requirement.expected_head, requirement.expected_head)
        elif requirement.binding_mode == "registry-generation":
            commit = event.payload.get("registry_commit_oid", "a" * 40)
            generation = event.payload.get("registry_generation", event.payload.get("prior_registry_generation", 0))
            binding = RegistryGenerationBinding(commit, generation)
        else:
            binding = CrossProjectBinding(event.target.get("successor_project_id", "successor-project"), requirement.expected_head, (11, 12, 13))
        return {
            "name": requirement.name,
            "artifact_kind": requirement.artifact_kind,
            "repository_role": requirement.repository_role,
            "branch": requirement.branch,
            "path": requirement.path,
            "binding_mode": requirement.binding_mode,
            "binding": event_module._binding_to_dict(binding),
            "value": value,
        }

    def _preconditions(self, event, head=HEAD, overrides=None):
        overrides = overrides or {}
        values = []
        for requirement in required_preconditions(event, expected_head=head):
            name = requirement.name
            override_name = name
            if override_name not in overrides:
                for prefix in ("coverage-state", "current-exemption-union"):
                    if name.startswith(prefix + "-") and prefix in overrides:
                        override_name = prefix
                        break
            if override_name in overrides:
                value = overrides[override_name]
            elif name == "generations-absence":
                value = None
            elif name == "keyring-affected-repositories":
                value = {"repository_ids": [11, 12, 13]}
            elif name in {"published-agreement", "target-activation", "scope-request", "source-event", "rule-event"}:
                linked_id = event.payload.get("published_event_id", event.payload.get("request_event_id", event.target.get("activation_event_id", event.target.get("source_event_id", event.target.get("rule_event_id")))))
                linked_type = {"published-agreement": "agreement_published", "target-activation": "agreement_activated", "scope-request": "enforcement_scope_requested", "source-event": "exemption", "rule-event": "exemption_rule_configured"}[name]
                if name == "published-agreement":
                    linked_target = {"agreement_id": event.target["agreement_id"], "version": event.target["version"]}
                    linked_payload = copy.deepcopy(self.rows["agreement_published"]["payload"])
                elif name == "target-activation":
                    linked_target = copy.deepcopy(self.rows["agreement_activated"]["target"])
                    linked_payload = copy.deepcopy(self.rows["agreement_activated"]["payload"])
                elif name == "scope-request":
                    linked_target = {"change_id": event.target["change_id"]}
                    linked_payload = {"prior_scope": [], "desired_scope": event.payload.get("desired_scope", self.rows["enforcement_scope_requested"]["payload"]["desired_scope"]), "prior_registry_generation": 0}
                elif name == "source-event":
                    linked_type = "exemption" if event.type == "exemption_source_withdrawn" else "records_reader_authorized"
                    linked_target = {"subject": event.target["subject"]}
                    linked_payload = {}
                else:
                    linked_type = "exemption_rule_configured" if event.type in {"exemption_rule_withdrawn", "exemption_materialized"} else "records_reader_rule_configured"
                    linked_target = {"team": self.rows["exemption_rule_configured"]["target"]["team"]}
                    linked_payload = {}
                value = {"event_id": linked_id, "type": linked_type, "project_id": event.project_id, "target": linked_target, "payload": linked_payload}
            elif name == "successor-project":
                value = {"event": {"event_id": event.payload["successor_connected_event_id"], "type": "project_connected", "project_id": event.target["successor_project_id"], "target": {}, "payload": {"successor_of": event.project_id, "repository_ids": {"records": 11, "coverage": 12, "control": 13}}}, "active_agreement": {"project_id": event.target["successor_project_id"], "agreement_id": "agreement-1", "version": "1", "state": "active"}}
            elif name == "current-configuration":
                value = self.rows["project_connected"]["payload"]["project_configuration"]
            elif name == "current-project-agreement":
                value = {
                    "project_id": event.project_id,
                    "recipient": event_module._thaw(event.payload["recipient"]),
                    "agreement_id": None,
                    "published_versions": [],
                }
            elif name in {"publication-snapshot-absence", "publication-metadata-absence"}:
                value = {"path": requirement.path, "present": False}
            elif name == "prior-generations":
                value = {"derived_index": event.event_id, "status_detail": event.event_id, "reader_authority": event.event_id}
            elif name == "project-lifecycle":
                value = {"project_id": event.project_id, "state": "active", "successor_project_id": None}
            elif name == "active-agreement":
                if event.type == "acceptance":
                    publication = {key: copy.deepcopy(self.rows["agreement_published"][key]) for key in ("event_id", "type", "project_id", "target", "payload")}
                    value = {"project_id": event.project_id, "agreement_id": event.target["coverage_tuple"]["agreement_id"], "version": event.target["version"], "recipient": event.target["recipient"], "digest": event.target["digest"], "state": "active", "accepted_versions": [event.target["version"]], "retired_versions": [], "active_version": event.target["version"], "activation_event_id": self.rows["agreement_activated"]["event_id"], "supersedes_coverage": False, "publication": publication}
                elif event.type == "agreement_activated":
                    value = {"agreement_id": event.target["agreement_id"], "active_version": event.target["version"], "activation_event_id": self.rows["agreement_activated"]["event_id"], "accepted_versions": [event.target["version"]], "retired_versions": [], "projection_format": 1, "shard_count": 32}
                elif event.type == "agreement_activation_restored":
                    value = {"agreement_id": event.target["agreement_id"], "active_version": "2", "activation_event_id": self.rows["agreement_activated"]["event_id"], "accepted_versions": ["2"], "retired_versions": ["1"], "projection_format": 1, "shard_count": 32}
                else:
                    value = {"project_id": event.project_id, "agreement_id": event.target.get("agreement_id", "agreement-1"), "version": event.target.get("version", "1"), "state": "active"}
            elif name == "current-repository-owner":
                generation = event.payload.get("registry_generation", 0)
                prior = {"project_id": event.project_id, "project_slug": event.payload["project_slug"], "repository_owner": event.target.get("prior_repository_owner"), "repository_ids": event.payload.get("repository_ids"), "registry_generation": max(0, generation - 1), "enforcement_scope": [], "request_event_links": {}}
                staged = json.loads(json.dumps(event_module._thaw(prior)))
                staged.update(repository_owner=event.payload["new_repository_owner"], registry_generation=generation)
                value = {"prior_entry": prior, "staged_entry": staged}
            elif name == "current-scope":
                links = {event.target["change_id"]: event.payload["request_event_id"]} if event.type == "enforcement_scope_activated" else {}
                entry = {"project_id": event.project_id, "project_slug": "project-one", "repository_owner": self.rows["project_connected"]["payload"]["repository_owner"], "repository_ids": self.rows["project_connected"]["payload"]["repository_ids"], "registry_generation": event.payload.get("prior_registry_generation", event.payload.get("registry_generation", 0)), "enforcement_scope": event.payload.get("prior_scope", []), "request_event_links": links}
                if event.type == "enforcement_scope_requested":
                    value = {"prior_entry": entry, "current_entry": copy.deepcopy(entry)}
                elif event.type == "enforcement_scope_activated":
                    entry["enforcement_scope"] = event.payload["desired_scope"]
                    entry["registry_generation"] = event.payload["registry_generation"]
                    value = {"staged_entry": entry}
                else:
                    value = {"current_entry": entry}
            elif name.startswith("coverage-state-") or name == "override-grant":
                if name == "override-grant":
                    value = {"event": {"event_id": event.target["override_event_id"], "type": "override", "project_id": event.project_id, "target": copy.deepcopy(self.rows["override"]["target"]), "payload": copy.deepcopy(self.rows["override"]["payload"])}, "active": True}
                else:
                    subjects = [event.target["coverage_tuple"]["github_user_id"]] if event.type == "revocation" else sorted(subject["github_user_id"] for subject in event.payload["subjects"] if subject["github_user_id"] % 32 == int(name.rsplit("-", 1)[1]))
                    value = {"project_id": event.project_id, "state": "current", "resource": event.target, "subject_ids": subjects}
            elif name.startswith("current-exemption-union-"):
                source_id = event.target.get("source_event_id", event.target.get("rule_event_id", self.rows["exemption"]["event_id"]))
                shard = int(name.rsplit("-", 1)[1])
                if event.type in {"exemption_rule_configured", "exemption_rule_withdrawn"}:
                    subjects = [self.rows["exemption"]["target"]["subject"]] if shard == self.rows["exemption"]["target"]["subject"]["github_user_id"] % 32 else []
                elif "subjects" in event.target:
                    subjects = [subject for subject in event.target["subjects"] if subject["github_user_id"] % 32 == shard]
                else:
                    subject = event.target.get("subject", self.rows["exemption"]["target"]["subject"])
                    subjects = [subject] if subject["github_user_id"] % 32 == shard else []
                value = {"project_id": event.project_id, "subjects": subjects, "provenance": {str(subject["github_user_id"]): [source_id] for subject in subjects}}
            elif name == "current-reader-authority":
                value = {"project_id": event.project_id, "class_state": "current", "sources": [], "cursor_event_id": event.event_id}
            elif name == "reader-authority-state":
                source_id = event.target.get("source_event_id", event.target.get("rule_event_id", self.rows["records_reader_authorized"]["event_id"]))
                value = {"project_id": event.project_id, "class_state": "current", "source_event_ids": [source_id], "cursor_event_id": event.event_id}
            elif name == "materialization-cursor":
                value = {"cursor_event_id": event.event_id, "prior_materialization_event_id": event.payload.get("prior_materialization_event_id"), "rule_event_id": event.target["rule_event_id"], "subject": event.target["subject"]}
            elif name.startswith("scope-terminal-"):
                descriptor = next(item for item in required_preconditions(event, expected_head=head) if item.name == name)
                value = {"path": descriptor.path, "present": False}
            else:
                value = {"ok": True}
            values.append(self._evidence(event, requirement, value))
        return values

    def _publication_fixture(self):
        row = copy.deepcopy(self.rows["agreement_published"])
        snapshot = b"agreement text"
        digest = "sha256:" + hashlib.sha256(snapshot).hexdigest()
        row["payload"]["digest"] = digest
        row["payload"]["snapshot_sha256"] = digest
        from dracla.conformance import derive_event_identity

        identity = derive_event_identity(row["project_id"], row["operation_nonce"], row["actor"], row["type"], row["target"], row["payload"], row["confirmed_canonical_oid"])
        row.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        event = validate_event(row)
        metadata = canonical_json({"metadata_version": 1, "agreement_id": row["target"]["agreement_id"], "version": row["target"]["version"], "recipient": row["payload"]["recipient"], "ref": row["payload"]["ref"], "content_commit_oid": row["payload"]["content_commit_oid"], "digest": digest, "snapshot_sha256": digest})
        return event, SideArtifact("agreement_snapshot", row["payload"]["snapshot_content_path"], snapshot), SideArtifact("agreement_metadata", row["payload"]["snapshot_metadata_path"], metadata)

    def _connection_fixture(self):
        event = validate_event(self.rows["project_connected"])
        config = canonical_json(event_module._thaw(event.payload["project_configuration"]))
        generations = canonical_json({"generations_version": 1, "derived_index": event.event_id, "status_detail": event.event_id, "reader_authority": event.event_id})
        return event, SideArtifact("materialization_generations", "config/materialization-generations.enc.json", generations), SideArtifact("project_config", "config/project.enc.json", config)

    def test_artifact_model_and_ordered_package_membership(self):
        artifact = SideArtifact("project_config", "config/project.enc.json", b"{}")
        digest = "sha256:" + hashlib.sha256(b"{}").hexdigest()
        self.assertEqual(artifact.sha256, digest)
        self.assertIs(event_module._coerce_side_artifact(artifact), artifact)
        decoded = event_module._coerce_side_artifact({"kind": "project_config", "path": "config/project.enc.json", "bytes_b64": "e30", "sha256": digest})
        self.assertEqual(decoded.bytes, b"{}")
        decoded = event_module._coerce_side_artifact({"kind": "project_config", "path": "config/project.enc.json", "bytes": b"{}", "sha256": digest})
        self.assertEqual(decoded.bytes, b"{}")
        with self.assertRaises(SideArtifactValidationError):
            SideArtifact("project_config", "config/project.enc.json", "{}")
        for kind, path in ((None, "config/project.enc.json"), ("", "config/project.enc.json"), ("project_config", None), ("project_config", [])):
            with self.subTest(kind=kind, path=path), self.assertRaises(SideArtifactValidationError):
                SideArtifact(kind, path, b"{}")
        for value in (
            None,
            {"kind": "project_config", "path": "config/project.enc.json", "bytes": b"{}", "sha256": digest, "extra": True},
            {"kind": "project_config", "path": "config/project.enc.json"},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes": b"{}"},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes": b"{}", "bytes_b64": "e30", "sha256": digest},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes": "{}", "sha256": digest},
            {"kind": "project_config", "path": [], "bytes": b"{}", "sha256": digest},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes_b64": None, "sha256": digest},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes_b64": "!", "sha256": digest},
            {"kind": [], "path": "config/project.enc.json", "bytes": b"{}", "sha256": digest},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes": b"{}", "sha256": None},
            {"kind": "project_config", "path": "config/project.enc.json", "bytes": b"{}", "sha256": "sha256:" + "0" * 64},
        ):
            with self.subTest(value=value), self.assertRaises(SideArtifactValidationError):
                event_module._coerce_side_artifact(value)
        with self.assertRaises(SideArtifactValidationError):
            SideArtifact("project_config", "config/project.enc.json", b"{}", "sha256:" + "0" * 64)
        event, generations, config = self._connection_fixture()
        preconditions = self._preconditions(event)
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(
                event,
                [{"kind": "materialization_generations", "path": [], "bytes": b"{}"}, config],
                preconditions=preconditions,
                expected_head=HEAD,
            )
        package = [generations, config]
        validate_side_artifact_package(event, package, preconditions=preconditions, expected_head=HEAD)
        for bad_package in (
            {item.path: item for item in package},
            object(),
            [package[0], package[0]],
            list(reversed(package)),
            [package[0]],
            package + [SideArtifact("extra", "extra.enc.json", b"{}")] ,
            [SideArtifact("wrong", generations.path, generations.bytes), config],
            [generations, SideArtifact(config.kind, "config/wrong.enc.json", config.bytes)],
        ):
            with self.subTest(package=bad_package), self.assertRaises(SideArtifactValidationError):
                validate_side_artifact_package(event, bad_package, preconditions=preconditions, expected_head=HEAD)

    def test_publication_snapshot_and_metadata_vectors(self):
        event, snapshot, metadata = self._publication_fixture()
        for case in self.corpus["package_cases"]:
            if case["fixture"] != "publication":
                continue
            package = [snapshot, metadata]
            current_event = event
            raw = base64.urlsafe_b64decode(case["bytes_b64"] + "===") if "bytes_b64" in case else None
            if case["mutation"] in {"snapshot_exact", "snapshot_digest_mismatch"}:
                package[0] = SideArtifact(snapshot.kind, snapshot.path, raw)
            elif case["mutation"] == "wrong_snapshot_path":
                package[0] = SideArtifact(snapshot.kind, "agreements/wrong.snapshot.enc.json", snapshot.bytes)
            elif case["mutation"] in {"digest_field_mismatch", "snapshot_sha_field_mismatch"}:
                row = copy.deepcopy(self.rows["agreement_published"])
                changed_digest = "sha256:" + hashlib.sha256(b"different").hexdigest()
                row["payload"]["digest" if case["mutation"] == "digest_field_mismatch" else "snapshot_sha256"] = changed_digest
                from dracla.conformance import derive_event_identity

                identity = derive_event_identity(row["project_id"], row["operation_nonce"], row["actor"], row["type"], row["target"], row["payload"], row["confirmed_canonical_oid"])
                row.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
                current_event = validate_event(row)
                package[0] = SideArtifact(snapshot.kind, current_event.payload["snapshot_content_path"], raw)
                metadata_bytes = canonical_json({"metadata_version": 1, "agreement_id": current_event.target["agreement_id"], "version": current_event.target["version"], "recipient": event_module._thaw(current_event.payload["recipient"]), "ref": current_event.payload["ref"], "content_commit_oid": current_event.payload["content_commit_oid"], "digest": current_event.payload["digest"], "snapshot_sha256": current_event.payload["snapshot_sha256"]})
                package[1] = SideArtifact(metadata.kind, current_event.payload["snapshot_metadata_path"], metadata_bytes)
            elif case["mutation"] in {"metadata_exact", "metadata_private_field", "metadata_ref_mismatch", "metadata_commit_mismatch", "metadata_private_member"}:
                package[1] = SideArtifact(metadata.kind, metadata.path, raw)
            accepted = True
            try:
                validate_side_artifact_package(current_event, package, preconditions=self._preconditions(current_event), expected_head=HEAD)
            except (PreconditionValidationError, SideArtifactValidationError):
                accepted = False
            self.assertEqual(accepted, case["expect"] == "accept", case["id"])

    def test_agreement_metadata_rejects_noncanonical_and_private_shapes(self):
        event, snapshot, metadata = self._publication_fixture()
        preconditions = self._preconditions(event)
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [SideArtifact(snapshot.kind, snapshot.path, b"\xff"), metadata], preconditions=preconditions, expected_head=HEAD)
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [snapshot, SideArtifact(metadata.kind, metadata.path, b"{")], preconditions=preconditions, expected_head=HEAD)
        malformed_version = {
            "metadata_version": True,
            "agreement_id": event.target["agreement_id"],
            "version": event.target["version"],
            "recipient": event_module._thaw(event.payload["recipient"]),
            "ref": event.payload["ref"],
            "content_commit_oid": event.payload["content_commit_oid"],
            "digest": event.payload["digest"],
            "snapshot_sha256": event.payload["snapshot_sha256"],
        }
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [snapshot, SideArtifact(metadata.kind, metadata.path, canonical_json(malformed_version))], preconditions=preconditions, expected_head=HEAD)
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [snapshot, SideArtifact(metadata.kind, metadata.path, canonical_json({"metadata_version": 1}))], preconditions=preconditions, expected_head=HEAD)

    def test_connection_configuration_and_genesis_vectors(self):
        event, generations, config = self._connection_fixture()
        for case in self.corpus["package_cases"]:
            if case["fixture"] != "connection":
                continue
            package = [generations, config]
            preconditions = self._preconditions(event)
            raw = base64.urlsafe_b64decode(case["bytes_b64"] + "===") if "bytes_b64" in case else None
            mutation = case["mutation"]
            if mutation in {"configuration_exact", "configuration_mismatch"}:
                package[1] = SideArtifact(config.kind, config.path, raw)
            elif mutation in {"genesis_exact", "genesis_nonmatching", "genesis_prior_exists"}:
                package[0] = SideArtifact(generations.kind, generations.path, raw)
                if mutation == "genesis_prior_exists":
                    next(item for item in preconditions if item["name"] == "generations-absence")["value"] = {"absent": False}
            elif mutation == "missing_required":
                package = []
            elif mutation == "extra_artifact":
                package.append(SideArtifact("extra", "extra.enc.json", raw))
            elif mutation == "duplicate_required":
                package = [package[0], package[0]]
            elif mutation == "reverse_order":
                package.reverse()
            elif mutation == "wrong_kind":
                package[0] = SideArtifact("wrong_kind", package[0].path, package[0].bytes)
            elif mutation == "wrong_path":
                package[0] = SideArtifact(package[0].kind, "config/wrong.enc.json", package[0].bytes)
            accepted = True
            try:
                validate_side_artifact_package(event, package, preconditions=preconditions, expected_head=HEAD)
            except (PreconditionValidationError, SideArtifactValidationError):
                accepted = False
            self.assertEqual(accepted, case["expect"] == "accept", case["id"])
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [SideArtifact(generations.kind, generations.path, b"{"), config], preconditions=self._preconditions(event), expected_head=HEAD)
        malformed = canonical_json({"generations_version": True, "derived_index": event.event_id, "status_detail": event.event_id, "reader_authority": event.event_id})
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [SideArtifact(generations.kind, generations.path, malformed), config], preconditions=self._preconditions(event), expected_head=HEAD)

    def test_currency_events_require_exact_active_agreement_bytes(self):
        for event_type, expected in (
            (
                "agreement_activated",
                {
                    "agreement_id": "agreement-1",
                    "active_version": "1",
                    "accepted_versions": ["1"],
                    "retired_versions": [],
                },
            ),
            (
                "agreement_activation_restored",
                {
                    "agreement_id": "agreement-1",
                    "active_version": "1",
                    "accepted_versions": ["1"],
                    "retired_versions": ["2"],
                },
            ),
        ):
            event = validate_event(self.rows[event_type])
            preconditions = self._preconditions(event)
            evidence = event_module._validate_preconditions(event, preconditions, HEAD)
            projection = event_module._expected_active_agreement(event, evidence)
            self.assertEqual(
                {key: projection[key] for key in expected},
                expected,
            )
            self.assertEqual(projection["activation_event_id"], event.event_id)
            artifact = SideArtifact("active_agreement", "agreements/active.enc.json", canonical_json(projection))
            validate_side_artifact_package(event, [artifact], preconditions=preconditions, expected_head=HEAD)
            for bad in (
                [],
                [SideArtifact("wrong", artifact.path, artifact.bytes)],
                [SideArtifact(artifact.kind, artifact.path, b"{}")],
                [SideArtifact(artifact.kind, artifact.path, artifact.bytes + b"\n")],
            ):
                with self.subTest(event_type=event_type, bad=bad), self.assertRaises(SideArtifactValidationError):
                    validate_side_artifact_package(event, bad, preconditions=preconditions, expected_head=HEAD)

        activation = validate_event(self.rows["agreement_activated"])
        superseding = replace(
            activation,
            target=event_module._freeze({"agreement_id": "agreement-1", "version": "2"}),
            payload=event_module._freeze({
                "published_event_id": activation.payload["published_event_id"],
                "supersedes_coverage": True,
                "accepted_versions": ["2"],
            }),
        )
        prior = {"agreement_id": "agreement-1", "active_version": "1", "activation_event_id": activation.event_id, "accepted_versions": ["1"], "retired_versions": [], "projection_format": 1, "shard_count": 32}
        preconditions = self._preconditions(superseding, overrides={"active-agreement": prior})
        evidence = event_module._validate_preconditions(superseding, preconditions, HEAD)
        projection = event_module._expected_active_agreement(superseding, evidence)
        self.assertEqual(projection["retired_versions"], ["1"])
        artifact = SideArtifact("active_agreement", "agreements/active.enc.json", canonical_json(projection))
        validate_side_artifact_package(superseding, [artifact], preconditions=preconditions, expected_head=HEAD)

    def test_acceptance_generation_vectors_and_expected_classes(self):
        connected, _, _ = self._connection_fixture()
        event = validate_event(self.rows["acceptance"])
        prior = {"derived_index": connected.event_id, "status_detail": connected.event_id, "reader_authority": connected.event_id}
        preconditions = self._preconditions(event, event.confirmed_canonical_oid, {"prior-generations": prior})
        expected = canonical_json({"generations_version": 1, "derived_index": event.event_id, "status_detail": event.event_id, "reader_authority": connected.event_id})
        for case in self.corpus["package_cases"]:
            if case["fixture"] != "acceptance":
                continue
            package = [SideArtifact("materialization_generations", "config/materialization-generations.enc.json", base64.urlsafe_b64decode(case["bytes_b64"] + "==="))]
            decoded = json.loads(package[0].bytes.decode("utf-8"))
            if case["mutation"] == "generations_exact":
                self.assertEqual(package[0].bytes, expected)
            elif case["mutation"] == "generations_wrong_successor":
                self.assertEqual(decoded["derived_index"], event.event_id)
                self.assertEqual(decoded["reader_authority"], connected.event_id)
            elif case["mutation"] == "generations_reset_unaffected":
                self.assertNotEqual(decoded["reader_authority"], prior["reader_authority"])
            elif case["mutation"] == "generations_missing_class":
                self.assertNotIn("reader_authority", decoded)
            else:
                self.assertIn("unknown_class", decoded)
            accepted = True
            try:
                validate_side_artifact_package(event, package, preconditions=preconditions, expected_head=event.confirmed_canonical_oid)
            except (PreconditionValidationError, SideArtifactValidationError):
                accepted = False
            self.assertEqual(accepted, case["expect"] == "accept", case["id"])

    def test_generation_derivation_and_public_head_boundaries(self):
        connected, _, _ = self._connection_fixture()
        self.assertEqual(event_module._expected_generations(connected, None), {name: connected.event_id for name in ("derived_index", "status_detail", "reader_authority")})
        event = validate_event(self.rows["acceptance"])
        prior = {"derived_index": "a" * 43, "status_detail": "b" * 43, "reader_authority": "c" * 43}
        self.assertEqual(event_module._expected_generations(event, prior, ("derived_index",)), {"derived_index": event.event_id, "status_detail": prior["status_detail"], "reader_authority": prior["reader_authority"]})
        with self.assertRaises(SideArtifactValidationError):
            event_module._expected_generations(event, None)
        with self.assertRaises(SideArtifactValidationError):
            validate_side_artifact_package(event, [], preconditions=self._preconditions(event, event.confirmed_canonical_oid), expected_head=HEAD)
        with self.assertRaises(EventValidationError):
            validate_side_artifact_package(event, [], preconditions=[], expected_head="bad")
