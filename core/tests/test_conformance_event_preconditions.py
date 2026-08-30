"""Resolved precondition and side-artifact declaration contract tests."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    AuthorizationEvidence,
    CanonicalShaBinding,
    CrossProjectBinding,
    EventValidationError,
    EventsHeadBinding,
    GenerationBinding,
    PreconditionEvidence,
    PreconditionValidationError,
    RegistryGenerationBinding,
    SideArtifactRequirement,
    required_preconditions,
    required_side_artifacts,
    validate_event,
)
from dracla.conformance import events as event_module  # noqa: E402


VECTORS = Path(__file__).parent / "vectors" / "events-v1.json"
HEAD = "b" * 40


class TestEventPreconditions(unittest.TestCase):
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

    def _activation_projection(
        self,
        event,
        *,
        agreement_id,
        active_version,
        activation_event_id,
        accepted_versions,
    ):
        return {
            "agreement_id": agreement_id,
            "active_version": active_version,
            "activation_event_id": activation_event_id,
            "accepted_versions": list(accepted_versions),
            "projection_format": 1,
            "shard_count": 32,
        }

    def _activation_event(self, version, supersedes_coverage):
        activation = validate_event(self.rows["agreement_activated"])
        return replace(
            activation,
            target=event_module._freeze({"agreement_id": "agreement-1", "version": version}),
            payload=event_module._freeze({
                "published_event_id": activation.payload["published_event_id"],
                "supersedes_coverage": supersedes_coverage,
            }),
        )

    def _preconditions(self, event, head=HEAD, overrides=None):
        overrides = overrides or {}
        values = []
        for requirement in required_preconditions(event, expected_head=head):
            override_name = requirement.name
            if override_name not in overrides:
                for prefix in ("coverage-state", "current-exemption-union"):
                    if override_name.startswith(prefix + "-") and prefix in overrides:
                        override_name = prefix
                        break
            if override_name in overrides:
                value = overrides[override_name]
            elif requirement.name == "generations-absence":
                value = None
            elif requirement.name == "keyring-affected-repositories":
                value = {"repository_ids": [11, 12, 13]}
            elif requirement.name in {"published-agreement", "scope-request", "source-event", "rule-event"}:
                linked_id = event.payload.get("published_event_id", event.payload.get("request_event_id", event.target.get("source_event_id", event.target.get("rule_event_id"))))
                linked_type = {"published-agreement": "agreement_published", "scope-request": "enforcement_scope_requested", "source-event": "exemption", "rule-event": "exemption_rule_configured"}[requirement.name]
                if requirement.name == "published-agreement":
                    linked_target = {"agreement_id": event.target["agreement_id"], "version": event.target["version"]}
                    linked_payload = copy.deepcopy(self.rows["agreement_published"]["payload"])
                elif requirement.name == "scope-request":
                    linked_target = {"change_id": event.target["change_id"]}
                    linked_payload = {"prior_scope": [], "desired_scope": event.payload.get("desired_scope", self.rows["enforcement_scope_requested"]["payload"]["desired_scope"]), "prior_registry_generation": 0}
                elif requirement.name == "source-event":
                    linked_type = "exemption" if event.type == "exemption_source_withdrawn" else "records_reader_authorized"
                    linked_target = {"subject": event.target["subject"]}
                    linked_payload = {}
                else:
                    linked_type = "exemption_rule_configured" if event.type in {"exemption_rule_withdrawn", "exemption_materialized"} else "records_reader_rule_configured"
                    linked_target = {"team": self.rows["exemption_rule_configured"]["target"]["team"]}
                    linked_payload = {}
                value = {"event_id": linked_id, "type": linked_type, "project_id": event.project_id, "target": linked_target, "payload": linked_payload}
            elif requirement.name == "successor-project":
                value = {"event": {"event_id": event.payload["successor_connected_event_id"], "type": "project_connected", "project_id": event.target["successor_project_id"], "target": {}, "payload": {"successor_of": event.project_id, "repository_ids": {"records": 11, "coverage": 12, "control": 13}}}, "active_agreement": {"project_id": event.target["successor_project_id"], "agreement_id": "agreement-1", "version": "1", "state": "active"}}
            elif requirement.name == "current-configuration":
                value = self.rows["project_connected"]["payload"]["project_configuration"]
            elif requirement.name == "prior-generations":
                value = {"derived_index": event.event_id, "status_detail": event.event_id, "reader_authority": event.event_id}
            elif requirement.name == "project-lifecycle":
                value = {"project_id": event.project_id, "state": "active", "successor_project_id": None}
            elif requirement.name == "active-agreement":
                if event.type == "acceptance":
                    publication_row = self.rows["agreement_published"]
                    publication = {key: copy.deepcopy(publication_row[key]) for key in ("event_id", "type", "project_id", "target", "payload")}
                    value = {
                        "project_id": event.project_id,
                        "agreement_id": event.target["coverage_tuple"]["agreement_id"],
                        "version": event.target["version"],
                        "recipient": event.target["recipient"],
                        "digest": event.target["digest"],
                        "state": "active",
                        "accepted_versions": [event.target["version"]],
                        "active_version": event.target["version"],
                        "activation_event_id": self.rows["agreement_activated"]["event_id"],
                        "supersedes_coverage": False,
                        "publication": publication,
                    }
                elif event.type == "agreement_activated":
                    version = event.target.get("version", "1")
                    value = self._activation_projection(
                        event,
                        agreement_id=event.target.get("agreement_id", "agreement-1"),
                        active_version=version,
                        activation_event_id=self.rows["agreement_activated"]["event_id"],
                        accepted_versions=[version],
                    )
                else:
                    value = {"project_id": event.project_id, "agreement_id": event.target.get("agreement_id", "agreement-1"), "version": event.target.get("version", "1"), "state": "active"}
            elif requirement.name == "current-repository-owner":
                staged_generation = event.payload.get("registry_generation", 0)
                prior_entry = {"project_id": event.project_id, "project_slug": event.payload["project_slug"], "repository_owner": event.target.get("prior_repository_owner"), "repository_ids": event.payload.get("repository_ids"), "registry_generation": max(0, staged_generation - 1), "enforcement_scope": [], "request_event_links": {}}
                staged_entry = json.loads(json.dumps(event_module._thaw(prior_entry)))
                staged_entry["repository_owner"] = event.payload["new_repository_owner"]
                staged_entry["registry_generation"] = staged_generation
                value = {"prior_entry": prior_entry, "staged_entry": staged_entry}
            elif requirement.name == "current-scope":
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
            elif requirement.name.startswith("coverage-state-") or requirement.name == "override-grant":
                if requirement.name == "override-grant":
                    value = {"event": {"event_id": event.target["override_event_id"], "type": "override", "project_id": event.project_id, "target": copy.deepcopy(self.rows["override"]["target"]), "payload": copy.deepcopy(self.rows["override"]["payload"])}, "active": True}
                else:
                    subject_ids = ([event.target["coverage_tuple"]["github_user_id"]] if event.type == "revocation" else sorted(subject["github_user_id"] for subject in event.payload["subjects"] if subject["github_user_id"] % 32 == int(requirement.name.rsplit("-", 1)[1])))
                    value = {"project_id": event.project_id, "state": "current", "resource": event.target, "subject_ids": subject_ids}
            elif requirement.name.startswith("current-exemption-union-"):
                source_id = event.target.get("source_event_id", event.target.get("rule_event_id", self.rows["exemption"]["event_id"]))
                shard = int(requirement.name.rsplit("-", 1)[1])
                if event.type in {"exemption_rule_configured", "exemption_rule_withdrawn"}:
                    subjects = [self.rows["exemption"]["target"]["subject"]] if shard == self.rows["exemption"]["target"]["subject"]["github_user_id"] % 32 else []
                elif "subjects" in event.target:
                    subjects = [subject for subject in event.target["subjects"] if subject["github_user_id"] % 32 == shard]
                else:
                    subject = event.target.get("subject", self.rows["exemption"]["target"]["subject"])
                    subjects = [subject] if subject["github_user_id"] % 32 == shard else []
                value = {"project_id": event.project_id, "subjects": subjects, "provenance": {str(subject["github_user_id"]): [source_id] for subject in subjects}}
            elif requirement.name == "current-reader-authority":
                value = {"project_id": event.project_id, "class_state": "current", "sources": [], "cursor_event_id": event.event_id}
            elif requirement.name.startswith("active-reader-rules-"):
                value = {"project_id": event.project_id, "rule_event_ids": []}
            elif requirement.name == "reader-authority-state":
                source_id = event.target.get("source_event_id", event.target.get("rule_event_id", self.rows["records_reader_authorized"]["event_id"]))
                value = {"project_id": event.project_id, "class_state": "current", "source_event_ids": [source_id], "cursor_event_id": event.event_id}
            elif requirement.name == "materialization-cursor":
                value = {"cursor_event_id": event.event_id, "prior_materialization_event_id": event.payload.get("prior_materialization_event_id"), "rule_event_id": event.target["rule_event_id"], "subject": event.target["subject"]}
            elif requirement.name in {"scope-terminal-activation-absence", "scope-terminal-abandonment-absence"}:
                descriptor = next(item for item in required_preconditions(event, expected_head=head) if item.name == requirement.name)
                value = {"path": descriptor.path, "present": False}
            else:
                value = {"ok": True}
            values.append(self._evidence(event, requirement, value))
        return values

    def test_evidence_models_and_coercion(self):
        event = validate_event(self.rows["project_connected"])
        requirement = required_preconditions(event, expected_head=HEAD)[0]
        evidence = PreconditionEvidence(requirement.name, requirement.artifact_kind, requirement.repository_role, requirement.branch, requirement.path, requirement.binding_mode, EventsHeadBinding(HEAD), {"ok": True})
        self.assertIs(event_module._coerce_precondition(evidence), evidence)
        self.assertEqual(evidence.to_dict()["value"], {"ok": True})
        evidence_dict = self._evidence(event, requirement, None)
        self.assertEqual(event_module._precondition_map({"alias": evidence})[requirement.name], evidence)
        without_name = dict(evidence_dict)
        del without_name["name"]
        self.assertEqual(event_module._precondition_map({requirement.name: without_name})[requirement.name].name, requirement.name)
        self.assertEqual(event_module._precondition_map({requirement.name: evidence_dict})[requirement.name].name, requirement.name)
        self.assertEqual(event_module._precondition_map([evidence_dict])[requirement.name].name, requirement.name)
        invalid = (None, {}, {**evidence_dict, "extra": True}, {**evidence_dict, "name": ""}, {**evidence_dict, "path": ""})
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(PreconditionValidationError):
                event_module._coerce_precondition(value)
        with self.assertRaises(PreconditionValidationError):
            event_module._precondition_map(object())
        with self.assertRaises(PreconditionValidationError):
            event_module._precondition_map([evidence_dict, evidence_dict])
        with self.assertRaises(PreconditionValidationError):
            PreconditionEvidence("name", "kind", "records", "events", "path", "events-head", EventsHeadBinding(HEAD), object())

    def test_binding_shapes_and_membership(self):
        connected = validate_event(self.rows["project_connected"])
        valid = {
            "events-head": {"mode": "events-head", "events_head": HEAD},
            "generation": {"mode": "generation", "events_head": HEAD, "canonical_generation": connected.event_id, "derived_generation": connected.event_id},
            "canonical-sha": {"mode": "canonical-sha", "coverage_commit_oid": HEAD, "canonical_sha": HEAD},
            "registry-generation": {"mode": "registry-generation", "registry_commit_oid": "a" * 40, "registry_generation": 1},
            "cross-project": {"mode": "cross-project", "successor_project_id": "successor-project", "successor_events_head": HEAD, "repository_ids": [11, 12, 13]},
        }
        for mode, value in valid.items():
            with self.subTest(mode=mode):
                self.assertEqual(event_module._parse_binding(value, mode=mode).mode, mode)
        malformed = (
            ("not-an-object", "events-head"),
            ({"mode": "events-head", "events_head": HEAD, "extra": True}, "events-head"),
            ({"mode": "events-head", "events_head": "bad"}, "events-head"),
            ({"mode": "generation", "events_head": HEAD}, "generation"),
            ({"mode": "generation", "events_head": HEAD, "canonical_generation": "bad", "derived_generation": connected.event_id}, "generation"),
            ({"mode": "canonical-sha", "canonical_sha": HEAD}, "canonical-sha"),
            ({"mode": "canonical-sha", "coverage_commit_oid": "bad", "canonical_sha": HEAD}, "canonical-sha"),
            ({"mode": "registry-generation", "registry_commit_oid": "bad", "registry_generation": 1}, "registry-generation"),
            ({"mode": "cross-project", "successor_project_id": "successor-project", "successor_events_head": HEAD}, "cross-project"),
            ({"mode": "cross-project", "successor_project_id": "successor-project", "successor_events_head": HEAD, "repository_ids": "bad"}, "cross-project"),
            ({"mode": "cross-project", "successor_project_id": "successor-project", "successor_events_head": HEAD, "repository_ids": [11, 11]}, "cross-project"),
            ({"mode": "cross-project", "successor_project_id": 1, "successor_events_head": HEAD, "repository_ids": [11, 12]}, "cross-project"),
            ({"mode": "unknown"}, "unknown"),
        )
        for value, mode in malformed:
            with self.subTest(mode=mode, value=value), self.assertRaises(PreconditionValidationError):
                event_module._parse_binding(value, mode=mode)
        requirement = event_module.PreconditionRequirement("x", "kind", "records", "events", "path", "events-head", "relation", HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(GenerationBinding(HEAD, connected.event_id, self.rows["revocation"]["event_id"]), event_module.PreconditionRequirement("x", "kind", "records", "events", "path", "generation", "relation", HEAD), HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(CanonicalShaBinding(HEAD, "c" * 40), event_module.PreconditionRequirement("x", "kind", "coverage", "coverage", "path", "canonical-sha", "relation", HEAD), HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(CrossProjectBinding("wrong", HEAD, (11, 12, 13)), event_module.PreconditionRequirement("x", "kind", "records", "events", "path", "cross-project", "successor-project:successor-project", HEAD), HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(RegistryGenerationBinding("a" * 40, -1), event_module.PreconditionRequirement("x", "kind", "records", "events", "path", "registry-generation", "relation", HEAD), HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(EventsHeadBinding("c" * 40), requirement, HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(GenerationBinding("c" * 40, connected.event_id, connected.event_id), event_module.PreconditionRequirement("x", "kind", "records", "events", "path", "generation", "relation", HEAD), HEAD)
        class UnknownBinding:
            mode = "events-head"
        event_module._validate_binding(UnknownBinding(), requirement, HEAD)

    def test_evidence_binding_and_registry_shapes_fail_closed(self):
        with self.assertRaises(PreconditionValidationError):
            PreconditionEvidence("name", "kind", "records", "events", "path", "events-head", object(), None)
        with self.assertRaises(PreconditionValidationError):
            PreconditionEvidence("name", "kind", "records", "events", "path", "generation", EventsHeadBinding(HEAD), None)
        with self.assertRaises(PreconditionValidationError):
            event_module._parse_binding({"mode": "registry-generation", "registry_generation": 1}, mode="registry-generation")
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_binding(
                EventsHeadBinding(HEAD),
                event_module.PreconditionRequirement("x", "kind", "records", "events", "path", "generation", "relation", HEAD),
                HEAD,
            )
        bad_registry = (
            None,
            {},
            {"project_id": "project-1"},
            {"project_id": "project-1", "project_slug": "BAD!", "repository_owner": {"github_account_id": 10, "login_snapshot": "owner"}, "repository_ids": {"records": 11, "coverage": 12, "control": 13}, "registry_generation": 1, "enforcement_scope": [], "request_event_links": {}},
            {"project_id": "project-1", "project_slug": "project-one", "repository_owner": {"github_account_id": 10, "login_snapshot": "owner"}, "repository_ids": {"records": 11, "coverage": 12, "control": 13}, "registry_generation": 1, "enforcement_scope": "bad", "request_event_links": {}},
            {"project_id": "project-1", "project_slug": "project-one", "repository_owner": {"github_account_id": 10, "login_snapshot": "owner"}, "repository_ids": {"records": 11, "coverage": 12, "control": 13}, "registry_generation": 1, "enforcement_scope": [], "request_event_links": []},
            {"project_id": "project-1", "project_slug": "project-one", "repository_owner": {"github_account_id": 10, "login_snapshot": "owner"}, "repository_ids": {"records": 11, "coverage": 12, "control": 13}, "registry_generation": 1, "enforcement_scope": [], "request_event_links": {"change": "bad"}},
        )
        for value in bad_registry:
            with self.subTest(value=value), self.assertRaises(PreconditionValidationError):
                event_module._registry_entry(value, "registry")

    def test_precondition_status_and_head_vectors(self):
        events = {row["type"]: validate_event(row) for row in self.corpus["events"]}
        by_descriptor = {}
        for event in events.values():
            event_head = event.confirmed_canonical_oid or HEAD
            for descriptor in required_preconditions(event, expected_head=event_head):
                by_descriptor.setdefault(descriptor.name, event)
        for case in self.corpus["precondition_cases"]:
            for name in case["descriptors"] if case["descriptor"] == "*" else [case["descriptor"]]:
                event = by_descriptor[name]
                event_head = event.confirmed_canonical_oid or HEAD
                preconditions = self._preconditions(event, event_head)
                if case["status"] == "satisfied":
                    required_side_artifacts(event, preconditions=preconditions, expected_head=event_head)

    def test_activation_prior_projection_vectors(self):
        activation_event_id = self.rows["agreement_activated"]["event_id"]
        projections = {
            "empty": {
                "agreement_id": None,
                "active_version": None,
                "activation_event_id": None,
                "accepted_versions": [],
                "projection_format": 1,
                "shard_count": 32,
            },
            "v1": {
                "agreement_id": "agreement-1",
                "active_version": "1",
                "activation_event_id": activation_event_id,
                "accepted_versions": ["1"],
                "projection_format": 1,
                "shard_count": 32,
            },
            "v2_after_supersession": {
                "agreement_id": "agreement-1",
                "active_version": "2",
                "activation_event_id": activation_event_id,
                "accepted_versions": ["2"],
                "projection_format": 1,
                "shard_count": 32,
            },
        }
        malformed = {
            "missing_shard_count": {**projections["empty"]},
            "format_two": {**projections["empty"], "projection_format": 2},
            "shard_count_sixteen": {**projections["empty"], "shard_count": 16},
            "partial_active": {**projections["empty"], "agreement_id": "agreement-1"},
            "duplicate_versions": {**projections["v1"], "accepted_versions": ["1", "1"]},
            "active_version_not_member": {**projections["v1"], "active_version": "2"},
            "bad_activation_event_id": {**projections["v1"], "activation_event_id": "bad"},
            "bad_accepted_versions": {**projections["v1"], "accepted_versions": "bad"},
            "non_string_version": {**projections["v1"], "accepted_versions": [1]},
            "missing_agreement_id": {**projections["v1"], "agreement_id": None},
            "missing_active_version": {**projections["v1"], "active_version": ""},
            "extra_project_id": {**projections["v1"], "project_id": "project-1"},
            "wrong_agreement": {**projections["v1"], "agreement_id": "other"},
        }
        malformed["missing_shard_count"].pop("shard_count")
        for case in self.corpus["activation_cases"]:
            with self.subTest(case=case["id"]):
                event = self._activation_event(case["event_version"], case["supersedes_coverage"])
                if case["prior"] in projections:
                    projection = copy.deepcopy(projections[case["prior"]])
                else:
                    projection = copy.deepcopy(malformed[case["prior"]])
                values = self._preconditions(event, overrides={"active-agreement": projection})
                if case["expect"] == "accept":
                    event_module._validate_preconditions(event, values, HEAD)
                else:
                    with self.assertRaises(PreconditionValidationError):
                        event_module._validate_preconditions(event, values, HEAD)


    def test_lifecycle_and_confirmed_head_vectors(self):
        for case in self.corpus["head_binding_cases"]:
            event = validate_event(self.rows[case["event_type"]])
            preconditions = self._preconditions(event, event.confirmed_canonical_oid or HEAD)
            if case["mutation"] == "confirmed_head":
                with self.assertRaises(PreconditionValidationError):
                    required_side_artifacts(event, preconditions=preconditions, expected_head=HEAD)
            elif case["mutation"] == "earlier_head":
                next(item for item in preconditions if item["name"] == "project-lifecycle")["binding"]["events_head"] = "c" * 40
                with self.assertRaises(PreconditionValidationError):
                    required_side_artifacts(event, preconditions=preconditions, expected_head=HEAD)
            else:
                lifecycle = next(item for item in preconditions if item["name"] == "project-lifecycle")
                lifecycle["value"].update(state="succeeded", successor_project_id="successor-project")
                with self.assertRaises(PreconditionValidationError):
                    required_side_artifacts(event, preconditions=preconditions, expected_head=HEAD)
        for case in self.corpus["lifecycle_cases"]:
            event = validate_event(self.rows[case["event_type"]])
            if "authorization_operation" in case:
                event = replace(event, authorizations=(AuthorizationEvidence(case["authorization_operation"], "organization", 41, "organization_owner", "admin", True, "2026-08-29T00:00:00Z", None),))
            head = event.confirmed_canonical_oid or HEAD
            values = self._preconditions(event, head, {"project-lifecycle": {"project_id": event.project_id, "state": case["state"], "successor_project_id": "successor-project" if case["state"] == "succeeded" else None}})
            accepted = True
            try:
                required_side_artifacts(event, preconditions=values, expected_head=head)
            except PreconditionValidationError:
                accepted = False
            self.assertEqual(accepted, case["expect"] == "accept")

    def test_event_links_and_active_agreement(self):
        for event_type, replacement in (("agreement_activated", {"event_id": "wrong"}), ("enforcement_scope_activated", {}), ("project_succeeded", {"successor_project_id": "wrong", "successor_of": "wrong"})):
            event = validate_event(self.rows[event_type])
            name = {"agreement_activated": "published-agreement", "enforcement_scope_activated": "scope-request", "project_succeeded": "successor-project"}[event_type]
            with self.assertRaises(PreconditionValidationError):
                required_side_artifacts(event, preconditions=self._preconditions(event, overrides={name: replacement}), expected_head=HEAD)
        acceptance = validate_event(self.rows["acceptance"])
        active = next(item["value"] for item in self._preconditions(acceptance, acceptance.confirmed_canonical_oid) if item["name"] == "active-agreement")
        publication = active["publication"]
        for replacement in ({**publication, "type": "wrong"}, {**publication, "target": {}}, {**publication, "payload": {}}, {**publication, "payload": {**publication["payload"], "recipient": {}}}, {**publication, "payload": {**publication["payload"], "digest": "bad"}}):
            with self.assertRaises(EventValidationError):
                event_module._validate_link_fact(acceptance, "active-publication", replacement)
        bad_active = {**active, "accepted_versions": ["2"]}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(acceptance, self._preconditions(acceptance, acceptance.confirmed_canonical_oid, {"active-agreement": bad_active}), acceptance.confirmed_canonical_oid)

    def test_registry_owner_and_scope_relations(self):
        owner = validate_event(self.rows["project_repository_owner_changed"])
        mutations = ("project", "prior_owner", "staged_owner", "routing", "generation", "repositories", "slug", "entry_generation")
        for mutation in mutations:
            values = self._preconditions(owner)
            value = next(item for item in values if item["name"] == "current-repository-owner")["value"]
            if mutation == "project":
                value["prior_entry"]["project_id"] = "other"
            elif mutation == "prior_owner":
                value["prior_entry"]["repository_owner"] = owner.payload["new_repository_owner"]
            elif mutation == "staged_owner":
                value["staged_entry"]["repository_owner"] = owner.target["prior_repository_owner"]
            elif mutation == "routing":
                value["staged_entry"]["project_slug"] = "other-project"
            elif mutation == "generation":
                value["staged_entry"]["registry_generation"] = value["prior_entry"]["registry_generation"]
            elif mutation == "repositories":
                replacement = {"records": 21, "coverage": 22, "control": 23}
                value["prior_entry"]["repository_ids"] = replacement
                value["staged_entry"]["repository_ids"] = replacement
            elif mutation == "slug":
                value["prior_entry"]["project_slug"] = "other-project"
                value["staged_entry"]["project_slug"] = "other-project"
            else:
                value["staged_entry"]["registry_generation"] = owner.payload["registry_generation"] + 1
            with self.subTest(mutation=mutation), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(owner, values, HEAD)
        scope = validate_event(self.rows["enforcement_scope_requested"])
        for mutation in ("project", "scope", "routing"):
            values = self._preconditions(scope)
            value = next(item for item in values if item["name"] == "current-scope")["value"]
            if mutation == "project":
                value["prior_entry"]["project_id"] = "other"
            elif mutation == "scope":
                value["current_entry"]["enforcement_scope"] = scope.payload["desired_scope"]
            else:
                value["current_entry"]["project_slug"] = "other-project"
            with self.subTest(scope_mutation=mutation), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(scope, values, HEAD)
        activated = validate_event(self.rows["enforcement_scope_activated"])
        for mutation in ("scope", "link", "binding"):
            values = self._preconditions(activated)
            item = next(item for item in values if item["name"] == "current-scope")
            if mutation == "scope":
                item["value"]["staged_entry"]["enforcement_scope"] = []
            elif mutation == "link":
                item["value"]["staged_entry"]["request_event_links"] = {}
            else:
                item["binding"]["registry_generation"] += 1
            with self.subTest(activation_mutation=mutation), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(activated, values, HEAD)
        abandoned = validate_event(self.rows["enforcement_scope_abandoned"])
        values = self._preconditions(abandoned)
        next(item for item in values if item["name"] == "current-scope")["value"]["current_entry"]["enforcement_scope"] = self.rows["enforcement_scope_requested"]["payload"]["desired_scope"]
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(abandoned, values, HEAD)

    def test_reader_and_materialization_facts_are_authenticated(self):
        materialized = validate_event(self.rows["exemption_materialized"])
        for replacement in (
            {"cursor_event_id": "bad", "prior_materialization_event_id": None, "rule_event_id": materialized.target["rule_event_id"], "subject": materialized.target["subject"]},
            {"cursor_event_id": materialized.event_id, "prior_materialization_event_id": materialized.event_id, "rule_event_id": materialized.target["rule_event_id"], "subject": materialized.target["subject"]},
            {"cursor_event_id": materialized.event_id, "prior_materialization_event_id": None, "rule_event_id": self.rows["revocation"]["event_id"], "subject": materialized.target["subject"]},
            {},
        ):
            values = self._preconditions(materialized)
            next(item for item in values if item["name"] == "materialization-cursor")["value"] = replacement
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(materialized, values, HEAD)

        reader = validate_event(self.rows["records_reader_withdrawn"])
        values = self._preconditions(reader)
        next(item for item in values if item["name"] == "reader-authority-state")["value"] = {}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(reader, values, HEAD)
        for replacement in (
            {"project_id": reader.project_id, "class_state": "current", "source_event_ids": [], "cursor_event_id": reader.event_id},
            {"project_id": reader.project_id, "class_state": "current", "source_event_ids": ["bad"], "cursor_event_id": reader.event_id},
            {"project_id": reader.project_id, "class_state": "current", "source_event_ids": [reader.target["source_event_id"], reader.target["source_event_id"]], "cursor_event_id": reader.event_id},
        ):
            values = self._preconditions(reader)
            item = next(item for item in values if item["name"] == "reader-authority-state")
            item["value"] = replacement
            if replacement["class_state"] == "current" and not replacement["source_event_ids"]:
                item["binding"]["derived_generation"] = self.rows["revocation"]["event_id"]
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(reader, values, HEAD)

        authorized = validate_event(self.rows["records_reader_authorized"])
        for replacement in (
            {},
            {"project_id": authorized.project_id, "class_state": "current", "sources": ["bad"], "cursor_event_id": authorized.event_id},
            {"project_id": authorized.project_id, "class_state": "current", "sources": [authorized.event_id, authorized.event_id], "cursor_event_id": authorized.event_id},
        ):
            values = self._preconditions(authorized)
            item = next(item for item in values if item["name"] == "current-reader-authority")
            item["value"] = replacement
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(authorized, values, HEAD)

    def test_reader_and_exemption_facts_reject_wrong_shapes(self):
        reader = validate_event(self.rows["records_reader_withdrawn"])
        values = self._preconditions(reader)
        item = next(item for item in values if item["name"] == "reader-authority-state")
        item["value"] = {"project_id": "other", "class_state": "current", "source_event_ids": [], "cursor_event_id": reader.event_id}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(reader, values, HEAD)
        authorized = validate_event(self.rows["records_reader_authorized"])
        values = self._preconditions(authorized)
        item = next(item for item in values if item["name"] == "current-reader-authority")
        item["value"] = {"project_id": "other", "class_state": "current", "sources": [], "cursor_event_id": authorized.event_id}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(authorized, values, HEAD)

    def test_active_reader_rule_shards_are_authenticated_and_countable(self):
        event = validate_event(self.rows["records_reader_rule_configured"])
        values = self._preconditions(event)
        active = [item for item in values if item["name"].startswith("active-reader-rules-")]
        self.assertEqual(len(active), 32)
        rule_event_id = event.event_id
        shard = int(event_module._reader_shard_path(rule_event_id).split("/")[-1][:2])
        next(item for item in active if item["name"] == f"active-reader-rules-{shard:02d}")["value"]["rule_event_ids"] = [rule_event_id]
        event_module._validate_preconditions(event, values, HEAD)

        cases = (
            {"project_id": "other", "rule_event_ids": []},
            {"project_id": event.project_id, "rule_event_ids": ["bad"]},
            {"project_id": event.project_id, "rule_event_ids": [rule_event_id, rule_event_id]},
        )
        for replacement in cases:
            trial = self._preconditions(event)
            next(item for item in trial if item["name"] == f"active-reader-rules-{shard:02d}")["value"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(event, trial, HEAD)

        wrong_shard = (shard + 1) % 32
        trial = self._preconditions(event)
        next(item for item in trial if item["name"] == f"active-reader-rules-{wrong_shard:02d}")["value"]["rule_event_ids"] = [rule_event_id]
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(event, trial, HEAD)
        exemption = validate_event(self.rows["exemption_rule_withdrawn"])
        values = self._preconditions(exemption)
        union = next(item for item in values if item["name"] == "current-exemption-union-07")
        union["value"]["provenance"] = {}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(exemption, values, HEAD)
        values = self._preconditions(exemption)
        union = next(item for item in values if item["name"] == "current-exemption-union-07")
        union["value"]["subjects"] = [{"github_user_id": 8, "login_snapshot": "other"}]
        union["value"]["provenance"] = {"8": [exemption.target["rule_event_id"]]}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(exemption, values, HEAD)
        for provenance in ({"7": []}, {"7": ["bad"]}, {"7": [exemption.target["rule_event_id"], exemption.target["rule_event_id"]]}):
            values = self._preconditions(exemption)
            union = next(item for item in values if item["name"] == "current-exemption-union-07")
            union["value"]["provenance"] = provenance
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(exemption, values, HEAD)

    def test_override_and_keyring_facts_are_bound_to_events(self):
        override = validate_event(self.rows["override_withdrawn"])
        values = self._preconditions(override)
        grant = next(item for item in values if item["name"] == "override-grant")["value"]
        for replacement in (
            {"event": {}, "active": True},
            {**grant, "active": False},
            {**grant, "event": {**grant["event"], "target": {}}},
            {**grant, "event": {**grant["event"], "payload": {"subjects": grant["event"]["payload"]["subjects"], "reason": "ok"}}},
            {**grant, "event": {**grant["event"], "payload": {"subjects": grant["event"]["payload"]["subjects"], "reason": "", "instrument_ref": None}}},
            {**grant, "event": {**grant["event"], "payload": {"subjects": grant["event"]["payload"]["subjects"], "reason": "ok", "instrument_ref": 1}}},
        ):
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(override, self._preconditions(override, overrides={"override-grant": replacement}), HEAD)
        keyring = validate_event(self.rows["keyring_activated"])
        for repository_ids in ([0, 12, 13], [11, 11, 12], [11, 12], "bad"):
            values = self._preconditions(keyring, overrides={"keyring-affected-repositories": {"repository_ids": repository_ids}})
            with self.subTest(repository_ids=repository_ids), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(keyring, values, HEAD)
        acceptance = validate_event(self.rows["acceptance"])
        head = acceptance.confirmed_canonical_oid
        for config in (
            {"privacy_policy_url": "https://example.test", "retention_statement": "r", "correction_procedure": "c", "required_fields": [], "confirmation_labels": ["I agree"]},
            {**self.rows["project_connected"]["payload"]["project_configuration"], "confirmation_labels": ["Wrong"]},
            {"privacy_policy_url": "bad", "retention_statement": "r", "correction_procedure": "c", "required_fields": [], "confirmation_labels": []},
        ):
            values = self._preconditions(acceptance, head, {"current-configuration": config})
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(acceptance, values, head)

    def test_lifecycle_and_agreement_facts_are_consistent(self):
        lifecycle_event = validate_event(self.rows["config_updated"])
        for replacement in (
            {"project_id": "other", "state": "active", "successor_project_id": None},
            {"project_id": lifecycle_event.project_id, "state": "unknown", "successor_project_id": None},
            {"project_id": lifecycle_event.project_id, "state": "active", "successor_project_id": "successor-project"},
        ):
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(lifecycle_event, self._preconditions(lifecycle_event, overrides={"project-lifecycle": replacement}), HEAD)
        succeeded = validate_event(self.rows["project_succeeded"])
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(succeeded, self._preconditions(succeeded, overrides={"project-lifecycle": {"project_id": succeeded.project_id, "state": "succeeded", "successor_project_id": None}}), HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(lifecycle_event, self._preconditions(lifecycle_event, overrides={"project-lifecycle": {"project_id": lifecycle_event.project_id, "state": "succeeded", "successor_project_id": "successor-project"}}), HEAD)
        acceptance = validate_event(self.rows["acceptance"])
        head = acceptance.confirmed_canonical_oid
        for replacement in (
            None,
            {"project_id": acceptance.project_id, "agreement_id": acceptance.target["coverage_tuple"]["agreement_id"], "version": acceptance.target["version"], "state": "active"},
            {"project_id": "other", "agreement_id": acceptance.target["coverage_tuple"]["agreement_id"], "version": acceptance.target["version"], "recipient": acceptance.target["recipient"], "digest": acceptance.target["digest"], "state": "active", "accepted_versions": [acceptance.target["version"]], "active_version": acceptance.target["version"], "activation_event_id": self.rows["agreement_activated"]["event_id"], "supersedes_coverage": False, "publication": next(item["value"] for item in self._preconditions(acceptance, head) if item["name"] == "active-agreement")["publication"]},
        ):
            values = self._preconditions(acceptance, head, {"active-agreement": replacement})
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(acceptance, values, head)
        valid = next(item["value"] for item in self._preconditions(acceptance, head) if item["name"] == "active-agreement")
        for replacement in (
            {**valid, "active_version": "2"},
            {**valid, "recipient": {"recipient_id": "other", "legal_name": "Other"}},
            {**valid, "accepted_versions": "bad"},
            {**valid, "accepted_versions": ["1", "1"]},
            {**valid, "accepted_versions": ["2"]},
        ):
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(acceptance, self._preconditions(acceptance, head, {"active-agreement": replacement}), head)
        activation = validate_event(self.rows["agreement_activated"])
        for replacement in (
            {"project_id": activation.project_id, "agreement_id": activation.target["agreement_id"], "version": activation.target["version"], "state": "inactive"},
            {"project_id": activation.project_id, "agreement_id": "other", "version": activation.target["version"], "state": "active"},
        ):
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(activation, self._preconditions(activation, overrides={"active-agreement": replacement}), HEAD)

    def test_dispatch_and_secondary_relation_guards_fail_closed(self):
        connected = validate_event(self.rows["project_connected"])
        unknown_requirement = event_module.PreconditionRequirement("unknown", "unknown", "records", "events", "unknown", "events-head", "unknown", HEAD)
        unknown_evidence = {"name": "unknown", "artifact_kind": "unknown", "repository_role": "records", "branch": "events", "path": "unknown", "binding_mode": "events-head", "binding": {"mode": "events-head", "events_head": HEAD}, "value": None}
        with patch.object(event_module, "required_preconditions", return_value=(unknown_requirement,)):
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(connected, [unknown_evidence], HEAD)
        with patch.object(event_module, "_validate_preconditions_impl", side_effect=KeyError("missing")):
            with self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(connected, [], HEAD)
        source = validate_event(self.rows["exemption_source_withdrawn"])
        values = self._preconditions(source)
        union = next(item for item in values if item["name"] == "current-exemption-union-07")
        union["value"]["provenance"] = {"7": [self.rows["revocation"]["event_id"]]}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(source, values, HEAD)
        owner = validate_event(self.rows["project_repository_owner_changed"])
        values = self._preconditions(owner)
        next(item for item in values if item["name"] == "current-repository-owner")["binding"]["registry_commit_oid"] = "b" * 40
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(owner, values, HEAD)
        abandoned = validate_event(self.rows["enforcement_scope_abandoned"])
        values = self._preconditions(abandoned)
        next(item for item in values if item["name"] == "current-scope")["binding"]["registry_generation"] = 1
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(abandoned, values, HEAD)
        revocation = validate_event(self.rows["revocation"])
        values = self._preconditions(revocation, revocation.confirmed_canonical_oid)
        coverage = next(item for item in values if item["name"].startswith("coverage-state-"))["value"]
        coverage["project_id"] = "other"
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(revocation, values, revocation.confirmed_canonical_oid)
        values = self._preconditions(revocation, revocation.confirmed_canonical_oid)
        coverage = next(item for item in values if item["name"].startswith("coverage-state-"))["value"]
        coverage["resource"] = {}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(revocation, values, revocation.confirmed_canonical_oid)

    def test_coverage_exemption_and_terminal_relations(self):
        terminal = validate_event(self.rows["enforcement_scope_activated"])
        values = self._preconditions(terminal)
        next(item for item in values if item["name"] == "scope-terminal-activation-absence")["value"]["present"] = True
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(terminal, values, HEAD)
        connected = validate_event(self.rows["project_connected"])
        values = self._preconditions(connected)
        values[0]["value"] = {"absent": False}
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(connected, values, HEAD)
        acceptance = validate_event(self.rows["acceptance"])
        values = self._preconditions(acceptance, acceptance.confirmed_canonical_oid)
        next(item for item in values if item["name"] == "prior-generations")["value"]["derived_index"] = "bad"
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(acceptance, values, acceptance.confirmed_canonical_oid)
        revocation = validate_event(self.rows["revocation"])
        for subject_ids in (["bad"], [7, 7], [8]):
            values = self._preconditions(revocation, revocation.confirmed_canonical_oid)
            next(item for item in values if item["name"].startswith("coverage-state-"))["value"]["subject_ids"] = subject_ids
            with self.subTest(subject_ids=subject_ids), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(revocation, values, revocation.confirmed_canonical_oid)
        exemption = validate_event(self.rows["exemption_rule_withdrawn"])
        for provenance in ({"7": []}, {"7": ["bad"]}, {"7": [exemption.target["rule_event_id"], exemption.target["rule_event_id"]]}):
            values = self._preconditions(exemption)
            union = next(item for item in values if item["name"] == "current-exemption-union-07")
            union["value"]["provenance"] = provenance
            with self.subTest(provenance=provenance), self.assertRaises(PreconditionValidationError):
                event_module._validate_preconditions(exemption, values, HEAD)

    def test_reader_materialization_and_affected_classes(self):
        withdrawal = validate_event(self.rows["records_reader_withdrawn"])
        source_id = withdrawal.target["source_event_id"]
        for source_ids, state, expected in (([source_id], "current", ("reader_authority",)), ([], "current", ()), ([], "stale", ("reader_authority",))):
            values = self._preconditions(withdrawal, overrides={"reader-authority-state": {"project_id": withdrawal.project_id, "class_state": state, "source_event_ids": source_ids, "cursor_event_id": withdrawal.event_id}})
            observation = next(item for item in values if item["name"] == "reader-authority-state")
            observation["binding"]["derived_generation"] = withdrawal.event_id if state == "current" else self.rows["revocation"]["event_id"]
            self.assertEqual(required_side_artifacts(withdrawal, preconditions=values, expected_head=HEAD) == (), expected == ())
            if expected:
                self.assertEqual(required_side_artifacts(withdrawal, preconditions=values, expected_head=HEAD)[0].affected_classes, expected)
        materialized_row = copy.deepcopy(self.rows["records_reader_materialized"])
        materialized_row["payload"]["result"] = "withdraw"
        materialized_row["payload"]["membership_evidence"]["state"] = "not_member"
        from dracla.conformance import derive_automation_nonce, derive_event_identity
        materialized_row["operation_nonce"] = derive_automation_nonce(materialized_row["target"]["rule_event_id"], 7, "withdraw", None)
        identity = derive_event_identity(materialized_row["project_id"], materialized_row["operation_nonce"], materialized_row["actor"], materialized_row["type"], materialized_row["target"], materialized_row["payload"], materialized_row["confirmed_canonical_oid"])
        materialized_row.update(event_id=identity.event_id, idempotency_key=identity.idempotency_key, operation_sha256=identity.operation_sha256)
        event = validate_event(materialized_row)
        values = self._preconditions(event, overrides={"current-reader-authority": {"project_id": event.project_id, "class_state": "stale", "sources": [], "cursor_event_id": event.event_id}})
        with self.assertRaises(PreconditionValidationError):
            required_side_artifacts(event, preconditions=values, expected_head=HEAD)

    def test_cross_project_and_successor_relations(self):
        event = validate_event(self.rows["project_succeeded"])
        for case in self.corpus["cross_project_cases"]:
            values = self._preconditions(event)
            successor = next(item for item in values if item["name"] == "successor-project")["value"]
            if case["mutation"] == "wrong_backlink":
                successor["event"]["payload"]["successor_of"] = "other"
            elif case["mutation"] == "missing_backlink":
                successor["event"]["payload"].pop("successor_of")
            elif case["mutation"] == "wrong_project":
                successor["event"]["project_id"] = "other"
            elif case["mutation"] == "wrong_repository_set":
                successor["event"]["payload"]["repository_ids"] = {"records": 21, "coverage": 22, "control": 23}
            elif case["mutation"] == "inactive_agreement":
                successor["active_agreement"]["state"] = "inactive"
            accepted = True
            try:
                required_side_artifacts(event, preconditions=values, expected_head=HEAD)
            except PreconditionValidationError:
                accepted = False
            self.assertEqual(accepted, case["expect"] == "accept")
        values = self._preconditions(event)
        next(item for item in values if item["name"] == "successor-project")["value"]["event"]["payload"].pop("repository_ids")
        with self.assertRaises(PreconditionValidationError):
            required_side_artifacts(event, preconditions=values, expected_head=HEAD)

    def test_side_artifact_declarations_and_public_fail_closed(self):
        connected = validate_event(self.rows["project_connected"])
        self.assertEqual(
            required_side_artifacts(connected, preconditions=self._preconditions(connected), expected_head=HEAD),
            (
                SideArtifactRequirement("materialization_generations", "config/materialization-generations.enc.json", "event-determined", ("derived_index", "status_detail", "reader_authority")),
                SideArtifactRequirement("project_config", "config/project.enc.json", "event-determined"),
            ),
        )
        published = validate_event(self.rows["agreement_published"])
        declarations = required_side_artifacts(published, preconditions=self._preconditions(published), expected_head=HEAD)
        self.assertEqual({item.kind for item in declarations}, {"agreement_snapshot", "agreement_metadata"})
        self.assertEqual({item.path for item in declarations}, {published.payload["snapshot_content_path"], published.payload["snapshot_metadata_path"]})
        config = validate_event(self.rows["config_updated"])
        self.assertEqual(required_side_artifacts(config, preconditions=self._preconditions(config), expected_head=HEAD), (SideArtifactRequirement("project_config", "config/project.enc.json", "event-determined"),))
        retry = validate_event(self.rows["retry_requested"])
        self.assertEqual(required_side_artifacts(retry, preconditions=self._preconditions(retry), expected_head=HEAD), ())
        with self.assertRaises(EventValidationError):
            required_side_artifacts(object(), preconditions=[], expected_head=HEAD)

    def test_event_link_relations_are_closed(self):
        acceptance = validate_event(self.rows["acceptance"])
        active = next(item["value"] for item in self._preconditions(acceptance, acceptance.confirmed_canonical_oid) if item["name"] == "active-agreement")
        publication = active["publication"]
        replacements = (
            {**publication, "project_id": "other"},
            {**publication, "type": "wrong"},
            {**publication, "target": {}},
            {**publication, "payload": {}},
            {**publication, "payload": {**publication["payload"], "recipient": {}}},
            {**publication, "payload": {**publication["payload"], "ref": ""}},
            {**publication, "payload": {**publication["payload"], "content_commit_oid": "bad"}},
            {**publication, "payload": {**publication["payload"], "digest": "bad"}},
            {**publication, "payload": {**publication["payload"], "snapshot_sha256": "bad"}},
            {**publication, "payload": {**publication["payload"], "recipient": {"recipient_id": "other", "legal_name": "Other"}}},
        )
        for value in replacements:
            with self.assertRaises(EventValidationError):
                event_module._validate_link_fact(acceptance, "active-publication", value)

        activation = validate_event(self.rows["agreement_activated"])
        published = next(item["value"] for item in self._preconditions(activation) if item["name"] == "published-agreement")
        for value in ({**published, "event_id": "bad"}, {**published, "type": "wrong"}, {**published, "target": {}}, {**published, "payload": {}}):
            with self.assertRaises(EventValidationError):
                event_module._validate_link_fact(activation, "published-agreement", value)

        scope = validate_event(self.rows["enforcement_scope_activated"])
        request = next(item["value"] for item in self._preconditions(scope) if item["name"] == "scope-request")
        for value in ({**request, "event_id": "bad"}, {**request, "type": "wrong"}, {**request, "target": {}}, {**request, "payload": {}}, {**request, "payload": {**request["payload"], "prior_scope": "bad"}}, {**request, "payload": {**request["payload"], "desired_scope": []}}):
            with self.assertRaises(EventValidationError):
                event_module._validate_link_fact(scope, "scope-request", value)

        source = validate_event(self.rows["records_reader_withdrawn"])
        source_fact = next(item["value"] for item in self._preconditions(source) if item["name"] == "source-event")
        for value in ({**source_fact, "type": "exemption"}, {**source_fact, "event_id": self.rows["revocation"]["event_id"]}, {**source_fact, "target": {"subject": {"github_user_id": 8, "login_snapshot": "other"}}}, {**source_fact, "type": "records_reader_snapshot_authorized", "target": {"subjects": []}}):
            with self.assertRaises(EventValidationError):
                event_module._validate_link_fact(source, "source-event", value)
        event_module._validate_link_fact(source, "source-event", {**source_fact, "type": "records_reader_snapshot_authorized", "target": {"subjects": [source.target["subject"]]}})

        rule = validate_event(self.rows["records_reader_rule_withdrawn"])
        rule_fact = next(item["value"] for item in self._preconditions(rule) if item["name"] == "rule-event")
        for value in ({**rule_fact, "type": "exemption_rule_configured"}, {**rule_fact, "event_id": self.rows["revocation"]["event_id"]}, {**rule_fact, "target": {}}):
            with self.assertRaises(EventValidationError):
                event_module._validate_link_fact(rule, "rule-event", value)
        materialized = validate_event(self.rows["exemption_materialized"])
        materialized_rule = next(item["value"] for item in self._preconditions(materialized) if item["name"] == "rule-event")
        with self.assertRaises(EventValidationError):
            event_module._validate_link_fact(materialized, "rule-event", {**materialized_rule, "target": {"team": {}}})
        with self.assertRaises(EventValidationError):
            event_module._validate_link_fact(materialized, "rule-event", {**materialized_rule, "target": {"team": {"organization_id": 41, "team_id": 42, "slug_snapshot": "other"}}})
        event_module._validate_link_fact(source, "opaque-link", source_fact)

    def test_terminal_and_precondition_descriptor_boundaries(self):
        terminal = validate_event(self.rows["enforcement_scope_activated"])
        values = self._preconditions(terminal)
        observation = next(item for item in values if item["name"] == "scope-terminal-activation-absence")["value"]
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_terminal_observation({}, observation["path"])
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_terminal_observation({**observation, "path": "events/wrong.enc.json"}, observation["path"])
        connected = validate_event(self.rows["project_connected"])
        with self.assertRaises(PreconditionValidationError):
            required_side_artifacts(connected, preconditions=[], expected_head=HEAD)
        values = self._preconditions(connected)
        values[0]["path"] = "wrong/path"
        with self.assertRaises(PreconditionValidationError):
            event_module._validate_preconditions(connected, values, HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._registry_entries({}, ("one",), "registry")
