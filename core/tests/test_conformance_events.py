"""Revision-13 closed event model and identity contract tests."""

from __future__ import annotations

import base64
import copy
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    AuthorizationEvidence,
    CanonicalShaBinding,
    CrossProjectBinding,
    EVENT_TYPES,
    EventValidationError,
    EventsHeadBinding,
    GenerationBinding,
    PreconditionBinding,
    PreconditionRequirement,
    PreconditionValidationError,
    RegistryGenerationBinding,
    canonical_json,
    parse_event_jcs,
    required_preconditions,
    validate_authorizations,
    validate_event,
)
from dracla.conformance import events as event_module  # noqa: E402
from dracla.conformance.artifacts import resolve_artifact_identity, segment  # noqa: E402


VECTORS = Path(__file__).parent / "vectors" / "events-v1.json"
HEAD = "b" * 40


class TestEventModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.rows = {row["type"]: row for row in cls.corpus["events"]}

    def test_vector_covers_closed_registry_and_recomputes_every_identity(self):
        self.assertEqual(set(self.rows), EVENT_TYPES)
        self.assertEqual(len(self.rows), 27)
        for value in self.rows.values():
            with self.subTest(event_type=value["type"]):
                event = validate_event(value, expected_project_id=value["project_id"])
                self.assertEqual(event.to_dict(), value)
                self.assertEqual(event.canonical_bytes, canonical_json(value))
                parsed = parse_event_jcs(event.canonical_bytes, expected_path=event.path)
                self.assertEqual(parsed, event)


    def test_precondition_declaration_matrix_is_exact_for_every_event(self):
        expected = self.corpus["precondition_names"]
        self.assertEqual(set(expected), EVENT_TYPES)
        self.assertEqual(len(expected), 27)
        for value in self.rows.values():
            event = validate_event(value)
            expected_head = event.confirmed_canonical_oid or HEAD
            descriptors = required_preconditions(event, expected_head=expected_head)
            self.assertEqual(
                tuple(item.name for item in descriptors),
                tuple(expected[event.type]),
            )
            self.assertEqual(
                descriptors,
                required_preconditions(event, expected_head=expected_head),
            )
            for descriptor in descriptors:
                with self.subTest(event_type=event.type, name=descriptor.name):
                    self.assertEqual(descriptor.expected_head, expected_head)
                    self.assertIn(
                        descriptor.binding_mode,
                        {"events-head", "generation", "canonical-sha", "cross-project", "registry-generation"},
                    )
                    self.assertTrue(descriptor.artifact_kind)
                    self.assertTrue(descriptor.repository_role)
                    self.assertTrue(descriptor.branch)
                    self.assertTrue(descriptor.path or descriptor.artifact_kind == "canonical-project-state")
                    self.assertTrue(descriptor.relation)


    def test_precondition_descriptors_resolve_to_deterministic_artifact_paths(self):
        for value in self.rows.values():
            event = validate_event(value)
            expected_head = event.confirmed_canonical_oid or HEAD
            for descriptor in required_preconditions(event, expected_head=expected_head):
                with self.subTest(event_type=event.type, name=descriptor.name):
                    if descriptor.artifact_kind == "canonical-project-state":
                        self.assertEqual(
                            (descriptor.repository_role, descriptor.branch, descriptor.path),
                            ("records", "events", ""),
                        )
                        continue
                    if descriptor.artifact_kind in {"agreement-snapshot", "agreement-metadata"}:
                        self.assertEqual(
                            (descriptor.repository_role, descriptor.branch),
                            ("records", "events"),
                        )
                        suffix = ".md" if descriptor.artifact_kind == "agreement-snapshot" else ".meta.json"
                        self.assertEqual(
                            descriptor.path,
                            f"agreements/{segment(event.target['agreement_id'])}/{segment(event.target['version'])}{suffix}",
                        )
                        continue
                    if descriptor.binding_mode == "registry-generation":
                        self.assertEqual(
                            (descriptor.artifact_kind, descriptor.repository_role, descriptor.branch),
                            ("signed-registry-entry", "registry", "main"),
                        )
                        self.assertEqual(
                            descriptor.path,
                            "projects/oz410wISW72OZHBDpAJbKfZZqtUcSoDWJEpF-rzc0jU.json",
                        )
                    else:
                        identity = resolve_artifact_identity(
                            descriptor.repository_role,
                            descriptor.branch,
                            descriptor.path,
                        )
                        self.assertEqual(identity.artifact_kind, descriptor.artifact_kind)
                        self.assertEqual(identity.repository_role, descriptor.repository_role)
                        self.assertEqual(identity.branch, descriptor.branch)
                        self.assertEqual(identity.path, descriptor.path)

        owner = validate_event(self.rows["project_repository_owner_changed"])
        owner_descriptor = next(
            item for item in required_preconditions(owner, expected_head=HEAD)
            if item.name == "current-repository-owner"
        )
        self.assertEqual(
            owner_descriptor.path,
            "projects/oz410wISW72OZHBDpAJbKfZZqtUcSoDWJEpF-rzc0jU.json",
        )

        from dracla.conformance import derive_event_identity

        for project_id, expected_path in (
            (
                "project-1",
                "projects/oz410wISW72OZHBDpAJbKfZZqtUcSoDWJEpF-rzc0jU.json",
            ),
            (
                "../escape",
                "projects/G6c0PEfcRC3n3sQ6mV3rmntiI07MoW18b1l7UVW9hbE.json",
            ),
            (
                "项目",
                "projects/efMmvkQJ1R_mD07cA7IMS5TelS1ibhYWeQ57I4TwjwA.json",
            ),
        ):
            value = copy.deepcopy(self.rows["project_repository_owner_changed"])
            value["project_id"] = project_id
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
            variant = validate_event(value)
            descriptor = next(
                item for item in required_preconditions(variant, expected_head=HEAD)
                if item.name == "current-repository-owner"
            )
            self.assertEqual(descriptor.path, expected_path)

        revocation = validate_event(self.rows["revocation"])
        self.assertEqual(
            next(item for item in required_preconditions(revocation, expected_head=revocation.confirmed_canonical_oid) if item.name == "coverage-state-07").path,
            "users/07.enc.json",
        )
        reader_rule = validate_event(self.rows["records_reader_rule_configured"])
        reader_rule_descriptors = [
            item
            for item in required_preconditions(reader_rule, expected_head=HEAD)
            if item.name.startswith("active-reader-rules-")
        ]
        self.assertEqual(
            [item.name for item in reader_rule_descriptors],
            [f"active-reader-rules-{shard:02d}" for shard in range(32)],
        )
        self.assertEqual(
            [item.path for item in reader_rule_descriptors],
            [f"derived/reader-authority/{shard:02d}.enc.json" for shard in range(32)],
        )
        self.assertEqual(
            {item.relation for item in reader_rule_descriptors},
            {"active-continuous-reader-rules-are-current"},
        )
        exemption = validate_event(self.rows["exemption_rule_withdrawn"])
        self.assertEqual(
            next(item for item in required_preconditions(exemption, expected_head=HEAD) if item.name == "current-exemption-union-07").path,
            "derived/status-detail/07.enc.json",
        )
        exemption_rule = validate_event(self.rows["exemption_rule_configured"])
        derived_state = next(
            item for item in required_preconditions(exemption_rule, expected_head=HEAD)
            if item.name == "current-derived-state"
        )
        self.assertEqual(
            (derived_state.artifact_kind, derived_state.repository_role, derived_state.branch, derived_state.path, derived_state.binding_mode, derived_state.relation),
            ("derived-state", "records", "derived", "derived/state.enc.json", "generation", "standing-rules-and-installed-profile-are-current"),
        )
        reader = validate_event(self.rows["records_reader_withdrawn"])
        self.assertEqual(
            next(item for item in required_preconditions(reader, expected_head=HEAD) if item.name == "reader-authority-state").path,
            "derived/reader-authority/10.enc.json",
        )

        override = validate_event(self.rows["override_withdrawn"])
        grant = next(
            item for item in required_preconditions(override, expected_head=HEAD)
            if item.name == "override-grant"
        )
        self.assertEqual(grant.path, event_module.event_path(override.target["override_event_id"]))

        published = validate_event(self.rows["agreement_activated"])
        published_descriptor = next(
            item for item in required_preconditions(published, expected_head=HEAD)
            if item.name == "published-agreement"
        )
        self.assertEqual(published_descriptor.path, event_module.event_path(published.payload["published_event_id"]))

        terminal = validate_event(self.rows["enforcement_scope_activated"])
        terminal_descriptors = {
            item.name: item
            for item in required_preconditions(terminal, expected_head=HEAD)
            if item.name.startswith("scope-terminal-")
        }
        self.assertEqual(
            terminal_descriptors["scope-terminal-activation-absence"].path,
            "events/1y/gG/1ygGR5kYEjiYEAFqy-V_hXJrB_RvauGDtKoMAkQwdFk.enc.json",
        )
        self.assertEqual(
            terminal_descriptors["scope-terminal-abandonment-absence"].path,
            "events/JR/O1/JRO1_GbfulQ9Y5yznKx0W_ToGGA5a_SdoU5cjm5G4Eg.enc.json",
        )
        self.assertNotEqual(
            terminal_descriptors["scope-terminal-activation-absence"].path,
            terminal_descriptors["scope-terminal-abandonment-absence"].path,
        )

        published = validate_event(self.rows["agreement_published"])
        publication_descriptors = required_preconditions(published, expected_head=HEAD)
        self.assertEqual(
            tuple(item.name for item in publication_descriptors),
            ("project-lifecycle", "current-project-agreement", "publication-snapshot-absence", "publication-metadata-absence"),
        )
        project_agreement = publication_descriptors[1]
        self.assertEqual(
            (project_agreement.artifact_kind, project_agreement.repository_role, project_agreement.branch, project_agreement.path, project_agreement.binding_mode, project_agreement.relation),
            ("canonical-project-state", "records", "events", "", "events-head", "project-agreement-and-recipient-are-current"),
        )
        publication_snapshot_absence = publication_descriptors[2]
        self.assertEqual(
            (publication_snapshot_absence.artifact_kind, publication_snapshot_absence.repository_role, publication_snapshot_absence.branch, publication_snapshot_absence.path, publication_snapshot_absence.binding_mode, publication_snapshot_absence.relation),
            ("agreement-snapshot", "records", "events", f"agreements/{segment(published.target['agreement_id'])}/{segment(published.target['version'])}.md", "events-head", "agreement-snapshot-is-absent"),
        )
        publication_metadata_absence = publication_descriptors[3]
        self.assertEqual(
            (publication_metadata_absence.artifact_kind, publication_metadata_absence.repository_role, publication_metadata_absence.branch, publication_metadata_absence.path, publication_metadata_absence.binding_mode, publication_metadata_absence.relation),
            ("agreement-metadata", "records", "events", f"agreements/{segment(published.target['agreement_id'])}/{segment(published.target['version'])}.meta.json", "events-head", "agreement-metadata-is-absent"),
        )


    def test_acceptance_correction_declares_existing_basis_and_link(self):
        from dracla.conformance import derive_event_identity

        correction = copy.deepcopy(self.rows["acceptance"])
        correction["payload"]["supersedes"] = correction["event_id"]
        identity = derive_event_identity(
            correction["project_id"],
            correction["operation_nonce"],
            correction["actor"],
            correction["type"],
            correction["target"],
            correction["payload"],
            correction["confirmed_canonical_oid"],
        )
        correction.update(
            event_id=identity.event_id,
            idempotency_key=identity.idempotency_key,
            operation_sha256=identity.operation_sha256,
        )
        event = validate_event(correction)
        descriptors = required_preconditions(event, expected_head=event.confirmed_canonical_oid)
        self.assertEqual(
            tuple(item.name for item in descriptors),
            (
                "project-lifecycle",
                "active-agreement",
                "current-configuration",
                "superseded-acceptance",
                "current-acceptance-basis",
                "prior-generations",
            ),
        )
        superseded = descriptors[3]
        self.assertEqual(
            (superseded.artifact_kind, superseded.repository_role, superseded.branch, superseded.path, superseded.binding_mode, superseded.relation),
            ("canonical-event", "records", "events", event_module.event_path(correction["payload"]["supersedes"]), "events-head", "superseded-acceptance-exists-and-matches-correction"),
        )
        basis = descriptors[4]
        self.assertEqual(
            (basis.artifact_kind, basis.repository_role, basis.branch, basis.path, basis.binding_mode, basis.relation),
            ("status-detail", "records", "derived", "derived/status-detail/07.enc.json", "generation", "current-acceptance-basis-matches-superseded-acceptance"),
        )


    def test_precondition_models_are_frozen_serializable_and_closed(self):
        canonical_generation = self.rows["project_connected"]["event_id"]
        derived_generation = self.rows["acceptance"]["event_id"]
        bindings = (
            (EventsHeadBinding(HEAD), "events-head"),
            (GenerationBinding(HEAD, canonical_generation, derived_generation), "generation"),
            (CanonicalShaBinding("a" * 40, "b" * 40), "canonical-sha"),
            (CrossProjectBinding("successor", HEAD, (11, 12, 13)), "cross-project"),
            (RegistryGenerationBinding("c" * 40, 3), "registry-generation"),
        )
        for binding, mode in bindings:
            with self.subTest(mode=mode):
                self.assertIsInstance(binding, PreconditionBinding)
                self.assertEqual(binding.mode, mode)
                serialized = asdict(binding)
                self.assertIsInstance(serialized, dict)
                with self.assertRaises(FrozenInstanceError):
                    setattr(binding, next(iter(serialized)), "changed")

        malformed = (
            lambda: EventsHeadBinding("not-an-oid"),
            lambda: GenerationBinding(HEAD, "not-an-event-id", derived_generation),
            lambda: CanonicalShaBinding("a" * 40, "sha256:" + "b" * 64),
            lambda: CrossProjectBinding("successor", "not-an-oid", (11, 12, 13)),
            lambda: CrossProjectBinding("successor", HEAD, []),
            lambda: CrossProjectBinding("successor", HEAD, (11, 11)),
            lambda: RegistryGenerationBinding("c" * 40, -1),
        )
        for make_binding in malformed:
            with self.assertRaises(PreconditionValidationError):
                make_binding()

        requirement = PreconditionRequirement(
            "project-lifecycle",
            "coverage-source",
            "coverage",
            "coverage",
            "source.enc.json",
            "canonical-sha",
            "project-lifecycle-policy",
            HEAD,
        )
        self.assertEqual(
            asdict(requirement),
            {
                "name": "project-lifecycle",
                "artifact_kind": "coverage-source",
                "repository_role": "coverage",
                "branch": "coverage",
                "path": "source.enc.json",
                "binding_mode": "canonical-sha",
                "relation": "project-lifecycle-policy",
                "expected_head": HEAD,
            },
        )
        with self.assertRaises(FrozenInstanceError):
            requirement.name = "other"


    def test_precondition_declaration_boundaries_reject_invalid_inputs(self):
        event = validate_event(self.rows["config_updated"])
        with self.assertRaises(EventValidationError):
            required_preconditions(object(), expected_head=HEAD)
        with self.assertRaises(PreconditionValidationError):
            event_module._requirement(
                "bad", kind="kind", role="records", branch="events", path="path",
                binding="unsupported", relation="relation", expected_head=HEAD,
            )
        with self.assertRaises(PreconditionValidationError):
            event_module._subject_shards(event, relation="unsupported")
        for invalid_head in (None, "A" * 40, 7):
            with self.subTest(invalid_head=invalid_head), self.assertRaises(EventValidationError):
                required_preconditions(event, expected_head=invalid_head)

        for event_type in ("acceptance", "revocation"):
            contributor_event = validate_event(self.rows[event_type])
            descriptors = required_preconditions(
                contributor_event,
                expected_head=contributor_event.confirmed_canonical_oid,
            )
            self.assertTrue(descriptors)
            self.assertTrue(
                all(
                    item.expected_head == contributor_event.confirmed_canonical_oid
                    for item in descriptors
                )
            )
            with self.subTest(event_type=event_type), self.assertRaises(PreconditionValidationError):
                required_preconditions(contributor_event, expected_head=HEAD)


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
