"""Fixed source-test history construction shared by replay tests and generator.

These builders only create canonical inputs. They do not fold or materialize.
"""
import copy
from dracla.conformance import (
    CanonicalEventRecord, base64url_encode, derive_event_identity,
    derive_automation_nonce, derive_github_retry_nonce, derive_scope_terminal_nonce,
    validate_event,
)

BASE = "b" * 40


class History:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)

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

    def scope_terminal_event(self, event_type, request, **changes):
        value = copy.deepcopy(self.rows[event_type])
        value["target"]["change_id"] = request.target["change_id"]
        value["payload"]["request_event_id"] = request.event_id
        if event_type == "enforcement_scope_activated":
            value["payload"]["desired_scope"] = copy.deepcopy(
                request.to_dict()["payload"]["desired_scope"]
            )
        value["authorizations"] = [item.to_dict() for item in request.authorizations]
        for path, replacement in changes.items():
            target = value
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = copy.deepcopy(replacement)
        value["operation_nonce"] = derive_scope_terminal_nonce(request.event_id, event_type)
        return self.validate(value)

    def scope_request_event(
        self,
        nonce,
        operation,
        prior_scope,
        desired_scope,
        prior_generation,
        change_id,
        resource_id,
    ):
        value = copy.deepcopy(self.rows["enforcement_scope_requested"])
        value["operation_nonce"] = base64url_encode(int(nonce).to_bytes(16, "big"))
        value["target"]["change_id"] = change_id
        value["payload"]["prior_scope"] = copy.deepcopy(prior_scope)
        value["payload"]["desired_scope"] = copy.deepcopy(desired_scope)
        value["payload"]["prior_registry_generation"] = prior_generation
        kind = "organization" if "_organization_" in operation else "repository"
        authorization = value["authorizations"][0]
        authorization["operation"] = operation
        authorization["resource_kind"] = kind
        authorization["resource_id"] = resource_id
        authorization["required_authority"] = (
            "organization_owner" if kind == "organization" else "contributing_repository_admin"
        )
        return self.validate(value)

    def retry_event(self, **changes):
        value = copy.deepcopy(self.rows["retry_requested"])
        for path, replacement in changes.items():
            target = value
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = copy.deepcopy(replacement)
        value["operation_nonce"] = derive_github_retry_nonce(
            value["target"]["repository_id"],
            value["target"]["check_kind"],
            value["target"]["check_identity"],
            value["payload"]["github_delivery_id"],
        )
        return self.validate(value)

    def exemption_event(self, nonce, source_kind="bot", **changes):
        value = copy.deepcopy(self.rows["exemption"])
        value["operation_nonce"] = base64url_encode(int(nonce).to_bytes(16, "big"))
        value["payload"]["source_kind"] = source_kind
        authorization = value["authorizations"][0]
        authorization["operation"] = f"exemption_{source_kind}_add"
        if source_kind == "individual":
            value["payload"]["basis"] = "contract"
            value["payload"]["instrument_ref"] = "ticket-individual"
        for path, replacement in changes.items():
            target = value
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = copy.deepcopy(replacement)
        return self.validate(value)

    def exemption_materialization_event(
        self,
        rule,
        result,
        prior_materialization_event_id,
        **changes,
    ):
        value = copy.deepcopy(self.rows["exemption_materialized"])
        value["target"]["rule_event_id"] = rule.event_id
        value["payload"]["team"] = copy.deepcopy(rule.to_dict()["target"]["team"])
        value["payload"]["result"] = result
        value["payload"]["membership_evidence"]["state"] = (
            "member" if result == "add" else "not_member"
        )
        value["payload"]["prior_materialization_event_id"] = prior_materialization_event_id
        for path, replacement in changes.items():
            target = value
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = copy.deepcopy(replacement)
        value["operation_nonce"] = derive_automation_nonce(
            value["target"]["rule_event_id"],
            value["target"]["subject"]["github_user_id"],
            value["payload"]["result"],
            value["payload"]["prior_materialization_event_id"],
        )
        return self.validate(value)

    def reader_materialization_event(
        self,
        rule,
        result,
        prior_materialization_event_id,
        **changes,
    ):
        value = copy.deepcopy(self.rows["records_reader_materialized"])
        value["target"]["rule_event_id"] = rule.event_id
        value["payload"]["team"] = copy.deepcopy(rule.to_dict()["target"]["team"])
        value["payload"]["result"] = result
        value["payload"]["membership_evidence"]["state"] = (
            "member" if result == "add" else "not_member"
        )
        value["payload"]["prior_materialization_event_id"] = prior_materialization_event_id
        for path, replacement in changes.items():
            target = value
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = copy.deepcopy(replacement)
        value["operation_nonce"] = derive_automation_nonce(
            value["target"]["rule_event_id"],
            value["target"]["subject"]["github_user_id"],
            value["payload"]["result"],
            value["payload"]["prior_materialization_event_id"],
        )
        return self.validate(value)

    def successor_owner_transfer_event(self, prior, nonce, generation, registry_commit_oid):
        value = copy.deepcopy(self.rows["project_repository_owner_changed"])
        value["operation_nonce"] = base64url_encode(int(nonce).to_bytes(16, "big"))
        value["target"]["prior_repository_owner"] = copy.deepcopy(
            dict(prior.payload["new_repository_owner"])
        )
        value["payload"]["new_repository_owner"]["github_account_id"] = 30
        value["payload"]["project_slug"] = prior.payload["project_slug"]
        value["payload"]["repository_ids"] = dict(prior.payload["repository_ids"])
        value["payload"]["registry_generation"] = generation
        value["payload"]["registry_commit_oid"] = registry_commit_oid
        repository_ids = value["payload"]["repository_ids"]
        for item in value["authorizations"]:
            if item["operation"].endswith("records_repository"):
                item["resource_id"] = repository_ids["records"]
            elif item["operation"].endswith("coverage_repository"):
                item["resource_id"] = repository_ids["coverage"]
            elif item["operation"].endswith("control_repository"):
                item["resource_id"] = repository_ids["control"]
            elif item["operation"].endswith("_owner"):
                item["resource_id"] = value["payload"]["new_repository_owner"]["github_account_id"]
        return self.validate(value)

    def vector_records(self, case_name):
        records = []
        if case_name == "empty":
            return records
        self.append(records, "project_connected", 100)
        if case_name == "connection":
            return records
        if case_name == "config-and-keyring":
            self.append(
                records,
                "config_updated",
                101,
                **{
                    "payload.project_configuration.retention_statement": (
                        "Retained for the project audit."
                    )
                },
            )
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

