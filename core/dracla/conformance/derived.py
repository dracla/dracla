"""Private-derived reference plaintext and read contracts (M1 LLD §M1-11).

No function reads GitHub, writes a repository, holds a data key, or infers live
operation state. Envelope authentication is the caller's M1-2 responsibility;
assembly binds the exact supplied envelope bytes, metadata and generations.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from . import events as _events
from . import coverage as _coverage
from . import envelope as _envelope
from .artifacts import resolve_artifact_identity
from .canonical import canonical_json, parse_canonical_json
from .encoding import base64url_decode
from .operations import DecisionFence, InFlightMarker, encode_decision_fence, encode_inflight_marker
from .release_profile import DERIVED_CLASSES, ReleaseProfile, ReleaseProfileError
from .replay import ReplayState, apply_event, initial_replay_state

_PREFIXES = dict(zip(DERIVED_CLASSES, ("index", "status-detail", "reader-authority")))
_PATHS = {name: tuple(f"derived/{prefix}/{i:02d}.enc.json" for i in range(32))
          for name, prefix in _PREFIXES.items()}
_SHARDS = tuple(path for paths in _PATHS.values() for path in paths)
_STATE = "derived/state.enc.json"
_FACTS = ("version", "accepted_at", "revoked_at", "basis")


class DerivedError(ValueError):
    """Private plaintext, source context or complete publication is invalid."""


class DerivedClassOverflow(DerivedError):
    """Only the named private class is unavailable; canonical/coverage truth survives."""

    def __init__(self, derived_class: str) -> None:
        self.derived_class = derived_class
        super().__init__(f"private derived class exceeds its profile: {derived_class}")


def _exact(value: Any, keys: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys):
        raise DerivedError("derived object has missing or unknown members")
    return value


def _scalar(validator: Any, value: Any) -> Any:
    try:
        return validator(value, "derived")
    except (ValueError, TypeError) as error:
        raise DerivedError("invalid derived scalar") from error


def _model(validator: Any, value: Any) -> Any:
    return _scalar(lambda item, _label: validator(item), value)


def _copy(value: Any) -> Any:
    try:
        return parse_canonical_json(canonical_json(value))
    except (ValueError, TypeError) as error:
        raise DerivedError("derived value must be canonical JSON") from error


def _profile(profile: ReleaseProfile) -> None:
    if type(profile) is not ReleaseProfile:
        raise DerivedError("a validated installed release profile is required")


def _count(value: Any) -> None:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise DerivedError("derived counter must be a nonnegative safe integer")


def _user(key: Any) -> int:
    try:
        return _coverage._id_key(key)
    except (ValueError, TypeError) as error:
        raise DerivedError("invalid derived subject key") from error


def reader_authority_shard(source_id: str) -> int:
    """First five bits of SHA-256 over the canonical source-event-ID string."""
    _scalar(_events._event_id, source_id)
    return hashlib.sha256(source_id.encode("utf-8")).digest()[0] >> 3


@dataclass(frozen=True, slots=True, init=False)
class CoverageReadContext:
    """The four authenticated coverage files needed by a selected data read."""

    project_id: str
    _files: Any

    def __init__(self, project_id: str, files: dict[str, Any]) -> None:
        _scalar(_events._string, project_id)
        files = _copy(files)
        _exact(files, ("source.enc.json", "agreements/active.enc.json",
                       "inflight.enc.json", "decision-fence.enc.json"))
        try:
            source = _coverage._exact(files["source.enc.json"],
                                      ("canonical_sha", "built_at", "dracla_version",
                                       "project_state", "successor_project_id"))
            _coverage._scalar(_events._oid, source["canonical_sha"])
            _coverage._scalar(_events._timestamp, source["built_at"])
            _coverage._scalar(_events._string, source["dracla_version"])
            if source["project_state"] == "active":
                if source["successor_project_id"] is not None:
                    raise DerivedError("active coverage source cannot name a successor")
            elif source["project_state"] == "succeeded":
                _coverage._scalar(_events._string, source["successor_project_id"])
            else:
                raise DerivedError("unknown or unconnected coverage lifecycle")
            _coverage._active(files["agreements/active.enc.json"])
            _coverage._operation_pair(files["inflight.enc.json"], files["decision-fence.enc.json"])
        except _coverage.CoverageError as error:
            raise DerivedError("coverage read context is invalid") from error
        object.__setattr__(self, "project_id", project_id)
        object.__setattr__(self, "_files", _events._freeze(files))

    def to_dict(self) -> dict[str, Any]:
        return _events._thaw(self._files)

    def validate(self, *, expected_project_id: str, expected_canonical_oid: str) -> None:
        _scalar(_events._string, expected_project_id)
        _scalar(_events._oid, expected_canonical_oid)
        if self.project_id != expected_project_id:
            raise DerivedError("coverage read project context does not match")
        files = self.to_dict()
        if files["source.enc.json"]["canonical_sha"] != expected_canonical_oid:
            raise DerivedError("coverage source does not match the selected read head")
        if files["source.enc.json"]["successor_project_id"] == expected_project_id:
            raise DerivedError("project cannot succeed itself")


def reader_source_for_subject(plaintext: DerivedPlaintext | DerivedReadProjection, source_id: str,
                              subject: int) -> dict[str, Any]:
    """Project a stored membership's narrow source identity after caller freshness checks."""
    if type(plaintext) not in {DerivedPlaintext, DerivedReadProjection}:
        raise DerivedError("reader lookup requires validated private plaintext")
    if type(plaintext) is DerivedReadProjection:
        if plaintext.selected_class != "reader_authority":
            raise DerivedError("reader lookup requires a selected reader-authority class")
        files = plaintext.selected_files()
    else:
        files = plaintext._files
    _scalar(_events._event_id, source_id)
    _scalar(_events._positive, subject)
    path = _PATHS["reader_authority"][reader_authority_shard(source_id)]
    shard = files.get(path)
    if shard is None:
        raise DerivedError("selected reader source shard is not present")
    source = shard.get(source_id)
    if source is None or str(subject) not in source["subjects"]:
        raise DerivedError("subject is not a member of the named reader source")
    team = source["team"] if source["kind"] == "continuous_team" else None
    return {"source_id": source_id, "kind": source["kind"],
            "organization_id": team["organization_id"] if team else None,
            "team_id": team["team_id"] if team else None}


def validate_project_configuration(value: dict[str, Any]) -> None:
    _model(_events._parse_configuration, value)


def validate_materialization_generations(value: dict[str, Any]) -> None:
    _exact(value, ("generations_version", *DERIVED_CLASSES))
    if type(value["generations_version"]) is not int or value["generations_version"] != 1:
        raise DerivedError("unsupported materialization generations")
    for name in DERIVED_CLASSES:
        _scalar(_events._event_id, value[name])


def _facts(value: Any) -> None:
    _exact(value, _FACTS)
    basis = _exact(value["basis"], ("event_id", "kind"))
    kind = basis["kind"]
    if type(kind) is not str or kind not in {"acceptance", "revocation", "none", "unresolved"}:
        raise DerivedError("unknown signature basis")
    if kind == "none":
        if any(value[name] is not None for name in _FACTS[:-1]) or basis["event_id"] is not None:
            raise DerivedError("absent signature basis must carry explicit null facts")
        return
    _scalar(_events._event_id, basis["event_id"])
    if kind == "acceptance":
        _scalar(_events._string, value["version"])
        _scalar(_events._timestamp, value["accepted_at"])
        if value["revoked_at"] is not None:
            raise DerivedError("acceptance cannot retain a revocation timestamp")
    elif kind == "revocation":
        if value["version"] is not None or value["accepted_at"] is not None:
            raise DerivedError("revocation clears acceptance facts")
        _scalar(_events._timestamp, value["revoked_at"])
    elif any(value[name] is not None for name in _FACTS[:-1]):
        raise DerivedError("unresolved basis cannot claim signature facts")


def _login(row: dict[str, Any]) -> None:
    login, observed = row["login_snapshot"], row["login_as_of"]
    if (login is None) != (observed is None):
        raise DerivedError("login snapshot and observation must appear together")
    if login is not None:
        _scalar(_events._string, login)
        _scalar(_events._timestamp, observed)


def _source(value: Any) -> None:
    _exact(value, ("source_kind", "team", "basis", "instrument_ref", "rule_event_id", "sequence"))
    kind = value["source_kind"]
    if type(kind) is not str or kind not in {"bot", "individual", "snapshot", "continuous_team"}:
        raise DerivedError("unsupported exemption source kind")
    _count(value["sequence"])
    if kind in {"snapshot", "continuous_team"}:
        _model(_events._parse_team, value["team"])
    elif value["team"] is not None:
        raise DerivedError("direct source cannot carry a team")
    for name in ("basis", "instrument_ref"):
        if kind != "bot" or value[name] is not None:
            _scalar(_events._string, value[name])
    if kind == "continuous_team":
        _scalar(_events._event_id, value["rule_event_id"])
    elif value["rule_event_id"] is not None:
        raise DerivedError("non-continuous source cannot name a rule")


def _subject(row: Any, *, detail: bool) -> None:
    fields = ("login_snapshot", "login_as_of", "agreements")
    _exact(row, (*fields, "exemption_sources", "exemption_sequence_next", "materialization_cursor")
           if detail else (*fields, "exempt"))
    _login(row)
    agreements = row["agreements"]
    if type(agreements) is not dict:
        raise DerivedError("agreements must be an object")
    for agreement, facts in agreements.items():
        _scalar(_events._string, agreement)
        _facts(facts)
    if not detail:
        if type(row["exempt"]) is not bool:
            raise DerivedError("index exemption flag must be boolean")
        return
    _count(row["exemption_sequence_next"])
    sources, cursor = row["exemption_sources"], row["materialization_cursor"]
    if type(sources) is not dict or type(cursor) is not dict:
        raise DerivedError("exemption provenance and cursors must be objects")
    sequences = []
    for source_id, source in sources.items():
        _scalar(_events._event_id, source_id)
        _source(source)
        if source["source_kind"] == "continuous_team" and source["rule_event_id"] != source_id:
            raise DerivedError("continuous exemption key must identify its rule")
        if source["sequence"] >= row["exemption_sequence_next"]:
            raise DerivedError("exemption sequence must precede the next counter")
        sequences.append(source["sequence"])
    if len(set(sequences)) != len(sequences):
        raise DerivedError("active exemption sequences must be unique")
    for rule, event in cursor.items():
        _scalar(_events._event_id, rule)
        _scalar(_events._event_id, event)
        if event == rule:
            raise DerivedError("exemption cursor must name a materialization, not its source rule")


def _reader(source_id: str, value: Any, profile: ReleaseProfile) -> None:
    _scalar(_events._event_id, source_id)
    _exact(value, ("kind", "team", "materialization_cursor", "subjects"))
    kind = value["kind"]
    if type(kind) is not str or kind not in {"individual", "snapshot", "continuous_team"}:
        raise DerivedError("unsupported reader source")
    if kind == "individual":
        if value["team"] is not None:
            raise DerivedError("individual source team must be explicit null")
    else:
        _model(_events._parse_team, value["team"])
    members, cursor = value["subjects"], value["materialization_cursor"]
    if type(members) is not dict or type(cursor) is not dict:
        raise DerivedError("reader membership and cursors must be objects")
    if kind == "individual" and len(members) != 1:
        raise DerivedError("individual reader source must contain one subject")
    if kind == "snapshot" and not members:
        raise DerivedError("empty snapshot source must be removed")
    if kind != "continuous_team" and cursor:
        raise DerivedError("only continuous reader sources have cursors")
    profile.check("max_reader_source_members", len(members))
    profile.check("max_reader_cursor_entries", len(cursor))
    for key, member in members.items():
        _user(key)
        _exact(member, ("added_event_id",))
        _scalar(_events._event_id, member["added_event_id"])
        if kind != "continuous_team" and member["added_event_id"] != source_id:
            raise DerivedError("direct reader membership must name its source event")
        if kind == "continuous_team" and key not in cursor:
            raise DerivedError("continuous membership lacks its retained cursor")
        if kind == "continuous_team" and (cursor[key] != member["added_event_id"] or member["added_event_id"] == source_id):
            raise DerivedError("active continuous membership must name its latest materialization")
    for key, event in cursor.items():
        _user(key)
        _scalar(_events._event_id, event)
        if event == source_id:
            raise DerivedError("reader cursor must name a materialization, not its source rule")


def _validate_standing_rules(rules: Any, profile: ReleaseProfile | None = None) -> None:
    if type(rules) is not dict:
        raise DerivedError("standing rules must be an object")
    if profile is not None:
        profile.check("max_continuous_exemption_rules", len(rules))
    for rule, value in rules.items():
        _scalar(_events._event_id, rule)
        _exact(value, ("team", "basis", "instrument_ref"))
        _model(_events._parse_team, value["team"])
        for key in ("basis", "instrument_ref"):
            _scalar(_events._string, value[key])


def _validate_class_shards(files: dict[str, Any], *, derived_class: str,
                           standing_rules: dict[str, Any], profile: ReleaseProfile) -> None:
    """Validate one class's supplied shards and its class-local count invariants."""
    paths = _PATHS[derived_class]
    if type(files) is not dict or not files or not set(files) <= set(paths):
        raise DerivedError("selected shard set is invalid")
    reader_rules = 0
    for path in files:
        number = paths.index(path)
        values = files[path]
        if type(values) is not dict:
            raise DerivedError("shard must be an object")
        for key, row in values.items():
            if derived_class == "reader_authority":
                if reader_authority_shard(key) != number:
                    raise DerivedError("reader source is in the wrong shard")
                _reader(key, row, profile)
                reader_rules += row["kind"] == "continuous_team"
            else:
                if _user(key) % 32 != number:
                    raise DerivedError("subject is in the wrong shard")
                _subject(row, detail=derived_class == "status_detail")
                if derived_class == "status_detail":
                    if not set(row["materialization_cursor"]) <= set(standing_rules):
                        raise DerivedError("exemption cursor names a retired rule")
                    for source in row["exemption_sources"].values():
                        if source["source_kind"] == "continuous_team" and source["rule_event_id"] not in standing_rules:
                            raise DerivedError("exemption source lacks its standing rule")
                        if source["source_kind"] == "continuous_team" and source["rule_event_id"] not in row["materialization_cursor"]:
                            raise DerivedError("continuous exemption lacks its retained cursor")
                        if source["source_kind"] == "continuous_team":
                            rule = standing_rules[source["rule_event_id"]]
                            if any(source[field] != rule[field] for field in ("team", "basis", "instrument_ref")):
                                raise DerivedError("continuous exemption disagrees with its standing rule")
    if derived_class == "reader_authority":
        profile.check("max_continuous_reader_rules", reader_rules)


def _validate_shards(files: Any, rules: Any, profile: ReleaseProfile) -> None:
    _profile(profile)
    _exact(files, _SHARDS)
    _validate_standing_rules(rules, profile)
    for name, paths in _PATHS.items():
        _validate_class_shards({path: files[path] for path in paths}, derived_class=name, standing_rules=rules,
                               profile=profile)
    for index_path, detail_path in zip(_PATHS["derived_index"], _PATHS["status_detail"]):
        index, detail = files[index_path], files[detail_path]
        if set(index) != set(detail):
            raise DerivedError("index and status detail subjects disagree")
        for key, row in detail.items():
            projected = {name: row[name] for name in ("login_snapshot", "login_as_of", "agreements")}
            projected["exempt"] = bool(row["exemption_sources"])
            if index[key] != projected:
                raise DerivedError("index and status detail facts disagree")


@dataclass(frozen=True, slots=True, init=False)
class DerivedPlaintext:
    project_id: str
    canonical_oid: str
    _files: Any
    _configuration: Any
    _rules: Any

    def __init__(self, project_id: str, canonical_oid: str, *, files: dict[str, Any],
                 configuration: dict[str, Any],
                 standing_rules: dict[str, Any], profile: ReleaseProfile) -> None:
        _scalar(_events._string, project_id)
        _scalar(_events._oid, canonical_oid)
        files, configuration = _copy(files), _copy(configuration)
        standing_rules = _copy(standing_rules)
        validate_project_configuration(configuration)
        _validate_shards(files, standing_rules, profile)
        for name, value in (("project_id", project_id), ("canonical_oid", canonical_oid),
                            ("_files", _events._freeze(files)),
                            ("_configuration", _events._freeze(configuration)),
                            ("_rules", _events._freeze(standing_rules))):
            object.__setattr__(self, name, value)

    def to_dict(self) -> dict[str, Any]:
        return {"files": _events._thaw(self._files),
                "configuration": _events._thaw(self._configuration),
                "standing_rules": _events._thaw(self._rules)}

    def plaintext_files(self) -> dict[str, bytes]:
        return {path: canonical_json(_events._thaw(value)) for path, value in self._files.items()}


def _empty_facts(kind: str = "none", event_id: str | None = None) -> dict[str, Any]:
    return {"version": None, "accepted_at": None, "revoked_at": None,
            "basis": {"kind": kind, "event_id": event_id}}


def _semantic_files(state: ReplayState) -> tuple[dict[str, Any], dict[str, Any]]:
    files: dict[str, Any] = {path: {} for path in _SHARDS}
    rules = {key: {"team": _events._thaw(rule.team), "basis": rule.basis,
                   "instrument_ref": rule.instrument_ref}
             for key, rule in state.exemption_rules.items() if rule.active}

    def row(subject: int) -> dict[str, Any]:
        _scalar(_events._positive, subject)
        return files[_PATHS["status_detail"][subject % 32]].setdefault(str(subject), {
            "login_snapshot": None, "login_as_of": None, "agreements": {},
            "exemption_sources": {}, "exemption_sequence_next": state.exemption_sequence_next.get(subject, 0),
            "materialization_cursor": {rule.event_id: rule.materialization_cursors[subject]
                                       for rule in state.exemption_rules.values()
                                       if rule.active and subject in rule.materialization_cursors}})

    for key, decision in state.tuple_decisions.items():
        if key != decision.tuple_key or decision.project_id != state.project_id or state.recipient is None or decision.recipient_id != state.recipient["recipient_id"]:
            raise DerivedError("signature tuple does not belong to this project/recipient")
        record = state.event_records.get(decision.event_id)
        if record is None or record.event.type != ("acceptance" if decision.is_covered else "revocation"):
            raise DerivedError("signature basis lacks its canonical event")
        facts = _empty_facts("acceptance" if decision.is_covered else "revocation", decision.event_id)
        if decision.is_covered:
            facts.update(version=decision.version, accepted_at=record.event.recorded_at)
        else:
            facts["revoked_at"] = record.event.recorded_at
        row(decision.github_user_id)["agreements"][decision.agreement_id] = facts
    for item in state.unresolved:
        if type(item) is not tuple or len(item) != 2 or type(item[0]) is not tuple or len(item[0]) != 2:
            raise DerivedError("unresolved replay identity is malformed")
        (subject, agreement), event_id = item
        _scalar(_events._event_id, event_id)
        _scalar(_events._string, agreement)
        row(subject)["agreements"][agreement] = _empty_facts("unresolved", event_id)
    for source in state.exemption_source_records.values():
        row(source.github_user_id)["exemption_sources"][source.source_event_id] = {
            key: _events._thaw(getattr(source, key))
            for key in ("source_kind", "team", "basis", "instrument_ref", "rule_event_id", "sequence")}
    # Empty source unions still retain monotone counters and active-rule cursors.
    for subject in state.exemption_sequence_next:
        row(subject)
    for rule in state.exemption_rules.values():
        for subject in rule.materialization_cursors:
            row(subject)
    for key, source in state.reader_source_records.items():
        if key != source.source_event_id:
            raise DerivedError("reader source key disagrees with its event")
        files[_PATHS["reader_authority"][reader_authority_shard(key)]][key] = {
            "kind": source.kind, "team": _events._thaw(source.team),
            "materialization_cursor": {str(k): v for k, v in source.materialization_cursors.items()},
            "subjects": {str(k): {"added_event_id": v} for k, v in source.subjects.items()}}
    _project_index(files)
    return files, rules


def _project_index(files: dict[str, Any]) -> None:
    for index_path, detail_path in zip(_PATHS["derived_index"], _PATHS["status_detail"]):
        files[index_path] = {key: {"login_snapshot": row["login_snapshot"],
                                   "login_as_of": row["login_as_of"],
                                   "agreements": row["agreements"],
                                   "exempt": bool(row["exemption_sources"])}
                             for key, row in files[detail_path].items()}


def _ancestry(state: ReplayState) -> list[Any]:
    by_commit = {record.commit_oid: record for record in state.event_records.values()}
    if len(by_commit) != len(state.event_records):
        raise DerivedError("canonical records repeat a commit")
    records, head = [], state.current_head_oid
    while head != state.base_commit_oid:
        record = by_commit.pop(head, None)
        if record is None:
            raise DerivedError("canonical records do not form the complete ancestry")
        records.append(record)
        head = record.parent_oid
    if by_commit:
        raise DerivedError("canonical records contain non-ancestral events")
    return list(reversed(records))


def _event_logins(event: Any) -> dict[str, tuple[str, str]]:
    values = []
    if event.actor["kind"] == "github":
        values.append(event.actor)
    for container in (event.target, event.payload):
        if "subject" in container:
            values.append(container["subject"])
        if "subjects" in container:
            values.extend(container["subjects"])
    return {str(item["github_user_id"]): (item["login_snapshot"], event.recorded_at)
            for item in values if "github_user_id" in item and "login_snapshot" in item}


def materialize_derived(state: ReplayState, *, profile: ReleaseProfile) -> DerivedPlaintext:
    """Reference facts and row-local ancestry logins, independent of live state.

    The assembler receives authenticated canonical generations explicitly;
    observation-dependent writer preconditions are not reconstructed here.
    """
    if type(state) is not ReplayState or state.project_state == "unconnected":
        raise DerivedError("derived materialization requires a connected replay state")
    _profile(profile)
    records = _ancestry(state)
    if not records:
        raise DerivedError("derived generations require the canonical connection event")
    current = initial_replay_state(state.project_id, state.base_commit_oid)
    previous = {path: {} for path in _SHARDS}
    logins: dict[str, tuple[str, str]] = {}
    for record in records:
        current = apply_event(current, record)
        files, rules = _semantic_files(current)
        observations = _event_logins(record.event)
        for path in _PATHS["status_detail"]:
            for key, row in files[path].items():
                # Only an event already writing this subject's facts advances its login.
                old = previous[path].get(key)
                facts_changed = old is None or any(row[k] != old[k] for k in row
                                                    if k not in {"login_snapshot", "login_as_of"})
                writes_index = "derived_index" in _events._AFFECTED_CLASSES.get(record.event.type, ())
                if record.event.type == "exemption_rule_withdrawn":
                    writes_index = old is not None and bool(row["exemption_sources"]) != bool(old["exemption_sources"])
                if facts_changed and writes_index and key in observations:
                    logins[key] = observations[key]
                row["login_snapshot"], row["login_as_of"] = logins.get(key, (None, None))
        _project_index(files)
        previous = files
    # Replay irresolution is explicit fold metadata, not a live marker or clock.
    final_files, final_rules = _semantic_files(state)
    for path in _PATHS["status_detail"]:
        for key, row in final_files[path].items():
            row["login_snapshot"], row["login_as_of"] = logins.get(key, (None, None))
    _project_index(final_files)
    return DerivedPlaintext(state.project_id, state.current_head_oid, files=final_files,
                            configuration=_events._thaw(state.configuration),
                            standing_rules=final_rules, profile=profile)


def _envelope_size(raw: bytes, project_id: str, path: str) -> int:
    try:
        value = _envelope._parse_envelope(raw)
        identity = resolve_artifact_identity("records", "derived", path)
        _envelope._require_metadata(value, expected_project_id=project_id, expected_identity=identity)
        base64url_decode(value["kid"], expected_length=_envelope.KEY_ID_BYTES)
        base64url_decode(value["nonce"], expected_length=_envelope.NONCE_BYTES)
        size = len(base64url_decode(value["ciphertext"]))
        if size < _envelope.TAG_BYTES:
            raise DerivedError("ciphertext must include its authentication tag")
        return size
    except (ValueError, TypeError) as error:
        raise DerivedError("derived envelope does not match its immutable artifact context") from error


def _validated_state(value: Any, profile: ReleaseProfile | None = None) -> dict[str, Any]:
    """Validate the authenticated state artifact without requiring private shards."""
    if profile is not None:
        _profile(profile)
    state = _copy(value)
    _exact(state, ("state_version", "generations", "shard_digests", "standing_rules", "shard_count", "profile"))
    if (type(state["state_version"]) is not int or state["state_version"] != 1 or
            type(state["shard_count"]) is not int or state["shard_count"] != 32):
        raise DerivedError("derived state requires version1 and32shards")
    validate_materialization_generations({"generations_version": 1, **_exact(state["generations"], DERIVED_CLASSES)})
    tables = _exact(state["shard_digests"], DERIVED_CLASSES)
    for table in tables.values():
        _exact(table, (f"{i:02d}" for i in range(32)))
        for digest in table.values():
            _scalar(_events._digest, digest)
    installed = _exact(state["profile"], ("max_shard_ciphertext_bytes", "max_reader_source_members", "max_continuous_reader_rules"))
    limits = _exact(installed["max_shard_ciphertext_bytes"], DERIVED_CLASSES)
    for limit in (*limits.values(), installed["max_reader_source_members"]):
        _scalar(_events._positive, limit)
    if type(installed["max_continuous_reader_rules"]) is not int or installed["max_continuous_reader_rules"] != 10:
        raise DerivedError("derived state requires the fixed reader-rule limit")
    _validate_standing_rules(state["standing_rules"], profile)
    if profile is not None:
        profile_value = profile.to_dict()
        if installed != {key: profile_value[key] for key in installed}:
            raise DerivedError("derived state carries a different installed profile")
        try:
            profile.check("max_state_ciphertext_bytes", len(canonical_json(state)) + _envelope.TAG_BYTES)
        except ReleaseProfileError as error:
            raise DerivedClassOverflow("state") from error
    return state


@dataclass(frozen=True, slots=True, init=False)
class DerivedProjection:
    plaintext: DerivedPlaintext
    _state: Any

    def __init__(self, plaintext: DerivedPlaintext, state: dict[str, Any]) -> None:
        if type(plaintext) is not DerivedPlaintext:
            raise DerivedError("projection requires validated private plaintext")
        state = _validated_state(state)
        if state["standing_rules"] != _events._thaw(plaintext._rules):
            raise DerivedError("derived state standing rules disagree with plaintext")
        object.__setattr__(self, "plaintext", plaintext)
        object.__setattr__(self, "_state", _events._freeze(state))

    def state_dict(self) -> dict[str, Any]:
        return _events._thaw(self._state)

    def plaintext_files(self) -> dict[str, bytes]:
        return {**self.plaintext.plaintext_files(), _STATE: canonical_json(self.state_dict())}


def _derived_class_for_path(path: Any) -> str:
    for name, paths in _PATHS.items():
        if path in paths:
            return name
    raise DerivedError("read selected an unknown derived shard")


def _validate_selected_shards(files: dict[str, Any], *, derived_class: str,
                              standing_rules: dict[str, Any], profile: ReleaseProfile) -> None:
    """Validate only one selected private class using the complete row validators."""
    _validate_class_shards(files, derived_class=derived_class,
                           standing_rules=standing_rules, profile=profile)


@dataclass(frozen=True, slots=True, init=False)
class DerivedReadProjection:
    """Immutable selected-class read evidence with no unrelated private shards."""

    project_id: str
    canonical_oid: str
    selected_class: str
    generation: str
    _files: Any
    _state: Any

    def __init__(self, project_id: str, canonical_oid: str, *, state: dict[str, Any],
                 selected_files: dict[str, Any], selected_envelopes: dict[str, bytes],
                 generation: str, profile: ReleaseProfile) -> None:
        _scalar(_events._string, project_id)
        _scalar(_events._oid, canonical_oid)
        _profile(profile)
        state = _validated_state(state, profile)
        if type(selected_files) is not dict or not selected_files:
            raise DerivedError("read requires at least one selected derived shard")
        if type(selected_envelopes) is not dict or set(selected_files) != set(selected_envelopes):
            raise DerivedError("selected plaintext and envelope paths must agree")
        classes = {_derived_class_for_path(path) for path in selected_files}
        if len(classes) != 1:
            raise DerivedError("a bounded read selects one derived class")
        selected_class = next(iter(classes))
        _scalar(_events._event_id, generation)
        if state["generations"][selected_class] != generation:
            raise DerivedError("selected derived class generation is stale")
        selected_files = _copy(selected_files)
        _validate_selected_shards(selected_files, derived_class=selected_class,
                                  standing_rules=state["standing_rules"], profile=profile)
        for path, raw in selected_envelopes.items():
            if type(raw) is not bytes:
                raise DerivedError("selected derived envelope must be bytes")
            size = _envelope_size(raw, project_id, path)
            try:
                profile.check("max_shard_ciphertext_bytes", size, derived_class=selected_class)
            except ReleaseProfileError as error:
                raise DerivedClassOverflow(selected_class) from error
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            number = _PATHS[selected_class].index(path)
            if state["shard_digests"][selected_class][f"{number:02d}"] != digest:
                raise DerivedError("selected envelope differs from its exact digest")
        for name, value in (("project_id", project_id), ("canonical_oid", canonical_oid),
                            ("selected_class", selected_class), ("generation", generation),
                            ("_files", _events._freeze(selected_files)),
                            ("_state", _events._freeze(state))):
            object.__setattr__(self, name, value)

    def state_dict(self) -> dict[str, Any]:
        return _events._thaw(self._state)

    def selected_files(self) -> dict[str, Any]:
        return _events._thaw(self._files)

    def plaintext_files(self) -> dict[str, bytes]:
        return {path: canonical_json(value) for path, value in self.selected_files().items()}

    def row_for_subject(self, subject: int) -> dict[str, Any]:
        if self.selected_class not in {"derived_index", "status_detail"}:
            raise DerivedError("selected reader authority has no status row")
        _scalar(_events._positive, subject)
        path = _PATHS[self.selected_class][subject % 32]
        shard = self.selected_files().get(path)
        if shard is None:
            raise DerivedError("selected subject shard is not present")
        row = shard.get(str(subject))
        if row is None:
            raise DerivedError("selected subject is absent from its derived shard")
        return row


def resolve_selected_read_status(read: DerivedReadProjection, *, subject: int,
                                 agreement_id: str, coverage: Any,
                                 effective_scope: Any,
                                 operation_state: tuple[InFlightMarker, DecisionFence]) -> ResolvedStatus:
    """Resolve one selected index/status row against minimal or complete coverage."""
    if type(read) is not DerivedReadProjection:
        raise DerivedError("selected read requires validated derived evidence")
    row = DerivedReadRow(read.project_id, read.canonical_oid, subject, agreement_id,
                         read.row_for_subject(subject))
    return resolve_read_status(row, coverage, effective_scope, operation_state)


def assemble_derived_projection(plaintext: DerivedPlaintext, *, canonical_oid: str,
                                generations: dict[str, Any], encrypted_shards: dict[str, bytes],
                                profile: ReleaseProfile) -> DerivedProjection:
    if type(plaintext) is not DerivedPlaintext:
        raise DerivedError("assembly requires validated plaintext")
    _profile(profile)
    _scalar(_events._oid, canonical_oid)
    validate_materialization_generations(generations)
    values = plaintext.to_dict()
    if canonical_oid != plaintext.canonical_oid:
        raise DerivedError("canonical source does not match plaintext")
    _validate_shards(values["files"], values["standing_rules"], profile)
    _exact(encrypted_shards, _SHARDS)
    digests: dict[str, Any] = {}
    for name, paths in _PATHS.items():
        digests[name] = {}
        for number, path in enumerate(paths):
            size = _envelope_size(encrypted_shards[path], plaintext.project_id, path)
            try:
                profile.check("max_shard_ciphertext_bytes", size, derived_class=name)
            except ReleaseProfileError as error:
                raise DerivedClassOverflow(name) from error
            digests[name][f"{number:02d}"] = "sha256:" + hashlib.sha256(encrypted_shards[path]).hexdigest()
    profile_value = profile.to_dict()
    state = {"state_version": 1, "generations": {name: generations[name] for name in DERIVED_CLASSES},
             "shard_digests": digests, "standing_rules": values["standing_rules"], "shard_count": 32,
             "profile": {name: profile_value[name] for name in ("max_shard_ciphertext_bytes",
                         "max_reader_source_members", "max_continuous_reader_rules")}}
    try:
        profile.check("max_state_ciphertext_bytes", len(canonical_json(state)) + _envelope.TAG_BYTES)
    except ReleaseProfileError as error:
        raise DerivedClassOverflow("state") from error
    return DerivedProjection(plaintext, state)


def validate_derived_projection(projection: DerivedProjection, *, generations: dict[str, Any],
                                encrypted_shards: dict[str, bytes], profile: ReleaseProfile) -> None:
    """Validate the supplied selected shards; stale unrelated classes stay independent."""
    if type(projection) is not DerivedProjection:
        raise DerivedError("validation requires a private derived projection")
    _profile(profile)
    validate_materialization_generations(generations)
    if type(encrypted_shards) is not dict or not encrypted_shards or not set(encrypted_shards) <= set(_SHARDS):
        raise DerivedError("read must select known derived shard envelopes")
    state = projection.state_dict()
    installed = profile.to_dict()
    if state["profile"] != {key: installed[key] for key in state["profile"]}:
        raise DerivedError("derived state carries a different installed profile")
    try:
        profile.check("max_state_ciphertext_bytes", len(canonical_json(state)) + _envelope.TAG_BYTES)
    except ReleaseProfileError as error:
        raise DerivedClassOverflow("state") from error
    for name, paths in _PATHS.items():
        selected = [(i, path) for i, path in enumerate(paths) if path in encrypted_shards]
        if not selected:
            continue
        if state["generations"][name] != generations[name]:
            raise DerivedError("selected derived class generation is stale")
        if name == "status_detail":
            profile.check("max_continuous_exemption_rules", len(state["standing_rules"]))
        for number, path in selected:
            size = _envelope_size(encrypted_shards[path], projection.plaintext.project_id, path)
            try:
                profile.check("max_shard_ciphertext_bytes", size, derived_class=name)
            except ReleaseProfileError as error:
                raise DerivedClassOverflow(name) from error
            digest = "sha256:" + hashlib.sha256(encrypted_shards[path]).hexdigest()
            if state["shard_digests"][name][f"{number:02d}"] != digest:
                raise DerivedError("selected envelope differs from its exact digest")
            if name == "reader_authority":
                for source_id, source in projection.plaintext._files[path].items():
                    _reader(source_id, _events._thaw(source), profile)


@dataclass(frozen=True, slots=True)
class DerivedDelta:
    files: tuple[str, ...]
    classes: tuple[str, ...]


def derived_delta(before: DerivedPlaintext | DerivedProjection,
                  after: DerivedPlaintext | DerivedProjection) -> DerivedDelta:
    """Affected shards plus state; assembled inputs also detect generation-only changes."""
    if type(before) not in {DerivedPlaintext, DerivedProjection} or type(after) is not type(before):
        raise DerivedError("delta requires two matching validated derived models")
    old_plain = before.plaintext if type(before) is DerivedProjection else before
    new_plain = after.plaintext if type(after) is DerivedProjection else after
    if old_plain.project_id != new_plain.project_id:
        raise DerivedError("delta cannot cross projects")
    old, new = before.plaintext_files(), after.plaintext_files()
    changed_set = {path for path in old if old[path] != new[path]}
    rules_changed = old_plain._rules != new_plain._rules
    if type(before) is DerivedPlaintext and (changed_set or rules_changed):
        changed_set.add(_STATE)
    changed = tuple(sorted(changed_set))
    classes = tuple(name for name, paths in _PATHS.items()
                    if any(path in changed_set for path in paths) or
                    (name == "status_detail" and rules_changed))
    return DerivedDelta(changed, classes)


@dataclass(frozen=True, slots=True, init=False)
class DerivedReadRow:
    """Caller-authenticated read context; these fields are never persisted in a shard."""

    project_id: str
    canonical_oid: str
    subject: int
    agreement_id: str
    _record: Any

    def __init__(self, project_id: str, canonical_oid: str, subject: int,
                 agreement_id: str, record: dict[str, Any]) -> None:
        _scalar(_events._string, project_id)
        _scalar(_events._oid, canonical_oid)
        _scalar(_events._positive, subject)
        _scalar(_events._string, agreement_id)
        record = _copy(record)
        _subject(record, detail="exemption_sources" in record)
        for name, value in (("project_id", project_id), ("canonical_oid", canonical_oid),
                            ("subject", subject), ("agreement_id", agreement_id),
                            ("_record", _events._freeze(record))):
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class ResolvedStatus:
    status: str
    reason_code: str
    event_id: str | None
    version: str | None
    accepted_at: str | None
    revoked_at: str | None
    enforcement_scope: tuple[Any, ...]
    coverage_decision: str
    coverage_reason_code: str


def resolve_read_status(row: DerivedReadRow,
                        active_agreement: _coverage.CoverageProjection | CoverageReadContext,
                        effective_scope: Any,
                        operation_state: tuple[InFlightMarker, DecisionFence]) -> ResolvedStatus:
    """Read stored facts with current source/currency/scope and one explicit live pair."""
    if type(row) is not DerivedReadRow:
        raise DerivedError("read requires explicit authenticated subject/source context")
    try:
        if type(active_agreement) is CoverageReadContext:
            active_agreement.validate(expected_project_id=row.project_id,
                                      expected_canonical_oid=row.canonical_oid)
        else:
            _coverage.validate_coverage_projection(active_agreement, expected_project_id=row.project_id,
                                                   expected_canonical_oid=row.canonical_oid)
        scope = _events._parse_scope(effective_scope, "effective scope")
        if type(operation_state) is not tuple or len(operation_state) != 2:
            raise DerivedError("read requires an explicit marker/fence pair")
        marker = parse_canonical_json(encode_inflight_marker(operation_state[0]))
        fence = parse_canonical_json(encode_decision_fence(operation_state[1]))
        _coverage._operation_pair(marker, fence)
    except (ValueError, TypeError) as error:
        raise DerivedError("read source, scope or operation state is invalid") from error
    coverage = active_agreement.to_dict()
    if coverage["source.enc.json"]["project_state"] == "succeeded":
        raise DerivedError("project has been succeeded; read the successor project")
    if marker != coverage["inflight.enc.json"] or fence != coverage["decision-fence.enc.json"]:
        raise DerivedError("read operation state is not from the same coverage observation")
    active = coverage["agreements/active.enc.json"]
    if active["agreement_id"] is not None and active["agreement_id"] != row.agreement_id:
        raise DerivedError("requested agreement differs from current currency")
    record = _events._thaw(row._record)
    facts = record["agreements"].get(row.agreement_id, _empty_facts())
    kind = facts["basis"]["kind"]
    event = facts["basis"]["event_id"]
    exempt = bool(record["exemption_sources"]) if "exemption_sources" in record else record["exempt"]
    if fence["state"] == "mutation" and (fence["project_wide"] or row.subject in fence["subjects"]):
        status, reason, generic = "indeterminate", "operation_in_flight", "indeterminate"
        event = None
    elif kind == "unresolved":
        status, reason, generic = "indeterminate", "replay_unresolved", "indeterminate"
    elif kind == "acceptance" and facts["version"] in active["accepted_versions"]:
        status, reason, generic = "current", "accepted_current_version", "signed"
    elif exempt:
        status, reason, generic = "exempt", "exempt_source_active", "exempt"
        if "exemption_sources" in record:
            event = max(record["exemption_sources"], key=lambda key: record["exemption_sources"][key]["sequence"])
        else:
            event = None  # Index has no exemption provenance by design.
    elif kind == "acceptance":
        retired = facts["version"] in active["retired_versions"]
        status, reason, generic = ("superseded" if retired else "revoked"), (
            "superseded_by_activation" if retired else "version_not_accepted"), "version_not_active"
    elif kind == "revocation":
        status, reason, generic = "revoked", "revoked_by_contributor", "revoked"
    else:
        status, reason, generic = "revoked", "no_acceptance_recorded", "not_signed"
    return ResolvedStatus(status, reason, event, facts["version"], facts["accepted_at"],
                          facts["revoked_at"], tuple(scope),
                          "covered" if status in {"current", "exempt"} else "uncovered", generic)
