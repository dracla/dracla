"""Durable M3 mutation primitives; projection completion belongs to reconcile.

The evidence provider supplies authenticated M1 preconditions for the requested
immutable head. It is an engine dependency, never business-data-selected code.
M1 validates the complete evidence and package before any mutation. The driver
does not invent a second event or operation-state contract.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from dracla.conformance import (
    CanonicalEventRecord, PreparedOperationReference, SideArtifact, ReplayError,
    acquire_mutation_fence, apply_event, base64url_decode, canonical_json,
    claim_append, decode_decision_fence, decode_inflight_marker,
    decode_prepared_operation, decrypt_json_artifact, encrypt_artifact,
    encrypt_json_artifact, event_path, load_release_profile, open_inflight_marker,
    parse_event_jcs, prepare_operation, required_side_artifacts,
    parse_canonical_json, resolve_artifact_identity, terminal_operation, validate_event,
    validate_operation_cross_bindings, validate_side_artifact_package,
)
from .credentials import RecordsError
from .github import HeadConflict, IndeterminateWrite
from .history import open_history, replay_history

CELL = 'prepared-operation.enc.json'
FENCE = 'decision-fence.enc.json'
MARKER = 'inflight.enc.json'


@dataclass(frozen=True)
class AppendOutcome:
    result: str
    observed_events_head: str
    canonical_commit: str | None = None


class MutationEngine:
    """Concrete frozen-package append and exact-head operation/fence writes.

    A landed append leaves its cell appending and marker open. Only m3/3's
    verified projection completion may terminalize, release and clear them.
    Indeterminate results retain every durable guard for repair forward.
    """

    def __init__(self, binding, key_provider, transport, preconditions, *,
                 sleep=time.sleep, jitter=lambda attempt: min(.05 * 2**attempt, 1.0)):
        self.binding, self.key_provider, self.transport = binding, key_provider, transport
        self.preconditions, self.sleep, self.jitter = preconditions, sleep, jitter
        self.profile = load_release_profile()
        self.limit = self.profile.limit('max_prepared_operation_bytes')

    def __repr__(self):
        return 'MutationEngine()'

    def snapshot(self):
        return open_history(self.binding, self.key_provider, self.transport)

    def _kids_at(self, snapshot, events_head):
        """Use authenticated M1 replay, including for immutable preparations."""
        if events_head == snapshot.events_oid:
            return snapshot.state.current_kids
        root = snapshot.records[0].parent_oid
        if events_head == root:
            return snapshot.bootstrap['current_kids']
        for index, record in enumerate(snapshot.records):
            if record.commit_oid == events_head:
                result = replay_history(self.binding.project_id, root, snapshot.records[:index + 1])
                if result.valid:
                    return result.state.current_kids
                break
        raise RecordsError('invalid-history')

    def _rotation_kids(self, snapshot, cell):
        """Only the exact last canonical activation can repair old live guards.

        Its append claim must name the real activation parent. Both the frozen
        preparation and that parent must select the same predecessor keys.
        The normal cross-binding checks still authenticate the original
        prepared commit/blob, operation, fence and marker before any write.
        """
        if cell.get('state') != 'appending':
            return None
        event = parse_event_jcs(base64url_decode(cell['event_jcs_b64']),
                               expected_project_id=self.binding.project_id)
        landed = snapshot.records[-1]
        if (event.type != 'keyring_activated' or snapshot.events_oid != landed.commit_oid
                or cell['append_head'] != landed.parent_oid
                or canonical_json(event.to_dict()) != canonical_json(landed.event.to_dict())
                or dict(event.payload['current_kids']) != dict(snapshot.state.current_kids)):
            return None
        prior = self._kids_at(snapshot, landed.parent_oid)
        if (dict(prior) != dict(self._kids_at(snapshot, cell['prepared_events_head']))
                or dict(prior) == dict(snapshot.state.current_kids)):
            return None
        return prior

    def _plain(self, snapshot, role, branch, head, path, *, historical=False, rotation_cell=None):
        repo = self.binding.repo(role)
        raw = self.transport.read(repo, head, path)
        envelope = parse_canonical_json(raw)
        if type(envelope) is not dict:
            raise RecordsError('invalid-key')
        expected_kid = snapshot.state.current_kids[role]
        value = None
        def decrypt():
            return decrypt_json_artifact(raw, expected_project_id=self.binding.project_id,
                expected_identity=resolve_artifact_identity(role, branch, path), keys=snapshot.keys[role])
        if historical:
            if (role, branch, path) != ('records', 'operations', CELL):
                raise RecordsError('scope-mismatch')
            value = decrypt()
            if type(value) is not dict or value.get('state') != 'prepared':
                raise RecordsError('invalid-history')
            expected_kid = self._kids_at(snapshot, value['prepared_events_head'])['records']
        elif envelope.get('kid') != expected_kid:
            if (role, branch, path) == ('records', 'operations', CELL):
                value = decrypt()
                rotation = self._rotation_kids(snapshot, value) if type(value) is dict else None
            elif role == 'coverage' and branch == 'coverage' and path in (FENCE, MARKER):
                rotation = self._rotation_kids(snapshot, rotation_cell.to_dict()) if rotation_cell else None
            else:
                rotation = None
            if rotation is None:
                raise RecordsError('invalid-key')
            expected_kid = rotation[role]
        if envelope.get('kid') != expected_kid:
            raise RecordsError('invalid-key')
        return value if value is not None else decrypt()

    def _cell(self, snapshot, head, *, historical=False):
        value = self._plain(snapshot, 'records', 'operations', head, CELL, historical=historical)
        if type(value) is not dict:
            raise RecordsError('invalid-history')
        evidence = None
        if value.get('state') in ('prepared', 'appending'):
            event = parse_event_jcs(base64url_decode(value['event_jcs_b64']),
                                   expected_project_id=self.binding.project_id)
            evidence = self.preconditions(event, value['prepared_events_head'])
        return decode_prepared_operation(canonical_json(value),
            expected_project_id=self.binding.project_id, preconditions=evidence,
            max_prepared_operation_bytes=self.limit)

    def _guards(self, snapshot, head, *, cell=None):
        return (decode_decision_fence(canonical_json(self._plain(snapshot, 'coverage', 'coverage', head, FENCE,
                                                                rotation_cell=cell))),
                decode_inflight_marker(canonical_json(self._plain(snapshot, 'coverage', 'coverage', head, MARKER,
                                                                  rotation_cell=cell))))

    def _encrypted(self, snapshot, role, branch, values):
        kid = snapshot.state.current_kids[role]
        return {path: encrypt_json_artifact(value, project_id=self.binding.project_id,
            identity=resolve_artifact_identity(role, branch, path), kid=base64url_decode(kid),
            key=snapshot.keys[role][kid]) for path, value in values.items()}

    def _write(self, snapshot, role, branch, head, values):
        return self.transport.conditional_commit(self.binding.repo(role), branch, head,
                                                self._encrypted(snapshot, role, branch, values))

    def _reference(self, snapshot, head, cell):
        if cell.state == 'prepared':
            blob = self.transport.tree(self.binding.repo('records'), head)[CELL].oid
            return PreparedOperationReference(head, blob, cell)
        fence, marker = self._guards(snapshot, snapshot.coverage_oid, cell=cell)
        f = fence.to_dict()
        if fence.state != 'mutation':
            raise RecordsError('invalid-history')
        original = self._cell(snapshot, f['prepared_commit_oid'], historical=True)
        blob = self.transport.tree(self.binding.repo('records'), f['prepared_commit_oid'])[CELL].oid
        reference = PreparedOperationReference(f['prepared_commit_oid'], blob, original)
        validate_operation_cross_bindings(cell, fence, marker, prepared_reference=reference)
        return reference

    def prepare(self, event, side_artifacts):
        """Durably freeze one complete M1-authorized package, or resume it."""
        snapshot = self.snapshot()
        event = validate_event(event.to_dict() if hasattr(event, 'to_dict') else event,
                               expected_project_id=self.binding.project_id)
        cell = self._cell(snapshot, snapshot.operations_oid)
        prepared_head = snapshot.events_oid
        if cell.state in ('prepared', 'appending'):
            prepared_head = cell.to_dict()['prepared_events_head']
        elif cell.state == 'terminal':
            prepared_head = self._reference(snapshot, snapshot.operations_oid, cell).cell.to_dict()['prepared_events_head']
        wanted = prepare_operation(cell, event, side_artifacts,
            expected_project_id=self.binding.project_id, expected_events_head=prepared_head,
            preconditions=self.preconditions(event, prepared_head),
            max_prepared_operation_bytes=self.limit)
        if wanted.to_dict() == cell.to_dict():
            return self._reference(snapshot, snapshot.operations_oid, cell)
        head = self._write(snapshot, 'records', 'operations', snapshot.operations_oid, {CELL: wanted.to_dict()})
        stored = self._cell(snapshot, head)
        if stored.to_dict() != wanted.to_dict():
            raise RecordsError('invalid-history')
        return self._reference(snapshot, head, stored)

    def pending(self):
        """Recover the frozen submission from durable authenticated state alone."""
        snapshot = self.snapshot()
        cell = self._cell(snapshot, snapshot.operations_oid)
        if cell.state == 'idle':
            return None
        return self._reference(snapshot, snapshot.operations_oid, cell)

    def begin(self, reference, *, subjects, project_wide, started_at):
        """Acquire the exact M1 fence, then open its marker at a fresh CAS head."""
        snapshot = self.snapshot()
        cell = self._cell(snapshot, snapshot.operations_oid)
        fence, marker = self._guards(snapshot, snapshot.coverage_oid, cell=cell)
        wanted = acquire_mutation_fence(fence, cell, reference,
                                       subjects=subjects, project_wide=project_wide)
        head = snapshot.coverage_oid
        if wanted.to_dict() != fence.to_dict():
            if marker.to_dict()['ops']:
                raise RecordsError('invalid-history')
            head = self._write(snapshot, 'coverage', 'coverage', head, {FENCE: wanted.to_dict()})
        fence, marker = self._guards(snapshot, head, cell=cell)
        opened = open_inflight_marker(marker, fence, cell=cell,
                                     prepared_reference=reference, started_at=started_at)
        if opened.to_dict() != marker.to_dict():
            head = self._write(snapshot, 'coverage', 'coverage', head, {MARKER: opened.to_dict()})
        fence, marker = self._guards(snapshot, head, cell=cell)
        validate_operation_cross_bindings(cell, fence, marker, prepared_reference=reference)
        return head

    def _package(self, cell, snapshot):
        value = cell.to_dict()
        event = parse_event_jcs(base64url_decode(value['event_jcs_b64']),
                               expected_project_id=self.binding.project_id)
        if event.confirmed_canonical_oid is not None and event.confirmed_canonical_oid != snapshot.events_oid:
            return None
        artifacts = [SideArtifact(a['kind'], a['path'], base64url_decode(a['bytes_b64']), a['sha256'])
                     for a in value['side_artifacts']]
        evidence = self.preconditions(event, snapshot.events_oid)
        # Only the deterministic generations artifact is rebuilt on a newer
        # base. Authorized snapshot/config inputs and the event stay frozen.
        requirements = required_side_artifacts(event, preconditions=evidence,
                                               expected_head=snapshot.events_oid)
        for req in requirements:
            if req.kind == 'materialization_generations':
                generations = dict(snapshot.generations)
                generations.update({name: event.event_id for name in req.affected_classes})
                raw = canonical_json({'generations_version': 1, **generations})
                artifacts = [SideArtifact(a.kind, a.path, raw) if a.path == req.path else a
                             for a in artifacts]
        validate_side_artifact_package(event, artifacts, preconditions=evidence,
                                       expected_head=snapshot.events_oid)
        return event, artifacts

    def _landed(self, snapshot, cell):
        """Full authenticated replay precedes this exact frozen-input match."""
        frozen = cell.to_dict()
        event = parse_event_jcs(base64url_decode(frozen['event_jcs_b64']),
                               expected_project_id=self.binding.project_id)
        for record in snapshot.records:
            if record.event.idempotency_key != event.idempotency_key:
                continue
            if record.event.operation_sha256 != event.operation_sha256:
                return AppendOutcome('conflict', snapshot.events_oid)
            if canonical_json(record.event.to_dict()) != canonical_json(event.to_dict()):
                raise RecordsError('invalid-history')
            for artifact in frozen['side_artifacts']:
                # open_history verifies the complete deterministic generation
                # update against this commit's real parent, not today's head.
                if artifact['kind'] == 'materialization_generations':
                    continue
                raw = self.transport.read(self.binding.repo('records'), record.commit_oid, artifact['path'])
                if artifact['kind'] == 'project_config':
                    value = decrypt_json_artifact(raw, expected_project_id=self.binding.project_id,
                        expected_identity=resolve_artifact_identity('records', 'events', artifact['path']),
                        keys=snapshot.keys['records'])
                    raw = canonical_json(value)
                if raw != base64url_decode(artifact['bytes_b64']):
                    raise RecordsError('invalid-history')
            return AppendOutcome('landed', snapshot.events_oid, record.commit_oid)
        return None

    def _terminal_absent(self, snapshot, cell, fence, marker, reference, result):
        value = cell.to_dict()
        terminal = terminal_operation(cell, operation_id=value['operation_id'],
            operation_sha256=value['operation_sha256'], fence=fence, marker=marker,
            prepared_reference=reference, result=result, observed_events_head=snapshot.events_oid,
            canonical_commit=None)
        # This is the competing CAS with prepared -> appending. Losing it
        # grants no right to claim a terminal result or release the fence.
        self._write(snapshot, 'records', 'operations', snapshot.operations_oid, {CELL: terminal.to_dict()})
        return AppendOutcome(result, snapshot.events_oid)

    def append(self, reference):
        """Append or discover exactly this operation, retaining uncertain state."""
        last_head = reference.cell.to_dict()['prepared_events_head']
        for attempt in range(self.profile.limit('max_mutation_retries')):
            snapshot = self.snapshot()
            last_head = snapshot.events_oid
            cell = self._cell(snapshot, snapshot.operations_oid)
            fence, marker = self._guards(snapshot, snapshot.coverage_oid, cell=cell)
            if fence.state != 'mutation':
                raise RecordsError('invalid-history')
            validate_operation_cross_bindings(cell, fence, marker, prepared_reference=reference)
            if cell.state not in ('prepared', 'appending'):
                if cell.state == 'terminal':
                    value = cell.to_dict()
                    return AppendOutcome(value['result'], value['observed_events_head'], value['canonical_commit'])
                raise RecordsError('invalid-history')
            found = self._landed(snapshot, cell)
            if found:
                if found.result == 'conflict' and cell.state == 'appending':
                    raise RecordsError('invalid-history')
                if found.result == 'conflict':
                    return self._terminal_absent(snapshot, cell, fence, marker, reference, 'conflict')
                return found
            event = parse_event_jcs(base64url_decode(cell.to_dict()['event_jcs_b64']))
            noop = (snapshot.state.project_state == 'active' and event.type == 'config_updated'
                    and canonical_json(event.to_dict()['payload']['project_configuration'])
                    == canonical_json(snapshot.state.to_dict()['configuration']))
            try:
                if noop:
                    if cell.state == 'appending':
                        return AppendOutcome('indeterminate', last_head)
                    return self._terminal_absent(snapshot, cell, fence, marker, reference, 'semantic_noop')
                # Replay authenticates current canonical semantics before the
                # append-only provider facts needed by an applicable append.
                try:
                    apply_event(snapshot.state, CanonicalEventRecord(event, 'f' * 40, snapshot.events_oid))
                except ReplayError:
                    if cell.state == 'appending':
                        return AppendOutcome('indeterminate', last_head)
                    return self._terminal_absent(snapshot, cell, fence, marker, reference, 'conflict')
                package = self._package(cell, snapshot)
                if package is None:
                    if cell.state == 'appending':
                        return AppendOutcome('indeterminate', last_head)
                    return self._terminal_absent(snapshot, cell, fence, marker, reference, 'conflict')
                event, artifacts = package
                value = cell.to_dict()
                claimed = claim_append(cell, operation_id=value['operation_id'],
                    operation_sha256=value['operation_sha256'], fence=fence, marker=marker,
                    prepared_reference=reference, append_head=snapshot.events_oid,
                    expected_append_claim=value.get('append_claim'), max_prepared_operation_bytes=self.limit)
                if claimed.to_dict() != value:
                    self._write(snapshot, 'records', 'operations', snapshot.operations_oid,
                                {CELL: claimed.to_dict()})
                kid = snapshot.state.current_kids['records']
                files = {event_path(event.event_id): encrypt_json_artifact(event.to_dict(),
                    project_id=self.binding.project_id,
                    identity=resolve_artifact_identity('records', 'events', event_path(event.event_id)),
                    kid=base64url_decode(kid), key=snapshot.keys['records'][kid])}
                for artifact in artifacts:
                    raw = artifact.bytes
                    if artifact.kind in ('project_config', 'materialization_generations'):
                        raw = encrypt_artifact(raw, project_id=self.binding.project_id,
                            identity=resolve_artifact_identity('records', 'events', artifact.path),
                            kid=base64url_decode(kid), key=snapshot.keys['records'][kid])
                    files[artifact.path] = raw
                repo = self.binding.repo('records')
                oid = self.transport.create_event_commit(repo, snapshot.events_oid, files)
                self.transport.update_events(repo, oid)
                # Even a successful response is returned only after complete
                # authenticated history proves event and artifact membership.
                verified = self._landed(self.snapshot(), claimed)
                if verified is None:
                    raise RecordsError('invalid-history')
                return verified
            except (HeadConflict, IndeterminateWrite):
                # Next iteration authenticates history and discovers the exact
                # event before any new write. The durable claim is not cleared.
                self.sleep(self.jitter(attempt))
        return AppendOutcome('indeterminate', last_head)
