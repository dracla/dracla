"""Explicit authenticated exports; canonical replay remains the M1 authority."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import secrets
import stat

from dracla.administration import numeric_id
from dracla.conformance import (
    DerivedReadRow, apply_event, base64url_decode, canonical_json,
    decrypt_artifact, encrypt_artifact, encrypt_json_artifact, exemption_sources,
    initial_replay_state, load_release_profile, materialize_coverage,
    parse_canonical_json, resolve_artifact_identity, resolve_read_status,
    validate_operation_cross_bindings,
)
from .append import MutationEngine
from .credentials import RecordsError, request_json
from .github import HeadConflict, object_id
from .history import authorize_reader, open_history
from .reconcile import StoredPreconditions

PLAINTEXT_LIMIT = 383_000
ENVELOPE_LIMIT = 512_000
PAIR_LIMIT = 1_024_000
RECORD_LIMIT = 10_000
CSV_COLUMNS = ('row_kind', 'export_version', 'project_id', 'request_id',
    'source_events_oid', 'view', 'context_json', 'github_user_id', 'login_snapshot',
    'login_as_of', 'agreement_id', 'recipient_id', 'status', 'reason_code',
    'basis_event_id', 'acceptance_json', 'revocation_json', 'exemption_sources_json',
    'canonical_event_json')


class ExportError(ValueError):
    """Closed non-private diagnostics; never include source values or destinations."""

    def __init__(self, reason='export-unavailable'):
        allowed = {'invalid-export-request', 'reader-denied', 'unsafe-destination',
            'export-io-failure', 'export-render-failure', 'snapshot-changed',
            'export-conflict', 'export-resource-limit', 'history-view-required',
            'hosted-authorization-required', 'export-unavailable'}
        self.reason = reason if reason in allowed else 'export-unavailable'
        super().__init__(self.reason)


@dataclass(frozen=True)
class ExportReport:
    source_events_oid: str
    view: str
    derived_oid: str | None = None
    reused: bool = False


def _plain(value):
    """Copy public immutable model values without depending on kernel internals."""
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _subjects(state):
    return ({d.github_user_id for d in state.tuple_decisions.values()}
            | {s.github_user_id for s in state.exemption_source_records.values()}
            | {key[0] for key, _ in state.unresolved})


def _facts(state, subject):
    """Build one M1 status-detail row from public replay facts, without shards."""
    agreements = {}
    for decision in state.tuple_decisions.values():
        if decision.github_user_id != subject:
            continue
        record = state.event_records[decision.event_id]
        accepted = decision.is_covered
        agreements[decision.agreement_id] = {
            'version': decision.version, 'accepted_at': record.event.recorded_at if accepted else None,
            'revoked_at': None if accepted else record.event.recorded_at,
            'basis': {'kind': 'acceptance' if accepted else 'revocation', 'event_id': decision.event_id}}
    for (user, agreement), event_id in state.unresolved:
        if user == subject:
            agreements[agreement] = {'version': None, 'accepted_at': None, 'revoked_at': None,
                                    'basis': {'kind': 'unresolved', 'event_id': event_id}}
    sources = {s.source_event_id: {k: s.to_dict()[k] for k in
        ('source_kind', 'team', 'basis', 'instrument_ref', 'rule_event_id', 'sequence')}
        for s in exemption_sources(state, subject)}
    return {'login_snapshot': None, 'login_as_of': None, 'agreements': agreements,
        'exemption_sources': sources,
        'exemption_sequence_next': state.exemption_sequence_next.get(subject, 0),
        'materialization_cursor': {r.event_id: r.materialization_cursors[subject]
            for r in state.exemption_rules.values() if r.active and subject in r.materialization_cursors}}


def _logins(snapshot):
    """Apply M1's row-local login observation rule using public replay states."""
    state = initial_replay_state(snapshot.binding.project_id, snapshot.records[0].parent_oid)
    previous, logins = {}, {}
    writes_index = {'acceptance', 'revocation', 'exemption', 'exemption_snapshot',
                    'exemption_source_withdrawn', 'exemption_materialized'}
    for record in snapshot.records:
        state = apply_event(state, record)
        event = record.event.to_dict()
        observed = [event['actor']] if event['actor']['kind'] == 'github' else []
        for container in (event['target'], event['payload']):
            if 'subject' in container:
                observed.append(container['subject'])
            observed.extend(container.get('subjects', ()))
        observations = {o['github_user_id']: (o['login_snapshot'], record.event.recorded_at)
            for o in observed if 'github_user_id' in o and 'login_snapshot' in o}
        # Cursor-only rows participate in the reference observation rule, but do
        # not by themselves make a subject eligible for current export.
        users = (_subjects(state) | set(state.exemption_sequence_next)
                 | {s for r in state.exemption_rules.values() for s in r.materialization_cursors})
        current = {s: _facts(state, s) for s in users}
        for subject, facts in current.items():
            old = previous.get(subject)
            writes = record.event.type in writes_index
            if record.event.type == 'exemption_rule_withdrawn':
                writes = old is not None and bool(facts['exemption_sources']) != bool(old['exemption_sources'])
            if old != facts and writes and subject in observations:
                logins[subject] = observations[subject]
        previous = current
    return logins


def _operation_pair(snapshot, key_provider, transport, observation=None):
    """Reuse M3's authenticated cell/guard readers and M1 cross-binding check."""
    from dataclasses import replace
    if observation is not None:
        if type(observation) is not dict or set(observation) != {'coverage_oid', 'operations_oid'}:
            raise ExportError('export-conflict')
        snapshot = replace(snapshot, **{k: object_id(v) for k, v in observation.items()})
    engine = MutationEngine(snapshot.binding, key_provider, transport,
                            StoredPreconditions(snapshot.binding, key_provider, transport))
    try:
        cell = engine._cell(snapshot, snapshot.operations_oid)
        fence, marker = engine._guards(snapshot, snapshot.coverage_oid, cell=cell)
        reference = engine._reference_from_fence(snapshot, fence) if fence.state == 'mutation' else None
        validate_operation_cross_bindings(cell, fence, marker, prepared_reference=reference)
        return marker, fence
    except RecordsError:
        raise
    except Exception:
        raise RecordsError('invalid-history') from None


@dataclass(frozen=True)
class _Rendering:
    snapshot: object = field(repr=False)
    view: str
    request_id: str | None
    context: dict = field(repr=False)
    pair: tuple | None = field(repr=False)
    logins: dict = field(repr=False)

    def metadata(self):
        return {'export_version': 1, 'project_id': self.snapshot.binding.project_id,
            'request_id': self.request_id, 'source_events_oid': self.snapshot.events_oid,
            'view': self.view, 'context': self.context}

    def records(self):
        snapshot, state = self.snapshot, self.snapshot.state
        if self.view == 'history':
            for record in snapshot.records:
                yield record.to_dict()
            return
        coverage = materialize_coverage(state, self.pair, canonical_oid=snapshot.events_oid,
            built_at='1970-01-01T00:00:00Z', dracla_version='export-v1')
        acceptances = {}
        for record in snapshot.records:
            if record.event.type == 'acceptance':
                key = record.event.target['coverage_tuple']
                acceptances[key['github_user_id'], key['agreement_id'], key['recipient_id']] = record
        for subject in sorted(_subjects(state)):
            facts = _facts(state, subject)
            login, as_of = self.logins.get(subject, (None, None))
            facts.update(login_snapshot=login, login_as_of=as_of)
            if state.agreement_id is None:
                fence = self.pair[1].to_dict()
                inflight = fence['state'] == 'mutation' and (fence['project_wide'] or subject in fence['subjects'])
                status, reason = ('indeterminate', 'operation_in_flight') if inflight else ('exempt', 'exempt_source_active')
                sources = exemption_sources(state, subject)
                basis = None if inflight else max(sources, key=lambda s: s.sequence).source_event_id
            else:
                resolved = resolve_read_status(DerivedReadRow(state.project_id, snapshot.events_oid,
                    subject, state.agreement_id, facts), coverage, _plain(state.enforcement_scope), self.pair)
                status, reason, basis = resolved.status, resolved.reason_code, resolved.event_id
            key = (subject, state.agreement_id, state.recipient['recipient_id'])
            decision = state.tuple_decisions.get(key)
            acceptance = acceptances.get(key)
            revocation = state.event_records[decision.event_id] if decision and not decision.is_covered else None
            yield {'github_user_id': subject, 'login_snapshot': login, 'login_as_of': as_of,
                'agreement_id': state.agreement_id, 'recipient_id': state.recipient['recipient_id'],
                'status': status, 'reason_code': reason, 'basis_event_id': basis,
                'acceptance': acceptance.to_dict() if acceptance else None,
                'revocation': revocation.to_dict() if revocation else None,
                'exemption_sources': [s.to_dict() for s in exemption_sources(state, subject)]}


def _rendering(snapshot, key_provider, transport, view, request_id=None, observation=None):
    state = snapshot.state
    if view == 'current' and state.project_state == 'succeeded':
        raise ExportError('history-view-required')
    pair = _operation_pair(snapshot, key_provider, transport, observation) if view == 'current' else None
    context = {'project_state': state.project_state, 'successor_project_id': state.successor_project_id,
        'recipient': _plain(state.recipient),
        'active_agreement': state.active_agreement.to_dict() if state.active_agreement else None,
        'enforcement_scope': _plain(state.enforcement_scope),
        'operational_observation': (observation or {'coverage_oid': snapshot.coverage_oid,
            'operations_oid': snapshot.operations_oid}) if pair is not None else None}
    return _Rendering(snapshot, view, request_id, context, pair, _logins(snapshot) if pair else {})


def json_chunks(rendering):
    """The whole document is JCS; records are canonicalized one at a time."""
    metadata = rendering.metadata()
    keys = sorted((*metadata, 'records'))  # These fixed ASCII keys have JCS order.
    yield b'{'
    for index, key in enumerate(keys):
        yield (b',' if index else b'') + canonical_json(key) + b':'
        if key != 'records':
            yield canonical_json(metadata[key])
        else:
            yield b'['
            for count, record in enumerate(rendering.records()):
                yield (b',' if count else b'') + canonical_json(record)
            yield b']'
    yield b'}'


def _csv_line(values, *, header=False):
    cells = []
    for value in values:
        text = '' if value is None else str(value) if type(value) is int else ('' if header else "'") + value
        if any(c in text for c in ',"\r\n'):
            text = '"' + text.replace('"', '""') + '"'
        cells.append(text)
    return (','.join(cells) + '\r\n').encode('utf-8')


def csv_chunks(rendering):
    metadata = rendering.metadata()
    scalar = {k: metadata[k] for k in ('export_version', 'project_id', 'request_id', 'source_events_oid', 'view')}
    yield _csv_line(CSV_COLUMNS, header=True)
    row = {**scalar, 'row_kind': 'metadata', 'context_json': canonical_json(metadata['context']).decode()}
    yield _csv_line([row.get(k) for k in CSV_COLUMNS])
    for record in rendering.records():
        row = {**scalar, 'row_kind': 'current' if rendering.view == 'current' else 'event'}
        if rendering.view == 'history':
            row['canonical_event_json'] = canonical_json(record).decode()
        else:
            row.update({k: v for k, v in record.items() if k not in ('acceptance', 'revocation', 'exemption_sources')})
            row.update({k + '_json': canonical_json(record[k]).decode()
                        for k in ('acceptance', 'revocation', 'exemption_sources')})
        yield _csv_line([row.get(k) for k in CSV_COLUMNS])


def _selection(view, source):
    if view not in ('current', 'history') or source is not None and view != 'history':
        raise ExportError('invalid-export-request')
    if source is not None:
        try:
            object_id(source)
        except Exception:
            raise ExportError('invalid-export-request') from None


def _source(latest, source, keys, transport):
    if source is None or source == latest.events_oid:
        return latest
    if source not in {r.commit_oid for r in latest.records}:
        raise ExportError('invalid-export-request')
    return open_history(latest.binding, keys, transport.at_events(source))


def _authorize(snapshot, principal, membership):
    if not authorize_reader(snapshot, principal, membership):
        raise ExportError('reader-denied')


def _final_gate(latest, transport, principal, membership, authenticate, *, rendering=None):
    repo = latest.binding.repo('records')
    if transport.head(repo, 'events') != latest.events_oid:
        return False
    if authenticate() != principal:
        raise ExportError('reader-denied')
    _authorize(latest, principal, membership)
    if transport.head(repo, 'events') != latest.events_oid:
        return False
    if rendering is not None and rendering.view == 'current':
        observation = rendering.context['operational_observation']
        if (transport.head(repo, 'operations') != observation['operations_oid'] or
            transport.head(latest.binding.repo('coverage'), 'coverage') != observation['coverage_oid']):
            return False
    return True


def operator_membership(credentials, organization_id, team_id, user_id):
    """Fresh numeric-ID membership; never follow a provider pagination URL."""
    for value in (organization_id, team_id, user_id):
        numeric_id(value)
    if credentials.mode != 'operator' or credentials.user_id != user_id:
        raise ExportError('reader-denied')
    seen = set()
    for page in range(1, 1001):
        members, headers = request_json(credentials.sender, 'GET',
            f'/organizations/{organization_id}/team/{team_id}/members?per_page=100&page={page}',
            credentials.token(), paginated=True)
        if type(members) is not list or len(members) > 100:
            raise ExportError('reader-denied')
        for member in members:
            identity = numeric_id(member['id'])
            if identity in seen:
                raise ExportError('reader-denied')
            seen.add(identity)
        if user_id in seen:
            return True
        if len(members) < 100:
            if any(k.lower() == 'link' and 'rel="next"' in v for k, v in headers.items()):
                raise ExportError('reader-denied')
            return False
    raise ExportError('reader-denied')


def _same_inode(info, other):
    return (info.st_dev, info.st_ino) == (other.st_dev, other.st_ino)


class _LocalFiles:
    """Held directory/file identities constrain publication and handled cleanup."""

    def __init__(self, destinations):
        self.entries, self.directories = [], []
        try:
            aliases = set()
            for kind, destination in destinations.items():
                if (type(destination) is not str or not destination or destination == '-'
                        or '..' in destination.split(os.sep)):
                    raise ExportError('unsafe-destination')
                path = Path(os.path.abspath(destination))
                descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                self.directories.append(descriptor)
                system_uid = os.fstat(descriptor).st_uid
                chain = []
                for part in path.parts[1:-1]:
                    parent = descriptor
                    descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    self.directories.append(descriptor)
                    info = os.fstat(descriptor)
                    if (info.st_uid not in (system_uid, os.getuid()) or
                        info.st_mode & 0o022 and not (info.st_uid == system_uid and info.st_mode & stat.S_ISVTX)):
                        raise ExportError('unsafe-destination')
                    chain.append((parent, part, info))
                info = os.fstat(descriptor)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ExportError('unsafe-destination')
                identity = (info.st_dev, info.st_ino, path.name)
                if identity in aliases:
                    raise ExportError('unsafe-destination')
                aliases.add(identity)
                try:
                    os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ExportError('unsafe-destination')
                self.entries.append({'kind': kind, 'parent': descriptor, 'name': path.name,
                    'chain': chain, 'stage': None, 'identity': None, 'published': False})
        except Exception:
            self.close()
            raise ExportError('unsafe-destination') from None

    def write(self, rendering):
        try:
            for entry in self.entries:
                parent = entry['parent']
                entry['stage'] = '.dracla-export-' + secrets.token_hex(16)
                descriptor = os.open(entry['stage'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent)
                with os.fdopen(descriptor, 'wb') as stream:
                    info = os.fstat(stream.fileno())
                    entry['identity'] = info
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_uid != os.getuid()):
                        raise ExportError('unsafe-destination')
                    os.fchmod(stream.fileno(), 0o600)
                    if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) != 0o600:
                        raise ExportError('unsafe-destination')
                    chunks = json_chunks(rendering) if entry['kind'] == 'json' else csv_chunks(rendering)
                    for chunk in chunks:
                        stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
            for entry in self.entries:
                for parent, name, identity in entry['chain']:
                    if not _same_inode(identity, os.stat(name, dir_fd=parent, follow_symlinks=False)):
                        raise ExportError('unsafe-destination')
                self._verify_stage(entry)
                os.link(entry['stage'], entry['name'], src_dir_fd=entry['parent'],
                        dst_dir_fd=entry['parent'], follow_symlinks=False)
                entry['published'] = True
                self._unlink(entry, entry['stage'])
                os.fsync(entry['parent'])
        except Exception as error:
            cleanup_failed = False
            for entry in self.entries:
                for name in (entry['name'] if entry['published'] else None, entry['stage']):
                    try:
                        self._unlink(entry, name)
                    except OSError:
                        cleanup_failed = True
            if cleanup_failed:
                raise ExportError('export-io-failure') from None
            if isinstance(error, ExportError):
                raise
            raise ExportError('export-io-failure' if isinstance(error, OSError) else 'export-render-failure') from None
        finally:
            self.close()

    def _verify_stage(self, entry):
        info = os.stat(entry['stage'], dir_fd=entry['parent'], follow_symlinks=False)
        if not _same_inode(entry['identity'], info) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ExportError('unsafe-destination')

    def _unlink(self, entry, name):
        if name is None or entry['identity'] is None:
            return
        try:
            if _same_inode(entry['identity'], os.stat(name, dir_fd=entry['parent'], follow_symlinks=False)):
                os.unlink(name, dir_fd=entry['parent'])
        except FileNotFoundError:
            pass

    def close(self):
        for descriptor in self.directories:
            os.close(descriptor)
        self.directories.clear()


def export_local(binding, key_provider, transport, *, json_path=None, csv_path=None,
                 view='current', source_events_oid=None):
    _selection(view, source_events_oid)
    destinations = {k: v for k, v in (('json', json_path), ('csv', csv_path)) if v is not None}
    if not destinations or transport.credentials.mode != 'operator':
        raise ExportError('invalid-export-request')
    def authenticate():
        transport.credentials.authorize(binding)
        return numeric_id(transport.credentials.user_id)
    membership = lambda org, team, user: operator_membership(transport.credentials, org, team, user)
    for _ in range(load_release_profile().limit('max_mutation_retries')):
        latest = open_history(binding, key_provider, transport)
        principal = numeric_id(transport.credentials.user_id)
        _authorize(latest, principal, membership)
        snapshot = _source(latest, source_events_oid, key_provider, transport)
        rendering = _rendering(snapshot, key_provider, transport, view)
        if not _final_gate(latest, transport, principal, membership, authenticate, rendering=rendering):
            continue
        _LocalFiles(destinations).write(rendering)
        return ExportReport(snapshot.events_oid, view)
    raise ExportError('snapshot-changed')


def _bounded(chunks):
    result = bytearray()
    for chunk in chunks:
        if len(result) + len(chunk) > PLAINTEXT_LIMIT:
            raise ExportError('export-resource-limit')
        result.extend(chunk)
    return bytes(result)


def _hosted_request(request, binding):
    try:
        if (type(request) is not dict or set(request) != {'export_version', 'project_id',
            'request_id', 'source_events_oid', 'view'} or type(request['export_version']) is not int
            or request['export_version'] != 1 or request['project_id'] != binding.project_id
            or request['view'] not in ('current', 'history')
            or len(base64url_decode(request['request_id'])) != 16):
            raise ValueError()
        object_id(request['source_events_oid'])
        return {kind: f"derived/exports/{request['request_id']}.enc.{kind}" for kind in ('json', 'csv')}
    except Exception:
        raise ExportError('invalid-export-request') from None


def export_hosted(binding, key_provider, transport, request, *, authority=None):
    if type(request) is not dict:
        raise ExportError('invalid-export-request')
    request = dict(request)  # The closed request has only scalar values.
    paths = _hosted_request(request, binding)
    if not all(callable(getattr(authority, k, None)) for k in ('authenticate_request', 'is_team_member')):
        raise ExportError('hosted-authorization-required')
    def authenticate():
        try:
            return numeric_id(authority.authenticate_request(dict(request)))
        except Exception:
            raise ExportError('reader-denied') from None
    for _ in range(load_release_profile().limit('max_mutation_retries')):
        principal = authenticate()  # Before the history reader can acquire data keys.
        latest = open_history(binding, key_provider, transport)
        _authorize(latest, principal, authority.is_team_member)
        snapshot = _source(latest, request['source_events_oid'], key_provider, transport)
        repo, derived = binding.repo('records'), latest.derived_oid
        tree = transport.tree(repo, derived)
        existing = [path in tree for path in paths.values()]
        if any(existing) and not all(existing):
            raise ExportError('export-conflict')
        retained, observation = None, None
        if all(existing):
            try:
                retained = {kind: decrypt_artifact(transport.read(repo, derived, path),
                    expected_project_id=binding.project_id,
                    expected_identity=resolve_artifact_identity('records', 'derived', path),
                    keys=snapshot.keys['records']) for kind, path in paths.items()}
                payload = parse_canonical_json(retained['json'])
                observation = payload['context']['operational_observation']
                if request['view'] == 'current' and observation is None:
                    raise ValueError()
            except Exception:
                raise ExportError('export-conflict') from None
        elif request['view'] == 'current' and snapshot.events_oid != latest.events_oid:
            raise ExportError('export-conflict')
        rendering = _rendering(snapshot, key_provider, transport, request['view'], request['request_id'], observation)
        for count, _record in enumerate(rendering.records(), 1):
            if count > RECORD_LIMIT:
                raise ExportError('export-resource-limit')
        rendered = {'json': _bounded(json_chunks(rendering)), 'csv': _bounded(csv_chunks(rendering))}
        if retained is not None and retained != rendered:
            raise ExportError('export-conflict')
        if retained is None:
            kid = latest.state.current_kids['records']
            kwargs = dict(project_id=binding.project_id, kid=base64url_decode(kid), key=latest.keys['records'][kid])
            encrypted = {paths[kind]: (encrypt_json_artifact(parse_canonical_json(raw),
                identity=resolve_artifact_identity('records', 'derived', paths[kind]), **kwargs) if kind == 'json'
                else encrypt_artifact(raw, identity=resolve_artifact_identity('records', 'derived', paths[kind]), **kwargs))
                for kind, raw in rendered.items()}
            if any(len(raw) > ENVELOPE_LIMIT for raw in encrypted.values()) or sum(map(len, encrypted.values())) > PAIR_LIMIT:
                raise ExportError('export-resource-limit')
        if not _final_gate(latest, transport, principal, authority.is_team_member, authenticate,
                           rendering=rendering if retained is None else None):
            continue
        if retained is not None:
            return ExportReport(snapshot.events_oid, request['view'], derived, True)
        try:
            result = transport.conditional_commit(repo, 'derived', derived, encrypted)
            return ExportReport(snapshot.events_oid, request['view'], result)
        except HeadConflict:
            continue
    raise ExportError('snapshot-changed')
