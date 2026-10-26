"""Authenticate immutable repository history and compare M1 reference projections."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping

from dracla.conformance import (
    CanonicalEventRecord, DerivedProjection, apply_event, canonical_json, decode_decision_fence,
    decode_inflight_marker, decode_keyring, decode_prepared_operation, decrypt_json_artifact,
    event_path, initial_replay_state, load_release_profile, materialize_coverage,
    materialize_derived, parse_canonical_json, reader_sources, replay_events,
    resolve_artifact_identity, unwrap_key_copy, validate_derived_projection,
    validate_materialization_generations, validate_operation_cross_bindings, validate_event,
)
from dracla.administration import numeric_id
from .credentials import ProjectBinding, RecordsError
from .github import RepositoryTransport, object_id

_GENERATIONS = 'config/materialization-generations.enc.json'
_CONFIGURATION = 'config/project.enc.json'
_MANIFEST = '.dracla/bootstrap.json'
_CLASSES = ('derived_index', 'status_detail', 'reader_authority')
_CLASS_PATHS = {'derived_index': 'derived/index', 'status_detail': 'derived/status-detail',
                'reader_authority': 'derived/reader-authority'}
# These select physical files to read. M1 remains the event/schema/replay authority.
_INDEX_STATUS = frozenset(('acceptance', 'revocation', 'exemption', 'exemption_snapshot',
                          'exemption_source_withdrawn', 'exemption_materialized'))
_READERS = frozenset(('records_reader_authorized', 'records_reader_snapshot_authorized',
                     'records_reader_withdrawn', 'records_reader_rule_configured',
                     'records_reader_rule_withdrawn', 'records_reader_materialized'))

# The public history fold is the existing kernel implementation.
replay_history = replay_events


def exact(value, keys, category='invalid-bootstrap'):
    if type(value) is not dict or set(value) != set(keys):
        raise RecordsError(category)
    return value


def sha256(raw: bytes):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class WrappedKeys:
    """Recovery keyrings or protected control copies, acquired only after scope checks."""

    def __init__(self, wrapper: str, wrapping_keys: Callable[[], Mapping[str, bytes]], *,
                 protected_keyrings: Callable[[str], bytes] | None = None):
        if wrapper not in ('recovery', 'control') or (wrapper == 'control') != (protected_keyrings is not None):
            raise RecordsError('invalid-configuration')
        self.wrapper, self._provider, self._protected = wrapper, wrapping_keys, protected_keyrings

    def __repr__(self):
        return f'WrappedKeys(wrapper={self.wrapper!r})'

    def at(self, binding, transport, key_commit, *, expected_generation=None):
        if (transport.binding != binding
                or (transport.credentials.mode == 'control') != (self.wrapper == 'control')):
            raise RecordsError('scope-mismatch')
        try:
            raw = (transport.read(binding.repo('records'), key_commit, '.dracla/recovery/keyring.json')
                   if self.wrapper == 'recovery' else self._protected(key_commit))
            wrapping = dict(self._provider())
            if not wrapping or any(type(k) is not str or not k or type(v) is not bytes or len(v) != 32
                                   for k, v in wrapping.items()):
                raise RecordsError('invalid-key')
            ring = decode_keyring(raw, expected_project_id=binding.project_id,
                                  allowed_capabilities={'records', 'coverage'}, allowed_wrappers={self.wrapper},
                                  known_generations={self.wrapper: tuple(wrapping)})
            result = {'records': {}, 'coverage': {}}
            for copy in ring.keys:
                if expected_generation is not None and copy.wrapper_generation != expected_generation:
                    raise RecordsError('invalid-key')
                result[copy.capability][copy.data_kid] = unwrap_key_copy(copy,
                    expected_project_id=binding.project_id, expected_capability=copy.capability,
                    wrapping_keys={(self.wrapper, g): key for g, key in wrapping.items()})
            if set(result['records'].values()).intersection(result['coverage'].values()):
                raise RecordsError('invalid-key')
            return result
        except Exception:
            raise RecordsError('invalid-key') from None


@dataclass(frozen=True)
class HistorySnapshot:
    binding: ProjectBinding
    events_oid: str
    keys_oid: str
    coverage_oid: str
    derived_oid: str
    operations_oid: str
    state: object = field(repr=False)
    records: tuple[CanonicalEventRecord, ...] = field(repr=False)
    keys: Mapping = field(repr=False)
    generations: Mapping = field(repr=False)
    bootstrap: Mapping = field(repr=False)


@dataclass(frozen=True)
class VerificationReport:
    source_oid: str
    coverage_oid: str
    derived_oid: str
    operations_oid: str
    discrepancies: tuple[str, ...]

    @property
    def valid(self):
        return not self.discrepancies


def _plain(transport, binding, repo, oid, branch, path, keys, *, kid=None):
    try:
        raw = transport.read(repo, oid, path)
        envelope = parse_canonical_json(raw)
        if kid is not None and envelope.get('kid') != kid:
            raise RecordsError('invalid-key')
        return decrypt_json_artifact(raw, expected_project_id=binding.project_id,
                                     expected_identity=resolve_artifact_identity(repo.role, branch, path), keys=keys)
    except RecordsError:
        raise
    except Exception:
        raise RecordsError('invalid-history') from None


def _bootstrap(binding, transport, key_history, event_root):
    repo = binding.repo('records')
    if len(key_history) < 3 or key_history[0].oid != event_root:
        raise RecordsError('invalid-bootstrap')
    k, b = key_history[1:3]
    before, after = transport.tree(repo, k.oid), transport.tree(repo, b.oid)
    if (_MANIFEST in before or _MANIFEST not in after
            or {p: e for p, e in after.items() if p != _MANIFEST} != dict(before)):
        raise RecordsError('invalid-bootstrap')
    raw = transport.read(repo, b.oid, _MANIFEST)
    if transport.read(repo, key_history[-1].oid, _MANIFEST) != raw:
        raise RecordsError('invalid-bootstrap')
    try:
        manifest = exact(parse_canonical_json(raw), ('bootstrap_version', 'project_id', 'install_generation',
                         'release', 'repository_ids', 'records_keyring_candidate_oid', 'current_kids'))
        release = exact(manifest['release'], ('package_version', 'release_policy_sha256', 'source_commit_oid',
                                             'provenance_identity', 'dependency_constraints_sha256'))
        exact(manifest['repository_ids'], ('records', 'coverage', 'control'))
        for value in manifest['repository_ids'].values():
            numeric_id(value)
        exact(manifest['current_kids'], ('records', 'coverage'))
        from packaging.version import Version
        if (type(manifest['bootstrap_version']) is not int or manifest['bootstrap_version'] != 1
                or manifest['project_id'] != binding.project_id or manifest['repository_ids'] != binding.ids()
                or manifest['records_keyring_candidate_oid'] != k.oid
                or type(manifest['install_generation']) is not str or not manifest['install_generation']
                or str(Version(release['package_version'])) != release['package_version']
                or type(release['provenance_identity']) is not str or not release['provenance_identity']):
            raise RecordsError('invalid-bootstrap')
        object_id(release['source_commit_oid'])
        import re
        if any(type(release[p]) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', release[p])
               for p in ('release_policy_sha256', 'dependency_constraints_sha256')):
            raise RecordsError('invalid-bootstrap')
        return manifest, raw, k.oid, b.oid
    except Exception:
        raise RecordsError('invalid-bootstrap') from None


def _keyring_metadata(binding, transport, oid):
    """Inspect pinned recovery-copy identities; these bytes grant no key authority."""
    raw = transport.read(binding.repo('records'), oid, '.dracla/recovery/keyring.json')
    try:
        # Historical wrapper generations need not still have usable secrets.
        # Decode their complete structure, then use only identities below.
        value = parse_canonical_json(raw)
        generations = tuple({copy['wrapper_generation'] for copy in value['keys']})
        return decode_keyring(raw, expected_project_id=binding.project_id,
                              allowed_capabilities={'records', 'coverage'}, allowed_wrappers={'recovery'},
                              known_generations={'recovery': generations})
    except Exception:
        raise RecordsError('invalid-key') from None


def _package(transport, binding, before_oid, commit, event, prior, state, keys, kid, generations):
    """Read exact event files; use authenticated replay for historical relations.

    Live writer observations are not reconstructed from present-day projections.
    They are distinct from canonical historical semantics, checked by M1 replay.
    """
    repo = binding.repo('records')
    before, after = transport.tree(repo, before_oid), transport.tree(repo, commit.oid)
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    expected = {event_path(event.event_id)}
    if event.type == 'agreement_published':
        payload = event.payload
        content, metadata = payload['snapshot_content_path'], payload['snapshot_metadata_path']
        expected.update((content, metadata))
        if content in before or metadata in before:
            raise RecordsError('invalid-history')
        raw = transport.read(repo, commit.oid, content)
        if sha256(raw) != payload['digest'] or sha256(raw) != payload['snapshot_sha256']:
            raise RecordsError('invalid-history')
        raw.decode('utf-8')
        wanted = {'metadata_version': 1, 'agreement_id': event.target['agreement_id'],
                  'version': event.target['version'], **{n: event.to_dict()['payload'][n] for n in
                  ('recipient', 'ref', 'content_commit_oid', 'digest', 'snapshot_sha256')}}
        if canonical_json(parse_canonical_json(transport.read(repo, commit.oid, metadata))) != canonical_json(wanted):
            raise RecordsError('invalid-history')
    if event.type in ('project_connected', 'config_updated'):
        expected.add(_CONFIGURATION)
        if canonical_json(_plain(transport, binding, repo, commit.oid, 'events', _CONFIGURATION, keys, kid=kid)) != canonical_json(event.to_dict()['payload']['project_configuration']):
            raise RecordsError('invalid-history')
    affected = set()
    if event.type == 'project_connected':
        affected.update(_CLASSES)
    elif event.type in _INDEX_STATUS:
        affected.update(('derived_index', 'status_detail'))
    elif event.type in ('exemption_rule_configured', 'exemption_rule_withdrawn'):
        affected.add('status_detail')
        if event.type == 'exemption_rule_withdrawn':
            old = {x.github_user_id for x in prior.exemption_source_records.values()}
            new = {x.github_user_id for x in state.exemption_source_records.values()}
            if old != new:
                affected.add('derived_index')
    elif event.type in _READERS:
        affected.add('reader_authority')
    if affected:
        expected.add(_GENERATIONS)
        desired = {'generations_version': 1, **dict(generations)}
        desired.update({name: event.event_id for name in affected})
        # A source already absent in canonical history can still require a
        # reader-class refresh when the writer observed a stale derivative.
        optional = (event.type == 'records_reader_withdrawn'
                    and prior.reader_source_records == state.reader_source_records)
        if event.type == 'records_reader_rule_withdrawn':
            optional = not prior.reader_rules[event.target['rule_event_id']].active
        if optional and _GENERATIONS not in changed:
            expected.remove(_GENERATIONS)
            current = {'generations_version': 1, **dict(generations)}
        else:
            current = _plain(transport, binding, repo, commit.oid, 'events', _GENERATIONS, keys, kid=kid)
            validate_materialization_generations(current)
            if current != desired:
                raise RecordsError('invalid-history')
        generations = {name: current[name] for name in _CLASSES}
    if changed != expected or any(p not in after for p in expected):
        raise RecordsError('invalid-history')
    return generations


def open_history(binding: ProjectBinding, key_provider: WrappedKeys, transport: RepositoryTransport) -> HistorySnapshot:
    """Return no state until the complete authenticated history passes M1 replay."""
    try:
        if (transport.credentials.mode == 'control') != (key_provider.wrapper == 'control'):
            raise RecordsError('scope-mismatch')
        transport.authorize(binding)  # Must precede the key provider.
        repo, coverage = binding.repo('records'), binding.repo('coverage')
        heads = {branch: transport.head(repo, branch) for branch in ('events', 'keys', 'derived', 'operations')}
        coverage_oid = transport.head(coverage, 'coverage')
        history, key_history = transport.ancestry(repo, heads['events']), transport.ancestry(repo, heads['keys'])
        root = history[0]
        root_tree = transport.tree(repo, root.oid)
        if set(root_tree) != {'README.md'} or not transport.read(repo, root.oid, 'README.md'):
            raise RecordsError('invalid-bootstrap')
        manifest, raw_manifest, key_commit, manifest_commit = _bootstrap(binding, transport, key_history, root.oid)
        if transport.read(coverage, coverage_oid, _MANIFEST) != raw_manifest:
            raise RecordsError('invalid-bootstrap')
        initial_ring = _keyring_metadata(binding, transport, key_commit)
        initial_ids = {(copy.capability, copy.data_kid) for copy in initial_ring.keys}
        if (any(copy.wrapper_generation != manifest['install_generation'] for copy in initial_ring.keys)
                or any((cap, manifest['current_kids'][cap]) not in initial_ids for cap in ('records', 'coverage'))):
            raise RecordsError('invalid-key')
        # A wrapper-only descendant can replace retired wrapping paths. Its
        # raw keys remain candidates until the pinned events authenticate them.
        keys = key_provider.at(binding, transport, heads['keys'])
        kids = manifest['current_kids']
        if any(kids[cap] not in keys[cap] for cap in ('records', 'coverage')):
            raise RecordsError('invalid-key')
        prior = initial_replay_state(binding.project_id, root.oid)
        records, generations = [], {}
        key_positions = {c.oid: number for number, c in enumerate(key_history)}
        activated_position = key_positions[manifest_commit]
        activated_kids = {cap: {kids[cap]} for cap in ('records', 'coverage')}
        activated_bytes = {cap: {keys[cap][kids[cap]]} for cap in ('records', 'coverage')}
        for commit in history[1:]:
            before = prior.current_head_oid
            tree = transport.tree(repo, commit.oid)
            parent = transport.tree(repo, before)
            event_files = [p for p in tree if p.startswith('events/') and tree.get(p) != parent.get(p)]
            if len(event_files) != 1 or event_files[0] in parent:
                raise RecordsError('invalid-history')
            value = _plain(transport, binding, repo, commit.oid, 'events', event_files[0], keys['records'], kid=kids['records'])
            event = validate_event(value, expected_project_id=binding.project_id, expected_path=event_files[0])
            record = CanonicalEventRecord(event, commit.oid, before)
            state = apply_event(prior, record)
            if not records:
                if event.type != 'project_connected' or event.to_dict()['payload']['bootstrap'] != {
                    'install_generation': manifest['install_generation'], 'manifest_commit_oid': manifest_commit,
                    'manifest_sha256': sha256(raw_manifest), 'records_keyring_candidate_oid': key_commit,
                    'repository_ids': manifest['repository_ids'], 'current_kids': manifest['current_kids']}:
                    raise RecordsError('invalid-bootstrap')
            generations = _package(transport, binding, before, commit, event, prior, state,
                                   keys['records'], kids['records'], generations)
            if event.type == 'keyring_activated':
                candidate = event.payload['keys_commit_oid']
                if (key_positions.get(candidate, -1) <= activated_position
                        or transport.read(repo, candidate, _MANIFEST) != raw_manifest):
                    raise RecordsError('invalid-key')
                candidate_ids = {(copy.capability, copy.data_kid)
                                 for copy in _keyring_metadata(binding, transport, candidate).keys}
                successors = state.current_kids
                if all(successors[cap] == kids[cap] for cap in ('records', 'coverage')):
                    raise RecordsError('invalid-key')
                for cap in ('records', 'coverage'):
                    selected = successors[cap]
                    if (cap, selected) not in candidate_ids or selected not in keys[cap]:
                        raise RecordsError('invalid-key')
                    if selected != kids[cap]:
                        if selected in activated_kids[cap] or keys[cap][selected] in activated_bytes[cap]:
                            raise RecordsError('invalid-key')
                        activated_kids[cap].add(selected)
                        activated_bytes[cap].add(keys[cap][selected])
                activated_position = key_positions[candidate]
            kids = state.current_kids
            if any(kids[cap] not in keys[cap] for cap in ('records', 'coverage')):
                raise RecordsError('invalid-key')
            records.append(record)
            prior = state
        result = replay_history(binding.project_id, root.oid, records)
        if (not result.valid or result.state.project_state == 'unconnected'
                or dict(result.state.repository_ids) != binding.ids()
                or result.state.repository_owner['github_account_id'] != binding.owner_id):
            raise RecordsError('invalid-history')
        return HistorySnapshot(binding, heads['events'], heads['keys'], coverage_oid, heads['derived'],
                               heads['operations'], result.state, tuple(records),
                               MappingProxyType({c: MappingProxyType(k) for c, k in keys.items()}),
                               MappingProxyType(generations), MappingProxyType(manifest))
    except RecordsError:
        raise
    except Exception:
        raise RecordsError('invalid-history') from None


def verify_project(binding, key_provider, transport) -> VerificationReport:
    """Compare every stored shard at frozen heads; never mutate a repository."""
    snapshot = open_history(binding, key_provider, transport)
    errors = []
    repo, cov = binding.repo('records'), binding.repo('coverage')
    state, keys, kids = snapshot.state, snapshot.keys, snapshot.state.current_kids
    try:
        coverage = {path: _plain(transport, binding, cov, snapshot.coverage_oid, 'coverage', path,
                                keys['coverage'], kid=kids['coverage'])
                    for path in ['source.enc.json', 'agreements/active.enc.json', 'exemptions.enc.json',
                                 'inflight.enc.json', 'decision-fence.enc.json'] +
                                [f'users/{n:02d}.enc.json' for n in range(32)]}
        marker = decode_inflight_marker(canonical_json(coverage['inflight.enc.json']))
        fence = decode_decision_fence(canonical_json(coverage['decision-fence.enc.json']))
        raw_cell = _plain(transport, binding, repo, snapshot.operations_oid, 'operations',
                          'prepared-operation.enc.json', keys['records'], kid=kids['records'])
        profile = load_release_profile()
        # A pending prepared package requires authenticated action-time
        # preconditions and is non-clean; the reconcile slice owns continuation.
        cell = decode_prepared_operation(canonical_json(raw_cell), expected_project_id=binding.project_id,
                                         max_prepared_operation_bytes=profile.limit('max_prepared_operation_bytes'))
        validate_operation_cross_bindings(cell, fence, marker)
        source = coverage['source.enc.json']
        expected = materialize_coverage(state, (marker, fence), canonical_oid=snapshot.events_oid,
                                       built_at=source['built_at'], dracla_version=source['dracla_version']).to_dict()
        if (canonical_json(coverage) != canonical_json(expected)
                or cell.state != 'idle' or fence.state != 'idle'):
            errors.append('coverage-or-operation-divergence')
        plaintext = materialize_derived(state, profile=profile)
        encrypted, files = {}, {}
        for prefix in _CLASS_PATHS.values():
            for number in range(32):
                path = f'{prefix}/{number:02d}.enc.json'
                encrypted[path] = transport.read(repo, snapshot.derived_oid, path)
                files[path] = _plain(transport, binding, repo, snapshot.derived_oid, 'derived', path,
                                     keys['records'], kid=kids['records'])
        stored = _plain(transport, binding, repo, snapshot.derived_oid, 'derived', 'derived/state.enc.json',
                        keys['records'], kid=kids['records'])
        projection = DerivedProjection(plaintext, stored)
        validate_derived_projection(projection,
            generations={'generations_version': 1, **dict(snapshot.generations)},
            encrypted_shards=encrypted, profile=profile)
        expected_files = {p: parse_canonical_json(raw) for p, raw in plaintext.plaintext_files().items()}
        if canonical_json(files) != canonical_json(expected_files):
            errors.append('private-projection-divergence')
    except Exception:
        errors.append('projection-or-operation-unavailable')
    return VerificationReport(snapshot.events_oid, snapshot.coverage_oid, snapshot.derived_oid,
                              snapshot.operations_oid, tuple(errors))


def authorize_reader(snapshot: HistorySnapshot, numeric_user_id: int,
                     membership: Callable[[int, int, int], bool]) -> bool:
    """Current canonical union; recovery capability alone grants no reader source."""
    if type(numeric_user_id) is not int or numeric_user_id <= 0:
        raise RecordsError('reader-denied')
    for source in reader_sources(snapshot.state, numeric_user_id):
        if source.kind in ('individual', 'snapshot'):
            return True
    uncertain = False
    for source in reader_sources(snapshot.state, numeric_user_id):
        if source.kind == 'continuous_team':
            try:
                if membership(source.team['organization_id'], source.team['team_id'], numeric_user_id) is True:
                    return True
            except Exception:
                uncertain = True
    if uncertain:
        raise RecordsError('reader-denied')
    return False
