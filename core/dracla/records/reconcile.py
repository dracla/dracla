"""Authenticated projection publication and repair-forward operation recovery."""
from __future__ import annotations

from dataclasses import dataclass
import time

from dracla.conformance import (
    DerivedClassOverflow, DerivedProjection, assemble_derived_projection,
    base64url_decode, canonical_json, decrypt_json_artifact, encrypt_json_artifact,
    materialize_coverage, materialize_derived, parse_canonical_json,
    parse_event_jcs, resolve_artifact_identity, validate_derived_projection,
    CanonicalShaBinding, EventsHeadBinding, GenerationBinding, PreconditionEvidence,
    decode_decision_fence, decode_inflight_marker, load_release_profile,
    reader_authority_shard, required_preconditions,
)
from .append import MutationEngine, RecoveryBlocked
from .credentials import RecordsError
from .github import HeadConflict, IndeterminateWrite
from .history import open_history, verify_project


@dataclass(frozen=True)
class ReconciliationReport:
    source_oid: str | None
    status: str
    reason: str | None = None

    @property
    def valid(self):
        return self.status == 'complete'


class StoredPreconditions:
    """Read M1 action facts from authenticated immutable repository versions.

    Replay authenticates canonical relations. Coverage and private observations
    must exist in actual stored commits and pass complete materialization
    comparison; replay is not a substitute for a writer's prior observation.
    Registry and cross-project facts require their external integration.
    """

    def __init__(self, binding, key_provider, transport):
        self.binding, self.key_provider, self.transport = binding, key_provider, transport
        self.profile = load_release_profile()

    def _canonical_value(self, snapshot, path):
        # open_history already authenticated each introduction at its actual
        # parent-selected key. Inherited canonical blobs remain decrypt-only
        # after rotation; unlike live projections they must not be rekeyed.
        raw = self.transport.read(self.binding.repo('records'), snapshot.events_oid, path)
        return decrypt_json_artifact(raw, expected_project_id=self.binding.project_id,
            expected_identity=resolve_artifact_identity('records', 'events', path), keys=snapshot.keys['records'])

    def _coverage(self, snapshot, *, historical):
        repo = self.binding.repo('coverage')
        paths = ['source.enc.json', 'agreements/active.enc.json', 'exemptions.enc.json',
                 'inflight.enc.json', 'decision-fence.enc.json'] + [f'users/{i:02d}.enc.json' for i in range(32)]
        commits = (reversed(self.transport.ancestry(repo, snapshot.coverage_oid)) if historical
                   else [self.transport.commit(repo, snapshot.coverage_oid)])
        for commit in commits:
            try:
                source = _plain(snapshot, self.transport, 'coverage', 'coverage', commit.oid, paths[0])
                if source['canonical_sha'] != snapshot.events_oid:
                    continue
                values = {p: _plain(snapshot, self.transport, 'coverage', 'coverage', commit.oid, p) for p in paths}
                marker = decode_inflight_marker(canonical_json(values['inflight.enc.json']))
                fence = decode_decision_fence(canonical_json(values['decision-fence.enc.json']))
                expected = materialize_coverage(snapshot.state, (marker, fence), canonical_oid=snapshot.events_oid,
                    built_at=source['built_at'], dracla_version=source['dracla_version']).to_dict()
                if canonical_json(values) == canonical_json(expected):
                    return commit.oid, values
            except (ValueError, RecordsError, KeyError, TypeError):
                continue
        raise RecoveryBlocked('authenticated-preconditions-unavailable')

    def _derived(self, snapshot, *, historical):
        plaintext = materialize_derived(snapshot.state, profile=self.profile)
        expected = {p: parse_canonical_json(raw) for p, raw in plaintext.plaintext_files().items()}
        repo = self.binding.repo('records')
        commits = (reversed(self.transport.ancestry(repo, snapshot.derived_oid)) if historical
                   else [self.transport.commit(repo, snapshot.derived_oid)])
        for commit in commits:
            try:
                state = _plain(snapshot, self.transport, 'records', 'derived', commit.oid, 'derived/state.enc.json')
                if state['generations'] != dict(snapshot.generations):
                    continue
                envelopes = {p: self.transport.read(repo, commit.oid, p) for p in expected}
                values = {p: _plain(snapshot, self.transport, 'records', 'derived', commit.oid, p) for p in expected}
                validate_derived_projection(DerivedProjection(plaintext, state),
                    generations={'generations_version': 1, **dict(snapshot.generations)},
                    encrypted_shards=envelopes, profile=self.profile)
                if canonical_json(values) == canonical_json(expected):
                    return values, state
            except (ValueError, RecordsError, KeyError, TypeError):
                continue
        raise RecoveryBlocked('authenticated-preconditions-unavailable')

    def __call__(self, event, head):
        latest = open_history(self.binding, self.key_provider, self.transport)
        if head not in {r.commit_oid for r in latest.records}:
            raise RecordsError('invalid-history')
        snapshot = (latest if head == latest.events_oid else
                    open_history(self.binding, self.key_provider, self.transport.at_events(head)))
        requirements = required_preconditions(event, expected_head=head)
        if event.type == 'project_connected' or any(r.binding_mode in ('registry-generation', 'cross-project') for r in requirements):
            raise RecoveryBlocked('authenticated-external-evidence-required')
        # Historical immutable reads reconstruct a frozen package. Live action
        # facts must use the exact observed heads, even when older clean data
        # exists. Otherwise current corruption could be hidden by fallback.
        historical = head != latest.events_oid
        coverage = self._coverage(snapshot, historical=historical) if any(r.binding_mode == 'canonical-sha' for r in requirements) else None
        derived = self._derived(snapshot, historical=historical) if any(r.binding_mode == 'generation' for r in requirements) else None
        replay = snapshot.state.to_dict()
        values = []
        def link(event_value):
            return {k: event_value[k] for k in ('event_id', 'type', 'project_id', 'target', 'payload')}
        for requirement in requirements:
            name = requirement.name
            if requirement.binding_mode == 'events-head':
                binding = EventsHeadBinding(head)
                if name == 'keyring-affected-repositories':
                    value = {'project_id': self.binding.project_id, 'repository_ids': self.binding.ids()}
                elif name == 'current-project-agreement':
                    value = {'project_id': self.binding.project_id, 'recipient': replay['recipient'],
                        'agreement_id': snapshot.state.agreement_id,
                        'published_versions': [{'agreement_id': a, 'version': v} for a, v in snapshot.state.publications]}
                else:
                    tree = self.transport.tree(self.binding.repo('records'), head)
                    if name in ('source-first-add', 'publication-snapshot-absence', 'publication-metadata-absence'):
                        present = requirement.path in tree
                        value = {'path': requirement.path, 'present': present}
                        if name == 'source-first-add' and present:
                            value['event'] = self._canonical_value(snapshot, requirement.path)
                    else:
                        raw = self._canonical_value(snapshot, requirement.path)
                        if name == 'prior-generations':
                            value = {k: raw[k] for k in snapshot.generations}
                        elif name == 'current-configuration':
                            value = raw
                        elif name == 'override-grant':
                            grant = snapshot.state.override_grants.get(event.target['override_event_id'])
                            value = {'event': link(raw), 'active': grant is not None and grant.active}
                        else:
                            value = link(raw)
            elif requirement.binding_mode == 'canonical-sha':
                coverage_head, files = coverage
                binding = CanonicalShaBinding(coverage_head, head)
                if name == 'project-lifecycle':
                    value = {'project_id': self.binding.project_id, 'state': files['source.enc.json']['project_state'],
                             'successor_project_id': files['source.enc.json']['successor_project_id']}
                elif name == 'active-agreement':
                    value = files['agreements/active.enc.json']
                    if event.type == 'acceptance':
                        publication = snapshot.state.publications[(snapshot.state.agreement_id, snapshot.state.active_version)]
                        published = link(snapshot.state.event_records[publication.event_id].event.to_dict())
                        value = {'project_id': self.binding.project_id, 'agreement_id': snapshot.state.agreement_id,
                            'version': snapshot.state.active_version, 'recipient': replay['recipient'],
                            'digest': published['payload']['digest'], 'state': 'active',
                            'accepted_versions': list(snapshot.state.accepted_versions),
                            'retired_versions': list(snapshot.state.retired_versions), 'active_version': snapshot.state.active_version,
                            'activation_event_id': snapshot.state.activation_event_id,
                            'supersedes_coverage': snapshot.state.supersedes_coverage, 'publication': published}
                else:
                    subject_ids, _ = _scope_from_event(event)
                    shard = int(name.rsplit('-', 1)[1])
                    value = {'project_id': self.binding.project_id, 'state': 'current',
                        'resource': event.to_dict()['target'], 'subject_ids': [n for n in subject_ids if n % 32 == shard]}
            else:
                files, state = derived
                klass = ('reader_authority' if requirement.artifact_kind == 'reader-authority'
                         or name == 'current-derived-state' and event.type == 'records_reader_rule_configured'
                         else 'status_detail')
                generation = state['generations'][klass]
                binding = GenerationBinding(head, snapshot.generations[klass], generation)
                value = self._derived_fact(event, name, requirement.path, files, state, generation)
            values.append(PreconditionEvidence(name, requirement.artifact_kind, requirement.repository_role,
                requirement.branch, requirement.path, requirement.binding_mode, binding, value))
        return values

    def _derived_fact(self, event, name, path, files, state, generation):
        project = {'project_id': self.binding.project_id}
        target = event.to_dict()['target']
        if name in ('current-derived-state', 'active-exemption-rule-state'):
            value = {**project, 'standing_rule_event_ids': list(state['standing_rules'])}
            if name == 'current-derived-state':
                for key in ('max_continuous_exemption_rules', 'max_state_ciphertext_bytes'):
                    value[key] = self.profile.limit(key)
                if event.type == 'records_reader_rule_configured':
                    value['max_continuous_reader_rules'] = self.profile.limit('max_continuous_reader_rules')
            return value
        if name.startswith('current-exemption-union-'):
            rows = files[path]
            subjects = [{'github_user_id': int(n), 'login_snapshot': row['login_snapshot']}
                        for n, row in rows.items() if row['exemption_sources']]
            return {**project, 'subjects': subjects,
                    'provenance': {str(s['github_user_id']): list(rows[str(s['github_user_id'])]['exemption_sources']) for s in subjects}}
        if name.startswith('active-reader-rules-'):
            return {**project, 'rule_event_ids': [n for n, row in files[path].items() if row['kind'] == 'continuous_team']}
        subject = target.get('subject')
        if name == 'current-acceptance-basis':
            user = target['coverage_tuple']['github_user_id']; agreement = target['coverage_tuple']['agreement_id']
            return {**project, 'github_user_id': user, 'agreement_id': agreement,
                    'basis': files[path][str(user)]['agreements'][agreement]['basis']}
        if name == 'materialization-cursor':
            rule = target['rule_event_id']; user = str(subject['github_user_id'])
            row = files[path].get(user, {}) if event.type == 'exemption_materialized' else files[path].get(rule, {})
            cursor = row.get('materialization_cursor', {}).get(rule if event.type == 'exemption_materialized' else user)
            return {'cursor_event_id': cursor, 'prior_materialization_event_id': cursor,
                    'rule_event_id': rule, 'subject': subject}
        source = target.get('source_event_id', target.get('rule_event_id'))
        rows = {key: row for p, shard in files.items() if p.startswith('derived/reader-authority/') for key, row in shard.items()}
        if name == 'reader-authority-state':
            members = [key for key, row in rows.items() if (key == source and
                (subject is None or str(subject['github_user_id']) in row['subjects']))]
            identity = {'source_event_id': source, 'subject': subject} if subject else {'rule_event_id': source}
            return {**project, 'class_state': 'current', 'source_event_ids': members,
                    'cursor_event_id': generation, **identity}
        if name == 'current-reader-authority':
            wanted = ([s['github_user_id'] for s in target['subjects']] if 'subjects' in target
                      else [subject['github_user_id']])
            sources = [key for key, row in rows.items() if any(str(n) in row['subjects'] for n in wanted)]
            value = {**project, 'class_state': 'current', 'sources': sources, 'cursor_event_id': generation}
            if event.type == 'records_reader_materialized':
                value.update(rule_event_id=source, subject=subject, source_record_present=source in rows)
            return value
        raise RecoveryBlocked('authenticated-preconditions-unavailable')


def _encrypt(snapshot, role, branch, values):
    kid = snapshot.state.current_kids[role]
    return {path: encrypt_json_artifact(value, project_id=snapshot.binding.project_id,
        identity=resolve_artifact_identity(role, branch, path), kid=base64url_decode(kid),
        key=snapshot.keys[role][kid]) for path, value in values.items()}


def _plain(snapshot, transport, role, branch, head, path):
    raw = transport.read(snapshot.binding.repo(role), head, path)
    envelope = parse_canonical_json(raw)
    if type(envelope) is not dict or envelope.get('kid') != snapshot.state.current_kids[role]:
        raise RecordsError('invalid-key')
    return decrypt_json_artifact(raw, expected_project_id=snapshot.binding.project_id,
        expected_identity=resolve_artifact_identity(role, branch, path), keys=snapshot.keys[role])


def _same_source(snapshot, transport):
    if transport.head(snapshot.binding.repo('records'), 'events') != snapshot.events_oid:
        raise HeadConflict('snapshot-changed')


def publish_coverage(state, transport, *, built_at, dracla_version):
    """Refresh public facts under the exact owner without a private-size cap."""
    snapshot = state.snapshot
    if state.fence.state != 'mutation' or state.released_fence is not None:
        raise RecoveryBlocked('route-unavailable-proof-required')
    _same_source(snapshot, transport)
    coverage = materialize_coverage(snapshot.state, (state.marker, state.fence),
        canonical_oid=snapshot.events_oid, built_at=built_at, dracla_version=dracla_version).to_dict()
    repo, head = snapshot.binding.repo('coverage'), snapshot.coverage_oid
    try:
        stored = {p: _plain(snapshot, transport, 'coverage', 'coverage', head, p) for p in coverage}
        source = stored['source.enc.json']
        current = materialize_coverage(snapshot.state, (state.marker, state.fence),
            canonical_oid=snapshot.events_oid, built_at=source['built_at'],
            dracla_version=source['dracla_version']).to_dict()
    except (ValueError, RecordsError, KeyError, TypeError):
        pass
    else:
        if canonical_json(stored) == canonical_json(current):
            # Valid observation metadata belongs to the existing writer.
            _same_source(snapshot, transport)
            return head
    head = transport.conditional_commit(repo, 'coverage', head,
                                        _encrypt(snapshot, 'coverage', 'coverage', coverage))
    values = {p: _plain(snapshot, transport, 'coverage', 'coverage', head, p) for p in coverage}
    if canonical_json(values) != canonical_json(coverage):
        raise RecordsError('invalid-history')
    _same_source(snapshot, transport)
    return head


def publish_projections(state, transport, *, profile, built_at, dracla_version):
    """Publish public coverage before private derived output, under this fence.

    A failed or partial bulk publication retains the old state and the open
    operation. Readers cannot mistake those shards for a complete generation.
    Overflow is checked before private writes and never alters canonical
    evidence; public coverage is already current when private output overflows.
    """
    snapshot = state.snapshot
    if state.fence.state != 'mutation' or state.released_fence is not None:
        raise RecoveryBlocked('route-unavailable-proof-required')
    # Coverage is the uncapped public result required for every landed
    # operation. Publish it before any private materialization or assembly can
    # raise DerivedClassOverflow, while retaining the same fence and source
    # checks used by the private publication path.
    coverage_head = publish_coverage(state, transport, built_at=built_at, dracla_version=dracla_version)
    plaintext = materialize_derived(snapshot.state, profile=profile)
    expected = {path: parse_canonical_json(raw) for path, raw in plaintext.plaintext_files().items()}
    encrypted = _encrypt(snapshot, 'records', 'derived', expected)
    projection = assemble_derived_projection(plaintext, canonical_oid=snapshot.events_oid,
        generations={'generations_version': 1, **dict(snapshot.generations)},
        encrypted_shards=encrypted, profile=profile)
    derived_repo = snapshot.binding.repo('records')
    derived_head = snapshot.derived_oid
    try:
        stored_envelopes = {p: transport.read(derived_repo, derived_head, p) for p in expected}
        stored_values = {p: _plain(snapshot, transport, 'records', 'derived', derived_head, p)
                         for p in expected}
        stored = _plain(snapshot, transport, 'records', 'derived', derived_head, 'derived/state.enc.json')
        validate_derived_projection(DerivedProjection(plaintext, stored),
            generations={'generations_version': 1, **dict(snapshot.generations)},
            encrypted_shards=stored_envelopes, profile=profile)
        derived_current = canonical_json(stored_values) == canonical_json(expected)
    except (ValueError, RecordsError, KeyError):
        derived_current = False
    if not derived_current:
        # The existing release profile limits each bulk write to at most 32
        # shards. The sole final state write binds all 96 encrypted envelopes.
        paths = sorted(encrypted)
        batch = profile.limit('max_bulk_shards_per_operation')
        for offset in range(0, len(paths), batch):
            _same_source(snapshot, transport)
            derived_head = transport.conditional_commit(derived_repo, 'derived', derived_head,
                {p: encrypted[p] for p in paths[offset:offset + batch]})
        _same_source(snapshot, transport)
        derived_head = transport.conditional_commit(derived_repo, 'derived', derived_head,
            _encrypt(snapshot, 'records', 'derived', {'derived/state.enc.json': projection.state_dict()}))
        # Read actual immutable envelopes and every plaintext shard. A success
        # response alone is not evidence of a valid projection.
        readback = {p: transport.read(derived_repo, derived_head, p) for p in expected}
        values = {p: _plain(snapshot, transport, 'records', 'derived', derived_head, p) for p in expected}
        stored = _plain(snapshot, transport, 'records', 'derived', derived_head, 'derived/state.enc.json')
        validate_derived_projection(DerivedProjection(plaintext, stored),
            generations={'generations_version': 1, **dict(snapshot.generations)},
            encrypted_shards=readback, profile=profile)
        if canonical_json(values) != canonical_json(expected):
            raise RecordsError('invalid-history')
    # The complete CAS includes the exact same-head operation guards. It can
    # neither overwrite another owner nor publish a stale marker/fence pair.
    _same_source(snapshot, transport)
    return coverage_head, derived_head


def _scope_from_event(event):
    target = event.to_dict()['target']
    if event.type in ('acceptance', 'revocation'):
        subjects = [target['coverage_tuple']['github_user_id']]
    elif event.type == 'override':
        subjects = [s['github_user_id'] for s in event.payload['subjects']]
    elif 'subject' in target:
        subjects = [target['subject']['github_user_id']]
    elif 'subjects' in target:
        subjects = [s['github_user_id'] for s in target['subjects']]
    else:
        return [], True
    return sorted(subjects), False


def _scope(reference):
    return _scope_from_event(parse_event_jcs(base64url_decode(reference.cell.to_dict()['event_jcs_b64'])))


def reconcile_project(binding, key_provider, transport, *, preconditions=None,
                      built_at, dracla_version, sleep=time.sleep):
    """Resume one durable operation; never infer M4 confirmation or liveness.

    Default evidence comes from actual immutable stored artifacts. A trusted
    host can supply its authenticated M1 provider for external facts. Neither
    configuration nor business data can select a provider or executable code.
    """
    engine = MutationEngine(binding, key_provider, transport,
        preconditions if preconditions is not None else StoredPreconditions(binding, key_provider, transport), sleep=sleep)
    source = None
    repaired_source = None
    retry_reason = 'indeterminate'
    for attempt in range(engine.profile.limit('max_mutation_retries')):
        try:
            state = engine.recovery_state()
            source = state.snapshot.events_oid
            if state.cell.state == 'idle':
                report = verify_project(binding, key_provider, transport)
                return ReconciliationReport(report.source_oid, 'complete' if report.valid else 'blocked',
                    None if report.valid else 'route-unavailable-proof-required')
            if state.released_fence is None:
                if state.cell.state in ('prepared', 'appending'):
                    subjects, project_wide = _scope(state.reference)
                    engine.begin(state.reference, subjects=subjects, project_wide=project_wide,
                                 started_at=built_at)
                    try:
                        outcome = engine.append(state.reference)
                    except RecoveryBlocked as error:
                        if error.reason != 'authenticated-preconditions-unavailable':
                            raise
                        current = engine.recovery_state()
                        source = current.snapshot.events_oid
                        if repaired_source == current.snapshot.events_oid:
                            raise
                        # A completed repair cannot manufacture missing facts.
                        # The publisher refreshes uncapped coverage first.
                        publish_projections(current, transport, profile=engine.profile,
                            built_at=built_at, dracla_version=dracla_version)
                        repaired_source = current.snapshot.events_oid
                        retry_reason = error.reason
                        continue
                    if outcome.result == 'indeterminate':
                        return ReconciliationReport(outcome.observed_events_head, 'blocked', 'indeterminate')
                    state = engine.recovery_state()
                coverage_head, derived_head = publish_projections(state, transport, profile=engine.profile,
                    built_at=built_at, dracla_version=dracla_version)
                refreshed = engine.recovery_state()
                if (refreshed.snapshot.events_oid != state.snapshot.events_oid
                        or refreshed.snapshot.coverage_oid != coverage_head
                        or refreshed.snapshot.derived_oid != derived_head
                        or refreshed.snapshot.operations_oid != state.snapshot.operations_oid):
                    raise HeadConflict('snapshot-changed')
                state = refreshed
            engine.complete(state, projection_verified=state.released_fence is None)
            report = verify_project(binding, key_provider, transport)
            return ReconciliationReport(report.source_oid, 'complete' if report.valid else 'blocked',
                None if report.valid else 'route-unavailable-proof-required')
        except DerivedClassOverflow:
            return ReconciliationReport(source, 'blocked', 'derived-overflow')
        except RecoveryBlocked as error:
            return ReconciliationReport(source, 'blocked', error.reason)
        except (HeadConflict, IndeterminateWrite):
            retry_reason = 'indeterminate'
            sleep(engine.jitter(attempt))
        except RecordsError:
            raise
        except ValueError:
            raise RecordsError('invalid-history') from None
    return ReconciliationReport(source, 'blocked', retry_reason)
