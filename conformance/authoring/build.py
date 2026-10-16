"""Source-test authors for the unchanged M1 corpus and reference transitions."""
from __future__ import annotations

import copy
import hashlib
import json
import runpy
from pathlib import Path
from unittest.mock import patch

from dracla.conformance import (
    artifacts, canonical, encoding, envelope, keyrings, event_identity, events,
    replay, action_forms, operations, coverage, derived, release_profile,
)

History = runpy.run_path(str(Path(__file__).with_name('histories.py')))['History']

OWNERS = {
    'artifact-identities-v1.json': ['M1-1'],
    'artifact-envelope-v1.json': ['M1-2'],
    'wrapped-key-v1.json': ['M1-3'],
    'event-identities-v1.json': ['M1-4'],
    'authorization-vocabulary-v1.json': ['M1-4'],
    'events-v1.json': ['M1-5'],
    'replay-v1.json': ['M1-6', 'M1-7'],
    'action-form-v1.json': ['M1-8'],
    'operation-state-v1.json': ['M1-9'],
    'coverage-v1.json': ['M1-10'],
    'derived-v1.json': ['M1-11'],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(row, *, common=None, event_type=None):
    value = dict(common or {}) | row
    result = event_identity.derive_event_identity(
        value['project_id'], value['operation_nonce'], value['actor'],
        event_type or value.get('event_type', value.get('type')),
        value['target'], value['payload'], value['confirmed_canonical_oid'])
    row.update(idempotency_key=result.idempotency_key,
               operation_sha256=result.operation_sha256, event_id=result.event_id)
    if 'event_path' in row:
        row['event_path'] = result.path
    return result


def artifact_vectors(value):
    for row in value['segments']:
        row['token'] = artifacts.segment(row['value'])
    row = value['override_key']
    row['key'] = artifacts.override_key(**{k: v for k, v in row.items() if k != 'key'})
    for row in value['identities']:
        result = artifacts.resolve_artifact_identity(*row[:3])
        row[3:] = [result.artifact_kind, result.capability]


def envelope_vectors(value):
    identity_value = artifacts.resolve_artifact_identity(
        value['repository_role'], value['branch'], value['path'])
    args = dict(project_id=value['project_id'], identity=identity_value,
                kid=bytes.fromhex(value['kid_hex']))
    value['aad_utf8'] = envelope.artifact_aad(**args).decode()
    with patch.object(envelope.secrets, 'token_bytes', return_value=bytes.fromhex(value['nonce_hex'])):
        raw = envelope.encrypt_artifact(value['plaintext_utf8'].encode(),
                                       key=bytes.fromhex(value['key_hex']), **args)
    value['envelope_utf8'] = raw.decode()
    value['ciphertext_base64url'] = json.loads(raw)['ciphertext']


def key_vectors(value):
    with patch.object(keyrings.secrets, 'token_bytes', return_value=bytes.fromhex(value['nonce_hex'])):
        wrapped = keyrings.wrap_key_copy(bytes.fromhex(value['data_key_hex']),
            project_id=value['project_id'], capability=value['capability'],
            data_kid=bytes.fromhex(value['data_kid_hex']), wrapper_id=value['wrapper_id'],
            wrapper_generation=value['wrapper_generation'],
            wrapping_key=bytes.fromhex(value['wrapping_key_hex']))
    value['wrapped_key_base64url'] = wrapped.wrapped_key
    value['aad_utf8'] = keyrings.wrapped_key_aad(wrapped).decode()
    value['copy_utf8'] = wrapped.canonical_bytes.decode()
    value['keyring_utf8'] = keyrings.encode_keyring([wrapped]).decode()


def event_identity_vectors(value):
    for row in value['actors']:
        row['stable'] = event_identity.stable_actor_identity(row['actor'])
    common = value['event_identity_common_input']
    for kind, row in value['event_identity_vectors'].items():
        identity(row, common=common, event_type=kind)
    identity(value['event_identity'])
    for row in value['scope_terminal_identity_variants']:
        identity(row)
    row = value['automation_nonce']
    row['nonce'] = event_identity.derive_automation_nonce(**{k: v for k, v in row.items() if k != 'nonce'})
    row = value['github_retry_nonce']
    row['nonce'] = event_identity.derive_github_retry_nonce(**{k: v for k, v in row.items() if k != 'nonce'})
    row = value['scope_terminal_nonces']
    for name, kind in [('activation', 'enforcement_scope_activated'),
                       ('abandonment', 'enforcement_scope_abandoned')]:
        row[name] = event_identity.derive_scope_terminal_nonce(row['request_event_id'], kind)
    for row in value['deterministic_nonce_variants']:
        args = {k: v for k, v in row.items() if k not in {'nonce', 'domain'}}
        if row['domain'] == 'automation':
            row['nonce'] = event_identity.derive_automation_nonce(**args)
        elif row['domain'] == 'github_retry':
            row['nonce'] = event_identity.derive_github_retry_nonce(**args)
        elif row['domain'] == 'scope_terminal':
            row['nonce'] = event_identity.derive_scope_terminal_nonce(**args)
        else:
            raise ValueError('unknown deterministic nonce fixture domain')
    require(set(value['event_types_v1']) == set(events.EVENT_TYPES), 'event registry changed')


def authorization_vectors(value):
    actual = {tuple(row[1:]) for row in event_identity.AUTHORIZATION_TABLE}
    require(actual == {tuple(row) for row in value['operation_rows']}, 'authorization registry changed')


def event_vectors(value):
    for row in value['events']:
        identity(row)
        event = events.validate_event(row)
        value['precondition_names'][event.type] = [r.name for r in
            events.required_preconditions(event, expected_head='a' * 40)]
    for row in value['source_first_add_paths']:
        row['operation_nonce'] = event_identity.derive_automation_nonce(
            row['source_event_id'], row['github_user_id'], 'add', None)
        digest = hashlib.sha256(b'dracla-idempotency-v1\0' + canonical.canonical_json({
            'project_id': row['project_id'], 'operation_nonce': row['operation_nonce']})).digest()
        row['event_id'] = encoding.base64url_encode(hashlib.sha256(b'dracla-event-v1\0' + digest).digest())
        row['path'] = event_identity.event_path(row['event_id'])


def form_vectors(value):
    keys = {r['kid']: bytes.fromhex(r['key_hex']) for r in value['keys']}
    for row in value['actions']:
        spec = action_forms.form_action_spec(row['type'])
        row.update(write_type=spec.write_type, terminal_types=list(spec.terminal_types))
    for row in [value['golden'], *value['terminal_noops']]:
        form = row['form']
        row['token'] = action_forms.encode_action_form(form, key=keys[form['kid']])
        if 'payload_jcs' in row:
            row['payload_jcs'] = canonical.canonical_json(form).decode()
            row['tag_hex'] = encoding.base64url_decode(row['token'].split('.')[1]).hex()


def operation_vectors(value):
    for field, function in [('append_claim', operations.append_claim),
                            ('check_identity', operations.authoritative_check_identity)]:
        row = value[field]
        row['jcs'] = canonical.canonical_json(row['input']).decode()
        row['expected'] = function(**row['input'])
    for row in value['fences'].values():
        require(operations.decode_decision_fence(canonical.canonical_json(row)).to_dict() == row,
                'decision fence golden does not round-trip')
    for row in value['markers'].values():
        require(operations.decode_inflight_marker(canonical.canonical_json(row)).to_dict() == row,
                'marker golden does not round-trip')
    # Crash expectations are derived from the same thirteen pure transition
    # authors exercised by the independent operation test.  The fixture keeps
    # explicit closed states and the authenticated prepared reference inputs;
    # no checked-in crash result is used as an input to this probe.
    profile = value['profile']
    project_id = value['project_id']
    limit = profile['max_prepared_operation_bytes']
    prepared_wire = value['cells']['prepared']
    prepared_event = events.validate_event(json.loads(
        encoding.base64url_decode(prepared_wire['event_jcs_b64'])))
    events_head = prepared_wire['prepared_events_head']
    preconditions = [{
        'name': 'generations-absence',
        'artifact_kind': 'materialization-generations',
        'repository_role': 'records',
        'branch': 'events',
        'path': 'config/materialization-generations.enc.json',
        'binding_mode': 'events-head',
        'binding': {'mode': 'events-head', 'events_head': events_head},
        'value': None,
    }]
    side_artifacts = [events.SideArtifact(
        row['kind'], row['path'], encoding.base64url_decode(row['bytes_b64']), row['sha256'])
        for row in prepared_wire['side_artifacts']]
    owner = {
        'operation_id': prepared_event.idempotency_key,
        'operation_sha256': prepared_event.operation_sha256,
    }

    def cell(name):
        return operations.decode_prepared_operation(
            canonical.canonical_json(value['cells'][name]),
            expected_project_id=project_id,
            max_prepared_operation_bytes=limit,
            preconditions=preconditions)

    def fence(name):
        return operations.decode_decision_fence(canonical.canonical_json(value['fences'][name]))

    def marker(name):
        return operations.decode_inflight_marker(canonical.canonical_json(value['markers'][name]))

    def reference():
        return operations.PreparedOperationReference(
            'd' * 40, 'e' * 40, cell('prepared'))

    def prepare(current):
        return operations.prepare_operation(
            current, prepared_event, side_artifacts,
            expected_project_id=project_id, expected_events_head=events_head,
            preconditions=preconditions, max_prepared_operation_bytes=limit)

    def terminal(current, result, binding):
        landed = result == 'landed'
        return operations.terminal_operation(
            current, **owner, **binding, result=result,
            observed_events_head='c' * 40,
            canonical_commit='c' * 40 if landed else None,
            projection_verified=landed, readback_verified=landed)

    def actions(current, current_fence, current_marker):
        binding = {
            'fence': current_fence, 'marker': current_marker,
            'prepared_reference': reference(),
        }
        return {
            'prepare': lambda: prepare(current),
            'acquire': lambda: operations.acquire_mutation_fence(
                current_fence, current, reference(), subjects=[], project_wide=True),
            'reserve': lambda: operations.reserve_success(
                current_fence, current_marker,
                check_identity=value['check_identity']['expected'],
                projection_commit=events_head),
            'open': lambda: operations.open_inflight_marker(
                current_marker, current_fence, cell=current,
                prepared_reference=reference(), started_at='2099-01-01T00:00:00Z'),
            'claim': lambda: operations.claim_append(
                current, **owner, **binding, append_head=events_head,
                max_prepared_operation_bytes=limit),
            'noop': lambda: terminal(current, 'semantic_noop', binding),
            'conflict': lambda: terminal(current, 'conflict', binding),
            'landed': lambda: terminal(current, 'landed', binding),
            'close': lambda: operations.close_inflight_marker(
                current_marker, current_fence, cell=current,
                prepared_reference=reference()),
            'close_projected': lambda: operations.close_inflight_marker(
                current_marker, current_fence, cell=current,
                prepared_reference=reference(), projection_verified=True),
            'release': lambda: operations.release_mutation_fence(
                current_fence, fence('mutation'), current, current_marker,
                prepared_reference=reference(), projection_verified=True,
                readback_verified=True),
            'clear': lambda: operations.clear_prepared_operation(
                current, cell('landed'), mutation_fence=fence('mutation'),
                released_fence=current_fence, marker=current_marker,
                prepared_reference=reference()),
            'release_success': lambda: operations.release_success(
                current_fence, fence('success'), completion_verified=True),
        }

    for crash in value['crashes']:
        current = cell(crash['cell'])
        current_fence = fence(crash['fence'])
        current_marker = marker(crash['marker'])
        accepted = []
        for name, action in actions(current, current_fence, current_marker).items():
            try:
                action()
            except (operations.OperationConflict, operations.OperationCorruption):
                continue
            accepted.append(name)
        crash['allowed'] = sorted(accepted)


def coverage_vectors(value):
    for row in value['shard_cases']:
        row['expected'] = coverage.coverage_shard(row['user'], shard_count=32)
    for row in value['evaluation_cases']:
        files = copy.deepcopy(value['empty_files'])
        files['agreements/active.enc.json'] = value['active']
        if row['basis']:
            files['users/07.enc.json']['7'] = {
                'agreements': {'agreement-1': value[row['basis']]}, 'overrides': {}}
        if row['exempt']:
            files['exemptions.enc.json']['7'] = {'active': True}
        result = coverage.evaluate_subject(coverage.CoverageProjection('project-1', files), 7, 'agreement-1')
        row['expected'] = [result.decision, result.reason_code]
    # Currency cases intentionally exercise the same signed row while only the
    # authenticated active-agreement projection changes.  Keep the expected
    # decisions derived from the current author so a change to version
    # ordering cannot leave a stale checked-in expectation behind.
    for row in value['currency_cases']:
        files = copy.deepcopy(value['empty_files'])
        files['agreements/active.enc.json'] = copy.deepcopy(value['active'])
        files['users/07.enc.json']['7'] = {
            'agreements': {'agreement-1': copy.deepcopy(value['signed'])},
            'overrides': {},
        }
        files['agreements/active.enc.json'].update(
            {key: row[key] for key in ('active_version', 'accepted_versions', 'retired_versions')})
        result = coverage.evaluate_subject(coverage.CoverageProjection('project-1', files), 7, 'agreement-1')
        row['expected'] = [result.decision, result.reason_code]
    # Combined-basis cases exercise the precedence between a contributor row
    # and an exemption.  These inputs mirror the independent coverage tests;
    # the exemption and basis are both evaluated by the current author.
    for row in value['combined_basis_cases']:
        files = copy.deepcopy(value['empty_files'])
        files['agreements/active.enc.json'] = copy.deepcopy(value['active'])
        if row['basis']:
            files['users/07.enc.json']['7'] = {
                'agreements': {'agreement-1': copy.deepcopy(value[row['basis']])},
                'overrides': {},
            }
        if row['exempt']:
            files['exemptions.enc.json']['7'] = {'active': True}
        files['agreements/active.enc.json'].update(row['active'])
        result = coverage.evaluate_subject(coverage.CoverageProjection('project-1', files), 7, 'agreement-1')
        row['expected'] = [result.decision, result.reason_code]
    for row in value['version_ordering_cases']:
        row['canonical_json'] = [canonical.canonical_json(x).decode() for x in row['canonical_values']]


def derived_vectors(value):
    for row in value['source_shards']:
        row['shard'] = derived.reader_authority_shard(row['source_id'])
    # Decode independent wire goldens, validate complete shard schemas, and
    # re-encode through the author. Their fixed expected bytes remain independent.
    profile = release_profile.load_release_profile()
    for group in ['status_rows', 'exemption_source_rows']:
        for row in value['wire_goldens'][group]:
            files = copy.deepcopy(value['empty_shards'])
            for field, path in [('status_detail_bytes_hex', 'derived/status-detail/07.enc.json'),
                                ('index_bytes_hex', 'derived/index/07.enc.json')]:
                chunks = row[field]
                raw = bytes.fromhex(''.join(chunks) if isinstance(chunks, list) else chunks)
                files[path] = json.loads(raw)
                require(canonical.canonical_json(files[path]) == raw, 'derived wire golden changed')
            rules = {}
            for detail in files['derived/status-detail/07.enc.json'].values():
                for source in detail['exemption_sources'].values():
                    if source['rule_event_id'] is not None:
                        rules[source['rule_event_id']] = {k: source[k] for k in ('team', 'basis', 'instrument_ref')}
            derived.DerivedPlaintext('project-1', 'b' * 40, files=files,
                standing_rules=rules, configuration=_configuration, profile=profile)


def hex_like(raw, previous):
    text = raw.hex()
    width = len(previous[0])
    return [text[i:i + width] for i in range(0, len(text), width)]


def rebuild_private_goldens(value, rows):
    history = History(rows)
    profile = release_profile.load_release_profile()

    def plain(records):
        result = replay.replay_events('project-1', 'b' * 40, records)
        require(result.valid, 'private golden history failed')
        return derived.materialize_derived(result.state, profile=profile)

    def stage(target, records):
        actual = plain(records).plaintext_files()
        for path, previous in target.items():
            target[path] = hex_like(actual[path], previous)

    goldens = value['wire_goldens']
    golden = goldens['pre_agreement_exemption']
    inputs = golden['inputs']
    records = []
    history.append(records, 'project_connected', inputs['connected_nonce'])
    source = history.exemption_event(inputs['exemption_nonce'], inputs['source_kind'])
    records.append(history.record(source, records[-1].commit_oid, len(records) + 1))
    golden['source_event_id'] = source.event_id
    stage(golden['stages']['exempted'], records)
    history.append(records, 'exemption_source_withdrawn', inputs['withdrawal_nonce'],
                   **{'target.source_event_id': source.event_id})
    stage(golden['stages']['withdrawn'], records)

    golden = goldens['canonical_signature']
    inputs = golden['inputs']
    records, _, _ = history.active_records(nonce=inputs['active_nonce'])
    acceptance = history.append(records, 'acceptance', inputs['acceptance_nonce'])
    golden['acceptance_event_id'] = acceptance.event_id
    stage(golden['stages']['accepted'], records)
    revocation = history.append(records, 'revocation', inputs['revocation_nonce'])
    golden['revocation_event_id'] = revocation.event_id
    stage(golden['stages']['revoked'], records)

    golden = goldens['canonical_recorded_exemption']
    inputs = golden['inputs']
    records, _, _ = history.active_records(nonce=inputs['active_nonce'])
    source = history.exemption_event(inputs['exemption_nonce'], inputs['source_kind'])
    records.append(history.record(source, records[-1].commit_oid, len(records) + 1))
    golden['source_event_id'] = source.event_id
    stage(golden['stage'], records)

    golden = goldens['canonical_readers']
    inputs = golden['inputs']
    records = []
    history.append(records, 'project_connected', inputs['connected_nonce'])
    individual = history.append(records, 'records_reader_authorized', inputs['individual_nonce'])
    snapshot = history.append(records, 'records_reader_snapshot_authorized', inputs['snapshot_nonce'])
    rule = history.append(records, 'records_reader_rule_configured', inputs['continuous_rule_nonce'])
    addition = history.reader_materialization_event(rule, 'add', None,
        **{'target.subject.github_user_id': inputs['continuous_add_subject'],
           'payload.membership_evidence.github_user_id': inputs['continuous_add_subject']})
    records.append(history.record(addition, records[-1].commit_oid, len(records) + 1))
    golden['source_event_ids'] = {'individual': individual.event_id, 'snapshot': snapshot.event_id,
                                'continuous_team': rule.event_id, 'continuous_add': addition.event_id}
    stage(golden['files'], records)

    for name in ['assembled_state', 'canonical_assembled_state']:
        golden = goldens[name]
        inputs = golden.get('inputs', {'connected_nonce': 1000})
        records = []
        history.append(records, 'project_connected', inputs['connected_nonce'])
        if 'standing_rule_nonce' in inputs:
            rule = history.append(records, 'exemption_rule_configured', inputs['standing_rule_nonce'])
            golden['rule_event_id'] = rule.event_id
        private = plain(records)
        fixture = golden['fixture']
        encrypted = {}
        with patch.object(envelope.secrets, 'token_bytes', return_value=bytes.fromhex(fixture['nonce_hex'])):
            for path, raw in private.plaintext_files().items():
                encrypted[path] = envelope.encrypt_artifact(raw, project_id=fixture['project_id'],
                    identity=artifacts.resolve_artifact_identity('records', 'derived', path),
                    kid=bytes.fromhex(fixture['kid_hex']), key=bytes.fromhex(fixture['key_hex']))
        assembled = derived.assemble_derived_projection(private, canonical_oid=private.canonical_oid,
            generations={'generations_version': 1, **golden['generations']},
            encrypted_shards=encrypted, profile=profile)
        golden['bytes_hex'] = hex_like(assembled.plaintext_files()['derived/state.enc.json'], golden['bytes_hex'])
        if 'standing_rule' in golden:
            golden['standing_rule'] = private.to_dict()['standing_rules'][golden['rule_event_id']]
            golden['digest_token_counts'] = {k: len(v) for k, v in assembled.state_dict()['shard_digests'].items()}


_configuration = None
BUILDERS = {
    'artifact-identities-v1.json': artifact_vectors,
    'artifact-envelope-v1.json': envelope_vectors,
    'wrapped-key-v1.json': key_vectors,
    'event-identities-v1.json': event_identity_vectors,
    'authorization-vocabulary-v1.json': authorization_vectors,
    'events-v1.json': event_vectors,
    'action-form-v1.json': form_vectors,
    'operation-state-v1.json': operation_vectors,
    'coverage-v1.json': coverage_vectors,
    'derived-v1.json': derived_vectors,
}


def case_registry(value):
    """Stable identities for every top-level field and every collection member."""
    result = []
    for field, data in value.items():
        result.append(field)
        if isinstance(data, list):
            for index, row in enumerate(data):
                label = row.get('id', row.get('name', str(index))) if isinstance(row, dict) else str(index)
                result.append(f'{field}/{label}')
        elif isinstance(data, dict):
            result.extend(f'{field}/{key}' for key in data)
    require(len(result) == len(set(result)), 'duplicate corpus case identity')
    return result


def build(root: Path):
    global _configuration
    source = root / 'conformance/authoring'
    fixtures = {name: json.loads((source / name).read_bytes()) for name in OWNERS}
    rows = {r['type']: r for r in fixtures['events-v1.json']['events']}
    _configuration = rows['project_connected']['payload']['project_configuration']
    outputs, registry = {}, {}
    for name, owners in OWNERS.items():
        original = (source / name).read_bytes()
        value = copy.deepcopy(fixtures[name])
        if name in BUILDERS:
            BUILDERS[name](value)
            if name == 'derived-v1.json':
                rebuild_private_goldens(value, rows)
        else:
            history = History(rows)
            for case in value['valid_cases']:
                records = history.vector_records(case['name'])
                result = replay.replay_events(case['project_id'], value['base_commit_oid'], records)
                require(result.valid, f"replay failed: {case['name']}")
                state = result.state
                case['record_types'] = [r.event.type for r in records]
                case['expected_project_state'] = state.project_state
                case['expected_unresolved'] = state.to_dict()['unresolved']
                for key, attr in [('expected_active_version', 'active_version'),
                                  ('expected_accepted_versions', 'accepted_versions'),
                                  ('expected_retired_versions', 'retired_versions'),
                                  ('expected_keyring_generation', 'keyring_generation'),
                                  ('expected_successor_project_id', 'successor_project_id')]:
                    if key in case:
                        actual = getattr(state, attr)
                        case[key] = list(actual) if isinstance(actual, tuple) else actual
                if 'expected_latest_decision' in case:
                    decision = replay.latest_contributor_tuple_decision(state, records[3].event.target['coverage_tuple'])
                    case['expected_latest_decision'] = decision.decision
        # Preserve historical formatting only after computing and comparing the
        # value. Destination files are never consulted by this author.
        outputs[name] = original if value == fixtures[name] else (json.dumps(value, indent=2) + '\n').encode()
        registry[name] = {'authoring_slices': owners, 'cases': case_registry(value)}
    # Loaded beside this file; source-test helpers are not installed runtime API.
    import importlib.util
    spec = importlib.util.spec_from_file_location('dracla_transition_author', source / 'transitions.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    value = module.build(rows, fixtures)
    name = 'incremental-v1.json'
    outputs[name] = (json.dumps(value, separators=(',', ':')) + '\n').encode()
    registry[name] = {'authoring_slices': ['M1-12'], 'cases': case_registry(value)}
    return outputs, registry
