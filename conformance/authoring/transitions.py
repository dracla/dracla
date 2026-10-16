"""Full-reference transition oracles. No incremental materializer lives here."""
from __future__ import annotations

import copy
import json
from unittest.mock import patch

from dracla.conformance import (
    canonical_json, replay_events, materialize_coverage, materialize_derived,
    decode_inflight_marker, decode_decision_fence, load_release_profile,
    coverage_delta, derived_delta, base64url_encode, assemble_derived_projection,
    artifacts, envelope, events,
)
from conformance.authoring.histories import History, BASE

TIME = '2026-01-01T00:00:00Z'
VERSION = 'conformance-test-only'
_DERIVED_CLASSES = ('derived_index', 'status_detail', 'reader_authority')
_CRYPTO = {
    # Fixed values are source-test inputs only. Production envelope generation
    # continues to select a fresh nonce and runtime key.
    'kid_hex': '6b' * 16,
    'key_hex': '6b' * 32,
    'nonce_hex': '00' * 12,
}


def _authenticated_affected_classes(event, before_private, before_records,
                                     before_generations):
    """Resolve classes through the existing authenticated effect author."""
    if event.type not in {'exemption_rule_withdrawn',
                          'records_reader_withdrawn',
                          'records_reader_rule_withdrawn'}:
        return events._affected_classes_for(event, {})

    head = before_records[-1]
    if event.type == 'exemption_rule_withdrawn':
        binding = events.GenerationBinding(
            events_head=head.commit_oid,
            canonical_generation=before_generations['status_detail'],
            derived_generation=before_generations['status_detail'],
        )
        evidence = {}
        for number in range(32):
            path = f'derived/status-detail/{number:02d}.enc.json'
            rows = json.loads(before_private.plaintext_files()[path])
            evidence[f'current-exemption-union-{number:02d}'] = events.PreconditionEvidence(
                name=f'current-exemption-union-{number:02d}',
                artifact_kind='status-detail', repository_role='records',
                branch='derived', path=path, binding_mode='generation',
                binding=binding,
                value={
                    'project_id': before_private.project_id,
                    'subjects': sorted(int(subject) for subject in rows),
                    'provenance': {
                        subject: sorted(row['exemption_sources'])
                        for subject, row in rows.items()
                    },
                },
            )
        return events._affected_classes_for(event, evidence)

    target_source = event.target.get('source_event_id', event.target.get('rule_event_id'))
    source_ids = []
    for number in range(32):
        path = f'derived/reader-authority/{number:02d}.enc.json'
        rows = json.loads(before_private.plaintext_files()[path])
        source_ids.extend(rows)
    binding = events.GenerationBinding(
        events_head=head.commit_oid,
        canonical_generation=before_generations['reader_authority'],
        derived_generation=before_generations['reader_authority'],
    )
    evidence = {
        'reader-authority-state': events.PreconditionEvidence(
            name='reader-authority-state', artifact_kind='reader-authority',
            repository_role='records', branch='derived',
            path='derived/reader-authority/00.enc.json',
            binding_mode='generation', binding=binding,
            value={
                'project_id': before_private.project_id,
                'class_state': 'current' if binding.canonical_generation == binding.derived_generation else 'stale',
                'source_event_ids': sorted(source_ids),
                'cursor_event_id': before_generations['reader_authority'],
                'source_event_id': target_source,
                'subject': event.target.get('subject', {'github_user_id': 1}),
            },
        ),
    }
    return events._affected_classes_for(event, evidence)


def _generation_map(records, idle):
    """Return class generations using authenticated effect resolution."""
    if not records:
        raise ValueError('a publication prefix needs a canonical connection')
    result = {name: records[0].event.event_id for name in _DERIVED_CLASSES}
    for index, record in enumerate(records[1:], 1):
        before_records = records[:index]
        before_private = references(before_records, idle)[2]
        affected = _authenticated_affected_classes(
            record.event, before_private, before_records, result)
        result = {
            'generations_version': 1,
            **events._expected_generations(
                record.event,
                {name: result[name] for name in _DERIVED_CLASSES},
                affected,
            ),
        }
    return {'generations_version': 1, **result}


def _encrypted_shards(plaintext):
    """Encrypt every derived shard with a deterministic source-test recipe."""
    key = bytes.fromhex(_CRYPTO['key_hex'])
    kid = bytes.fromhex(_CRYPTO['kid_hex'])
    nonce = bytes.fromhex(_CRYPTO['nonce_hex'])
    with patch.object(envelope.secrets, 'token_bytes', return_value=nonce):
        return {
            path: envelope.encrypt_artifact(
                raw,
                project_id=plaintext.project_id,
                identity=artifacts.resolve_artifact_identity('records', 'derived', path),
                kid=kid,
                key=key,
            )
            for path, raw in plaintext.plaintext_files().items()
        }


def _publication(plaintext, generations, *, include_plaintext=False):
    """Capture complete assembled state bytes and exact shard digest bindings."""
    encrypted = _encrypted_shards(plaintext)
    projection = assemble_derived_projection(
        plaintext,
        canonical_oid=plaintext.canonical_oid,
        generations=generations,
        encrypted_shards=encrypted,
        profile=load_release_profile(),
    )
    state_raw = projection.plaintext_files()['derived/state.enc.json']
    state = json.loads(state_raw)
    result = {
        'crypto': dict(_CRYPTO),
        'canonical_oid': plaintext.canonical_oid,
        'generations': generations,
        'state_bytes_b64': base64url_encode(state_raw),
        'envelope_digests': state['shard_digests'],
        'shard_paths': sorted(encrypted),
    }
    if include_plaintext:
        # The retained stale-reader fixture is consumed by a reader-side
        # implementation that cannot replay the authoring history.  Include
        # the complete deterministic endpoint input beside the crypto recipe
        # so it can assemble and validate both the denied stale read and the
        # repaired read directly.
        result['plaintext'] = plaintext.to_dict()
    return result


def _publication_pair(before_private, after_private, before_generations, after_generations):
    before = _publication(before_private, before_generations)
    after = _publication(after_private, after_generations)
    # The state file is separate from shard carry-forward.  Digest equality is
    # sufficient to prove that an unchanged encrypted shard was carried across
    # the publication.  Keep the complete class/shard digest tables above;
    # flattening them by class would overwrite 31 of the 32 shard bindings.
    unchanged = sorted(path for path in before_private.plaintext_files()
                       if path != 'derived/state.enc.json'
                       and before_private.plaintext_files()[path] == after_private.plaintext_files()[path])
    return {
        'crypto': dict(_CRYPTO),
        'before': before,
        'after': after,
        'unchanged_shards': unchanged,
    }


def _stale_reader_case(rows, idle):
    """Author the shrink-only withdrawal that skips a stale reader class."""
    history = History(rows)
    records = []
    history.append(records, 'project_connected', 7200)
    source = history.append(records, 'records_reader_authorized', 7201)
    # This intervening source makes reader_authority behind the canonical head
    # while the first source remains known in the stale private projection.
    history.append(records, 'records_reader_authorized', 7202)
    canonical_before = list(records)
    stale_records = records[:2]
    history.append(records, 'records_reader_withdrawn', 7203,
                   **{'target.source_event_id': source.event_id})
    withdrawal = records[-1]
    canonical_after = records
    before_state, before_coverage, _ = references(canonical_before, idle)
    after_state, after_coverage, after_private = references(canonical_after, idle)
    stale_private = references(stale_records, idle)[2]
    before_generations = _generation_map(canonical_before, idle)
    stale_generations = _generation_map(stale_records, idle)
    repaired_generations = _generation_map(canonical_after, idle)
    return {
        'id': 'reader-withdrawal/stale-reader-authority/skip-repair',
        'history': [record_value(r) for r in canonical_before],
        'before': {
            'canonical_oid': before_state.current_head_oid,
            'coverage': before_coverage.to_dict(),
            'reader_generation': before_generations['reader_authority'],
        },
        'input': {
            'record': record_value(withdrawal),
            'stale_private_history': [record_value(r) for r in stale_records],
            'skip_reason': 'reader_authority_generation_is_stale',
            'affected_classes': ['reader_authority'],
        },
        'after': {
            'canonical_oid': after_state.current_head_oid,
            'coverage': after_coverage.to_dict(),
            'canonical_source_advanced': after_coverage.to_dict()['source.enc.json']['canonical_sha'],
        },
        'stale_private': _publication(stale_private, stale_generations,
                                      include_plaintext=True),
        'repair': _publication(after_private, repaired_generations,
                               include_plaintext=True),
        'read_assertions': {
            'stale_reader_generation': stale_generations['reader_authority'],
            'repaired_reader_generation': repaired_generations['reader_authority'],
            'before_repair': 'deny_stale_generation',
            'after_repair': 'allow_complete_reference',
        },
    }


def _partial_bulk_case(rows, fixtures, idle):
    """Author a complete bulk fan-out and its missing-shard publication window."""
    history = History(rows)
    all_records = []
    history.append(all_records, 'project_connected', 7300)
    for nonce in (7301, 7303, 7304, 7305, 7306, 7307, 7308, 7309,
                  7310, 7311, 7312, 7313, 7315, 7316, 7318, 7319,
                  7320, 7321, 7322, 7324, 7326, 7331, 7334, 7346,
                  7352, 7354, 7356, 7357, 7358, 7364, 7385, 7419):
        history.append(all_records, 'records_reader_authorized', nonce)
    before_state, before_coverage, before_private = references(all_records[:1], idle)
    after_state, after_coverage, after_private = references(all_records, idle)
    before_generations = _generation_map(all_records[:1], idle)
    after_generations = _generation_map(all_records, idle)
    publication = _publication_pair(
        before_private, after_private, before_generations, after_generations)
    required = [f'derived/reader-authority/{i:02d}.enc.json' for i in range(32)]
    return {
        'id': 'reader-authority/bulk-fanout/partial-publication',
        'history': [record_value(r) for r in all_records[:1]],
        'before': {
            'canonical_oid': before_state.current_head_oid,
            'coverage': before_coverage.to_dict(),
            'derived': before_private.to_dict(),
        },
        'input': {
            'records': [record_value(r) for r in all_records[1:]],
            'publication_mode': 'bulk',
            'required_shards': required,
            'missing_shard': required[0],
        },
        'after': {
            'canonical_oid': after_state.current_head_oid,
            'coverage': after_coverage.to_dict(),
            'derived': after_private.to_dict(),
        },
        'publication': publication,
        'partial_publication': {
            'missing_shards': [required[0]],
            'published_generation': before_generations['reader_authority'],
            'required_generation': after_generations['reader_authority'],
            'read': 'deny_until_all_shards_and_state_complete',
        },
    }


def operation_pair(fixtures, *, fence='idle', marker='empty', subjects=None):
    values = fixtures['coverage-v1.json']['operation_states']
    f = copy.deepcopy(values['fences']['success' if fence == 'success_reserved' else fence])
    m = copy.deepcopy(values['markers'][marker])
    if fence == 'idle':
        f['generation'] = 0
    if subjects is not None and fence == 'mutation':
        f.update(subjects=subjects, project_wide=not subjects)
        for entry in m['ops'].values():
            entry.update(subjects=subjects, project_wide=not subjects)
    return decode_inflight_marker(canonical_json(m)), decode_decision_fence(canonical_json(f))


def state_for(records):
    result = replay_events('project-1', BASE, records)
    if not result.valid:
        raise ValueError(f'invalid reference history: {result.error}')
    return result.state


def references(records, pair):
    state = state_for(records)
    coverage = materialize_coverage(state, pair, canonical_oid=state.current_head_oid,
                                   built_at=TIME, dracla_version=VERSION)
    private = materialize_derived(state, profile=load_release_profile())
    return state, coverage, private


def record_value(record):
    return {'event': record.event.to_dict(), 'commit_oid': record.commit_oid,
            'parent_oid': record.parent_oid}


def build(rows, fixtures):
    history = History(rows)
    histories = {case['name']: history.vector_records(case['name'])
                 for case in fixtures['replay-v1.json']['valid_cases'] if case['record_types']}
    records, _, _ = history.active_records(nonce=3000)
    for subject in range(1, 33):
        history.append(records, 'acceptance', 3010 + subject,
                       **{'actor.github_user_id': subject,
                          'target.coverage_tuple.github_user_id': subject})
    histories['all-subject-shards'] = records

    records = []
    history.append(records, 'project_connected', 4000)
    # Two independently attributable sources. Removing one must retain exemption.
    first = history.exemption_event(4001, source_kind='individual')
    records.append(history.record(first, records[-1].commit_oid, len(records) + 1))
    second = history.exemption_event(4002, source_kind='bot')
    records.append(history.record(second, records[-1].commit_oid, len(records) + 1))
    history.append(records, 'exemption_source_withdrawn', 4003,
                   **{'target.source_event_id': first.event_id})
    history.append(records, 'exemption_source_withdrawn', 4004,
                   **{'target.source_event_id': second.event_id})
    histories['exemption-source-union'] = records

    records, _, _ = history.active_records(nonce=4100)
    grant = history.append(records, 'override', 4103)
    history.append(records, 'override_withdrawn', 4104,
                   **{'target.override_event_id': grant.event_id})
    histories['override-grant-withdraw'] = records

    for reader in (False, True):
        prefix = 'records_reader' if reader else 'exemption'
        records = []
        history.append(records, 'project_connected', 4200 + int(reader) * 100)
        rule = history.append(records, prefix + '_rule_configured', 4201 + int(reader) * 100)
        builder = history.reader_materialization_event if reader else history.exemption_materialization_event
        prior = None
        for result in ('add', 'withdraw', 'add'):
            event = builder(rule, result, prior)
            records.append(history.record(event, records[-1].commit_oid, len(records) + 1))
            prior = event.event_id
        history.append(records, prefix + '_rule_withdrawn', 4209 + int(reader) * 100,
                       **{'target.rule_event_id': rule.event_id})
        histories[prefix + '-continuous-lifecycle'] = records

    for reader in (False, True):
        records = []
        history.append(records, 'project_connected', 4400 + int(reader) * 100)
        kind = 'records_reader_snapshot_authorized' if reader else 'exemption_snapshot'
        source = history.append(records, kind, 4401 + int(reader) * 100,
            **{'target.subjects': [{'github_user_id': 7, 'login_snapshot': 'alice'},
                                   {'github_user_id': 8, 'login_snapshot': 'bob'}]})
        for subject in (7, 8):
            history.append(records, 'records_reader_withdrawn' if reader else 'exemption_source_withdrawn',
                4410 + int(reader) * 100 + subject,
                **{'target.source_event_id': source.event_id,
                   'target.subject.github_user_id': subject})
        histories[('reader' if reader else 'exemption') + '-snapshot-members'] = records

    # All reader source shards are exercised by complete event histories, not
    # synthetic private rows or an incremental implementation.
    records = []
    history.append(records, 'project_connected', 5000)
    reader_nonces = (5001, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012, 5013, 5015, 5016, 5018, 5019, 5020, 5021, 5022, 5024, 5026, 5031, 5034, 5046, 5052, 5054, 5056, 5057, 5058, 5064, 5085, 5119)
    for nonce in reader_nonces:
        history.append(records, 'records_reader_authorized', nonce)
    histories['all-reader-shards'] = records
    source = records[1].event
    history.append(records, 'records_reader_withdrawn', 10001,
                   **{'target.source_event_id': source.event_id})
    # An unrelated canonical update must not make the already-absent reader
    # source look stale.  The repeated withdrawal remains an appending no-op
    # for both projection facts and its reader generation.
    config = copy.deepcopy(rows['config_updated']['payload']['project_configuration'])
    config['retention_statement'] += ' Updated.'
    history.append(records, 'config_updated', 10002,
                   **{'payload.project_configuration': config})
    history.append(records, 'records_reader_withdrawn', 10003,
                   **{'target.source_event_id': source.event_id})

    records = []
    history.append(records, 'project_connected', 6100)
    request = history.append(records, 'enforcement_scope_requested', 6101)
    terminal = history.scope_terminal_event('enforcement_scope_activated', request)
    records.append(history.record(terminal, records[-1].commit_oid, len(records) + 1))
    histories['scope-activation'] = records

    idle = operation_pair(fixtures)
    cases = []
    for name, records in histories.items():
        # Build the canonical generation prefix list alongside the full
        # endpoint references below.  Re-running _generation_map for every
        # prefix would replay every earlier prefix repeatedly and turns this
        # authoring pass cubic in history length.
        generation_maps = [{
            'generations_version': 1,
            **{name: records[0].event.event_id for name in _DERIVED_CLASSES},
        }]
        for index in range(1, len(records)):
            before_records, after_records = records[:index], records[:index + 1]
            before_state, before_coverage, before_private = references(before_records, idle)
            _, after_coverage, after_private = references(after_records, idle)
            event = after_records[-1]
            generations = generation_maps[-1]
            affected = _authenticated_affected_classes(
                event.event, before_private, before_records, generations)
            after_generations = {
                'generations_version': 1,
                **events._expected_generations(
                    event.event,
                    {name: generations[name] for name in _DERIVED_CLASSES},
                    affected,
                ),
            }
            generation_maps.append(after_generations)
            subjects = set(before_state.exemption_sequence_next)
            if 'subject' in event.event.target:
                subjects.add(event.event.target['subject']['github_user_id'])
            subjects.update(s['github_user_id'] for s in event.event.target.get('subjects', ()))
            prior_union = {str(subject): sorted(source.source_event_id
                for source in before_state.exemption_source_records.values()
                if source.github_user_id == subject) for subject in sorted(subjects)}
            changed_derived = list(derived_delta(before_private, after_private).files)
            case = {
                'id': f'{name}/{index:02d}/{event.event.type}',
                'history': [record_value(r) for r in before_records],
                'before': {'canonical_oid': before_state.current_head_oid,
                           'coverage': before_coverage.to_dict(), 'derived': before_private.to_dict(),
                           'generations': generations},
                'input': {'record': record_value(event),
                          'operation_state': [x.to_dict() for x in idle],
                          'prior_exemption_union': prior_union,
                          'built_at': TIME, 'dracla_version': VERSION},
                'after': {'canonical_oid': event.commit_oid,
                          'coverage': after_coverage.to_dict(), 'derived': after_private.to_dict(),
                          'generations': after_generations},
                'changed': {'coverage': list(coverage_delta(before_coverage, after_coverage).files),
                            'derived': changed_derived},
            }
            if changed_derived:
                case['publication'] = _publication_pair(
                    before_private, after_private, generations, after_generations)
            cases.append(case)

    # The live operational pair affects coverage reads while private stored facts
    # remain identical. Cases cover every serialization/crash window that changes
    # that pair, subject-scoped and project-wide ownership, and success reservation.
    operational = []
    records, _, _ = history.active_records(nonce=6000)
    history.append(records, 'acceptance', 6003)
    _, before_coverage, before_private = references(records, idle)
    for fence, marker in [('mutation', 'empty'), ('mutation', 'open'),
                          ('success_reserved', 'empty'), ('idle', 'empty')]:
        for subjects in ([7], [8], []) if fence == 'mutation' else ([],):
            pair = operation_pair(fixtures, fence=fence, marker=marker, subjects=subjects)
            _, after_coverage, after_private = references(records, pair)
            operational.append({'id': f'{fence}/{marker}/' + (','.join(map(str, subjects)) or 'project'),
                'history': [record_value(r) for r in records],
                'before': {'coverage': before_coverage.to_dict(), 'derived': before_private.to_dict()},
                'input': {'operation_state': [x.to_dict() for x in pair],
                          'built_at': TIME, 'dracla_version': VERSION},
                'after': {'coverage': after_coverage.to_dict(), 'derived': after_private.to_dict()}})
    # Read-time overlays use the same stored row under each live operation pair.
    # These are computed by the M1-11 read author, never baked into stored facts.
    from dataclasses import asdict
    from dracla.conformance import CoverageProjection, DerivedReadRow, resolve_read_status
    read_cases = []
    for golden in fixtures['derived-v1.json']['wire_goldens']['status_rows']:
        raw = golden['status_detail_bytes_hex']
        detail = json.loads(bytes.fromhex(''.join(raw) if isinstance(raw, list) else raw))['7']
        for operation in operational:
            pair_values = operation['input']['operation_state']
            pair = (decode_inflight_marker(canonical_json(pair_values[0])),
                    decode_decision_fence(canonical_json(pair_values[1])))
            files = copy.deepcopy(fixtures['coverage-v1.json']['empty_files'])
            files['agreements/active.enc.json'] = fixtures['derived-v1.json']['active_agreement']
            files['inflight.enc.json'], files['decision-fence.enc.json'] = pair_values
            projection = CoverageProjection('project-1', files)
            row = DerivedReadRow('project-1', BASE, 7, 'agreement-1', detail)
            resolved = asdict(resolve_read_status(row, projection, [], pair))
            resolved['enforcement_scope'] = list(resolved['enforcement_scope'])
            read_cases.append({'id': golden['name'] + '/' + operation['id'],
                'row': detail, 'coverage': files, 'subject': 7, 'agreement_id': 'agreement-1',
                'canonical_oid': BASE, 'effective_scope': [], 'operation_state': pair_values,
                'expected': resolved})
    publication_cases = [
        _stale_reader_case(rows, idle),
        _partial_bulk_case(rows, fixtures, idle),
    ]
    return {'schema_version': 1, 'oracle': 'full canonical replay and full M1-10/M1-11 materializers',
            'project_id': 'project-1', 'base_commit_oid': BASE,
            'cases': cases, 'operational_cases': operational, 'read_cases': read_cases,
            'publication_cases': publication_cases}
