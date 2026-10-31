"""M3/4.1: real encrypted history/HTTP exports and private output boundaries."""
from __future__ import annotations

from dataclasses import replace
import csv
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dracla.conformance import (
    DerivedReadRow, base64url_encode, canonical_json, decrypt_artifact,
    decode_decision_fence, decode_inflight_marker, load_release_profile,
    materialize_coverage, materialize_derived, parse_canonical_json, resolve_artifact_identity,
    resolve_read_status,
)
from dracla.records import RecordsError, open_history
from dracla.records import exports as ex
from dracla.cli.app import main
from core.tests.test_records_1 import EncryptedRepository, response
from core.tests.test_records_2 import MutationRepository


def fixture():
    f = MutationRepository(rotate=True)
    f.values['/user'] = {'id': 7, 'login': 'contributor'}
    return f


def append(f, event, affected=('reader_authority',)):
    f.append(event, affected)
    f.set_head('records', 'events', f.e)


def request(f, *, view='current', source=None, nonce=0):
    return {'export_version': 1, 'project_id': f.binding.project_id,
        'request_id': base64url_encode(nonce.to_bytes(16, 'big')),
        'source_events_oid': source or f.e, 'view': view}


class Authority:
    def __init__(self, user=7):
        self.user, self.calls, self.member_calls = user, [], []
        self.callback = None

    def authenticate_request(self, value):
        self.calls.append(dict(value))
        if self.callback:
            self.callback(self, value)
        return self.user

    def is_team_member(self, *args):
        self.member_calls.append(args)
        return False


def hosted(f, value=None, authority=None):
    return ex.export_hosted(f.binding, *f.reader(), value or request(f), authority=authority or Authority())


def decrypt_pair(f, report, value):
    keys, transport = f.reader()
    snapshot = open_history(f.binding, keys, transport)
    return {kind: decrypt_artifact(f.files['records', report.derived_oid][
        path := f"derived/exports/{value['request_id']}.enc.{kind}"],
        expected_project_id=f.binding.project_id,
        expected_identity=resolve_artifact_identity('records', 'derived', path),
        keys=snapshot.keys['records']) for kind in ('json', 'csv')}


def decoded_csv(raw):
    rows = list(csv.DictReader(io.StringIO(raw.decode(), newline='')))
    for row in rows:
        for key, value in row.items():
            if key not in ('export_version', 'github_user_id') and value:
                assert value.startswith("'"), (key, value)
                row[key] = value[1:]
    return rows


class TestExportRendering(unittest.TestCase):
    def test_version1_header_and_resource_limits_match_independent_contract_goldens(self):
        expected = (b'row_kind,export_version,project_id,request_id,source_events_oid,view,context_json,'
            b'github_user_id,login_snapshot,login_as_of,agreement_id,recipient_id,status,reason_code,'
            b'basis_event_id,acceptance_json,revocation_json,exemption_sources_json,canonical_event_json')
        f = fixture(); keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
        for view in ('current','history'):
            self.assertEqual(next(ex.csv_chunks(ex._rendering(snapshot,keys,transport,view))),expected+b'\r\n')
        self.assertEqual((ex.PLAINTEXT_LIMIT,ex.ENVELOPE_LIMIT,ex.PAIR_LIMIT,ex.RECORD_LIMIT),
                         (383000,512000,1024000,10000))

    def test_signature_precedes_exemption_and_unresolved_status_remains_explicit(self):
        f = fixture()
        original = next(r.event for r in f.state.event_records.values() if r.event.type == 'acceptance')
        event = f.builder.event('acceptance', 980, f.e, **{'target.digest': original.target['digest']})
        append(f, event, ('derived_index', 'status_detail'))
        keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
        rendering = ex._rendering(snapshot, keys, transport, 'current')
        row, = list(rendering.records())
        self.assertEqual((row['status'], row['reason_code']), ('current', 'accepted_current_version'))
        self.assertIsNone(row['revocation']); self.assertEqual(row['acceptance']['event']['event_id'], event.event_id)
        unresolved = replace(snapshot, state=replace(snapshot.state,
            unresolved=frozenset({((7, snapshot.state.agreement_id), event.event_id)})))
        row, = list(ex._rendering(unresolved, keys, transport, 'current').records())
        self.assertEqual((row['status'], row['reason_code']), ('indeterminate', 'replay_unresolved'))
        other = replace(snapshot, state=replace(snapshot.state,
            unresolved=frozenset({((8, snapshot.state.agreement_id), event.event_id)})))
        self.assertEqual([r['github_user_id'] for r in ex._rendering(other, keys, transport, 'current').records()], [7,8])

    def test_real_mutation_pair_is_indeterminate_and_success_reservation_is_not(self):
        from dracla.records.append import FENCE
        for mutation in (False, True):
            f = fixture()
            if mutation:
                event, artifacts = f.config(); engine = f.engine(); reference = engine.prepare(event, artifacts)
                engine.begin(reference, subjects=[], project_wide=True, started_at='2026-10-31T00:00:00Z')
            else:
                values = dict(f.files['coverage', f.c])
                values[FENCE] = f.encrypt('coverage', 'coverage', FENCE,
                    {'state': 'success_reserved', 'generation': 0,
                     'check_identity': base64url_encode(b'x'*32), 'projection_commit': f.e})
                f.set_head('coverage', 'coverage', f.commit('coverage', values, f.c))
            keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
            row, = list(ex._rendering(snapshot, keys, transport, 'current').records())
            self.assertEqual(row['status'], 'indeterminate' if mutation else 'exempt')
            self.assertEqual(row['reason_code'], 'operation_in_flight' if mutation else 'exempt_source_active')

    def test_private_shard_capacity_does_not_cap_canonical_export(self):
        f = fixture(); keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
        from dracla.conformance import DerivedClassOverflow, assemble_derived_projection
        profile = load_release_profile().to_dict()
        profile['max_shard_ciphertext_bytes'] = {k: 1 for k in profile['max_shard_ciphertext_bytes']}
        small = load_release_profile(canonical_json(profile))
        plaintext = materialize_derived(snapshot.state, profile=small)
        with self.assertRaises(DerivedClassOverflow):
            assemble_derived_projection(plaintext, canonical_oid=snapshot.events_oid,
                generations={'generations_version': 1, **dict(snapshot.generations)},
                encrypted_shards={p: f.files['records', f.d][p] for p in plaintext.plaintext_files()}, profile=small)
        with patch('dracla.records.append.load_release_profile', return_value=small):
            rendering = ex._rendering(snapshot, keys, transport, 'current')
            self.assertTrue(parse_canonical_json(b''.join(ex.json_chunks(rendering)))['records'])

    def test_preagreement_exemption_has_no_signature_or_synthetic_agreement(self):
        f = MutationRepository()
        append(f, f.builder.event('exemption', 982), ('derived_index', 'status_detail'))
        keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
        row, = list(ex._rendering(snapshot, keys, transport, 'current').records())
        self.assertIsNone(row['agreement_id']); self.assertIsNone(row['acceptance']); self.assertIsNone(row['revocation'])
        self.assertEqual((row['status'], row['reason_code']), ('exempt', 'exempt_source_active'))

    def test_complete_json_and_csv_vectors_match_canonical_public_records(self):
        f = fixture()
        keys, transport = f.reader()
        snapshot = open_history(f.binding, keys, transport)
        for view in ('current', 'history'):
            with self.subTest(view=view):
                rendering = ex._rendering(snapshot, keys, transport, view)
                raw = b''.join(ex.json_chunks(rendering))
                value = parse_canonical_json(raw)
                self.assertEqual(raw, canonical_json(value))
                self.assertEqual(set(value), {'export_version', 'project_id', 'request_id',
                    'source_events_oid', 'view', 'context', 'records'})
                self.assertEqual(value['source_events_oid'], f.e)
                self.assertIsNone(value['request_id'])
                self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
                self.assertFalse(raw.endswith(b'\n'))
                csv_raw = b''.join(ex.csv_chunks(rendering))
                self.assertEqual(csv_raw.split(b'\r\n')[0].decode(), ','.join(ex.CSV_COLUMNS))
                self.assertTrue(csv_raw.endswith(b'\r\n'))
                rows = decoded_csv(csv_raw)
                self.assertEqual(rows[0]['row_kind'], 'metadata')
                self.assertEqual(json.loads(rows[0]['context_json']), value['context'])
                self.assertEqual(len(rows), len(value['records']) + 1)
                if view == 'history':
                    self.assertEqual(value['records'], [r.to_dict() for r in snapshot.records])
                    self.assertEqual([json.loads(r['canonical_event_json']) for r in rows[1:]], value['records'])
                    self.assertIsNone(value['context']['operational_observation'])
                else:
                    record = value['records'][0]
                    self.assertEqual(record['status'], 'exempt')
                    self.assertEqual(record['reason_code'], 'exempt_source_active')
                    self.assertIsNotNone(record['acceptance'])
                    self.assertIsNotNone(record['revocation'])
                    self.assertEqual(record['acceptance']['event']['type'], 'acceptance')
                    self.assertEqual(record['revocation']['event']['type'], 'revocation')
                    for name in ('acceptance', 'revocation', 'exemption_sources'):
                        self.assertEqual(json.loads(rows[1][name + '_json']), record[name])

    def test_csv_text_roundtrips_formula_empty_null_unicode_and_nested_values(self):
        values = [None, '', '=1+1', '+calc', '-1', '@call', "'leading", ' \t=1',
                  'comma,quote"CR\rLF\n', '雪😀', 17]
        raw = ex._csv_line(values)
        cells = next(csv.reader(io.StringIO(raw.decode(), newline='')))
        self.assertEqual(cells, ['' if v is None else str(v) if type(v) is int else "'" + v for v in values])
        self.assertEqual([None if v == '' else int(v) if i == len(values)-1 else v[1:]
                          for i, v in enumerate(cells)], values)
        self.assertIn(b'"\'comma,quote""CR\rLF\n"', raw)

    def test_reference_status_and_login_parity_without_loading_derived_shards(self):
        for extra in (False, True):
            f = MutationRepository(rotate=True, extra_rules=extra)
            keys, transport = f.reader()
            snapshot = open_history(f.binding, keys, transport)
            rendering = ex._rendering(snapshot, keys, transport, 'current')
            reference = materialize_derived(snapshot.state, profile=load_release_profile())
            files = {p: parse_canonical_json(v) for p, v in reference.plaintext_files().items()}
            coverage = materialize_coverage(snapshot.state, rendering.pair,
                canonical_oid=snapshot.events_oid, built_at='1970-01-01T00:00:00Z', dracla_version='test')
            for row in rendering.records():
                detail = files[f"derived/status-detail/{row['github_user_id'] % 32:02d}.enc.json"][str(row['github_user_id'])]
                status = resolve_read_status(DerivedReadRow('project-1', snapshot.events_oid,
                    row['github_user_id'], row['agreement_id'], detail), coverage,
                    ex._plain(snapshot.state.enforcement_scope), rendering.pair)
                self.assertEqual((row['status'], row['reason_code'], row['basis_event_id']),
                                 (status.status, status.reason_code, status.event_id))
                self.assertEqual((row['login_snapshot'], row['login_as_of']),
                                 (detail['login_snapshot'], detail['login_as_of']))
            self.assertEqual({r['github_user_id'] for r in rendering.records()}, {7})

    def test_empty_current_and_history_have_explicit_metadata(self):
        f = MutationRepository()
        keys, transport = f.reader()
        snapshot = open_history(f.binding, keys, transport)
        rendering = ex._rendering(snapshot, keys, transport, 'current')
        self.assertEqual(parse_canonical_json(b''.join(ex.json_chunks(rendering)))['records'], [])
        rows = decoded_csv(b''.join(ex.csv_chunks(rendering)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['row_kind'], 'metadata')

    def test_current_succeeded_rejects_while_history_retains_evidence(self):
        f = fixture(); keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
        snapshot = replace(snapshot, state=replace(snapshot.state, project_state='succeeded', successor_project_id='project-2'))
        with self.assertRaisesRegex(ex.ExportError, 'history-view-required'):
            ex._rendering(snapshot, keys, transport, 'current')
        value = parse_canonical_json(b''.join(ex.json_chunks(ex._rendering(snapshot, keys, transport, 'history'))))
        self.assertEqual(value['context']['successor_project_id'], 'project-2')


class TestLocalExports(unittest.TestCase):
    def test_invalid_destinations_and_restrictive_umask_independent_private_mode(self):
        for path in ('', '-', '../out', None, 5):
            with self.subTest(path=path), self.assertRaisesRegex(ex.ExportError, 'unsafe-destination'):
                ex._LocalFiles({'json': path})
        with tempfile.TemporaryDirectory() as root:
            sink = ex._LocalFiles({'json': str(Path(root)/'out')})
            previous = os.umask(0o777)
            try:
                with patch.object(ex,'json_chunks',return_value=iter([b'{}'])): sink.write(None)
            finally:
                os.umask(previous)
            self.assertEqual((Path(root)/'out').read_bytes(),b'{}')
            self.assertEqual(stat.S_IMODE((Path(root)/'out').stat().st_mode),0o600)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); (p/'shared').mkdir(mode=0o700); (p/'shared').chmod(0o777)
            with self.assertRaisesRegex(ex.ExportError, 'unsafe-destination'):
                ex._LocalFiles({'json': str(p/'shared'/'out')})

    def test_owned_descriptor_and_exact_mode_are_verified_before_plaintext(self):
        for fault in ('owner','chmod-fails','chmod-ignored'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as root:
                p=Path(root);sink=ex._LocalFiles({'json':str(p/'out')});real_stat=os.fstat
                def wrong_owner(descriptor):
                    values=list(real_stat(descriptor));values[4]=os.getuid()+1
                    return os.stat_result(values)
                target='os.fstat' if fault=='owner' else 'os.fchmod'
                replacement=(wrong_owner if fault=='owner' else
                    (lambda *args: (_ for _ in ()).throw(OSError('PRIVATE'))) if fault=='chmod-fails' else lambda *args:None)
                previous=os.umask(0o777)
                try:
                    with patch('dracla.records.exports.'+target,replacement),self.assertRaises(ex.ExportError) as caught:
                        sink.write(None)
                finally:os.umask(previous)
                self.assertNotIn('PRIVATE',str(caught.exception));self.assertEqual(list(p.iterdir()),[])

    def test_cleanup_failure_still_attempts_every_other_owned_file_and_redacts_error(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);sink=ex._LocalFiles({'json':str(p/'one'),'csv':str(p/'two')});real=os.unlink;calls=[]
            def fail_first(name,**kwargs):
                calls.append(name)
                if len(calls)==1:raise OSError('PRIVATE cleanup failure')
                return real(name,**kwargs)
            def broken(_):
                yield b'partial'
                raise ValueError('PRIVATE renderer failure')
            with patch.object(ex,'json_chunks',return_value=iter([b'{}'])),patch.object(ex,'csv_chunks',broken),\
                    patch.object(ex.os,'unlink',fail_first),self.assertRaisesRegex(ex.ExportError,'export-io-failure') as caught:
                sink.write(None)
            self.assertNotIn('PRIVATE',str(caught.exception));self.assertEqual(len(calls),2)
            stages=list(p.glob('.dracla-export-*'));self.assertEqual(len(stages),1)
            self.assertEqual(stages[0].read_bytes(),b'{}');self.assertFalse((p/'one').exists());self.assertFalse((p/'two').exists())

    def test_stage_disappearance_and_hardlink_are_rejected_by_held_identity(self):
        for fault in ('missing', 'linked'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                p = Path(root); sink = ex._LocalFiles({'json': str(p/'out')})
                def chunks(_):
                    yield b'private'
                    stage = next(p.glob('.dracla-export-*'))
                    if fault == 'missing': stage.unlink()
                    else: os.link(stage, p/'foreign-link')
                with patch.object(ex, 'json_chunks', chunks), self.assertRaises(ex.ExportError): sink.write(None)
                self.assertFalse((p/'out').exists()); self.assertFalse(list(p.glob('.dracla-export-*')))
                if fault == 'linked': self.assertEqual((p/'foreign-link').read_bytes(), b'private')

    def test_cleanup_never_removes_a_different_file_replacing_stage_name(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); sink = ex._LocalFiles({'json': str(p/'out')})
            def chunks(_):
                yield b'private'
                stage = next(p.glob('.dracla-export-*'))
                stage.rename(p/'owner-moved-private-file')
                stage.write_bytes(b'unrelated replacement')
            with patch.object(ex, 'json_chunks', chunks), self.assertRaises(ex.ExportError): sink.write(None)
            self.assertEqual(next(p.glob('.dracla-export-*')).read_bytes(), b'unrelated replacement')
            self.assertEqual((p/'owner-moved-private-file').read_bytes(), b'private')
            self.assertFalse((p/'out').exists())

    def test_canonical_drift_before_final_gate_reselects_implicit_current_source(self):
        f = fixture(); rendering = ex._rendering; calls = []
        def drift(*args, **kwargs):
            result = rendering(*args, **kwargs)
            calls.append(True)
            if len(calls) == 1: f.concurrent_config()
            return result
        with tempfile.TemporaryDirectory() as root, patch.object(ex, '_rendering', drift):
            p = Path(root)/'out'; report = ex.export_local(f.binding, *f.reader(), json_path=str(p))
            self.assertEqual(report.source_events_oid, f.head('records', 'events'))
            self.assertEqual(parse_canonical_json(p.read_bytes())['source_events_oid'], report.source_events_oid)
        self.assertEqual(len(calls), 2)

    def test_exhausted_observation_and_missing_sink_return_non_success(self):
        f = fixture()
        with self.assertRaisesRegex(ex.ExportError, 'invalid-export-request'):
            ex.export_local(f.binding, *f.reader())
        with tempfile.TemporaryDirectory() as root, patch.object(ex, '_final_gate', return_value=False) as gate:
            with self.assertRaisesRegex(ex.ExportError, 'snapshot-changed'):
                ex.export_local(f.binding, *f.reader(), json_path=str(Path(root)/'out'))
            self.assertEqual(gate.call_count, load_release_profile().limit('max_mutation_retries'))
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_private_complete_pair_under_umask_022_and_no_repository_write(self):
        f = fixture(); keys, transport = f.reader()
        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root)/name for name in ('result.json', 'result.csv')]
            original = os.umask(0o022)
            try:
                report = ex.export_local(f.binding, keys, transport, json_path=str(paths[0]), csv_path=str(paths[1]))
            finally:
                os.umask(original)
            self.assertEqual(report.source_events_oid, f.e)
            for path in paths:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(parse_canonical_json(paths[0].read_bytes())['records'][0]['github_user_id'], 7)
            self.assertEqual(len(list(Path(root).iterdir())), 2)
        self.assertFalse(f.writes)
        self.assertGreaterEqual(f.calls.count('/user'), 2)
        self.assertFalse(any('/control' in path for path in f.calls))

    def test_denied_operator_with_keys_cannot_open_sink_or_export_history(self):
        f = fixture(); f.values['/user'] = {'id': 21, 'login': 'operator'}
        for view in ('current', 'history'):
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex((ex.ExportError, RecordsError), 'reader-denied'):
                    ex.export_local(f.binding, *f.reader(), json_path=str(Path(root)/'output'), view=view)
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_historical_prefix_uses_current_authorization_and_exact_source(self):
        f = fixture(); keys, transport = f.reader(); snapshot = open_history(f.binding, keys, transport)
        source = snapshot.records[1].commit_oid
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'history'
            ex.export_local(f.binding, keys, transport, json_path=str(path), view='history', source_events_oid=source)
            value = parse_canonical_json(path.read_bytes())
            self.assertEqual(value['source_events_oid'], source)
            self.assertEqual(value['records'], [r.to_dict() for r in snapshot.records[:2]])
        for source in ('f'*40, snapshot.records[0].parent_oid):
            with tempfile.TemporaryDirectory() as root, self.assertRaises(ex.ExportError):
                ex.export_local(f.binding, *f.reader(), json_path=str(Path(root)/'output'), view='history', source_events_oid=source)

    def test_existing_symlink_hardlink_directory_fifo_and_alias_reject_without_overwrite(self):
        for kind in ('existing', 'symlink', 'hardlink', 'directory', 'fifo', 'same', 'parent-symlink', 'public-parent'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                p = Path(root); destination = p/'output'; original = p/'original'
                original.write_bytes(b'preserve')
                if kind == 'existing': destination.write_bytes(b'preserve')
                elif kind == 'symlink': destination.symlink_to(original)
                elif kind == 'hardlink': os.link(original, destination)
                elif kind == 'directory': destination.mkdir()
                elif kind == 'fifo': os.mkfifo(destination)
                elif kind == 'parent-symlink':
                    (p/'private').mkdir(mode=0o700); (p/'alias').symlink_to(p/'private'); destination = p/'alias'/'output'
                elif kind == 'public-parent':
                    (p/'public').mkdir(mode=0o755); destination = p/'public'/'output'
                paths = {'json': str(destination)}
                if kind == 'same': paths['csv'] = str(destination)
                with self.assertRaisesRegex(ex.ExportError, 'unsafe-destination'):
                    ex._LocalFiles(paths)
                self.assertEqual(original.read_bytes(), b'preserve')
                self.assertFalse(any(x.name.startswith('.dracla-export-') for x in p.iterdir()))

    def test_render_and_second_publication_failure_remove_held_created_outputs(self):
        f = fixture(); keys, transport = f.reader(); rendering = ex._rendering(open_history(f.binding, keys, transport), keys, transport, 'current')
        def broken(_):
            yield b'private partial'
            raise ValueError('PRIVATE')
        for failure in ('renderer', 'publication', 'fsync'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root:
                p = Path(root); sink = ex._LocalFiles({'json': str(p/'one'), 'csv': str(p/'two')})
                real_link = os.link
                def failing_link(src, dst, **kwargs):
                    if dst == 'two': raise OSError('PRIVATE')
                    return real_link(src, dst, **kwargs)
                target, value = {'renderer': ('csv_chunks', broken), 'publication': ('os.link', failing_link),
                                 'fsync': ('os.fsync', lambda _: (_ for _ in ()).throw(OSError('PRIVATE')))}[failure]
                with patch('dracla.records.exports.'+target, value), self.assertRaises(ex.ExportError) as caught:
                    sink.write(rendering)
                self.assertNotIn('PRIVATE', str(caught.exception))
                self.assertEqual(list(p.iterdir()), [])

    def test_destination_created_during_render_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'output'
            sink = ex._LocalFiles({'json': str(path)})
            def race(_):
                yield b'private'
                path.write_bytes(b'other')
            with patch.object(ex, 'json_chunks', race), self.assertRaises(ex.ExportError):
                sink.write(None)
            self.assertEqual(path.read_bytes(), b'other')
            self.assertEqual(list(Path(root).iterdir()), [path])

    def test_parent_replacement_is_detected_and_cleanup_stays_in_held_directory(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); (p/'private').mkdir(mode=0o700)
            sink = ex._LocalFiles({'json': str(p/'private'/'out')})
            def race(_):
                yield b'private'
                (p/'private').rename(p/'held'); (p/'private').mkdir(mode=0o700)
                (p/'private'/'unrelated').write_bytes(b'keep')
            with patch.object(ex, 'json_chunks', race), self.assertRaises(ex.ExportError): sink.write(None)
            self.assertEqual(list((p/'held').iterdir()), [])
            self.assertEqual((p/'private'/'unrelated').read_bytes(), b'keep')

    def test_local_streaming_has_no_hosted_limit_and_no_whole_document_buffer(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'large'
            chunks_written = []
            def chunks(_):
                for i in range(1000):
                    chunks_written.append(i)
                    yield b'x'*4096
            with patch.object(ex, 'json_chunks', chunks), patch.object(ex, '_bounded', side_effect=AssertionError()):
                ex._LocalFiles({'json': str(path)}).write(None)
            self.assertEqual(path.stat().st_size, 4096000)
            self.assertEqual(len(chunks_written), 1000)

    def test_history_does_not_require_valid_live_operation_pair(self):
        f = fixture(); files = {**f.files['records', f.o], 'prepared-operation.enc.json': b'corrupt'}
        f.set_head('records', 'operations', f.commit('records', files, f.o))
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            with self.assertRaises(RecordsError):
                ex.export_local(f.binding, *f.reader(), json_path=str(p/'current'))
            ex.export_local(f.binding, *f.reader(), json_path=str(p/'history'), view='history')
            self.assertFalse((p/'current').exists())
            self.assertTrue(parse_canonical_json((p/'history').read_bytes())['records'])

    def test_current_operation_envelope_must_use_event_selected_key(self):
        from dracla.conformance import encrypt_json_artifact
        f = fixture(); path = 'prepared-operation.enc.json'
        raw = encrypt_json_artifact({'state':'idle','generation':0}, project_id='project-1',
            identity=resolve_artifact_identity('records','operations',path), kid=b'r'*16, key=b'r'*32)
        f.set_head('records','operations',f.commit('records',{path:raw},f.o))
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(RecordsError,'invalid-key'):
            ex.export_local(f.binding,*f.reader(),json_path=str(Path(root)/'out'))


class TestExportAuthorization(unittest.TestCase):
    def test_numeric_membership_pagination_and_invalid_provider_results(self):
        f = fixture(); credentials = f.reader()[1].credentials; credentials.authorize(f.binding)
        pages = []
        def sender(method, url, headers, timeout, body=None):
            pages.append(url)
            page = int(url.rsplit('=', 1)[1])
            return response([{'id': n} for n in range(100,200)] if page == 1 else [{'id': 7}])
        credentials.sender = sender
        self.assertTrue(ex.operator_membership(credentials, 41, 42, 7)); self.assertEqual(len(pages), 2)
        for value, headers in (({}, {}), ([{'id': 8}, {'id': 8}], {}),
                               ([{'id': n} for n in range(101)], {}),
                               ([], {'Link': '<https://untrusted>; rel="next"'})):
            credentials.sender = lambda *args: response(value, headers=headers)
            with self.subTest(value=value), self.assertRaisesRegex(ex.ExportError, 'reader-denied'):
                ex.operator_membership(credentials, 41, 42, 7)
        with self.assertRaisesRegex(ex.ExportError, 'reader-denied'):
            ex.operator_membership(credentials, 41, 42, 21)
        count = []
        def full_pages(method, url, *args):
            page = int(url.rsplit('=', 1)[1]); count.append(page)
            return response([{'id': 100+page*100+i} for i in range(100)])
        credentials.sender = full_pages
        with self.assertRaisesRegex(ex.ExportError, 'reader-denied'):
            ex.operator_membership(credentials, 41, 42, 7)
        self.assertEqual(len(count), 1000)

    def continuous(self):
        f = fixture()
        rule = f.builder.event('records_reader_rule_configured', 950)
        append(f, rule)
        materialization = f.builder.reader_materialization_event(rule, 'add', None, **{
            'target.subject.github_user_id': 21, 'payload.membership_evidence.github_user_id': 21})
        append(f, materialization)
        f.values['/user'] = {'id': 21, 'login': 'operator'}
        return f

    def test_fresh_membership_repeated_even_when_canonical_head_unchanged(self):
        for responses, succeeds in (([True, True], True), ([True, False], False), ([True, None], False)):
            with self.subTest(responses=responses), tempfile.TemporaryDirectory() as root:
                f = self.continuous(); keys, transport = f.reader(); seen = []
                def sender(method, url, headers, timeout, body=None):
                    path = url.removeprefix('https://api.github.com')
                    if path.startswith('/organizations/'):
                        seen.append(path); answer = responses[len(seen)-1]
                        return response([{'id': 21}] if answer else [], 500 if answer is None else 200)
                    return f.send(method, url, headers, timeout, body)
                transport.credentials.sender = sender
                path = Path(root)/'output'
                if succeeds:
                    ex.export_local(f.binding, keys, transport, json_path=str(path))
                else:
                    with self.assertRaises((RecordsError, ex.ExportError)):
                        ex.export_local(f.binding, keys, transport, json_path=str(path))
                self.assertEqual(len(seen), 2)
                self.assertEqual(seen[0], '/organizations/41/team/42/members?per_page=100&page=1')
                self.assertEqual(path.exists(), succeeds)
                self.assertFalse(f.writes)

    def test_individual_source_preserves_union_with_uncertain_continuous_source(self):
        f = self.continuous()
        append(f, f.builder.event('records_reader_authorized', 951, **{'target.subject.github_user_id': 21}))
        with tempfile.TemporaryDirectory() as root:
            ex.export_local(f.binding, *f.reader(), json_path=str(Path(root)/'output'))
        self.assertFalse(any(path.startswith('/organizations/') for path in f.calls))

    def test_snapshot_source_authorizes_without_live_membership(self):
        f = fixture(); f.values['/user'] = {'id': 21, 'login': 'operator'}
        append(f, f.builder.event('records_reader_snapshot_authorized', 953,
                                 **{'target.subjects': [{'github_user_id': 21, 'login_snapshot': 'operator'}]}))
        with tempfile.TemporaryDirectory() as root:
            ex.export_local(f.binding, *f.reader(), csv_path=str(Path(root)/'output'))
        self.assertFalse(any(path.startswith('/organizations/') for path in f.calls))

    def test_withdrawal_during_final_identity_read_restarts_and_denies(self):
        f = fixture(); keys, transport = f.reader(); calls = []
        original = next(r for r in f.state.reader_source_records.values() if r.kind == 'individual')
        def sender(method, url, headers, timeout, body=None):
            if url.endswith('/user'):
                calls.append(True)
                if len(calls) == 2:
                    append(f, f.builder.event('records_reader_withdrawn', 954,
                        **{'target.source_event_id': original.source_event_id}))
            return f.send(method, url, headers, timeout, body)
        transport.credentials.sender = sender
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex((ex.ExportError, RecordsError), 'reader-denied'):
                ex.export_local(f.binding, keys, transport, json_path=str(Path(root)/'output'))
            self.assertEqual(list(Path(root).iterdir()), [])


class TestHostedExports(unittest.TestCase):
    def test_request_is_pinned_before_validation_and_authority_adapter_inspection(self):
        f=fixture();value=request(f);original_id=value['request_id'];other_id=request(f,nonce=1)['request_id'];seen=[]
        class ChangingAuthority:
            @property
            def authenticate_request(self):
                value['request_id']=other_id
                def authenticate(pinned):seen.append(dict(pinned));return 7
                return authenticate
            def is_team_member(self,*args):return False
        result=hosted(f,value,ChangingAuthority())
        self.assertEqual(value['request_id'],other_id)
        original={**value,'request_id':original_id};pair=decrypt_pair(f,result,original)
        self.assertEqual(parse_canonical_json(pair['json'])['request_id'],original_id)
        self.assertEqual(decoded_csv(pair['csv'])[0]['request_id'],original_id)
        self.assertEqual({item['request_id'] for item in seen},{original_id})
        self.assertTrue(all(p.endswith(('.enc.json','.enc.csv')) and original_id in p
            for p in f.files['records',result.derived_oid] if p.startswith('derived/exports/')))

    def test_original_observation_missing_or_malformed_is_a_conflict(self):
        for observation in (None, {'coverage_oid': 'bad'}, {'coverage_oid': 'f'*40, 'operations_oid': 'bad'}):
            f = fixture(); value = request(f); first = hosted(f, value); payload = parse_canonical_json(decrypt_pair(f, first, value)['json'])
            payload['context']['operational_observation'] = observation
            path = f"derived/exports/{value['request_id']}.enc.json"
            files = {**f.files['records', first.derived_oid], path: f.encrypt('records', 'derived', path, payload)}
            f.set_head('records', 'derived', f.commit('records', files, first.derived_oid))
            with self.assertRaises((ex.ExportError, RecordsError)): hosted(f, value)

    def test_new_current_requires_latest_source_and_history_retains_prefix(self):
        f = fixture(); source = next(iter(f.state.event_records.values())).commit_oid
        with self.assertRaisesRegex(ex.ExportError, 'export-conflict'): hosted(f, request(f, source=source))
        value = request(f, view='history', source=source)
        report = hosted(f, value)
        payload = parse_canonical_json(decrypt_pair(f, report, value)['json'])
        self.assertEqual(len(payload['records']), 1); self.assertIsNone(payload['context']['operational_observation'])

    def test_live_operation_drift_retries_before_new_hosted_pair(self):
        f = fixture(); auth = Authority()
        def drift(a, value):
            if len(a.calls) == 2:
                f.set_head('records', 'operations', f.commit('records', f.files['records', f.o], f.o))
        auth.callback = drift
        value = request(f); report = hosted(f, value, auth)
        payload = parse_canonical_json(decrypt_pair(f, report, value)['json'])
        self.assertEqual(payload['context']['operational_observation']['operations_oid'], f.head('records', 'operations'))
        self.assertEqual(len(auth.calls), 4); self.assertEqual(f.graphql_count, 1)

    def test_hosted_exhausted_observation_publishes_nothing(self):
        f = fixture()
        with patch.object(ex, '_final_gate', return_value=False) as gate:
            with self.assertRaisesRegex(ex.ExportError, 'snapshot-changed'): hosted(f)
        self.assertEqual(gate.call_count, load_release_profile().limit('max_mutation_retries'))
        self.assertFalse(f.writes)

    def test_mid_write_indeterminate_response_remains_non_success(self):
        from dracla.records.github import IndeterminateWrite
        f = fixture()
        f.before_cas = lambda role, branch: f.set_head(role, branch,
            f.commit(role, f.files[role, f.head(role, branch)], f.head(role, branch)))
        with self.assertRaises(IndeterminateWrite): hosted(f)
        self.assertEqual(f.graphql_count, 1)
        self.assertFalse(any(p.startswith('derived/exports/') for p in f.files['records', f.head('records', 'derived')]))

    def test_atomic_encrypted_pair_and_exact_no_write_reuse(self):
        f = fixture(); value = request(f); auth = Authority()
        first = hosted(f, value, auth); writes = len(f.writes)
        pair = decrypt_pair(f, first, value)
        payload = parse_canonical_json(pair['json'])
        self.assertEqual(payload['request_id'], value['request_id'])
        self.assertEqual(payload['source_events_oid'], f.e)
        self.assertEqual(json.loads(decoded_csv(pair['csv'])[0]['context_json']), payload['context'])
        again = hosted(f, value, auth)
        self.assertTrue(again.reused); self.assertEqual(first.derived_oid, again.derived_oid)
        self.assertEqual(len(f.writes), writes)
        self.assertGreaterEqual(len(auth.calls), 4)
        additions = f.writes[-1][2]['variables']['input']['fileChanges']['additions']
        self.assertEqual({v['path'] for v in additions}, {
            f"derived/exports/{value['request_id']}.enc.json", f"derived/exports/{value['request_id']}.enc.csv"})
        self.assertTrue(all(f.files['records', first.derived_oid][path] == raw for path, raw in f.files['records', f.d].items()))
        self.assertEqual(len(f.writes), 1)

    def test_missing_adapter_and_rejected_authentication_precede_key_access(self):
        f = fixture(); keys, transport = f.reader()
        for adapter in (None, True, 7, {'authorized': True}, SimpleNamespace(authenticate_request=lambda _: 7)):
            with self.subTest(adapter=adapter), self.assertRaisesRegex(ex.ExportError, 'hosted-authorization-required'):
                ex.export_hosted(f.binding, keys, transport, request(f), authority=adapter)
        auth = Authority(True)
        with self.assertRaisesRegex(ex.ExportError, 'reader-denied'):
            ex.export_hosted(f.binding, keys, transport, request(f), authority=auth)
        self.assertFalse(f.key_calls); self.assertFalse(f.writes)

    def test_final_hosted_principal_change_denies_without_any_write(self):
        f = fixture(); auth = Authority()
        def changed(a, value):
            if len(a.calls) == 2: a.user = 21
        auth.callback = changed
        with self.assertRaisesRegex(ex.ExportError, 'reader-denied'): hosted(f, authority=auth)
        self.assertFalse(f.writes)

    def test_closed_request_rejects_unknown_missing_noncanonical_and_unsafe_values(self):
        f = fixture(); value = request(f)
        class CustomRequest(dict):
            pass
        for candidate in (None,True,[],CustomRequest(value)):
            keys,transport=f.reader()
            with self.subTest(candidate=candidate),self.assertRaisesRegex(ex.ExportError,'invalid-export-request'):
                ex.export_hosted(f.binding,keys,transport,candidate,authority=Authority())
            self.assertFalse(f.key_calls)
        invalid = [{**value, 'path': '/tmp/private'}, {**value, 'request_id': '../bad'},
            {**value, 'request_id': value['request_id']+'='}, {**value, 'export_version': True},
            {**value, 'project_id': 'foreign'}, {**value, 'source_events_oid': 'main'},
            {**value, 'view': 'all'}, {k:v for k,v in value.items() if k != 'view'}]
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ex.ExportError, 'invalid-export-request'):
                hosted(f, candidate)
        self.assertFalse(f.writes)

    def test_conflicting_view_source_partial_or_corrupt_pair_cannot_overwrite(self):
        for conflict in ('view', 'source', 'partial', 'corrupt'):
            with self.subTest(conflict=conflict):
                f = fixture(); value = request(f); first = hosted(f, value); writes = len(f.writes)
                if conflict == 'view': value['view'] = 'history'
                elif conflict == 'source': value.update(view='history', source_events_oid=next(iter(f.state.event_records.values())).commit_oid)
                else:
                    files = dict(f.files['records', first.derived_oid]); path = f"derived/exports/{value['request_id']}.enc.csv"
                    if conflict == 'partial': del files[path]
                    else: files[path] = b'corrupt'
                    f.set_head('records', 'derived', f.commit('records', files, first.derived_oid))
                with self.assertRaisesRegex(ex.ExportError, 'export-conflict'): hosted(f, value)
                self.assertEqual(len(f.writes), writes)

    def test_reuse_retains_original_operation_observation_after_live_heads_change(self):
        f = fixture(); value = request(f); first = hosted(f, value); pair = decrypt_pair(f, first, value)
        # Immutable retained O/V remain valid even when the live operation cell is corrupt.
        f.set_head('records', 'operations', f.commit('records', {'prepared-operation.enc.json': b'corrupt'}, f.o))
        again = hosted(f, value)
        self.assertTrue(again.reused)
        self.assertEqual(decrypt_pair(f, again, value), pair)
        with self.assertRaises(RecordsError): hosted(f, request(f, nonce=1))

    def test_reuse_after_canonical_advance_uses_current_authority_and_original_source(self):
        f = fixture(); value = request(f); first = hosted(f, value)
        old = first.source_events_oid
        f.e = f.concurrent_config()
        f.state = open_history(f.binding, *f.reader()).state
        self.assertNotEqual(f.e, old)
        again = hosted(f, value)
        self.assertTrue(again.reused); self.assertEqual(again.source_events_oid, old)
        source = next(s for s in f.state.reader_source_records.values() if s.kind == 'individual')
        append(f, f.builder.event('records_reader_withdrawn', 970, **{'target.source_event_id': source.source_event_id}))
        with self.assertRaisesRegex((ex.ExportError, RecordsError), 'reader-denied'): hosted(f, value)

    def test_cas_conflict_retries_and_lost_response_uses_existing_exact_writer(self):
        for fault in ('race', 'lost-cas', 'lost-cas-followed-by-newer'):
            with self.subTest(fault=fault):
                f = fixture()
                keys, transport = f.reader()
                if fault == 'race':
                    original = transport.head
                    calls = []
                    def raced_head(repo, branch):
                        if branch == 'derived':
                            calls.append(True)
                            if len(calls) == 2:
                                parent = f.head('records', 'derived')
                                f.set_head('records', 'derived', f.commit('records',
                                    {**f.files['records', parent], 'unrelated': b'keep'}, parent))
                        return original(repo, branch)
                    transport.head = raced_head
                else: f.fault = fault
                result = ex.export_hosted(f.binding, keys, transport, request(f), authority=Authority())
                self.assertTrue(result.derived_oid)
                if fault == 'race': self.assertEqual(f.files['records', result.derived_oid]['unrelated'], b'keep')
                paths = [p for p in f.files['records', result.derived_oid] if p.startswith('derived/exports/')]
                self.assertEqual(len(paths), 2)

    def test_plaintext_record_and_serialized_envelope_bounds_are_inclusive(self):
        for size in (ex.PLAINTEXT_LIMIT-1, ex.PLAINTEXT_LIMIT, ex.PLAINTEXT_LIMIT+1):
            with self.subTest(size=size):
                chunks = (b'x'*min(4096, size-i) for i in range(0,size,4096))
                if size <= ex.PLAINTEXT_LIMIT: self.assertEqual(len(ex._bounded(chunks)), size)
                else:
                    with self.assertRaisesRegex(ex.ExportError, 'export-resource-limit'): ex._bounded(chunks)
        for bound in ('ENVELOPE_LIMIT', 'PAIR_LIMIT', 'RECORD_LIMIT'):
            f = fixture()
            result = hosted(f); pair = decrypt_pair(f, result, request(f))
            sizes = [len(f.files['records', result.derived_oid][f"derived/exports/{request(f)['request_id']}.enc.{kind}"]) for kind in ('json','csv')]
            limit = max(sizes) if bound == 'ENVELOPE_LIMIT' else sum(sizes) if bound == 'PAIR_LIMIT' else len(parse_canonical_json(pair['json'])['records'])
            for delta in (-1, 0, 1):
                other = fixture()
                with self.subTest(bound=bound, delta=delta), patch.object(ex, bound, limit+delta):
                    if delta < 0:
                        with self.assertRaisesRegex(ex.ExportError, 'export-resource-limit'): hosted(other)
                        self.assertFalse(other.writes)
                    else: self.assertTrue(hosted(other).derived_oid)


class TestExportCommand(unittest.TestCase):
    def test_default_command_composes_real_operator_transport_and_recovery_prompt(self):
        from dracla.records import OperatorCredentials
        f = fixture(); out = io.StringIO()
        with tempfile.TemporaryDirectory() as root, patch('dracla.records.OperatorCredentials',
                lambda provider: OperatorCredentials(provider, sender=f.send)), patch(
                'dracla.cli.app.prompt_recovery_keys', return_value={'install-1':f.wrapping}) as prompt:
            path = Path(root)/'out'
            result = main(['export','--json',str(path),*self.args(f)],output=out,
                release_loader=lambda:object(),credential_provider=lambda:'opaque')
            self.assertEqual(result,0,out.getvalue()); prompt.assert_called_once()
            self.assertEqual(parse_canonical_json(path.read_bytes())['source_events_oid'],f.e)
        self.assertFalse(f.writes)

    def test_installed_wheel_executes_export_command_and_hosted_pair(self):
        root = Path(__file__).resolve().parents[2]
        code = '''import pathlib,sys,io
target,source=map(pathlib.Path,sys.argv[1:])
sys.path.insert(0,str(target));sys.path.append(str(source))
from dracla.cli.app import main
from dracla.records import exports
assert pathlib.Path(exports.__file__).is_relative_to(target)
assert pathlib.Path(sys.modules[main.__module__].__file__).is_relative_to(target)
from core.tests.test_records_4 import fixture,request,Authority,TestExportCommand
f=fixture();output=io.StringIO();destination=pathlib.Path.cwd()/'private-output';destination.mkdir(mode=0o700)
result=main(['export','--json',str(destination/'out.json'),'--csv',str(destination/'out.csv'),*TestExportCommand().args(f)],
 output=output,release_loader=lambda:object(),verify_factory=lambda binding:f.reader())
assert result==0,output.getvalue()
assert (destination/'out.json').is_file() and (destination/'out.csv').is_file()
assert not f.writes
first=exports.export_hosted(f.binding,*f.reader(),request(f),authority=Authority())
again=exports.export_hosted(f.binding,*f.reader(),request(f),authority=Authority())
assert first.derived_oid==again.derived_oid and again.reused and len(f.writes)==1
assert 'contributor' not in output.getvalue()
print('installed export: actual encrypted HTTP history, private JSON/CSV, atomic encrypted hosted pair and exact reuse')
'''
        with tempfile.TemporaryDirectory(prefix='dracla-m3-export-installed-') as temporary:
            work = Path(temporary); dist = work/'dist'; target = work/'installed'
            build = subprocess.run([sys.executable,'-m','hatchling','build','-t','wheel','-d',str(dist)],
                cwd=root,capture_output=True,text=True,timeout=180)
            self.assertEqual(build.returncode,0,build.stdout+build.stderr)
            wheel, = dist.glob('*.whl')
            install = subprocess.run([sys.executable,'-m','pip','install','--no-deps','--no-index','--target',str(target),str(wheel)],
                capture_output=True,text=True,timeout=180)
            self.assertEqual(install.returncode,0,install.stdout+install.stderr)
            run = subprocess.run([sys.executable,'-I','-c',code,str(target),str(root)],cwd=work,
                capture_output=True,text=True,timeout=180)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertIn('installed export: actual encrypted HTTP history',run.stdout)

    def test_all_export_failures_use_fixed_redacted_exit_contract(self):
        f = fixture()
        for error, code in ((ex.ExportError('export-io-failure'), 1),
                            (ex.ExportError('export-render-failure'), 1),
                            (ex.ExportError('reader-denied'), 2),
                            (RecordsError('invalid-history'), 2), (RuntimeError('PRIVATE'), 1)):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as root:
                out = io.StringIO()
                with patch.object(ex, 'export_local', side_effect=error):
                    result = main(['export', '--json', str(Path(root)/'out'), *self.args(f)], output=out,
                        release_loader=lambda: object(), verify_factory=lambda binding: f.reader())
                self.assertEqual(result, code); self.assertNotIn('PRIVATE', out.getvalue())

    def args(self, f):
        return ['project.id=project-1', 'github.owner=acme', 'github.owner_id='+str(f.binding.owner_id),
            *[item for repo in f.binding.repositories for item in (repo.role+'.name='+repo.name, repo.role+'.id='+str(repo.id))]]

    def test_registered_command_runs_real_export_and_only_redacted_receipt(self):
        f = fixture()
        for option in ('--json', '--csv'):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as root:
                out = io.StringIO(); path = Path(root)/'result'
                code = main(['export', option, str(path), *self.args(f)], output=out,
                    release_loader=lambda: object(), verify_factory=lambda binding: f.reader())
                self.assertEqual(code, 0, out.getvalue()); self.assertTrue(path.exists())
                self.assertIn(f.e, out.getvalue()); self.assertNotIn('contributor', out.getvalue())
                self.assertNotIn(str(path), out.getvalue())

    def test_invalid_options_fail_before_factory_or_keys(self):
        f = fixture()
        cases = [[], ['--json'], ['--json','-'], ['--json','x','--json','y'],
            ['--json','x','--csv','./x'], ['--json','x','--at',f.e],
            ['--json','x','--view','bad'], ['--json','x','--view','history','--at','main'],
            ['--json','x','--unknown','y'], ['--json','x','--view','history','--at'],
            ['--json','parent/../x']]
        for options in cases:
            with self.subTest(options=options):
                factory = unittest.mock.Mock(side_effect=AssertionError('must not access keys'))
                out = io.StringIO()
                code = main(['export', *options, *self.args(f)], output=out,
                    release_loader=lambda: object(), verify_factory=factory)
                self.assertEqual(code, 2); factory.assert_not_called()
                self.assertNotIn('PRIVATE', out.getvalue())


if __name__ == '__main__':
    unittest.main()
