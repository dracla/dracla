"""Concrete encrypted REST/GraphQL mutations, races and ambiguous responses."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from conformance.authoring.histories import History
from dracla.conformance import (
    PreconditionValidationError, SideArtifact, base64url_decode, base64url_encode, canonical_json, decrypt_json_artifact,
    encrypt_json_artifact, event_path, resolve_artifact_identity,
)
from dracla.records.append import MutationEngine, CELL, FENCE, MARKER
from dracla.records.credentials import RecordsError
from dracla.records.github import HeadConflict, IndeterminateWrite, RejectedWrite
from core.tests.test_records_1 import EncryptedRepository, response
from core.tests import test_conformance_event_artifacts as artifact_fixtures


class MutationRepository(EncryptedRepository):
    def __init__(self, *, rotate=False, extra_rules=False):
        super().__init__(complete_history=rotate, rotate=rotate, extra_rules=extra_rules)
        self.kids = {cap: base64url_encode(kid) for cap, kid in self.kid_bytes.items()}
        self.all_keys = {cap: {base64url_encode(old * 16): old * 32,
                              self.kids[cap]: self.data_keys[cap]}
                         for cap, old in [('records', b'r'), ('coverage', b'c')]}
        self.writes, self.trees = [], {}
        self.fault = None
        self.before_cas = None
        self.before_ref = None
        self.graphql_count = 0
        rows = json.loads((Path(__file__).resolve().parents[2] / 'conformance/vectors/events-v1.json').read_text())
        self.builder = History({r['type']: r for r in rows['events']})
        artifact_fixtures.TestSideArtifactPackages.setUpClass()
        self.evidence_fixture = artifact_fixtures.TestSideArtifactPackages()

    def head(self, role, branch):
        return self.values[f'/repos/acme/{role}/git/ref/heads/{branch}']['object']['sha']

    def set_head(self, role, branch, oid):
        self.values[f'/repos/acme/{role}/git/ref/heads/{branch}']['object']['sha'] = oid

    def plain(self, role, branch, head, path):
        return decrypt_json_artifact(self.files[role, head][path], expected_project_id='project-1',
            expected_identity=resolve_artifact_identity(role, branch, path),
            keys=self.all_keys[role])

    def evidence(self, event, head):
        overrides = {}
        if event.type == 'keyring_activated':
            overrides['keyring-affected-repositories'] = {
                'project_id': self.binding.project_id, 'repository_ids': self.binding.ids()}
        files = self.files['records', head]
        if 'config/project.enc.json' in files:
            overrides['current-configuration'] = self.plain('records', 'events', head, 'config/project.enc.json')
        if 'config/materialization-generations.enc.json' in files:
            g = self.plain('records', 'events', head, 'config/materialization-generations.enc.json')
            overrides['prior-generations'] = {k: v for k, v in g.items() if k != 'generations_version'}
        evidence = self.evidence_fixture._preconditions(event, head, overrides)
        for row in evidence:
            if row['binding_mode'] == 'generation':
                name = 'reader_authority' if row['artifact_kind'] == 'reader-authority' else 'status_detail'
                generation = overrides['prior-generations'][name]
                row['binding'].update(canonical_generation=generation, derived_generation=generation)
        return evidence

    def engine(self):
        keys, transport = self.reader()
        return MutationEngine(self.binding, keys, transport, self.evidence,
                              sleep=lambda _: None, jitter=lambda _: 0)

    def config(self, nonce=700, statement='Mutation test retention'):
        config = copy.deepcopy(self.event.to_dict()['payload']['project_configuration'])
        config['retention_statement'] = statement
        event = self.builder.event('config_updated', nonce, **{'payload.project_configuration': config})
        return event, [SideArtifact('project_config', 'config/project.enc.json', canonical_json(config))]

    def concurrent_config(self, statement='Concurrent retention'):
        event, _ = self.config(990, statement)
        parent = self.head('records', 'events')
        files = dict(self.files['records', parent])
        files[event_path(event.event_id)] = self.encrypt('records', 'events', event_path(event.event_id), event.to_dict())
        files['config/project.enc.json'] = self.encrypt('records', 'events', 'config/project.enc.json',
                                                       event.to_dict()['payload']['project_configuration'])
        oid = self.commit('records', files, parent)
        self.set_head('records', 'events', oid)
        return oid

    def send(self, method, url, headers, timeout, body=None):
        path = url.removeprefix('https://api.github.com')
        self.calls.append(path)
        if method == 'GET':
            return response(self.values[path]) if path in self.values else response({}, 404)
        value = json.loads(body)
        self.writes.append((method, path, copy.deepcopy(value)))
        if path == '/graphql':
            self.graphql_count += 1
            data = value['variables']['input']
            role = data['branch']['repositoryNameWithOwner'].split('/')[1]
            branch = data['branch']['branchName']
            parent = self.head(role, branch)
            if self.before_cas:
                callback, self.before_cas = self.before_cas, None
                callback(role, branch)
                parent = self.head(role, branch)
            if parent != data['expectedHeadOid']:
                return response({'data': {'createCommitOnBranch': None},
                                 'errors': [{'type': 'UNPROCESSABLE', 'message': 'stale head'}]})
            files = dict(self.files[role, parent])
            for item in data['fileChanges']['additions']:
                files[item['path']] = base64.b64decode(item['contents'], validate=True)
            oid = self.commit(role, files, parent)
            self.set_head(role, branch, oid)
            if self.fault == 'lost-cas':
                self.fault = None
                raise TimeoutError('opaque-token or private provider text must not escape')
            if self.fault == 'lost-cas-followed-by-newer':
                self.fault = None
                newer = self.commit(role, {**files, 'other.enc.json': b'newer'}, oid)
                self.set_head(role, branch, newer)
                raise TimeoutError()
            return response({'data': {'createCommitOnBranch': {'commit': {'oid': oid}}}})
        role = path.split('/')[3]
        prefix = f'/repos/acme/{role}/git/'
        if path == prefix + 'blobs':
            raw = base64.b64decode(value['content'], validate=True)
            oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.values[prefix + 'blobs/' + oid] = {
                'sha': oid, 'size': len(raw), 'encoding': 'base64', 'content': value['content']}
            return response({'sha': oid}, 201)
        if path == prefix + 'trees':
            source = next(oid for (r, oid) in self.files
                          if r == role and self.values[prefix + 'commits/' + oid]['tree']['sha'] == value['base_tree'])
            files = dict(self.files[role, source])
            for item in value['tree']:
                files[item['path']] = base64.b64decode(self.values[prefix + 'blobs/' + item['sha']]['content'])
            self.serial += 1
            tree = f'{self.serial + 50000:040x}'
            self.trees[tree] = files
            return response({'sha': tree}, 201)
        if path == prefix + 'commits':
            oid = self.commit(role, self.trees[value['tree']], value['parents'][0])
            return response({'sha': oid}, 201)
        if method == 'PATCH' and path == prefix + 'refs/heads/events':
            if self.before_ref:
                callback, self.before_ref = self.before_ref, None
                callback()
            if self.fault == 'other-422':
                return response({'message': 'Validation Failed'}, 422)
            if self.fault == 'lost-ref-absent':
                self.fault = None
                raise TimeoutError()
            oid = value['sha']
            parent = self.values[prefix + 'commits/' + oid]['parents'][0]['sha']
            if parent != self.head(role, 'events'):
                return response({'message': 'Update is not a fast forward'}, 422)
            assert value['force'] is False
            self.set_head(role, 'events', oid)
            if self.fault == 'lost-ref':
                self.fault = None
                raise TimeoutError('private provider text')
            return response({'ref': 'refs/heads/events', 'object': {'sha': oid, 'type': 'commit'}})
        raise AssertionError((method, path))


class TestConditionalWrites(unittest.TestCase):
    def test_unrelated_transition_after_timeout_is_not_adopted(self):
        f = MutationRepository(); e = f.engine(); s = e.snapshot(); original = f.send
        def sender(method, url, *args):
            if method == 'POST' and url.endswith('/graphql'):
                files = dict(f.files['coverage', f.c])
                files[MARKER] = f.encrypt('coverage', 'coverage', MARKER, {'ops': {}})
                f.set_head('coverage', 'coverage', f.commit('coverage', files, f.c))
                raise TimeoutError()
            return original(method, url, *args)
        e.transport.credentials.sender = sender
        with self.assertRaises(IndeterminateWrite):
            e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c,
                e._encrypted(s, 'coverage', 'coverage', {FENCE: {'state': 'idle', 'generation': 1}}))

    def test_wrong_branch_control_repository_and_unknown_paths_never_write(self):
        f = MutationRepository(); e = f.engine(); e.snapshot()
        for role, branch, path in [('records', 'events', CELL), ('control', 'operations', CELL),
                                    ('coverage', 'coverage', '../x'), ('coverage', 'coverage', 'unknown.enc.json')]:
            with self.subTest(role=role, branch=branch, path=path), self.assertRaises(RecordsError):
                e.transport.conditional_commit(f.binding.repo(role), branch, f.c, {path: b'{}'})
        self.assertFalse(f.writes)

    def test_exact_expected_head_complete_file_set_and_other_files_preserved(self):
        f = MutationRepository(); engine = f.engine(); snapshot = engine.snapshot()
        repo = f.binding.repo('coverage')
        values = {FENCE: {'state': 'idle', 'generation': 1}, MARKER: {'ops': {}}}
        files = engine._encrypted(snapshot, 'coverage', 'coverage', values)
        oid = engine.transport.conditional_commit(repo, 'coverage', f.c, files)
        self.assertEqual(set(f.files['coverage', oid]), set(f.files['coverage', f.c]))
        request = f.writes[-1][2]['variables']['input']
        self.assertEqual(request['expectedHeadOid'], f.c)
        self.assertEqual({i['path'] for i in request['fileChanges']['additions']}, set(values))
        for path in set(f.files['coverage', f.c]) - set(values):
            self.assertEqual(f.files['coverage', oid][path], f.files['coverage', f.c][path])

    def test_stale_head_rejected_before_mutation(self):
        f = MutationRepository(); e = f.engine(); s = e.snapshot()
        newer = f.commit('coverage', f.files['coverage', f.c], f.c)
        f.set_head('coverage', 'coverage', newer)
        with self.assertRaises(HeadConflict):
            e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c,
                e._encrypted(s, 'coverage', 'coverage', {MARKER: {'ops': {}}}))
        self.assertFalse(f.writes)

    def test_race_after_read_uses_server_expected_head_without_retry(self):
        f = MutationRepository(); e = f.engine(); s = e.snapshot()
        f.before_cas = lambda role, branch: f.set_head(role, branch,
            f.commit(role, f.files[role, f.head(role, branch)], f.head(role, branch)))
        with self.assertRaises(IndeterminateWrite):
            e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c,
                e._encrypted(s, 'coverage', 'coverage', {MARKER: {'ops': {}}}))
        self.assertEqual(f.graphql_count, 1)

    def test_lost_response_discovers_exact_transition_even_after_newer_commit(self):
        for fault in ('lost-cas', 'lost-cas-followed-by-newer'):
            with self.subTest(fault=fault):
                f = MutationRepository(); e = f.engine(); s = e.snapshot(); f.fault = fault
                files = e._encrypted(s, 'coverage', 'coverage', {MARKER: {'ops': {}}})
                oid = e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c, files)
                self.assertEqual(f.values['/repos/acme/coverage/git/commits/' + oid]['parents'], [{'sha': f.c}])
                self.assertEqual(f.graphql_count, 1)

    def test_uncertain_absent_write_stays_indeterminate_and_does_not_retry(self):
        f = MutationRepository(); e = f.engine(); s = e.snapshot(); original = f.send
        def sender(method, *args):
            if method == 'POST':
                raise TimeoutError('secret')
            return original(method, *args)
        e.transport.credentials.sender = sender
        with self.assertRaises(IndeterminateWrite) as caught:
            e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c,
                e._encrypted(s, 'coverage', 'coverage', {MARKER: {'ops': {}}}))
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(f.head('coverage', 'coverage'), f.c)

    def test_execution_errors_recover_exact_write_even_with_null_data(self):
        for data in (None, {'createCommitOnBranch': None}):
            with self.subTest(data=data):
                f = MutationRepository(); e = f.engine(); s = e.snapshot(); original = f.send
                def sender(method, url, *args):
                    result = original(method, url, *args)
                    if method == 'POST' and url.endswith('/graphql'):
                        return response({'data': data, 'errors': [
                            {'message': 'Execution result unavailable', 'path': ['createCommitOnBranch']}]})
                    return result
                e.transport.credentials.sender = sender
                files = e._encrypted(s, 'coverage', 'coverage', {MARKER: {'ops': {}}})
                oid = e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c, files)
                self.assertEqual(oid, f.head('coverage', 'coverage'))
                self.assertEqual(f.graphql_count, 1)

    def test_request_error_without_data_rejects_without_mutation(self):
        f = MutationRepository(); e = f.engine(); s = e.snapshot(); original = f.send
        def sender(method, url, *args):
            if method == 'POST' and url.endswith('/graphql'):
                return response({'errors': [{'message': 'Request validation failed'}]})
            return original(method, url, *args)
        e.transport.credentials.sender = sender
        with self.assertRaises(RejectedWrite):
            e.transport.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c,
                e._encrypted(s, 'coverage', 'coverage', {MARKER: {'ops': {}}}))
        self.assertEqual(f.head('coverage', 'coverage'), f.c)
        self.assertFalse(f.writes)

    def test_immutable_events_view_cannot_mutate_any_branch(self):
        f = MutationRepository(); e = f.engine(); e.snapshot()
        view = e.transport.at_events(f.e)
        for write in (
                lambda: view.create_event_commit(f.binding.repo('records'), f.e, {'events/x.json': b'{}'}),
                lambda: view.update_events(f.binding.repo('records'), f.e),
                lambda: view.conditional_commit(f.binding.repo('coverage'), 'coverage', f.c,
                                               {MARKER: b'{}'})):
            with self.assertRaises(RecordsError):
                write()
        self.assertFalse(f.writes)
        self.assertEqual(e.transport.head(f.binding.repo('records'), 'events'), f.e)


class TestDurableAppend(unittest.TestCase):
    @staticmethod
    def complete_derived(fixture):
        from dracla.conformance import (assemble_derived_projection, encrypt_artifact,
            load_release_profile, materialize_derived)
        profile = load_release_profile()
        plaintext = materialize_derived(fixture.state, profile=profile)
        encrypted = {
            path: encrypt_artifact(raw, project_id=fixture.binding.project_id,
                identity=resolve_artifact_identity('records', 'derived', path),
                kid=fixture.kid_bytes['records'], key=fixture.data_keys['records'])
            for path, raw in plaintext.plaintext_files().items()
        }
        assembled = assemble_derived_projection(plaintext, canonical_oid=fixture.e,
            generations=fixture.generations, encrypted_shards=encrypted, profile=profile)
        encrypted['derived/state.enc.json'] = fixture.encrypt(
            'records', 'derived', 'derived/state.enc.json', assembled.state_dict())
        fixture.d = fixture.commit('records', encrypted, fixture.d)
        fixture.set_head('records', 'derived', fixture.d)

    def prepared(self, fixture, event=None, artifacts=None):
        engine = fixture.engine()
        if event is None:
            event, artifacts = fixture.config()
        reference = engine.prepare(event, artifacts)
        subjects = [event.target['subject']['github_user_id']] if 'subject' in event.target else []
        engine.begin(reference, subjects=subjects, project_wide=not subjects, started_at='2026-10-27T00:00:00Z')
        return engine, reference, event

    def test_prepare_fence_marker_claim_event_and_exact_artifacts(self):
        f = MutationRepository(); e, ref, event = self.prepared(f)
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        self.assertEqual(result.observed_events_head, result.canonical_commit)
        s = e.snapshot(); cell = e._cell(s, s.operations_oid)
        fence, marker = e._guards(s, s.coverage_oid)
        self.assertEqual(cell.state, 'appending')
        self.assertEqual(fence.state, 'mutation')
        self.assertEqual(set(marker.to_dict()['ops']), {event.idempotency_key})
        before, after = f.files['records', f.e], f.files['records', result.canonical_commit]
        self.assertEqual({p for p in set(before) | set(after) if before.get(p) != after.get(p)},
                         {event_path(event.event_id), 'config/project.enc.json'})
        writes = len(f.writes)
        again = e.append(ref)
        self.assertEqual(again.canonical_commit, result.canonical_commit)
        self.assertEqual(len(f.writes), writes)

    def test_identical_prepare_retry_after_landing_reuses_original_frozen_reference(self):
        f = MutationRepository(); event, artifacts = f.config()
        e, ref, _ = self.prepared(f, event, artifacts)
        landed = e.append(ref)
        writes = len(f.writes)
        retried = e.prepare(event, artifacts)
        self.assertEqual(retried.commit_oid, ref.commit_oid)
        self.assertEqual(retried.cell.to_dict(), ref.cell.to_dict())
        self.assertEqual(e.append(retried).canonical_commit, landed.canonical_commit)
        self.assertEqual(len(f.writes), writes)

    def test_identical_prepare_retry_after_unrelated_head_advance_preserves_package(self):
        f = MutationRepository(); e = f.engine(); event, artifacts = f.config()
        ref = e.prepare(event, artifacts)
        f.concurrent_config()
        writes = len(f.writes)
        retried = e.prepare(event, artifacts)
        self.assertEqual(retried.cell.to_dict(), ref.cell.to_dict())
        self.assertEqual(retried.commit_oid, ref.commit_oid)
        self.assertEqual(len(f.writes), writes)
        altered = [SideArtifact('project_config', 'config/project.enc.json', b'{}')]
        with self.assertRaises(ValueError):
            e.prepare(event, altered)
        other, package = f.config(statement='Changed retry effect')
        with self.assertRaises(ValueError):
            e.prepare(other, package)
        self.assertEqual(len(f.writes), writes)

    def test_large_preparation_rejects_before_any_durable_write_or_fence(self):
        f = MutationRepository(); e = f.engine()
        event, artifacts = f.config(statement='X' * 143069)
        with self.assertRaises(ValueError):
            e.prepare(event, artifacts)
        self.assertFalse(f.writes)
        snapshot = e.snapshot()
        self.assertEqual(e._cell(snapshot, snapshot.operations_oid).state, 'idle')
        fence, marker = e._guards(snapshot, snapshot.coverage_oid)
        self.assertEqual(fence.state, 'idle')
        self.assertFalse(marker.to_dict()['ops'])

    def test_accepted_preparation_fits_the_largest_encrypted_append_form(self):
        from dracla.conformance import claim_append
        # Exercise the boundary through public preparation, not a copy of its
        # budget formula. Smaller configured transports must obey it as well.
        low, high = 0, 8000
        while low < high:
            middle = (low + high + 1) // 2
            f = MutationRepository(); e = f.engine(); e.transport.max_blob_bytes = 8192
            event, artifacts = f.config(statement='X' * middle)
            try:
                e.prepare(event, artifacts)
            except ValueError:
                self.assertFalse(f.writes)
                high = middle - 1
            else:
                low = middle
        self.assertGreater(low, 0)
        f = MutationRepository(); e = f.engine(); e.transport.max_blob_bytes = 8192
        event, artifacts = f.config(statement='X' * low)
        reference = e.prepare(event, artifacts)
        e.begin(reference, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
        snapshot = e.snapshot(); cell = e._cell(snapshot, snapshot.operations_oid)
        fence, marker = e._guards(snapshot, snapshot.coverage_oid)
        value = cell.to_dict()
        largest = claim_append(cell, operation_id=value['operation_id'],
            operation_sha256=value['operation_sha256'], fence=fence, marker=marker,
            prepared_reference=reference, append_head='f' * 64,
            max_prepared_operation_bytes=e.limit)
        self.assertLessEqual(len(e._encrypted(snapshot, 'records', 'operations',
                                             {CELL: largest.to_dict()})[CELL]), 8192)
        self.assertEqual(e.append(reference).result, 'landed')
        restarted = f.engine(); restarted.transport.max_blob_bytes = 8192
        self.assertEqual(restarted.append(restarted.pending()).result, 'landed')
        f = MutationRepository(); e = f.engine(); e.transport.max_blob_bytes = 8192
        event, artifacts = f.config(statement='X' * (low + 1))
        with self.assertRaises(ValueError):
            e.prepare(event, artifacts)
        self.assertFalse(f.writes)

    def test_prepare_and_begin_resume_from_fresh_heads_after_cas_races(self):
        for phase in ('prepare', 'fence', 'marker'):
            with self.subTest(phase=phase):
                f = MutationRepository(); e = f.engine(); event, artifacts = f.config()
                def race(role, branch):
                    if phase == 'marker' and f.plain(role, branch, f.head(role, branch), FENCE)['state'] == 'idle':
                        f.before_cas = race
                        return
                    parent = f.head(role, branch)
                    f.set_head(role, branch, f.commit(role, f.files[role, parent], parent))
                if phase == 'prepare':
                    f.before_cas = race
                    with self.assertRaises(IndeterminateWrite):
                        e.prepare(event, artifacts)
                    reference = e.prepare(event, artifacts)
                else:
                    reference = e.prepare(event, artifacts)
                    f.before_cas = race
                    with self.assertRaises(IndeterminateWrite):
                        e.begin(reference, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
                e.begin(reference, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
                self.assertEqual(e.append(reference).result, 'landed')
                snapshot = e.snapshot(); cell = e._cell(snapshot, snapshot.operations_oid)
                fence, marker = e._guards(snapshot, snapshot.coverage_oid, cell=cell)
                self.assertEqual(cell.state, 'appending')
                self.assertEqual(fence.state, 'mutation')
                self.assertIn(event.idempotency_key, marker.to_dict()['ops'])

    def test_append_claim_replacement_race_reloads_without_duplicate_event(self):
        f = MutationRepository(); e, reference, event = self.prepared(f)
        def move_events_then_race_claim():
            f.concurrent_config()
            def race_claim(role, branch):
                self.assertEqual((role, branch), ('records', 'operations'))
                parent = f.head(role, branch)
                f.set_head(role, branch, f.commit(role, f.files[role, parent], parent))
            f.before_cas = race_claim
        f.before_ref = move_events_then_race_claim
        result = e.append(reference)
        self.assertEqual(result.result, 'landed')
        self.assertEqual(sum(r.event.event_id == event.event_id for r in e.snapshot().records), 1)

    def test_terminalization_race_reloads_still_prepared_cell(self):
        f = MutationRepository()
        event, artifacts = f.config(statement=f.event.payload['project_configuration']['retention_statement'])
        e, reference, _ = self.prepared(f, event, artifacts)
        def race(role, branch):
            parent = f.head(role, branch)
            f.set_head(role, branch, f.commit(role, f.files[role, parent], parent))
        f.before_cas = race
        self.assertEqual(e.append(reference).result, 'semantic_noop')
        snapshot = e.snapshot()
        self.assertEqual(e._cell(snapshot, snapshot.operations_oid).state, 'terminal')
        self.assertEqual(f.head('records', 'events'), f.e)

    def test_lost_successful_ref_response_is_discovered_without_duplicate_append(self):
        f = MutationRepository(); e, ref, _ = self.prepared(f); f.fault = 'lost-ref'
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        self.assertEqual(sum(p.endswith('/refs/heads/events') for _, p, _ in f.writes), 1)
        self.assertEqual(len(e.snapshot().records), 2)

    def test_absent_ref_after_timeout_revalidates_before_retry(self):
        f = MutationRepository(); e, ref, _ = self.prepared(f); f.fault = 'lost-ref-absent'
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        self.assertEqual(sum(p.endswith('/refs/heads/events') for _, p, _ in f.writes), 2)
        self.assertEqual(len(e.snapshot().records), 2)

    def test_non_fast_forward_rebuild_preserves_concurrent_event(self):
        f = MutationRepository(); e, ref, event = self.prepared(f)
        f.before_ref = f.concurrent_config
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        records = e.snapshot().records
        self.assertEqual(len(records), 3)
        self.assertEqual(records[-1].event.event_id, event.event_id)
        self.assertEqual(records[-1].parent_oid, records[-2].commit_oid)

    def test_other_422_is_not_retried_as_a_race(self):
        f = MutationRepository(); e, ref, _ = self.prepared(f); f.fault = 'other-422'
        with self.assertRaises(RejectedWrite):
            e.append(ref)
        self.assertEqual(sum(p.endswith('/refs/heads/events') for _, p, _ in f.writes), 1)
        s = e.snapshot(); self.assertEqual(e._cell(s, s.operations_oid).state, 'appending')

    def test_semantic_noop_wins_terminal_cas_before_any_append_claim(self):
        f = MutationRepository(); event, artifacts = f.config(statement=f.event.payload['project_configuration']['retention_statement'])
        e, ref, _ = self.prepared(f, event, artifacts)
        result = e.append(ref)
        self.assertEqual(result.result, 'semantic_noop')
        s = e.snapshot(); self.assertEqual(e._cell(s, s.operations_oid).state, 'terminal')
        self.assertEqual(f.head('records', 'events'), f.e)
        self.assertFalse(any('/git/blobs' in p for _, p, _ in f.writes))

    def test_invalid_package_prevents_all_writes(self):
        f = MutationRepository(); e = f.engine(); event, artifacts = f.config()
        with self.assertRaises(ValueError):
            e.prepare(event, [])
        self.assertFalse(f.writes)

    def test_other_operation_and_wrong_scope_cannot_acquire_fence(self):
        f = MutationRepository(); e = f.engine(); event, artifacts = f.config()
        ref = e.prepare(event, artifacts); writes = len(f.writes)
        with self.assertRaises(ValueError):
            e.begin(ref, subjects=[7], project_wide=False, started_at='2026-10-27T00:00:00Z')
        self.assertEqual(len(f.writes), writes)
        other, artifacts = f.config(701)
        with self.assertRaises(ValueError):
            e.prepare(other, artifacts)
        self.assertEqual(len(f.writes), writes)

    def test_restart_recovers_frozen_submission_without_original_request(self):
        f = MutationRepository(); e, ref, event = self.prepared(f)
        restarted = f.engine()
        recovered = restarted.pending()
        self.assertEqual(recovered.cell.to_dict(), ref.cell.to_dict())
        self.assertEqual(recovered.commit_oid, ref.commit_oid)
        result = restarted.append(recovered)
        self.assertEqual(result.result, 'landed')
        again = f.engine().pending()
        self.assertEqual(again.cell.to_dict(), ref.cell.to_dict())
        self.assertEqual(f.engine().append(again).canonical_commit, result.canonical_commit)

    def test_publication_commits_event_and_exact_plaintext_snapshot_metadata_together(self):
        f = MutationRepository()
        event, snapshot, metadata = f.evidence_fixture._publication_fixture()
        e, ref, _ = self.prepared(f, event, [snapshot, metadata])
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        files = f.files['records', result.canonical_commit]
        self.assertEqual(files[snapshot.path], snapshot.bytes)
        self.assertEqual(files[metadata.path], metadata.bytes)
        self.assertIn(event_path(event.event_id), files)

    def test_changed_generation_artifact_uses_current_base_after_race(self):
        from dracla.conformance import required_side_artifacts
        f = MutationRepository()
        event = f.builder.event('records_reader_authorized', 710)
        required = required_side_artifacts(event, preconditions=f.evidence(event, f.e), expected_head=f.e)
        artifacts = []
        for req in required:
            self.assertEqual(req.kind, 'materialization_generations')
            values = {k: v for k, v in f.generations.items() if k != 'generations_version'}
            values.update({k: event.event_id for k in req.affected_classes})
            artifacts.append(SideArtifact(req.kind, req.path, canonical_json({'generations_version': 1, **values})))
        e, ref, _ = self.prepared(f, event, artifacts)
        f.before_ref = f.concurrent_config
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        self.assertEqual(len(e.snapshot().records), 3)
        self.assertEqual(e.snapshot().generations['reader_authority'], event.event_id)

    def test_generation_membership_rebases_required_to_absent_and_preserves_frozen_package(self):
        from dracla.conformance import required_side_artifacts
        f = MutationRepository(rotate=True); e = f.engine(); initial = e.snapshot()
        source = next(record.event for record in initial.records
                       if record.event.type == 'records_reader_authorized')
        event = f.builder.event('records_reader_withdrawn', 850,
                                **{'target.source_event_id': source.event_id})
        prepared_head = initial.events_oid
        original = e.preconditions

        def evidence(current_event, head):
            values = original(current_event, head)
            for row in values:
                if row['name'] == 'reader-authority-state':
                    generation = row['binding']['canonical_generation']
                    row['value'].update(
                        cursor_event_id=generation,
                        source_event_id=current_event.target['source_event_id'],
                        subject=current_event.to_dict()['target']['subject'],
                        source_event_ids=[source.event_id] if head == prepared_head else [],
                    )
            return values

        e.preconditions = evidence
        requirements = required_side_artifacts(event,
            preconditions=evidence(event, prepared_head), expected_head=prepared_head)
        self.assertEqual([item.kind for item in requirements], ['materialization_generations'])
        generations = dict(initial.generations)
        generations.update({name: event.event_id for name in requirements[0].affected_classes})
        artifacts = [SideArtifact(requirements[0].kind, requirements[0].path,
                                   canonical_json({'generations_version': 1, **generations}))]
        reference = e.prepare(event, artifacts)
        frozen = reference.cell.to_dict()
        e.begin(reference, subjects=[event.target['subject']['github_user_id']],
                project_wide=False, started_at='2026-10-27T00:00:00Z')

        competing = f.builder.event('records_reader_withdrawn', 851,
                                    **{'target.source_event_id': source.event_id})
        f.append(competing, ('reader_authority',)); f.set_head('records', 'events', f.e)
        self.complete_derived(f)
        before_head = f.e
        before_files = dict(f.files['records', before_head])
        self.assertEqual([item.kind for item in required_side_artifacts(
            event, preconditions=evidence(event, before_head), expected_head=before_head)], [])

        result = e.append(reference)
        self.assertEqual(result.result, 'landed')
        after_files = f.files['records', result.canonical_commit]
        changed = {path for path in set(before_files) | set(after_files)
                   if before_files.get(path) != after_files.get(path)}
        self.assertEqual(changed, {event_path(event.event_id)})
        self.assertEqual(after_files['config/materialization-generations.enc.json'],
                         before_files['config/materialization-generations.enc.json'])
        restarted = f.engine(); restarted.preconditions = evidence
        recovered = restarted.pending()
        self.assertEqual(recovered.commit_oid, reference.commit_oid)
        self.assertEqual(recovered.cell.to_dict()['event_jcs_b64'], frozen['event_jcs_b64'])
        self.assertEqual(recovered.cell.to_dict()['side_artifacts'], frozen['side_artifacts'])
        writes = len(f.writes)
        restarted_again = f.engine(); restarted_again.preconditions = evidence
        self.assertEqual(restarted_again.append(recovered).canonical_commit, result.canonical_commit)
        self.assertEqual(len(f.writes), writes)

    def test_generation_membership_rebases_absent_to_required_with_stale_derived_reader_state(self):
        from dracla.conformance import required_side_artifacts
        f = MutationRepository(rotate=True); e = f.engine(); initial = e.snapshot()
        source = next(record.event for record in initial.records
                       if record.event.type == 'records_reader_authorized')
        first = f.builder.event('records_reader_withdrawn', 860,
                                **{'target.source_event_id': source.event_id})
        f.append(first, ('reader_authority',)); f.set_head('records', 'events', f.e)
        self.complete_derived(f)
        derived_generation = f.generations['reader_authority']
        prepared_head = f.e
        original = e.preconditions

        def evidence(current_event, head):
            values = original(current_event, head)
            for row in values:
                if row['name'] == 'reader-authority-state':
                    canonical = row['binding']['canonical_generation']
                    row['binding']['derived_generation'] = derived_generation
                    row['value'].update(
                        cursor_event_id=derived_generation,
                        source_event_id=current_event.target['source_event_id'],
                        subject=current_event.to_dict()['target']['subject'],
                        source_event_ids=[],
                        class_state='current' if canonical == derived_generation else 'stale',
                    )
            return values

        e.preconditions = evidence
        event = f.builder.event('records_reader_withdrawn', 861,
                                **{'target.source_event_id': source.event_id})
        self.assertEqual(required_side_artifacts(event, preconditions=evidence(event, prepared_head),
                                                 expected_head=prepared_head), ())
        reference = e.prepare(event, [])
        frozen = reference.cell.to_dict()
        e.begin(reference, subjects=[event.target['subject']['github_user_id']],
                project_wide=False, started_at='2026-10-27T00:00:00Z')

        competing = f.builder.event('records_reader_authorized', 862)
        f.append(competing, ('reader_authority',)); f.set_head('records', 'events', f.e)
        before_head = f.e
        before_files = dict(f.files['records', before_head])
        requirements = required_side_artifacts(event, preconditions=evidence(event, before_head),
                                                expected_head=before_head)
        self.assertEqual([item.kind for item in requirements], ['materialization_generations'])
        result = e.append(reference)
        self.assertEqual(result.result, 'landed')
        after_files = f.files['records', result.canonical_commit]
        changed = {path for path in set(before_files) | set(after_files)
                   if before_files.get(path) != after_files.get(path)}
        self.assertEqual(changed, {event_path(event.event_id),
                                   'config/materialization-generations.enc.json'})
        current_generations = f.plain('records', 'events', result.canonical_commit,
                                      'config/materialization-generations.enc.json')
        self.assertEqual(current_generations['reader_authority'], event.event_id)
        self.assertEqual(current_generations['derived_index'], f.generations['derived_index'])
        restarted = f.engine(); restarted.preconditions = evidence
        recovered = restarted.pending()
        self.assertEqual(recovered.commit_oid, reference.commit_oid)
        self.assertEqual(recovered.cell.to_dict()['event_jcs_b64'], frozen['event_jcs_b64'])
        self.assertEqual(recovered.cell.to_dict()['side_artifacts'], frozen['side_artifacts'])
        writes = len(f.writes)
        restarted_again = f.engine(); restarted_again.preconditions = evidence
        self.assertEqual(restarted_again.append(recovered).canonical_commit, result.canonical_commit)
        self.assertEqual(len(f.writes), writes)

    def test_generation_membership_rebases_absent_to_required_for_reader_rule_withdrawal(self):
        from dracla.conformance import required_side_artifacts
        f = MutationRepository(rotate=True, extra_rules=True); e = f.engine(); initial = e.snapshot()
        rule = next(record.event for record in initial.records
                    if record.event.type == 'records_reader_rule_configured')
        derived_generation = f.generations['reader_authority']
        prepared_head = initial.events_oid
        original = e.preconditions

        def evidence(current_event, head):
            values = original(current_event, head)
            for row in values:
                if row['name'] == 'reader-authority-state':
                    canonical = row['binding']['canonical_generation']
                    row['binding']['derived_generation'] = derived_generation
                    row['value'].update(
                        cursor_event_id=derived_generation,
                        rule_event_id=current_event.target['rule_event_id'],
                        source_event_ids=[],
                        class_state='current' if canonical == derived_generation else 'stale',
                    )
            return values

        e.preconditions = evidence
        event = f.builder.event('records_reader_rule_withdrawn', 870,
                                **{'target.rule_event_id': rule.event_id})
        self.assertEqual(required_side_artifacts(event, preconditions=evidence(event, prepared_head),
                                                 expected_head=prepared_head), ())
        reference = e.prepare(event, [])
        e.begin(reference, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
        competing = f.builder.event('records_reader_rule_configured', 871)
        f.append(competing, ('reader_authority',)); f.set_head('records', 'events', f.e)
        before_files = dict(f.files['records', f.e])
        requirements = required_side_artifacts(event, preconditions=evidence(event, f.e), expected_head=f.e)
        self.assertEqual([item.kind for item in requirements], ['materialization_generations'])
        result = e.append(reference)
        self.assertEqual(result.result, 'landed')
        after_files = f.files['records', result.canonical_commit]
        changed = {path for path in set(before_files) | set(after_files)
                   if before_files.get(path) != after_files.get(path)}
        self.assertEqual(changed, {event_path(event.event_id),
                                   'config/materialization-generations.enc.json'})
        generations = f.plain('records', 'events', result.canonical_commit,
                              'config/materialization-generations.enc.json')
        self.assertEqual(generations['reader_authority'], event.event_id)

    def test_competing_append_claim_prevents_prepared_noop_terminalization(self):
        from dracla.conformance import claim_append
        f = MutationRepository()
        event, artifacts = f.config(statement=f.event.payload['project_configuration']['retention_statement'])
        e, ref, _ = self.prepared(f, event, artifacts)
        def claim(role, branch):
            self.assertEqual(branch, 'operations')
            s = e.snapshot(); cell = e._cell(s, s.operations_oid); fence, marker = e._guards(s, s.coverage_oid)
            value = cell.to_dict()
            claimed = claim_append(cell, operation_id=value['operation_id'], operation_sha256=value['operation_sha256'],
                fence=fence, marker=marker, prepared_reference=ref, append_head=s.events_oid,
                max_prepared_operation_bytes=e.limit)
            e._write(s, 'records', 'operations', s.operations_oid, {CELL: claimed.to_dict()})
        f.before_cas = claim
        self.assertEqual(e.append(ref).result, 'indeterminate')
        s = e.snapshot(); self.assertEqual(e._cell(s, s.operations_oid).state, 'appending')
        writes = len(f.writes)
        self.assertEqual(e.append(ref).result, 'indeterminate')
        self.assertEqual(len(f.writes), writes)
        self.assertEqual(e._guards(s, s.coverage_oid)[0].state, 'mutation')

    def test_conflicting_publication_terminalizes_only_the_still_prepared_cell(self):
        f = MutationRepository(); event, snapshot, metadata = f.evidence_fixture._publication_fixture()
        e, ref, _ = self.prepared(f, event, [snapshot, metadata])
        content = b'Concurrent agreement text'
        digest = 'sha256:' + hashlib.sha256(content).hexdigest()
        other = f.builder.event('agreement_published', 999, **{'payload.digest': digest, 'payload.snapshot_sha256': digest})
        details = {'metadata_version': 1, **other.to_dict()['target'], **{k: other.to_dict()['payload'][k]
                   for k in ('recipient', 'ref', 'content_commit_oid', 'digest', 'snapshot_sha256')}}
        f.append(other, (), {other.payload['snapshot_content_path']: content,
                            other.payload['snapshot_metadata_path']: canonical_json(details)})
        f.set_head('records', 'events', f.e)
        current_head = f.head('records', 'events')
        self.assertIn(snapshot.path, f.files['records', current_head])
        self.assertIn(metadata.path, f.files['records', current_head])
        original_evidence = e.preconditions
        requested_heads = []
        def truthful_evidence(current_event, head):
            values = original_evidence(current_event, head)
            if head == current_head:
                requested_heads.append(head)
                files = f.files['records', head]
                for item in values:
                    if item['name'] in {'publication-snapshot-absence', 'publication-metadata-absence'}:
                        item['value']['present'] = item['path'] in files
            return values
        e.preconditions = truthful_evidence
        result = e.append(ref)
        self.assertEqual(result.result, 'conflict')
        self.assertNotIn(current_head, requested_heads)
        s = e.snapshot(); self.assertEqual(e._cell(s, s.operations_oid).state, 'terminal')
        fence, marker = e._guards(s, s.coverage_oid)
        self.assertEqual(fence.state, 'mutation')
        self.assertIn(event.idempotency_key, marker.to_dict()['ops'])
        self.assertFalse(any('/git/blobs' in path for _, path, _ in f.writes))
        writes = len(f.writes)
        restarted = f.engine()
        recovered = restarted.pending()
        self.assertEqual(restarted.append(recovered).result, 'conflict')
        terminal = restarted._cell(restarted.snapshot(), restarted.snapshot().operations_oid)
        self.assertEqual(terminal.state, 'terminal')
        self.assertEqual(len(f.writes), writes)

    def test_corrupt_current_head_evidence_stays_fail_closed_for_applicable_append(self):
        f = MutationRepository(); e, ref, _ = self.prepared(f)
        f.concurrent_config()
        current_head = f.head('records', 'events')
        original_evidence = e.preconditions
        def corrupt_current_head_evidence(current_event, head):
            if head == current_head:
                return []
            return original_evidence(current_event, head)
        e.preconditions = corrupt_current_head_evidence
        writes = len(f.writes)
        with self.assertRaises(PreconditionValidationError):
            e.append(ref)
        self.assertEqual(len(f.writes), writes)
        s = e.snapshot(); self.assertEqual(e._cell(s, s.operations_oid).state, 'prepared')

    def test_corrupt_or_incomplete_frozen_package_cannot_be_recovered_as_success(self):
        f = MutationRepository(); e, ref, _ = self.prepared(f)
        current = f.head('records', 'operations')
        raw = f.plain('records', 'operations', current, CELL)
        raw['side_artifacts'] = []
        bad = f.commit('records', {CELL: f.encrypt('records', 'operations', CELL, raw)}, current)
        f.set_head('records', 'operations', bad)
        writes = len(f.writes)
        with self.assertRaises(ValueError):
            e.append(ref)
        self.assertEqual(len(f.writes), writes)

    def test_missing_precondition_evidence_does_not_turn_provider_failure_into_conflict(self):
        f = MutationRepository(); e, ref, _ = self.prepared(f)
        f.concurrent_config()
        current_head = f.head('records', 'events')
        original_evidence = e.preconditions
        def unavailable(current_event, head):
            if head == current_head:
                raise RecordsError()
            return original_evidence(current_event, head)
        e.preconditions = unavailable
        writes = len(f.writes)
        with self.assertRaises(RecordsError):
            e.append(ref)
        self.assertEqual(len(f.writes), writes)


class TestMutationKeySelection(unittest.TestCase):
    def predecessor(self, f, role, branch, head, path):
        old = b'r' if role == 'records' else b'c'
        return encrypt_json_artifact(f.plain(role, branch, head, path), project_id=f.binding.project_id,
            identity=resolve_artifact_identity(role, branch, path), kid=old * 16, key=old * 32)

    def test_retired_key_idle_operation_fence_and_marker_are_rejected_without_writes(self):
        for role, branch, path in [('records', 'operations', CELL),
                                  ('coverage', 'coverage', FENCE), ('coverage', 'coverage', MARKER)]:
            with self.subTest(path=path):
                f = MutationRepository(rotate=True); e = f.engine()
                head = f.head(role, branch)
                files = {**f.files[role, head], path: self.predecessor(f, role, branch, head, path)}
                bad = f.commit(role, files, head); f.set_head(role, branch, bad)
                s = e.snapshot()
                with self.assertRaises(RecordsError) as caught:
                    e._cell(s, s.operations_oid) if role == 'records' else e._guards(s, s.coverage_oid)
                self.assertEqual(caught.exception.category, 'invalid-key')
                self.assertFalse(f.writes)

    def test_retired_key_unrelated_prepared_operation_is_not_a_rotation_exception(self):
        f = MutationRepository(rotate=True); e = f.engine(); event, artifacts = f.config()
        ref = e.prepare(event, artifacts); head = f.head('records', 'operations')
        bad = f.commit('records', {CELL: self.predecessor(f, 'records', 'operations', head, CELL)}, head)
        f.set_head('records', 'operations', bad); writes = len(f.writes)
        with self.assertRaises(RecordsError):
            e.pending()
        with self.assertRaises(RecordsError):
            e.begin(ref, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
        self.assertEqual(len(f.writes), writes)

    def test_retired_fence_or_marker_cannot_join_an_unrelated_current_key_operation(self):
        for path in (FENCE, MARKER):
            with self.subTest(path=path):
                f = MutationRepository(rotate=True); e = f.engine(); event, artifacts = f.config()
                ref = e.prepare(event, artifacts)
                e.begin(ref, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
                head = f.head('coverage', 'coverage')
                files = {**f.files['coverage', head], path: self.predecessor(f, 'coverage', 'coverage', head, path)}
                bad = f.commit('coverage', files, head); f.set_head('coverage', 'coverage', bad)
                writes = len(f.writes)
                with self.assertRaises(RecordsError) as caught:
                    e.append(ref)
                self.assertEqual(caught.exception.category, 'invalid-key')
                self.assertEqual(len(f.writes), writes)

    def test_historical_reference_requires_the_key_selected_at_its_prepared_head(self):
        f = MutationRepository(rotate=True); e = f.engine(); event, artifacts = f.config()
        e.prepare(event, artifacts); head = f.head('records', 'operations')
        bad = f.commit('records', {CELL: self.predecessor(f, 'records', 'operations', head, CELL)}, head)
        s = e.snapshot()
        with self.assertRaises(RecordsError) as caught:
            e._cell(s, bad, historical=True)
        self.assertEqual(caught.exception.category, 'invalid-key')

    def test_invalid_activation_never_publishes_or_acquires_append_rights(self):
        from dracla.conformance import Keyring, encode_keyring, wrap_key_copy
        from core.tests.test_records_1 import TestKeyLifecycle
        for defect in ('missing-selected-key', 'backward', 'non-ancestral', 'retired-kid', 'retired-bytes'):
            with self.subTest(defect=defect):
                f = MutationRepository(rotate=True)
                lifecycle = TestKeyLifecycle()
                ring = lifecycle.ring(f)
                kids = dict(f.kids)
                if defect == 'retired-kid':
                    kids['records'] = base64url_encode(b'r' * 16)
                else:
                    kid, key = b'Z' * 16, b'r' * 32 if defect == 'retired-bytes' else b'Z' * 32
                    ring = Keyring(ring.keys + (wrap_key_copy(key, project_id=f.binding.project_id,
                        capability='records', data_kid=kid, wrapper_id='recovery',
                        wrapper_generation='install-1', wrapping_key=f.wrapping),))
                    kids['records'] = base64url_encode(kid)
                candidate = f.commit('records', {**f.files['records', f.b],
                    '.dracla/recovery/keyring.json': encode_keyring(ring)}, f.b)
                f.set_head('records', 'keys', candidate)
                if defect == 'missing-selected-key':
                    kids['records'] = base64url_encode(b'X' * 16)
                elif defect == 'backward':
                    candidate = f.b
                elif defect == 'non-ancestral':
                    candidate = f.commit('records', f.files['records', candidate], f.b)
                event = f.builder.event('keyring_activated', 750, **{'payload.generation': 3,
                    'payload.keys_commit_oid': candidate, 'payload.current_kids': kids})
                e = f.engine(); ref = e.prepare(event, [])
                e.begin(ref, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
                events = f.head('records', 'events'); operations = f.head('records', 'operations')
                with self.assertRaises(RecordsError):
                    e.append(ref)
                self.assertEqual(f.head('records', 'events'), events)
                self.assertEqual(f.head('records', 'operations'), operations)
                self.assertEqual(f.plain('records', 'operations', operations, CELL)['state'], 'prepared')
                self.assertFalse(any(method == 'PATCH' and path.endswith('/refs/heads/events')
                                     for method, path, _ in f.writes))

    def activated_inflight(self):
        from dracla.conformance import Keyring, encode_keyring, wrap_key_copy
        f = MutationRepository()
        next_bytes = {'records': b'R' * 16, 'coverage': b'C' * 16}
        next_keys = {'records': b'R' * 32, 'coverage': b'C' * 32}
        ring = Keyring(tuple(wrap_key_copy(key, project_id=f.binding.project_id, capability=cap,
            data_kid=kid, wrapper_id='recovery', wrapper_generation='install-1', wrapping_key=f.wrapping)
            for cap in ('records', 'coverage')
            for kid, key in [(f.kid_bytes[cap], f.data_keys[cap]), (next_bytes[cap], next_keys[cap])]))
        candidate = f.commit('records', {**f.key_files, '.dracla/bootstrap.json': f.manifest,
            '.dracla/recovery/keyring.json': encode_keyring(ring)}, f.b)
        f.set_head('records', 'keys', candidate)
        event = f.builder.event('keyring_activated', 740, **{'payload.generation': 2,
            'payload.keys_commit_oid': candidate,
            'payload.current_kids': {cap: base64url_encode(kid) for cap, kid in next_bytes.items()}})
        e = f.engine(); ref = e.prepare(event, [])
        e.begin(ref, subjects=[], project_wide=True, started_at='2026-10-27T00:00:00Z')
        result = e.append(ref)
        self.assertEqual(result.result, 'landed')
        return f, ref, result, next_bytes, next_keys

    def test_exact_post_activation_crash_recovers_original_predecessor_state(self):
        f, ref, landed, _, _ = self.activated_inflight()
        restarted = f.engine(); s = restarted.snapshot()
        self.assertNotEqual(s.state.current_kids['records'], f.kids['records'])
        writes = len(f.writes)
        recovered = restarted.pending()
        self.assertEqual(recovered.commit_oid, ref.commit_oid)
        self.assertEqual(recovered.cell.to_dict(), ref.cell.to_dict())
        self.assertEqual(restarted.append(recovered).canonical_commit, landed.canonical_commit)
        self.assertEqual(len(f.writes), writes)
        # Only immutable original-head reference reads may use their original kid.
        original = restarted._cell(s, ref.commit_oid, historical=True)
        self.assertEqual(original.to_dict(), ref.cell.to_dict())
        with self.assertRaises(RecordsError):
            restarted._cell(s, ref.commit_oid)

    def test_old_rotation_state_is_rejected_after_a_later_canonical_event(self):
        f, _, _, kids, keys = self.activated_inflight()
        f.kid_bytes, f.data_keys = kids, keys
        f.concurrent_config('Later current-key configuration')
        with self.assertRaises(RecordsError) as caught:
            f.engine().pending()
        self.assertEqual(caught.exception.category, 'invalid-key')


if __name__ == '__main__':
    unittest.main()
