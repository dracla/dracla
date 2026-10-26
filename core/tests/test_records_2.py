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
    def __init__(self, *, rotate=False):
        super().__init__(complete_history=rotate, rotate=rotate)
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
                return response({'errors': [{'type': 'UNPROCESSABLE', 'message': 'stale head'}]})
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
        with self.assertRaises(RejectedWrite):
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


class TestDurableAppend(unittest.TestCase):
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
        with self.assertRaises(RejectedWrite):
            e.append(ref)
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
