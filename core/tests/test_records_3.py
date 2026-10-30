"""Concrete encrypted recovery, branch CAS and persisted crash boundaries."""
from __future__ import annotations

import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from dracla.conformance import (
    canonical_json, load_release_profile, base64url_encode, encode_keyring,
    SideArtifact, required_side_artifacts, event_path,
    decode_decision_fence, decode_inflight_marker, materialize_coverage,
    derive_event_identity, validate_event, reserve_success, release_success,
)
from dracla.records.append import CELL, FENCE, MARKER, RecoveryBlocked
from dracla.records.credentials import RecordsError
from dracla.records.github import HeadConflict, IndeterminateWrite
from dracla.records.history import verify_project
from dracla.records.reconcile import reconcile_project, StoredPreconditions, publish_coverage
from core.tests.test_records_2 import MutationRepository

NOW = '2026-10-27T00:00:00Z'


class Crash(BaseException):
    pass


def reconcile(f):
    keys, transport = f.reader()
    return reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                             built_at=NOW, dracla_version='test-1', sleep=lambda _: None)


def prepared(f):
    event, artifacts = f.config()
    engine = f.engine()
    reference = engine.prepare(event, artifacts)
    return engine, reference


def prepare_with_stored_evidence(f, event):
    from dracla.records.append import MutationEngine
    keys, transport = f.reader()
    provider = StoredPreconditions(f.binding, keys, transport)
    engine = MutationEngine(f.binding, keys, transport, provider, sleep=lambda _: None)
    snapshot = engine.snapshot()
    evidence = provider(event, snapshot.events_oid)
    artifacts = []
    for requirement in required_side_artifacts(event, preconditions=evidence, expected_head=snapshot.events_oid):
        if requirement.kind == 'materialization_generations':
            generations = dict(snapshot.generations)
            generations.update({k: event.event_id for k in requirement.affected_classes})
            artifacts.append(SideArtifact(requirement.kind, requirement.path,
                canonical_json({'generations_version': 1, **generations})))
        elif requirement.kind == 'project_config':
            artifacts.append(SideArtifact(requirement.kind, requirement.path,
                                          canonical_json(event.to_dict()['payload']['project_configuration'])))
        else:
            raise AssertionError(requirement.kind)
    engine.prepare(event, artifacts)


def default_reconcile(f):
    keys, transport = f.reader()
    return reconcile_project(f.binding, keys, transport, built_at=NOW,
                             dracla_version='test-1', sleep=lambda _: None)


class TestDerivedConditionalWrites(unittest.TestCase):
    def test_derived_cas_and_lost_response_preserve_unrelated_files(self):
        for fault in (None, 'lost-cas', 'lost-cas-followed-by-newer'):
            with self.subTest(fault=fault):
                f = MutationRepository(); engine = f.engine(); s = engine.snapshot()
                path = 'derived/index/00.enc.json'
                raw = f.files['records', f.d][path]
                f.fault = fault
                oid = engine.transport.conditional_commit(f.binding.repo('records'), 'derived', f.d, {path: raw})
                self.assertEqual(f.files['records', oid], f.files['records', f.d])
                self.assertEqual(f.graphql_count, 1)
                data = f.writes[-1][2]['variables']['input']
                self.assertEqual(data['expectedHeadOid'], s.derived_oid)
                self.assertEqual(data['branch']['branchName'], 'derived')

    def test_stale_derived_head_and_wrong_branch_paths_do_not_write(self):
        f = MutationRepository(); engine = f.engine(); engine.snapshot()
        raw = f.files['records', f.d]['derived/index/00.enc.json']
        newer = f.commit('records', f.files['records', f.d], f.d)
        f.set_head('records', 'derived', newer)
        with self.assertRaises(HeadConflict):
            engine.transport.conditional_commit(f.binding.repo('records'), 'derived', f.d,
                                                {'derived/index/00.enc.json': raw})
        for branch, path in [('derived', CELL), ('events', 'derived/index/00.enc.json'),
                             ('operations', 'derived/index/00.enc.json')]:
            with self.subTest(branch=branch, path=path), self.assertRaises(RecordsError):
                engine.transport.conditional_commit(f.binding.repo('records'), branch, newer, {path: raw})
        self.assertFalse(f.writes)


class TestReconciliation(unittest.TestCase):
    def assert_complete(self, f):
        report = reconcile(f)
        self.assertTrue(report.valid, report)
        keys, transport = f.reader()
        actual = verify_project(f.binding, keys, transport)
        self.assertTrue(actual.valid, actual.discrepancies)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'idle')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'idle')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), MARKER), {'ops': {}})

    def test_clean_idle_reconcile_is_read_only(self):
        f = MutationRepository()
        self.assert_complete(f)
        self.assertFalse(f.writes)

    def test_prepared_operation_completes_without_original_request(self):
        f = MutationRepository(); prepared(f)
        self.assert_complete(f)
        keys, transport = f.reader()
        transport.authorize(f.binding)
        self.assertEqual(len(transport.ancestry(f.binding.repo('records'), f.head('records', 'events'))), 3)
        writes = len(f.writes)
        self.assert_complete(f)
        self.assertEqual(len(f.writes), writes)

    def test_already_landed_operation_is_not_appended_again(self):
        f = MutationRepository(); engine, reference = prepared(f)
        engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        outcome = engine.append(reference)
        head = f.head('records', 'events')
        self.assertEqual(outcome.result, 'landed')
        self.assert_complete(f)
        self.assertEqual(f.head('records', 'events'), head)

    def test_semantic_noop_releases_exact_guards_without_event(self):
        f = MutationRepository(); event, artifacts = f.config(statement='Initial retention statement')
        # Use the real initial canonical configuration, rather than guessing a
        # fixture string. Its package still requires normal M1 validation.
        current = f.event.to_dict()['payload']['project_configuration']['retention_statement']
        event, artifacts = f.config(statement=current)
        f.engine().prepare(event, artifacts)
        head = f.head('records', 'events')
        self.assert_complete(f)
        self.assertEqual(f.head('records', 'events'), head)

    def test_every_mutation_crash_boundary_recovers_forward(self):
        def setup(f, family):
            if family == 'configuration':
                prepared(f)
            else:
                prepare_with_stored_evidence(f, f.builder.event('records_reader_authorized', 783))
        for family in ('configuration', 'private-generation'):
            baseline = MutationRepository(); setup(baseline, family)
            start = len(baseline.writes)
            self.assert_complete(baseline)
            count = len(baseline.writes) - start
            self.assertGreater(count, 6)
            for phase in ('before', 'after'):
                for stop in range(1, count + 1):
                    with self.subTest(family=family, phase=phase, mutation=stop):
                        f = MutationRepository(); setup(f, family)
                        keys, transport = f.reader()
                        original = transport.credentials.sender
                        seen = 0
                        def sender(method, *args):
                            nonlocal seen
                            if method != 'GET':
                                seen += 1
                                if seen == stop and phase == 'before':
                                    raise Crash()
                            result = original(method, *args)
                            if method != 'GET' and seen == stop and phase == 'after':
                                raise Crash()
                            return result
                        transport.credentials.sender = sender
                        with self.assertRaises(Crash):
                            reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
                        self.assert_complete(f)

    def test_idle_corrupt_projection_requires_route_unavailable_proof(self):
        f = MutationRepository()
        values = dict(f.files['records', f.d]); values['derived/index/00.enc.json'] = b'{}'
        f.set_head('records', 'derived', f.commit('records', values, f.d))
        report = reconcile(f)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'route-unavailable-proof-required')
        self.assertFalse(f.writes)

    def test_success_reservation_requires_m4_check_confirmation(self):
        f = MutationRepository()
        values = dict(f.files['coverage', f.c])
        values[FENCE] = f.encrypt('coverage', 'coverage', FENCE,
            {'state': 'success_reserved', 'generation': 0,
             'check_identity': base64url_encode(b'x' * 32), 'projection_commit': f.c})
        f.set_head('coverage', 'coverage', f.commit('coverage', values, f.c))
        report = reconcile(f)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'check-confirmation-required')
        self.assertFalse(f.writes)

    def test_changed_private_generation_publishes_all_shards_before_state(self):
        from dracla.conformance import SideArtifact
        f = MutationRepository(); engine = f.engine()
        event = f.builder.event('records_reader_authorized', 710)
        generations = dict(engine.snapshot().generations); generations['reader_authority'] = event.event_id
        artifacts = [SideArtifact('materialization_generations',
            'config/materialization-generations.enc.json',
            canonical_json({'generations_version': 1, **generations}))]
        engine.prepare(event, artifacts)
        self.assert_complete(f)
        writes = [w[2]['variables']['input'] for w in f.writes if w[1] == '/graphql'
                  and w[2]['variables']['input']['branch']['branchName'] == 'derived']
        self.assertEqual([len(w['fileChanges']['additions']) for w in writes], [32, 32, 32, 1])
        self.assertEqual(writes[-1]['fileChanges']['additions'][0]['path'], 'derived/state.enc.json')
        stored = f.plain('records', 'derived', f.head('records', 'derived'), 'derived/state.enc.json')
        self.assertEqual(stored['generations']['reader_authority'], event.event_id)

    def test_key_activation_recovery_reencrypts_all_guards_and_projections(self):
        from core.tests.test_records_2 import TestMutationKeySelection
        f, _, _, kids, keys = TestMutationKeySelection().activated_inflight()
        for role in keys:
            f.all_keys[role][base64url_encode(kids[role])] = keys[role]
        self.assert_complete(f)

    def test_newer_canonical_head_during_private_publication_restarts_before_release(self):
        f = MutationRepository(); event = f.builder.event('records_reader_authorized', 780)
        prepare_with_stored_evidence(f, event)
        engine = f.engine(); reference = engine.pending()
        engine.begin(reference, subjects=[7], project_wide=False, started_at=NOW)
        engine.append(reference)
        moved = []
        f.before_cas = lambda role, branch: moved.append(f.concurrent_config())
        self.assert_complete(f)
        source = f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), 'source.enc.json')
        self.assertEqual(source['canonical_sha'], moved[0])
        records = f.engine().snapshot().records
        self.assertEqual(sum(r.event.event_id == event.event_id for r in records), 1)

    def test_derived_head_race_keeps_newer_unrelated_bytes_and_retries_exact_cas(self):
        f = MutationRepository(); event = f.builder.event('records_reader_authorized', 781)
        prepare_with_stored_evidence(f, event)
        engine = f.engine(); reference = engine.pending()
        engine.begin(reference, subjects=[7], project_wide=False, started_at=NOW)
        engine.append(reference)
        def competing(role, branch):
            if (role, branch) != ('records', 'derived'):
                f.before_cas = competing
                return
            head = f.head(role, branch)
            f.set_head(role, branch, f.commit(role, {**f.files[role, head], 'README.md': b'concurrent inert file'}, head))
        f.before_cas = competing
        self.assert_complete(f)
        self.assertEqual(f.files['records', f.head('records', 'derived')]['README.md'], b'concurrent inert file')

    def test_derived_overflow_keeps_canonical_event_and_live_guards(self):
        from unittest.mock import patch
        from dracla.conformance import ReleaseProfile
        f = MutationRepository(); prepared(f)
        values = load_release_profile().to_dict()
        values['max_state_ciphertext_bytes'] = 1
        with patch('dracla.records.append.load_release_profile', return_value=ReleaseProfile(values)):
            report = reconcile(f)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'derived-overflow')
        self.assertEqual(len(f.engine().snapshot().records), 2)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'appending')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'mutation')

    def test_terminal_with_wrong_canonical_commit_cannot_clear_guards(self):
        f = MutationRepository(); engine, reference = prepared(f)
        engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        engine.append(reference)
        from dracla.records.reconcile import publish_projections
        state = engine.recovery_state()
        publish_projections(state, engine.transport, profile=engine.profile, built_at=NOW, dracla_version='test-1')
        # Capture the persisted terminal state, then crash before its release.
        original = engine.transport.credentials.sender
        def sender(method, url, headers, timeout, body=None):
            if method == 'POST' and url.endswith('/graphql'):
                additions = json.loads(body)['variables']['input']['fileChanges']['additions']
                if len(additions) == 1 and additions[0]['path'] == FENCE:
                    raise Crash()
            return original(method, url, headers, timeout, body)
        engine.transport.credentials.sender = sender
        with self.assertRaises(Crash):
            engine.complete(engine.recovery_state(), projection_verified=True)
        head = f.head('records', 'operations'); cell = f.plain('records', 'operations', head, CELL)
        self.assertEqual(cell['state'], 'terminal')
        cell['canonical_commit'] = f.e
        f.set_head('records', 'operations', f.commit('records', {CELL: f.encrypt('records', 'operations', CELL, cell)}, head))
        writes = len(f.writes)
        with self.assertRaises(RecordsError):
            reconcile(f)
        self.assertEqual(len(f.writes), writes)

    def test_forged_noop_cannot_discard_a_durable_append_claim(self):
        f = MutationRepository(); engine, reference = prepared(f)
        engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        f.before_ref = lambda: f.concurrent_config(statement='Mutation test retention')
        self.assertEqual(engine.append(reference).result, 'indeterminate')
        head = f.head('records', 'operations'); cell = f.plain('records', 'operations', head, CELL)
        self.assertEqual(cell['state'], 'appending')
        forged = {k: cell[k] for k in ('generation', 'operation_id', 'operation_sha256', 'event_id')}
        forged.update(state='terminal', result='semantic_noop',
                      observed_events_head=f.head('records', 'events'), canonical_commit=None)
        f.set_head('records', 'operations', f.commit('records',
            {CELL: f.encrypt('records', 'operations', CELL, forged)}, head))
        writes = len(f.writes)
        with self.assertRaises(RecordsError):
            reconcile(f)
        self.assertEqual(len(f.writes), writes)

    def test_persistent_uncertain_append_retains_its_claim_and_guards(self):
        from core.tests.test_records_1 import response
        f = MutationRepository(); prepared(f); keys, transport = f.reader()
        original = transport.credentials.sender; attempts = []
        def sender(method, url, *args):
            if method == 'PATCH' and url.endswith('/refs/heads/events'):
                attempts.append(True)
                return response({}, 503)
            return original(method, url, *args)
        transport.credentials.sender = sender
        report = reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                   built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'indeterminate')
        self.assertEqual(len(attempts), load_release_profile().limit('max_mutation_retries'))
        self.assertEqual(f.head('records', 'events'), f.e)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'appending')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'mutation')

    def test_repeated_guard_cas_races_stop_without_abandoning_preparation(self):
        f = MutationRepository(); prepared(f)
        start = f.graphql_count
        def race(role, branch):
            head = f.head(role, branch)
            f.set_head(role, branch, f.commit(role, f.files[role, head], head))
            f.before_cas = race
        f.before_cas = race
        report = reconcile(f)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'indeterminate')
        self.assertEqual(f.graphql_count - start, load_release_profile().limit('max_mutation_retries'))
        self.assertEqual(f.head('records', 'events'), f.e)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'prepared')


class TestStoredRecoveryAndCommand(unittest.TestCase):
    def args(self, f):
        return ['reconcile', 'project.id=' + f.binding.project_id, 'github.owner=acme', 'github.owner_id=10'] + [
            v for repo in f.binding.repositories for v in (repo.role + '.name=' + repo.name, repo.role + '.id=' + str(repo.id))]

    def _activated_inflight(self, *, records_only):
        from dracla.conformance import Keyring, wrap_key_copy

        f = MutationRepository()
        next_bytes = {'records': b'R' * 16,
                      'coverage': f.kid_bytes['coverage'] if records_only else b'C' * 16}
        next_keys = {'records': b'R' * 32,
                     'coverage': f.data_keys['coverage'] if records_only else b'C' * 32}
        copies = []
        for capability in ('records', 'coverage'):
            copies.append(wrap_key_copy(f.data_keys[capability], project_id=f.binding.project_id,
                                        capability=capability, data_kid=f.kid_bytes[capability],
                                        wrapper_id='recovery', wrapper_generation='install-1',
                                        wrapping_key=f.wrapping))
            if not records_only or capability == 'records':
                copies.append(wrap_key_copy(next_keys[capability], project_id=f.binding.project_id,
                                            capability=capability, data_kid=next_bytes[capability],
                                            wrapper_id='recovery', wrapper_generation='install-1',
                                            wrapping_key=f.wrapping))
        ring = Keyring(tuple(copies))
        candidate = f.commit('records', {**f.key_files, '.dracla/bootstrap.json': f.manifest,
                                         '.dracla/recovery/keyring.json': encode_keyring(ring)}, f.b)
        f.set_head('records', 'keys', candidate)
        event = f.builder.event('keyring_activated', 741 if records_only else 742,
                                **{'payload.generation': 2,
                                   'payload.keys_commit_oid': candidate,
                                   'payload.current_kids': {
                                       capability: base64url_encode(next_bytes[capability])
                                       for capability in ('records', 'coverage')}})
        engine = f.engine()
        reference = engine.prepare(event, [])
        engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        result = engine.append(reference)
        self.assertEqual(result.result, 'landed')
        for capability in ('records', 'coverage'):
            f.all_keys[capability][base64url_encode(next_bytes[capability])] = next_keys[capability]
        original_record = next(record for record in engine.snapshot().records
                               if record.event.event_id == event.event_id)
        original_raw = f.files['records', original_record.commit_oid][event_path(event.event_id)]
        return f, event, original_record, original_raw

    def test_same_id_key_substitution_cannot_write_during_activation_recovery(self):
        from dracla.conformance import Keyring, base64url_decode, decode_keyring, unwrap_key_copy, wrap_key_copy
        from dracla.records.history import open_history
        from core.tests.test_records_1 import control_reader

        for mode, changed in ((mode, changed) for mode in ('recovery', 'control')
                for changed in (('records',), ('coverage',), ('records', 'coverage'))):
            with self.subTest(mode=mode, changed=changed):
                f, _, _, _ = self._activated_inflight(records_only=False)
                snapshot = f.engine().snapshot()
                head = f.head('records', 'keys')
                ring = decode_keyring(f.files['records', head]['.dracla/recovery/keyring.json'],
                    expected_project_id=f.binding.project_id, allowed_capabilities={'records', 'coverage'},
                    allowed_wrappers={'recovery'}, known_generations={'recovery': ('install-1',)})
                copies, control_copies = [], []
                for wrapped in ring.keys:
                    key = unwrap_key_copy(wrapped, expected_project_id=f.binding.project_id,
                        expected_capability=wrapped.capability,
                        wrapping_keys={('recovery', 'install-1'): f.wrapping})
                    if (wrapped.capability in changed
                            and wrapped.data_kid == snapshot.state.current_kids[wrapped.capability]):
                        key = (b'x' if wrapped.capability == 'records' else b'y') * 32
                    copies.append(wrap_key_copy(key, project_id=f.binding.project_id,
                        capability=wrapped.capability, data_kid=base64url_decode(wrapped.data_kid),
                        wrapper_id='recovery', wrapper_generation='install-1', wrapping_key=f.wrapping))
                    control_copies.append(wrap_key_copy(key, project_id=f.binding.project_id,
                        capability=wrapped.capability, data_kid=base64url_decode(wrapped.data_kid),
                        wrapper_id='control', wrapper_generation='install-1', wrapping_key=f.wrapping))
                files = {**f.files['records', head], '.dracla/recovery/keyring.json': encode_keyring(Keyring(tuple(copies)))}
                f.set_head('records', 'keys', f.commit('records', files, head))
                if mode == 'control':
                    protected = encode_keyring(Keyring(tuple(control_copies)))
                    f.reader = lambda: control_reader(f, protected)
                before, canonical = len(f.writes), f.head('records', 'events')
                with self.assertRaises(RecordsError) as caught:
                    open_history(f.binding, *f.reader())
                self.assertEqual(str(caught.exception), 'invalid-key')
                with self.assertRaises(RecordsError) as caught:
                    default_reconcile(f)
                self.assertEqual(str(caught.exception), 'invalid-key')
                self.assertEqual(len(f.writes), before)
                self.assertEqual(f.head('records', 'events'), canonical)

    def _crash_after_activation_release(self, f, event, original_record, original_raw):
        keys, transport = f.reader()
        sender = transport.credentials.sender
        release_writes = 0

        def crash_after_release(method, url, headers, timeout, body=None):
            nonlocal release_writes
            result = sender(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                    release_writes += 1
                    if release_writes == 1:
                        raise Crash()
            return result

        transport.credentials.sender = crash_after_release
        with self.assertRaises(Crash):
            reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                              built_at=NOW, dracla_version='test-1', sleep=lambda _: None)

    def test_default_recovery_uses_real_stored_lifecycle_and_frozen_package(self):
        f = MutationRepository(); prepared(f)
        result = default_reconcile(f)
        self.assertTrue(result.valid, result)
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_default_recovery_revalidates_after_competing_canonical_append(self):
        f = MutationRepository(); prepared(f); other = f.concurrent_config()
        result = default_reconcile(f)
        self.assertTrue(result.valid, result)
        snapshot = f.engine().snapshot()
        self.assertEqual(len(snapshot.records), 3)
        self.assertIn(other, [r.commit_oid for r in snapshot.records])

    def generation_race(self):
        f = MutationRepository()
        pending = f.builder.event('records_reader_authorized', 820)
        prepare_with_stored_evidence(f, pending)
        engine = f.engine(); reference = engine.pending()
        engine.begin(reference, subjects=[7], project_wide=False, started_at=NOW)
        snapshot = engine.snapshot()
        newer = f.builder.event('records_reader_authorized', 821)
        generations = dict(snapshot.generations, reader_authority=newer.event_id)
        files = dict(f.files['records', snapshot.events_oid])
        files[event_path(newer.event_id)] = f.encrypt('records', 'events',
            event_path(newer.event_id), newer.to_dict())
        path = 'config/materialization-generations.enc.json'
        files[path] = f.encrypt('records', 'events', path,
                               {'generations_version': 1, **generations})
        head = f.commit('records', files, snapshot.events_oid)
        f.set_head('records', 'events', head)
        # The competing event is real authenticated canonical history; both
        # stored projections deliberately still represent its predecessor.
        self.assertEqual(f.engine().snapshot().events_oid, head)
        return f, pending, newer

    def test_generation_advancing_race_repairs_private_preconditions_before_retry(self):
        f, pending, newer = self.generation_race()
        report = default_reconcile(f)
        self.assertTrue(report.valid, report)
        records = f.engine().snapshot().records
        for event in (pending, newer):
            self.assertEqual(sum(r.event.event_id == event.event_id for r in records), 1)
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_generation_race_restarts_after_repairing_historical_source_and_release(self):
        for damaged_source in ('invalid-envelope', 'non-object'):
            with self.subTest(damaged_source=damaged_source):
                f, pending, newer = self.generation_race()
                head = f.head('coverage', 'coverage')
                files = dict(f.files['coverage', head])
                files['source.enc.json'] = (b'{}' if damaged_source == 'invalid-envelope'
                                             else f.encrypt('coverage', 'coverage', 'source.enc.json', []))
                f.set_head('coverage', 'coverage', f.commit('coverage', files, head))

                keys, transport = f.reader()
                sender = transport.credentials.sender
                release_writes = 0

                def crash_after_release(method, url, headers, timeout, body=None):
                    nonlocal release_writes
                    result = sender(method, url, headers, timeout, body)
                    if method == 'POST' and url.endswith('/graphql'):
                        data = json.loads(body)['variables']['input']
                        paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                        if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                            release_writes += 1
                            if release_writes == 1:
                                raise Crash()
                    return result

                transport.credentials.sender = crash_after_release
                with self.assertRaises(Crash):
                    reconcile_project(f.binding, keys, transport, built_at=NOW,
                                      dracla_version='test-1', sleep=lambda _: None)

                self.assertEqual(release_writes, 1)
                snapshot = f.engine().snapshot()
                self.assertEqual(sum(r.event.event_id == pending.event_id for r in snapshot.records), 1)
                self.assertEqual(sum(r.event.event_id == newer.event_id for r in snapshot.records), 1)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                 'terminal')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'],
                                 'idle')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'),
                                         'source.enc.json')['canonical_sha'], snapshot.events_oid)

                report = default_reconcile(f)
                self.assertTrue(report.valid, report)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                 'idle')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'],
                                 'idle')
                self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_unavailable_live_fact_preserves_reason_after_one_projection_repair(self):
        from unittest.mock import patch
        from dracla.conformance import ReleaseProfile
        for damaged_source, retry_limit in ((None, 1), (None, 3),
                ('non-object', 1), ('non-object', 3),
                ('invalid-envelope', 1), ('invalid-envelope', 3)):
            with self.subTest(damaged_source=damaged_source, retry_limit=retry_limit):
                f, _, _ = self.generation_race()
                if damaged_source:
                    head = f.head('coverage', 'coverage')
                    files = dict(f.files['coverage', head])
                    files['source.enc.json'] = (f.encrypt('coverage', 'coverage', 'source.enc.json', [])
                        if damaged_source == 'non-object' else b'{}')
                    f.set_head('coverage', 'coverage', f.commit('coverage', files, head))
                keys, transport = f.reader()
                original = StoredPreconditions(f.binding, keys, transport)
                live = f.head('records', 'events')
                calls = []
                def unavailable(event, head):
                    if head == live:
                        calls.append(head)
                        raise RecoveryBlocked('authenticated-preconditions-unavailable')
                    return original(event, head)
                profile = load_release_profile().to_dict()
                profile['max_mutation_retries'] = retry_limit
                start = len(f.writes)
                with patch('dracla.records.append.load_release_profile', return_value=ReleaseProfile(profile)):
                    report = reconcile_project(f.binding, keys, transport, preconditions=unavailable,
                        built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
                writes = [body['variables']['input'] for _, url, body in f.writes[start:]
                          if url.endswith('/graphql')]
                coverage = [value for value in writes if value['branch']['branchName'] == 'coverage'
                            and len(value['fileChanges']['additions']) == 37]
                self.assertEqual((report.status, report.reason),
                                 ('blocked', 'authenticated-preconditions-unavailable'))
                self.assertEqual(len(calls), min(2, retry_limit))
                self.assertEqual(len(coverage), 1)
                self.assertEqual(f.head('records', 'events'), live)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'prepared')
                self.assertTrue(default_reconcile(f).valid)

    def test_current_coverage_is_not_rewritten_for_observation_metadata(self):
        f, _, _ = self.generation_race()
        engine = f.engine()
        state = engine.recovery_state()
        engine.begin(state.reference, subjects=[7], project_wide=False, started_at=NOW)
        state = engine.recovery_state()
        head = publish_coverage(state, engine.transport, built_at=NOW, dracla_version='test-1')
        state = engine.recovery_state()
        writes = len(f.writes)
        stored = dict(f.files['coverage', head])
        repeated = publish_coverage(state, engine.transport,
            built_at='2026-10-28T00:00:00Z', dracla_version='test-2')
        self.assertEqual(repeated, head)
        self.assertEqual(len(f.writes), writes)
        self.assertEqual(f.files['coverage', head], stored)
        self.assertEqual(f.plain('coverage', 'coverage', head, 'source.enc.json')['dracla_version'], 'test-1')

    def test_unrelated_block_reason_does_not_read_a_damaged_projection_source(self):
        f, _, _ = self.generation_race()
        keys, transport = f.reader()
        original = StoredPreconditions(f.binding, keys, transport)
        live = f.head('records', 'events')
        def unavailable(event, head):
            if head == live:
                coverage_head = f.head('coverage', 'coverage')
                files = dict(f.files['coverage', coverage_head])
                files['source.enc.json'] = b'{}'
                f.set_head('coverage', 'coverage', f.commit('coverage', files, coverage_head))
                raise RecoveryBlocked('route-unavailable-proof-required')
            return original(event, head)
        report = reconcile_project(f.binding, keys, transport, preconditions=unavailable,
            built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        self.assertEqual((report.status, report.reason), ('blocked', 'route-unavailable-proof-required'))
        self.assertEqual(f.head('records', 'events'), live)
        self.assertTrue(default_reconcile(f).valid)

    def test_current_coverage_noop_rechecks_canonical_head_without_writing(self):
        from unittest.mock import patch
        f, _, _ = self.generation_race()
        engine = f.engine()
        state = engine.recovery_state()
        engine.begin(state.reference, subjects=[7], project_wide=False, started_at=NOW)
        state = engine.recovery_state()
        head = publish_coverage(state, engine.transport, built_at=NOW, dracla_version='test-1')
        state = engine.recovery_state()
        original = engine.transport.head
        reads = []
        def race(repo, branch):
            if branch == 'events':
                reads.append(branch)
                if len(reads) == 2:
                    f.concurrent_config()
            return original(repo, branch)
        writes = len(f.writes)
        with patch.object(engine.transport, 'head', side_effect=race):
            with self.assertRaises(HeadConflict):
                publish_coverage(state, engine.transport, built_at=NOW, dracla_version='test-1')
        self.assertEqual(len(f.writes), writes)
        self.assertEqual(f.head('coverage', 'coverage'), head)

    def test_generation_race_recovers_after_coverage_only_crash(self):
        f, pending, newer = self.generation_race()
        keys, transport = f.reader(); original = transport.credentials.sender
        def sender(method, url, headers, timeout, body=None):
            result = original(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                if data['branch']['branchName'] == 'coverage' and len(data['fileChanges']['additions']) == 37:
                    raise Crash()
            return result
        transport.credentials.sender = sender
        with self.assertRaises(Crash):
            reconcile_project(f.binding, keys, transport, built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        source = f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), 'source.enc.json')
        self.assertEqual(source['canonical_sha'], f.head('records', 'events'))
        self.assertTrue(default_reconcile(f).valid)
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_generation_race_overflow_preserves_current_public_source_and_guards(self):
        from unittest.mock import patch
        from dracla.conformance import ReleaseProfile
        f, _, _ = self.generation_race()
        values = load_release_profile().to_dict(); values['max_state_ciphertext_bytes'] = 1
        with patch('dracla.records.append.load_release_profile', return_value=ReleaseProfile(values)):
            report = default_reconcile(f)
        self.assertEqual((report.status, report.reason), ('blocked', 'derived-overflow'))
        source = f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), 'source.enc.json')
        self.assertEqual(source['canonical_sha'], f.head('records', 'events'))
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'prepared')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'mutation')
        self.assertTrue(default_reconcile(f).valid)

    def test_generation_race_private_cas_uncertainty_retains_recoverable_owner(self):
        from core.tests.test_records_1 import response
        f, _, _ = self.generation_race()
        keys, transport = f.reader(); original = transport.credentials.sender
        def sender(method, url, headers, timeout, body=None):
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                if data['branch']['branchName'] == 'derived':
                    return response({}, 503)
            return original(method, url, headers, timeout, body)
        transport.credentials.sender = sender
        report = reconcile_project(f.binding, keys, transport, built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        self.assertEqual((report.status, report.reason), ('blocked', 'indeterminate'))
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'prepared')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'mutation')
        self.assertTrue(default_reconcile(f).valid)

    def test_default_reader_grant_and_withdrawal_use_authenticated_all_shard_evidence(self):
        f = MutationRepository()
        grant = f.builder.event('records_reader_authorized', 710)
        prepare_with_stored_evidence(f, grant)
        self.assertTrue(default_reconcile(f).valid)
        withdrawal = f.builder.event('records_reader_withdrawn', 711,
            **{'target.source_event_id': grant.event_id})
        prepare_with_stored_evidence(f, withdrawal)
        self.assertTrue(default_reconcile(f).valid)
        self.assertFalse(f.engine().snapshot().state.reader_source_records)
        snapshot = f.builder.event('records_reader_snapshot_authorized', 713)
        prepare_with_stored_evidence(f, snapshot)
        self.assertTrue(default_reconcile(f).valid)

    def test_default_key_activation_recovers_original_historical_preconditions(self):
        from core.tests.test_records_2 import TestMutationKeySelection
        f, _, result, _, _ = TestMutationKeySelection().activated_inflight()
        report = default_reconcile(f)
        self.assertTrue(report.valid, report)
        self.assertEqual(f.head('records', 'events'), result.canonical_commit)
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_prepared_conflict_completes_without_an_append(self):
        f = MutationRepository(rotate=True); snapshot = f.engine().snapshot()
        publication = snapshot.state.publications[(snapshot.state.agreement_id, snapshot.state.active_version)]
        event = f.builder.event('acceptance', 814, snapshot.events_oid,
            **{'target.digest': publication.digest, 'target.version': publication.version,
               'target.recipient': dict(publication.recipient)})
        prepare_with_stored_evidence(f, event)
        newer = f.concurrent_config()
        report = default_reconcile(f)
        self.assertTrue(report.valid, report)
        self.assertEqual(f.head('records', 'events'), newer)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'idle')

    def test_external_provider_cannot_leak_an_unbounded_block_reason(self):
        from dracla.records.append import RecoveryBlocked
        f = MutationRepository(); prepared(f); keys, transport = f.reader()
        def provider(event, head):
            raise RecoveryBlocked('PRIVATE-WRAPPING-KEY-OR-CONTACT')
        report = reconcile_project(f.binding, keys, transport, preconditions=provider,
                                   built_at=NOW, dracla_version='test-1')
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'records-unavailable')

    def test_real_exemption_and_reader_rule_materializations_and_withdrawals(self):
        f = MutationRepository()
        for kind, method, withdrawal in [
                ('exemption_rule_configured', f.builder.exemption_materialization_event, 'exemption_source_withdrawn'),
                ('records_reader_rule_configured', f.builder.reader_materialization_event, 'records_reader_withdrawn')]:
            with self.subTest(kind=kind):
                rule = f.builder.event(kind, 790 if kind.startswith('exemption') else 791)
                prepare_with_stored_evidence(f, rule); self.assertTrue(default_reconcile(f).valid)
                added = method(rule, 'add', None)
                prepare_with_stored_evidence(f, added); self.assertTrue(default_reconcile(f).valid)
                event = f.builder.event(withdrawal, 792 if kind.startswith('exemption') else 793,
                                        **{'target.source_event_id': rule.event_id})
                prepare_with_stored_evidence(f, event); self.assertTrue(default_reconcile(f).valid)

    def test_acceptance_correction_and_revocation_preserve_inherited_key_history(self):
        f = MutationRepository(rotate=True); snapshot = f.engine().snapshot()
        publication = snapshot.state.publications[(snapshot.state.agreement_id, snapshot.state.active_version)]
        event = f.builder.event('acceptance', 794, snapshot.events_oid,
            **{'target.digest': publication.digest, 'target.version': publication.version,
               'target.recipient': dict(publication.recipient)})
        prepare_with_stored_evidence(f, event); self.assertTrue(default_reconcile(f).valid)
        head = f.engine().snapshot().events_oid
        correction = f.builder.event('acceptance', 795, head,
            **{'target.digest': publication.digest, 'target.version': publication.version,
               'target.recipient': dict(publication.recipient), 'payload.supersedes': event.event_id})
        prepare_with_stored_evidence(f, correction); self.assertTrue(default_reconcile(f).valid)
        head = f.engine().snapshot().events_oid
        revoke = f.builder.event('revocation', 796, head)
        prepare_with_stored_evidence(f, revoke); self.assertTrue(default_reconcile(f).valid)

    def test_acceptance_and_revocation_publish_coverage_before_private_overflow(self):
        from unittest.mock import patch
        from dracla.conformance import ReleaseProfile
        for event_type in ('acceptance', 'revocation'):
            for overflow in ('shard', 'state'):
                with self.subTest(event_type=event_type, overflow=overflow):
                    f = MutationRepository(rotate=True)
                    snapshot = f.engine().snapshot()
                    publication = snapshot.state.publications[(snapshot.state.agreement_id,
                                                               snapshot.state.active_version)]
                    acceptance = f.builder.event('acceptance', 894, snapshot.events_oid,
                        **{'target.digest': publication.digest, 'target.version': publication.version,
                           'target.recipient': dict(publication.recipient)})
                    if event_type == 'acceptance':
                        event = acceptance
                    else:
                        prepare_with_stored_evidence(f, acceptance)
                        self.assertTrue(default_reconcile(f).valid)
                        snapshot = f.engine().snapshot()
                        event = f.builder.event('revocation', 895, snapshot.events_oid)
                    prepare_with_stored_evidence(f, event)
                    events_before = f.head('records', 'events')
                    derived_before = f.head('records', 'derived')
                    values = load_release_profile().to_dict()
                    if overflow == 'shard':
                        values['max_shard_ciphertext_bytes'] = dict(values['max_shard_ciphertext_bytes'])
                        values['max_shard_ciphertext_bytes']['derived_index'] = 1
                        values['max_shard_ciphertext_bytes']['status_detail'] = 1
                    else:
                        values['max_state_ciphertext_bytes'] = 1
                    with patch('dracla.records.append.load_release_profile',
                               return_value=ReleaseProfile(values)):
                        report = default_reconcile(f)
                    self.assertEqual((report.status, report.reason), ('blocked', 'derived-overflow'))
                    current = f.engine().snapshot()
                    self.assertNotEqual(current.events_oid, events_before)
                    self.assertEqual(f.head('records', 'derived'), derived_before)
                    self.assertEqual(sum(r.event.event_id == event.event_id for r in current.records), 1)

                    fence = decode_decision_fence(canonical_json(
                        f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)))
                    marker = decode_inflight_marker(canonical_json(
                        f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), MARKER)))
                    expected = materialize_coverage(current.state, (marker, fence),
                        canonical_oid=current.events_oid, built_at=NOW,
                        dracla_version='test-1').to_dict()
                    actual = {path: f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), path)
                              for path in expected}
                    self.assertEqual(actual, expected)
                    self.assertEqual(f.plain('records', 'operations',
                        f.head('records', 'operations'), CELL)['state'], 'appending')
                    self.assertEqual(f.plain('coverage', 'coverage',
                        f.head('coverage', 'coverage'), FENCE)['state'], 'mutation')
                    self.assertTrue(default_reconcile(f).valid)
                    final = f.engine().snapshot()
                    self.assertEqual(sum(r.event.event_id == event.event_id for r in final.records), 1)
                    self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def _completed_operation_retry(self, field=None, *, marker_open=False):
        f = MutationRepository()
        event, artifacts = f.config()
        f.engine().prepare(event, artifacts)
        self.assertTrue(default_reconcile(f).valid)
        original_record = next(r for r in f.engine().snapshot().records
                               if r.event.event_id == event.event_id)
        original_raw = f.files['records', original_record.commit_oid][event_path(event.event_id)]
        value = event.to_dict()
        if field == 'recorded_at':
            value['recorded_at'] = '2026-10-27T01:00:00Z'
        elif field == 'actor.login_snapshot':
            value['actor']['login_snapshot'] = 'renamed-maintainer'
        retry = validate_event(value)
        self.assertEqual((retry.idempotency_key, retry.event_id, retry.operation_sha256),
                         (event.idempotency_key, event.event_id, event.operation_sha256))
        engine = f.engine()
        reference = engine.prepare(retry, artifacts)
        self.assertEqual(reference.cell.state, 'prepared')
        if marker_open:
            engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        return f, event, original_record, original_raw

    def _assert_completed_retry(self, f, event, original_record, original_raw):
        report = default_reconcile(f)
        self.assertTrue(report.valid, report)
        current = f.engine().snapshot()
        records = [r for r in current.records if r.event.event_id == event.event_id]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].commit_oid, original_record.commit_oid)
        self.assertEqual(records[0].event.to_dict(), original_record.event.to_dict())
        self.assertEqual(f.files['records', records[0].commit_oid][event_path(event.event_id)], original_raw)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'idle')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'idle')
        self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), MARKER), {'ops': {}})
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_completed_operation_retries_recover_before_and_after_marker_open(self):
        for field in (None, 'recorded_at', 'actor.login_snapshot'):
            for marker_open in (False, True):
                with self.subTest(field=field, marker_open=marker_open):
                    self._assert_completed_retry(*self._completed_operation_retry(
                        field, marker_open=marker_open))

    def test_completed_operation_semantic_changes_remain_conflicts(self):
        for change in ('actor.github_user_id', 'payload.project_configuration'):
            with self.subTest(change=change):
                f = MutationRepository()
                event, artifacts = f.config()
                f.engine().prepare(event, artifacts)
                self.assertTrue(default_reconcile(f).valid)
                value = event.to_dict()
                if change == 'actor.github_user_id':
                    value['actor']['github_user_id'] = 8
                    retry_artifacts = artifacts
                else:
                    config = dict(value['payload']['project_configuration'])
                    config['retention_statement'] = 'Changed operation'
                    value['payload']['project_configuration'] = config
                    retry_artifacts = [SideArtifact('project_config', 'config/project.enc.json',
                        canonical_json(config))]
                identity = derive_event_identity(value['project_id'], value['operation_nonce'],
                    value['actor'], value['type'], value['target'], value['payload'],
                    value['confirmed_canonical_oid'])
                value['operation_sha256'] = identity.operation_sha256
                retry = validate_event(value)
                self.assertEqual(retry.idempotency_key, event.idempotency_key)
                self.assertEqual(retry.event_id, event.event_id)
                self.assertNotEqual(retry.operation_sha256, event.operation_sha256)
                f.engine().prepare(retry, retry_artifacts)
                report = default_reconcile(f)
                self.assertTrue(report.valid, report)
                records = [r for r in f.engine().snapshot().records if r.event.event_id == event.event_id]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].event.to_dict(), event.to_dict())
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'idle')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'], 'idle')

    def test_completed_retry_claim_and_terminal_crashes_recover(self):
        for fail_on_operations_write in (1, 2):
            with self.subTest(fail_on_operations_write=fail_on_operations_write):
                f, event, original_record, original_raw = self._completed_operation_retry()
                keys, transport = f.reader()
                original = transport.credentials.sender
                operations_writes = 0

                def sender(method, url, headers, timeout, body=None):
                    nonlocal operations_writes
                    result = original(method, url, headers, timeout, body)
                    if method == 'POST' and url.endswith('/graphql'):
                        data = json.loads(body)['variables']['input']
                        branch = data['branch']['branchName']
                        if branch == 'operations':
                            operations_writes += 1
                            if operations_writes == fail_on_operations_write:
                                raise Crash()
                    return result

                transport.credentials.sender = sender
                with self.assertRaises(Crash):
                    reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                      built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
                self._assert_completed_retry(f, event, original_record, original_raw)

    def test_completed_retry_claim_retries_after_delayed_operations_writer(self):
        f, event, original_record, original_raw = self._completed_operation_retry()

        def race(role, branch):
            if (role, branch) != ('records', 'operations'):
                f.before_cas = race
                return
            head = f.head(role, branch)
            f.set_head(role, branch, f.commit(role, f.files[role, head], head))

        f.before_cas = race
        self._assert_completed_retry(f, event, original_record, original_raw)

    def test_delayed_operations_writer_then_release_crash_restarts_exact_reference(self):
        f, event, original_record, original_raw = self._completed_operation_retry()

        def race(role, branch):
            if (role, branch) != ('records', 'operations'):
                f.before_cas = race
                return
            head = f.head(role, branch)
            f.set_head(role, branch, f.commit(role, f.files[role, head], head))

        keys, transport = f.reader()
        sender = transport.credentials.sender
        single_fence_writes = 0

        def crash_after_release(method, url, headers, timeout, body=None):
            nonlocal single_fence_writes
            result = sender(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                    single_fence_writes += 1
                    if single_fence_writes == 2:
                        raise Crash()
            return result

        f.before_cas = race
        transport.credentials.sender = crash_after_release
        with self.assertRaises(Crash):
            reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                              built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        self._assert_completed_retry(f, event, original_record, original_raw)

    def test_mutation_recovery_keeps_fence_reference_after_delayed_noop_head(self):
        f, event, original_record, original_raw = self._completed_operation_retry()
        engine = f.engine()
        reference = engine.pending()
        engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        head = f.head('records', 'operations')
        f.set_head('records', 'operations', f.commit('records', f.files['records', head], head))
        recovered = f.engine().recovery_state()
        self.assertEqual(recovered.reference.commit_oid, reference.commit_oid)
        self.assertEqual(recovered.reference.blob_sha, reference.blob_sha)
        self._assert_completed_retry(f, event, original_record, original_raw)

    def test_released_fence_from_older_identical_execution_is_rejected(self):
        f, event, original_record, original_raw = self._completed_operation_retry()
        # Finish the first identical retry, then retain its idle coverage head
        # while preparing a second identical retry.
        self._assert_completed_retry(f, event, original_record, original_raw)
        older_idle_head = f.head('coverage', 'coverage')
        retry_event, retry_artifacts = f.config()
        f.engine().prepare(retry_event, retry_artifacts)

        keys, transport = f.reader()
        sender = transport.credentials.sender
        single_fence_writes = 0

        def crash_after_release(method, url, headers, timeout, body=None):
            nonlocal single_fence_writes
            result = sender(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                    single_fence_writes += 1
                    if single_fence_writes == 2:
                        raise Crash()
            return result

        transport.credentials.sender = crash_after_release
        with self.assertRaises(Crash):
            reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                              built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        # Remove the current execution's release proof while retaining the
        # older byte-identical execution's valid release proof.
        f.set_head('coverage', 'coverage', older_idle_head)
        report = default_reconcile(f)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'route-unavailable-proof-required')
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'terminal')

    def test_ambiguous_current_execution_release_proofs_are_rejected(self):
        f, event, original_record, original_raw = self._completed_operation_retry()
        keys, transport = f.reader()
        sender = transport.credentials.sender
        single_fence_writes = 0

        def crash_after_release(method, url, headers, timeout, body=None):
            nonlocal single_fence_writes
            result = sender(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                    single_fence_writes += 1
                    if single_fence_writes == 2:
                        raise Crash()
            return result

        transport.credentials.sender = crash_after_release
        with self.assertRaises(Crash):
            reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                              built_at=NOW, dracla_version='test-1', sleep=lambda _: None)

        # Duplicate the authenticated current mutation -> idle proof twice in
        # coverage history. The prepared commit remains in the same current
        # operations execution, so recovery must reject the ambiguity.
        engine = f.engine()
        snapshot = engine.snapshot()
        current_cell = engine._cell(snapshot, snapshot.operations_oid)
        coverage_history = engine.transport.ancestry(f.binding.repo('coverage'), snapshot.coverage_oid)
        current_pair = None
        for before, after in zip(coverage_history, coverage_history[1:]):
            old, _ = engine._historical_guards(snapshot, before.oid)
            released, _ = engine._historical_guards(snapshot, after.oid)
            if (old.state == 'mutation' and released.state == 'idle'
                    and old.to_dict()['operation_id'] == current_cell.to_dict()['operation_id']):
                current_pair = old.to_dict(), released.to_dict()
        self.assertIsNotNone(current_pair)
        old_fence, released_fence = current_pair

        for fence_value in (old_fence, released_fence, old_fence, released_fence):
            head = f.head('coverage', 'coverage')
            values = dict(f.files['coverage', head])
            values[FENCE] = f.encrypt('coverage', 'coverage', FENCE, fence_value)
            values[MARKER] = f.encrypt('coverage', 'coverage', MARKER, {'ops': {}})
            f.set_head('coverage', 'coverage', f.commit('coverage', values, head))

        writes = len(f.writes)
        report = default_reconcile(f)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, 'route-unavailable-proof-required')
        self.assertEqual(len(f.writes), writes)
        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'], 'terminal')

    def test_key_activation_release_crash_recovers_historical_idle_boundary(self):
        for records_only in (True, False):
            for later_cycles in (0, 2):
                with self.subTest(records_only=records_only, later_cycles=later_cycles):
                    f, event, original_record, original_raw = self._activated_inflight(
                        records_only=records_only)
                    self._crash_after_activation_release(f, event, original_record, original_raw)
                    if later_cycles:
                        self._confirmed_success_cycles(f, later_cycles)
                    self._assert_completed_retry(f, event, original_record, original_raw)

    def test_historical_idle_boundary_rejects_live_key_context(self):
        f, event, original_record, original_raw = self._activated_inflight(records_only=True)
        self._crash_after_activation_release(f, event, original_record, original_raw)
        engine = f.engine()
        snapshot = engine.snapshot()
        terminal = engine._cell(snapshot, snapshot.operations_oid)
        predecessor_oid, predecessor = engine._terminal_predecessor(snapshot, terminal)
        history = engine.transport.ancestry(f.binding.repo('records'), snapshot.operations_oid)
        predecessor_index = next(index for index, commit in enumerate(history)
                                 if commit.oid == predecessor_oid)
        boundary_oid = None
        for commit in reversed(history[:predecessor_index + 1]):
            stored = f.plain('records', 'operations', commit.oid, CELL)
            if stored['state'] == 'idle':
                boundary_oid = commit.oid
                break
        self.assertIsNotNone(boundary_oid)
        # The old boundary is encrypted with the predecessor-era records key.
        # Supplying the live activation head must reject it, not treat any
        # decryptable retained key as acceptable historical evidence.
        with self.assertRaises(RecordsError) as caught:
            engine._cell(snapshot, boundary_oid,
                         historical_events_head=snapshot.events_oid)
        self.assertEqual(caught.exception.category, 'invalid-key')

    def _semantic_operation_retry(self, change):
        f = MutationRepository()
        event, artifacts = f.config()
        f.engine().prepare(event, artifacts)
        self.assertTrue(default_reconcile(f).valid)
        original_record = next(r for r in f.engine().snapshot().records
                               if r.event.event_id == event.event_id)
        original_raw = f.files['records', original_record.commit_oid][event_path(event.event_id)]
        value = event.to_dict()
        if change == 'actor.github_user_id':
            value['actor']['github_user_id'] = 8
            retry_artifacts = artifacts
        elif change == 'payload.project_configuration':
            config = dict(value['payload']['project_configuration'])
            config['retention_statement'] = 'Changed operation'
            value['payload']['project_configuration'] = config
            retry_artifacts = [SideArtifact('project_config', 'config/project.enc.json',
                canonical_json(config))]
        else:
            raise AssertionError(change)
        identity = derive_event_identity(value['project_id'], value['operation_nonce'],
            value['actor'], value['type'], value['target'], value['payload'],
            value['confirmed_canonical_oid'])
        value['operation_sha256'] = identity.operation_sha256
        retry = validate_event(value)
        self.assertEqual((retry.idempotency_key, retry.event_id),
                         (event.idempotency_key, event.event_id))
        self.assertNotEqual(retry.operation_sha256, event.operation_sha256)
        f.engine().prepare(retry, retry_artifacts)
        return f, event, original_record, original_raw

    def _assert_retry_after_each_persisted_write(self, factory):
        """Crash after each first-pass write, then recover from the same state."""
        probe = factory()[0]
        keys, transport = probe.reader()
        original = transport.credentials.sender
        writes = []
        cells, fences, markers = [], [], []

        def observe(method, url, headers, timeout, body=None):
            result = original(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                branch = data['branch']['branchName']
                writes.append(branch)
                paths = {item['path'] for item in data['fileChanges']['additions']}
                if branch == 'operations' and CELL in paths:
                    cells.append(probe.plain('records', branch, probe.head('records', branch), CELL)['state'])
                if branch == 'coverage':
                    head = probe.head('coverage', branch)
                    if FENCE in paths:
                        fences.append(probe.plain('coverage', branch, head, FENCE)['state'])
                    if MARKER in paths:
                        markers.append(bool(probe.plain('coverage', branch, head, MARKER)['ops']))
            return result

        transport.credentials.sender = observe
        report = reconcile_project(probe.binding, keys, transport, preconditions=probe.evidence,
                                   built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        self.assertTrue(report.valid, report)
        self.assertIn('terminal', cells)
        self.assertEqual(cells[-1], 'idle')
        self.assertIn('mutation', fences)
        self.assertEqual(fences[-1], 'idle')
        self.assertIn(True, markers)
        self.assertFalse(markers[-1])

        for fail_at in range(1, len(writes) + 1):
            with self.subTest(fail_at=fail_at):
                f, event, original_record, original_raw = factory()
                keys, transport = f.reader()
                sender = transport.credentials.sender
                count = 0

                def crash_after(method, url, headers, timeout, body=None):
                    nonlocal count
                    result = sender(method, url, headers, timeout, body)
                    if method == 'POST' and url.endswith('/graphql'):
                        count += 1
                        if count == fail_at:
                            raise Crash()
                    return result

                transport.credentials.sender = crash_after
                with self.assertRaises(Crash):
                    reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                      built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
                # The process restart uses a fresh transport with the sender restored.
                self._assert_completed_retry(f, event, original_record, original_raw)

    def test_completed_retry_and_conflict_restart_after_every_persisted_write(self):
        for field in (None, 'recorded_at', 'actor.login_snapshot'):
            with self.subTest(kind='retry', field=field):
                self._assert_retry_after_each_persisted_write(
                    lambda field=field: self._completed_operation_retry(field))
        for change in ('actor.github_user_id', 'payload.project_configuration'):
            with self.subTest(kind='conflict', change=change):
                self._assert_retry_after_each_persisted_write(
                    lambda change=change: self._semantic_operation_retry(change))

    def _crash_completed_retry_after_mutation_release(self, factory):
        f, event, original_record, original_raw = factory()
        keys, transport = f.reader()
        sender = transport.credentials.sender
        single_fence_writes = 0

        def crash_after_release(method, url, headers, timeout, body=None):
            nonlocal single_fence_writes
            result = sender(method, url, headers, timeout, body)
            if method == 'POST' and url.endswith('/graphql'):
                data = json.loads(body)['variables']['input']
                paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                    single_fence_writes += 1
                    if single_fence_writes == 2:
                        raise Crash()
            return result

        transport.credentials.sender = crash_after_release
        with self.assertRaises(Crash):
            reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                              built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
        return f, event, original_record, original_raw

    def test_historical_release_reads_preserve_transport_failure_categories(self):
        for category in ('records-unavailable', 'resource-limit'):
            with self.subTest(category=category):
                f, event, original_record, original_raw = self._crash_completed_retry_after_mutation_release(
                    lambda: self._completed_operation_retry())
                keys, transport = f.reader()
                transport.authorize(f.binding)
                coverage = f.binding.repo('coverage')
                released_head = f.head('coverage', 'coverage')
                mutation_head = transport.commit(coverage, released_head).parents[0]
                self.assertEqual(f.plain('coverage', 'coverage', mutation_head, FENCE)['state'], 'mutation')
                read = transport.read
                error = RecordsError(category)
                writes = len(f.writes)
                canonical_head = f.head('records', 'events')

                def fail_historical_fence(repo, head, path):
                    if repo == coverage and head == mutation_head and path == FENCE:
                        raise error
                    return read(repo, head, path)

                transport.read = fail_historical_fence
                with self.assertRaises(RecordsError) as caught:
                    reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                      built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
                self.assertIs(caught.exception, error)
                self.assertEqual(caught.exception.category, category)
                self.assertEqual(len(f.writes), writes)
                self.assertEqual(f.head('records', 'events'), canonical_head)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                 'terminal')
                transport.read = read
                self._assert_completed_retry(f, event, original_record, original_raw)

    def test_historical_release_reads_retry_conflicts_within_existing_budget(self):
        for error_type in (HeadConflict, IndeterminateWrite):
            for persistent in (False, True):
                with self.subTest(error_type=error_type.__name__, persistent=persistent):
                    f, event, original_record, original_raw = self._crash_completed_retry_after_mutation_release(
                        lambda: self._completed_operation_retry())
                    keys, transport = f.reader()
                    transport.authorize(f.binding)
                    coverage = f.binding.repo('coverage')
                    mutation_head = transport.commit(coverage, f.head('coverage', 'coverage')).parents[0]
                    read = transport.read
                    failures = 0
                    sleeps = []
                    writes = len(f.writes)
                    canonical_head = f.head('records', 'events')

                    def fail_historical_fence(repo, head, path):
                        nonlocal failures
                        if (repo == coverage and head == mutation_head and path == FENCE
                                and (persistent or failures == 0)):
                            failures += 1
                            raise error_type('records-unavailable')
                        return read(repo, head, path)

                    transport.read = fail_historical_fence
                    report = reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                        built_at=NOW, dracla_version='test-1', sleep=sleeps.append)
                    expected_failures = load_release_profile().limit('max_mutation_retries') if persistent else 1
                    self.assertEqual(failures, expected_failures)
                    self.assertEqual(len(sleeps), expected_failures)
                    self.assertEqual(f.head('records', 'events'), canonical_head)
                    if persistent:
                        self.assertEqual((report.status, report.reason), ('blocked', 'indeterminate'))
                        self.assertEqual(len(f.writes), writes)
                        self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                         'terminal')
                    else:
                        self.assertTrue(report.valid, report)
                    transport.read = read
                    self._assert_completed_retry(f, event, original_record, original_raw)

    def test_historical_release_reads_preserve_real_http_failures(self):
        from dracla.github_admin import HttpResponse

        for fault, category in (('http-503', 'records-unavailable'),
                                ('oversized-response', 'resource-limit'),
                                ('malformed-base64', 'invalid-history')):
            with self.subTest(fault=fault):
                f, event, original_record, original_raw = self._crash_completed_retry_after_mutation_release(
                    lambda: self._completed_operation_retry())
                keys, transport = f.reader()
                transport.authorize(f.binding)
                coverage = f.binding.repo('coverage')
                mutation_head = transport.commit(coverage, f.head('coverage', 'coverage')).parents[0]
                blob = transport.tree(coverage, mutation_head)[FENCE].oid
                path = '/repos/acme/coverage/git/blobs/' + blob
                sender = transport.credentials.sender
                requests = 0
                writes = len(f.writes)
                canonical_head = f.head('records', 'events')

                def fail_historical_blob(method, url, headers, timeout, body=None):
                    nonlocal requests
                    if method == 'GET' and url.endswith(path):
                        requests += 1
                        if fault == 'http-503':
                            return HttpResponse(503, {}, b'{}')
                        if fault == 'oversized-response':
                            return HttpResponse(200, {}, b'x' * (1024 * 1024 + 1))
                        value = dict(f.values[path])
                        value['content'] = '***'
                        return HttpResponse(200, {}, json.dumps(value).encode())
                    return sender(method, url, headers, timeout, body)

                transport.credentials.sender = fail_historical_blob
                with self.assertRaises(RecordsError) as caught:
                    reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                      built_at=NOW, dracla_version='test-1', sleep=lambda _: None)
                self.assertEqual(caught.exception.category, category)
                self.assertEqual(requests, 1)
                self.assertEqual(len(f.writes), writes)
                self.assertEqual(f.head('records', 'events'), canonical_head)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                 'terminal')
                transport.credentials.sender = sender
                self._assert_completed_retry(f, event, original_record, original_raw)

    def _confirmed_success_cycles(self, f, count):
        for index in range(count):
            engine = f.engine()
            snapshot = engine.snapshot()
            fence, marker = engine._guards(snapshot, snapshot.coverage_oid)
            self.assertEqual(fence.state, 'idle')
            reserved = reserve_success(fence, marker,
                check_identity=base64url_encode((b'success-cycle-' + bytes([index]))[:32].ljust(32, b'!')),
                projection_commit=snapshot.events_oid)
            coverage_head = engine._write(snapshot, 'coverage', 'coverage', snapshot.coverage_oid,
                                          {FENCE: reserved.to_dict()})
            snapshot = engine.snapshot()
            fence, marker = engine._guards(snapshot, coverage_head)
            released = release_success(fence, reserved, completion_verified=True)
            engine._write(snapshot, 'coverage', 'coverage', coverage_head,
                          {FENCE: released.to_dict()})

    def _prepare_repeated_identical_retry(self, f):
        event, artifacts = f.config()
        f.engine().prepare(event, artifacts)

    def test_completed_retry_recovers_after_later_success_cycles(self):
        factories = [
            ('exact', lambda: self._completed_operation_retry()),
            ('recorded_at', lambda: self._completed_operation_retry('recorded_at')),
            ('login_snapshot', lambda: self._completed_operation_retry('actor.login_snapshot')),
            ('actor_conflict', lambda: self._semantic_operation_retry('actor.github_user_id')),
            ('payload_conflict', lambda: self._semantic_operation_retry('payload.project_configuration')),
        ]
        for name, factory in factories:
            with self.subTest(name=name):
                f, event, original_record, original_raw = self._crash_completed_retry_after_mutation_release(factory)
                self._confirmed_success_cycles(f, 2)
                coverage_head = f.head('coverage', 'coverage')
                fence_raw = f.files['coverage', coverage_head][FENCE]
                self._assert_completed_retry(f, event, original_record, original_raw)
                self.assertEqual(f.files['coverage', f.head('coverage', 'coverage')][FENCE], fence_raw)

    def test_repeated_identical_execution_uses_current_prepared_reference(self):
        f, event, original_record, original_raw = self._completed_operation_retry()
        self.assertTrue(default_reconcile(f).valid)
        # A second byte-identical preparation has the same owner, fingerprint,
        # package and prepared generation but a new immutable operation commit.
        self._prepare_repeated_identical_retry(f)
        # An authenticated no-op operations-head advance must not make the
        # current prepared reference depend on direct parent adjacency.
        head = f.head('records', 'operations')
        f.set_head('records', 'operations', f.commit('records', f.files['records', head], head))
        f, event, original_record, original_raw = self._crash_completed_retry_after_mutation_release(
            lambda: (f, event, original_record, original_raw))
        self._confirmed_success_cycles(f, 2)
        self._assert_completed_retry(f, event, original_record, original_raw)

    def test_repeated_identical_execution_skips_damaged_older_release_source(self):
        from dracla.records.reconcile import publish_projections
        for damaged_source in ('invalid-envelope', 'non-object'):
            with self.subTest(damaged_source=damaged_source):
                f = MutationRepository()
                event, artifacts = f.config()
                engine = f.engine()
                engine.prepare(event, artifacts)
                reference = engine.pending()
                engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
                self.assertEqual(engine.append(reference).result, 'landed')
                state = engine.recovery_state()
                publish_projections(state, engine.transport, profile=engine.profile,
                                    built_at=NOW, dracla_version='test-1')

                coverage_head = f.head('coverage', 'coverage')
                files = dict(f.files['coverage', coverage_head])
                damaged = (b'{}' if damaged_source == 'invalid-envelope'
                            else f.encrypt('coverage', 'coverage', 'source.enc.json', []))
                files['source.enc.json'] = damaged
                f.set_head('coverage', 'coverage', f.commit('coverage', files, coverage_head))
                engine = f.engine()
                engine.complete(engine.recovery_state(), projection_verified=True)
                self.assertEqual(f.files['coverage', f.head('coverage', 'coverage')]['source.enc.json'], damaged)

                retry_event, retry_artifacts = f.config()
                f.engine().prepare(retry_event, retry_artifacts)
                keys, transport = f.reader()
                sender = transport.credentials.sender
                release_writes = 0

                def crash_after_current_release(method, url, headers, timeout, body=None):
                    nonlocal release_writes
                    result = sender(method, url, headers, timeout, body)
                    if method == 'POST' and url.endswith('/graphql'):
                        data = json.loads(body)['variables']['input']
                        paths = sorted(item['path'] for item in data['fileChanges']['additions'])
                        if data['branch']['branchName'] == 'coverage' and paths == [FENCE]:
                            release_writes += 1
                            if release_writes == 2:
                                raise Crash()
                    return result

                transport.credentials.sender = crash_after_current_release
                with self.assertRaises(Crash):
                    reconcile_project(f.binding, keys, transport, preconditions=f.evidence,
                                      built_at=NOW, dracla_version='test-1', sleep=lambda _: None)

                self.assertEqual(release_writes, 2)
                snapshot = f.engine().snapshot()
                self.assertEqual(sum(r.event.event_id == event.event_id for r in snapshot.records), 1)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                 'terminal')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'],
                                 'idle')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'),
                                         'source.enc.json')['canonical_sha'], snapshot.events_oid)

                report = default_reconcile(f)
                self.assertTrue(report.valid, report)
                self.assertEqual(f.plain('records', 'operations', f.head('records', 'operations'), CELL)['state'],
                                 'idle')
                self.assertEqual(f.plain('coverage', 'coverage', f.head('coverage', 'coverage'), FENCE)['state'],
                                 'idle')
                self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_active_success_reservation_remains_blocked(self):
        f, event, original_record, original_raw = self._crash_completed_retry_after_mutation_release(
            lambda: self._completed_operation_retry())
        engine = f.engine()
        snapshot = engine.snapshot()
        fence, marker = engine._guards(snapshot, snapshot.coverage_oid)
        reserved = reserve_success(fence, marker, check_identity=base64url_encode(b'blocked-success'[:32].ljust(32, b'!')),
                                   projection_commit=snapshot.events_oid)
        engine._write(snapshot, 'coverage', 'coverage', snapshot.coverage_oid, {FENCE: reserved.to_dict()})
        with self.assertRaises(RecordsError) as caught:
            f.engine().recovery_state()
        self.assertEqual(getattr(caught.exception, 'reason', None), 'check-confirmation-required')

    def test_external_registry_facts_are_not_invented_from_event_claims(self):
        f = MutationRepository(); keys, transport = f.reader()
        provider = StoredPreconditions(f.binding, keys, transport)
        head = f.engine().snapshot().events_oid
        event = f.builder.event('enforcement_scope_requested', 712)
        with self.assertRaises(RecordsError) as caught:
            provider(event, head)
        self.assertEqual(caught.exception.reason, 'authenticated-external-evidence-required')
        self.assertFalse(f.writes)

    def test_current_corruption_cannot_borrow_an_older_clean_precondition(self):
        for role, branch, path in [('coverage', 'coverage', 'source.enc.json'),
                                    ('records', 'derived', 'derived/reader-authority/00.enc.json')]:
            with self.subTest(role=role):
                f = MutationRepository()
                prepare_with_stored_evidence(f, f.builder.event('records_reader_authorized', 810))
                head = f.head(role, branch); values = dict(f.files[role, head])
                values[path] = f.encrypt(role, branch, path, [])
                f.set_head(role, branch, f.commit(role, values, head))
                before = f.head('records', 'events'); writes = len(f.writes)
                report = default_reconcile(f)
                self.assertFalse(report.valid)
                self.assertEqual(report.reason, 'authenticated-preconditions-unavailable')
                self.assertEqual(f.head('records', 'events'), before)
                self.assertEqual(len(f.writes), writes)

    def test_public_projectors_and_completion_require_the_matching_mutation_fence(self):
        from dracla.records.reconcile import publish_coverage, publish_projections
        f = MutationRepository(); engine = f.engine(); state = engine.recovery_state()
        for action in (lambda: publish_coverage(state, engine.transport, built_at=NOW, dracla_version='test-1'),
                       lambda: publish_projections(state, engine.transport, profile=engine.profile,
                                                   built_at=NOW, dracla_version='test-1'),
                       lambda: engine.complete(state, projection_verified=True)):
            with self.assertRaises(RecordsError):
                action()
        self.assertFalse(f.writes)

    def test_unknown_canonical_head_cannot_supply_preconditions(self):
        f = MutationRepository(); keys, transport = f.reader()
        provider = StoredPreconditions(f.binding, keys, transport)
        with self.assertRaises(RecordsError):
            provider(f.config()[0], f.d)
        self.assertFalse(f.writes)

    def test_real_cli_recovers_with_default_provider_and_redacts_output(self):
        from dracla.cli.app import main
        f = MutationRepository(); prepared(f); out = io.StringIO()
        result = main(self.args(f), output=out, release_loader=lambda: SimpleNamespace(package_version='test-1'),
                      verify_factory=lambda b: f.reader())
        self.assertEqual(result, 0, out.getvalue())
        self.assertIn('Reconciliation complete', out.getvalue())
        self.assertNotIn('opaque', out.getvalue())
        self.assertNotIn('Mutation test retention', out.getvalue())
        self.assertFalse(any('/control/' in p for p in f.calls))

    def test_interactive_recovery_prompts_once_only_after_repository_authorization(self):
        from unittest.mock import patch
        from dracla.cli.app import main
        f = MutationRepository(); prepared(f); _, transport = f.reader()
        prompts = []
        def prompt():
            self.assertIn('/user', f.calls)
            self.assertIn('/repos/acme/records', f.calls)
            self.assertIn('/repos/acme/coverage', f.calls)
            prompts.append(True)
            return {'install-1': f.wrapping}
        with patch('dracla.cli.app.prompt_recovery_keys', side_effect=prompt), \
             patch('dracla.records.RepositoryTransport', return_value=transport):
            output = io.StringIO()
            result = main(self.args(f), output=output,
                          release_loader=lambda: SimpleNamespace(package_version='test-1'))
        self.assertEqual(result, 0, output.getvalue())
        self.assertEqual(prompts, [True])

    def test_publication_activation_and_override_use_stored_catalog_and_link_facts(self):
        from dracla.records.append import MutationEngine
        f = MutationRepository(); event, snapshot, metadata = f.evidence_fixture._publication_fixture()
        keys, transport = f.reader()
        engine = MutationEngine(f.binding, keys, transport, StoredPreconditions(f.binding, keys, transport))
        engine.prepare(event, [snapshot, metadata]); self.assertTrue(default_reconcile(f).valid)
        active = f.builder.event('agreement_activated', 797, **{'payload.published_event_id': event.event_id})
        prepare_with_stored_evidence(f, active); self.assertTrue(default_reconcile(f).valid)
        override = f.builder.event('override', 798)
        prepare_with_stored_evidence(f, override); self.assertTrue(default_reconcile(f).valid)
        withdrawn = f.builder.event('override_withdrawn', 799, **{'target.override_event_id': override.event_id})
        prepare_with_stored_evidence(f, withdrawn); self.assertTrue(default_reconcile(f).valid)

    def test_cli_binding_and_release_errors_precede_credentials(self):
        from dracla.cli.app import main
        from dracla.cli.release import ReleaseError
        f = MutationRepository()
        def forbidden(*args):
            raise AssertionError('must not request credentials')
        for args, loader in [(['reconcile', 'project.id=${secret}'], forbidden),
                             (self.args(f), lambda: (_ for _ in ()).throw(ReleaseError('Unavailable release evidence')))]:
            out = io.StringIO()
            self.assertEqual(main(args, output=out, release_loader=loader, verify_factory=forbidden), 2)
            self.assertNotIn('${secret}', out.getvalue())

    def test_cli_reports_corrupt_guard_as_unavailable_without_writes_or_private_text(self):
        from dracla.cli.app import main
        f = MutationRepository(); values = dict(f.files['coverage', f.c])
        values[FENCE] = f.encrypt('coverage', 'coverage', FENCE,
                                  {'state': 'private malformed provider value', 'generation': 0})
        f.set_head('coverage', 'coverage', f.commit('coverage', values, f.c))
        output = io.StringIO()
        result = main(self.args(f), output=output, release_loader=lambda: SimpleNamespace(package_version='test-1'),
                      verify_factory=lambda b: f.reader())
        self.assertEqual(result, 2, output.getvalue())
        self.assertIn('invalid-history', output.getvalue())
        self.assertNotIn('private malformed', output.getvalue())
        self.assertFalse(f.writes)

    def test_cli_redacts_unexpected_provider_failure(self):
        from dracla.cli.app import main
        f = MutationRepository(); output = io.StringIO()
        def broken(binding):
            raise RuntimeError('PRIVATE-RECOVERY-KEY-AND-CONTACT')
        result = main(self.args(f), output=output, release_loader=lambda: SimpleNamespace(package_version='test-1'),
                      verify_factory=broken)
        self.assertEqual(result, 1)
        self.assertNotIn('PRIVATE', output.getvalue())
        self.assertFalse(f.writes)

    def test_cli_leaves_success_reservation_blocked_without_a_check_assertion(self):
        from dracla.cli.app import main
        f = MutationRepository(); values = dict(f.files['coverage', f.c])
        values[FENCE] = f.encrypt('coverage', 'coverage', FENCE,
            {'state': 'success_reserved', 'generation': 0,
             'check_identity': base64url_encode(b'z' * 32), 'projection_commit': f.c})
        f.set_head('coverage', 'coverage', f.commit('coverage', values, f.c))
        output = io.StringIO()
        result = main(self.args(f), output=output, release_loader=lambda: SimpleNamespace(package_version='test-1'),
                      verify_factory=lambda b: f.reader())
        self.assertEqual(result, 2, output.getvalue())
        self.assertIn('check-confirmation-required', output.getvalue())
        self.assertFalse(f.writes)

    def test_installed_wheel_executes_actual_recovery_engine(self):
        root = Path(__file__).resolve().parents[2]
        code = r'''
import io,pathlib,sys
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
import dracla.records.reconcile
assert pathlib.Path(dracla.records.reconcile.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
sys.path.append(sys.argv[2])
from core.tests.test_records_2 import MutationRepository
from core.tests.test_records_3 import prepared,TestStoredRecoveryAndCommand
from dracla.cli.app import main
from dracla.records.history import verify_project
f=MutationRepository();prepared(f);out=io.StringIO()
assert main(TestStoredRecoveryAndCommand().args(f),output=out,
 release_loader=lambda:SimpleNamespace(package_version='test-1'),verify_factory=lambda b:f.reader())==0,out.getvalue()
assert verify_project(f.binding,*f.reader()).valid
assert 'Mutation test retention' not in out.getvalue() and 'opaque' not in out.getvalue()
assert all(pathlib.Path(m.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
 for n,m in sys.modules.items() if n.startswith('dracla.') and getattr(m,'__file__',None))
print('installed reconcile: actual encrypted REST/GraphQL recovery, all projections and guards verified')
'''
        with tempfile.TemporaryDirectory(prefix='dracla-m3-reconcile-installed-') as temporary:
            work = Path(temporary); dist = work / 'dist'; target = work / 'installed'
            built = subprocess.run([sys.executable, '-m', 'hatchling', 'build', '-t', 'wheel', '-d', str(dist)],
                                   cwd=root, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel, = dist.glob('*.whl')
            installed = subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps',
                                       '--target', str(target), str(wheel)], capture_output=True, text=True)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            run = subprocess.run([sys.executable, '-I', '-c', code, str(target), str(root)], cwd=work,
                                 capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
