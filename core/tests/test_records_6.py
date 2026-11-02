"""M3/6.1 operator restore and installed-engine acceptance exercises.

The mirror below is an inert test fixture, not a new backup format or command.
Its preflight represents the operator's all-repository mirror check. The App
transport remains unable to access control. Synthetic package versions and
publisher responses are not authentic release or live-recovery evidence.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from dracla.cli.app import main
from dracla.records import RecordsError
from dracla.records.history import open_history, verify_project
from core.tests.test_records_2 import MutationRepository
from core.tests import test_records_3 as recovery
from core.tests.test_records_3 import NOW, prepared, default_reconcile
from core.tests.test_records_5 import prepared_fixture, fixture_wheel, gate, RUNTIME_VERSION
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def capture(f):
    """Save ciphertext/objects and the operator's independent source/ref list."""
    # Control and an additional archival branch exercise the complete mirror,
    # rather than reducing backup to the five branches the data engine reads.
    if '/repos/acme/control' not in f.values:
        repo = f.binding.repo('control')
        f.values['/repos/acme/control'] = {'id': repo.id, 'private': True,
            'owner': {'id': f.binding.owner_id, 'login': 'acme'}, 'name': 'control'}
        oid = f.commit('control', {'reconcile.yml': b'protected fixture workflow'})
        for role, branch, head in [('control', 'main', oid),
                                   ('records', 'archive/before-recovery', f.root)]:
            f.values[f'/repos/acme/{role}/git/ref/heads/{branch}'] = {
                'ref': 'refs/heads/' + branch, 'object': {'type': 'commit', 'sha': head}}
    manifest = {'snapshot_time': NOW, 'repositories': []}
    for repo in f.binding.repositories:
        prefix = f'/repos/acme/{repo.name}/git/ref/heads/'
        manifest['repositories'].append({'role': repo.role, 'id': repo.id,
            'branches': {path[len(prefix):]: value['object']['sha']
                for path, value in sorted(f.values.items()) if path.startswith(prefix)}})
    return {'manifest': manifest, 'objects': copy.deepcopy(f.values), 'serial': f.serial,
        'files': [[role, oid, {path: base64.b64encode(raw).decode() for path, raw in files.items()}]
            for (role, oid), files in sorted(f.files.items())]}


def restore(snapshot):
    # Recovery material is supplied separately. It is deliberately not captured
    # with the repository objects. These fixtures use the existing test wrapper.
    f = MutationRepository()
    f.values = copy.deepcopy(snapshot['objects'])
    f.files = {(role, oid): {path: base64.b64decode(raw, validate=True)
                           for path, raw in files.items()}
               for role, oid, files in snapshot['files']}
    f.serial = snapshot['serial']
    f.e, f.b = f.head('records', 'events'), f.head('records', 'keys')
    f.c, f.d = f.head('coverage', 'coverage'), f.head('records', 'derived')
    f.o = f.head('records', 'operations')
    return f


def mirror_preflight(f, manifest):
    """Exercise documented operator checks, without granting the App access."""
    expected = {repo.role: repo for repo in f.binding.repositories}
    if {r['role'] for r in manifest['repositories']} != set(expected):
        raise ValueError('incomplete mirror')
    for saved in manifest['repositories']:
        repo = expected[saved['role']]
        actual = f.values[f'/repos/acme/{repo.name}']
        if actual['id'] != saved['id'] or repo.id != saved['id']:
            raise ValueError('repository identity changed; administrator rebind required')
        prefix = f'/repos/acme/{repo.name}/git/'
        refs = {path.removeprefix(prefix + 'ref/heads/'): value['object']['sha']
                for path, value in f.values.items() if path.startswith(prefix + 'ref/heads/')}
        if refs != saved['branches']:
            raise ValueError('restored refs differ from snapshot')
        pending, visited = list(refs.values()), set()
        while pending:
            oid = pending.pop()
            if oid in visited:
                continue
            visited.add(oid)
            commit = f.values.get(prefix + 'commits/' + oid)
            if commit is None or (repo.role, oid) not in f.files:
                raise ValueError('incomplete commit history')
            pending.extend(parent['sha'] for parent in commit['parents'])


def canonical_objects(f):
    """Exact retained canonical/key commit contents, not just current heads."""
    heads = [f.head('records', branch) for branch in ('events', 'keys')]
    result = {}
    while heads:
        oid = heads.pop()
        if oid in result:
            continue
        result[oid] = copy.deepcopy(f.files['records', oid])
        heads.extend(p['sha'] for p in f.values['/repos/acme/records/git/commits/' + oid]['parents'])
    return result


class BackupRecoveryTests(unittest.TestCase):
    def test_restore_authenticates_complete_rotated_history_and_retained_keys(self):
        snapshot = capture(MutationRepository(rotate=True, extra_rules=True))
        f = restore(snapshot)
        mirror_preflight(f, snapshot['manifest'])
        before = canonical_objects(f)
        history = open_history(f.binding, *f.reader())
        self.assertGreater(len(history.records), 10)
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)
        self.assertTrue(default_reconcile(f).valid)
        self.assertEqual(canonical_objects(f), before)
        self.assertFalse(f.writes)

    def test_restore_recovers_persisted_work_and_preserves_complete_canonical_prefix(self):
        original = MutationRepository()
        prepared(original)
        snapshot = capture(original)
        f = restore(snapshot)
        mirror_preflight(f, snapshot['manifest'])
        before = canonical_objects(f)
        keys_oid = f.head('records', 'keys')
        out = io.StringIO()
        args = recovery.TestStoredRecoveryAndCommand().args(f)
        self.assertEqual(main(args, output=out,
            release_loader=lambda: SimpleNamespace(package_version='fixture'),
            verify_factory=lambda binding: f.reader()), 0, out.getvalue())
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)
        self.assertEqual(f.head('records', 'keys'), keys_oid)
        self.assertTrue(all(canonical_objects(f)[oid] == files for oid, files in before.items()))
        self.assertNotIn('Mutation test retention', out.getvalue())
        self.assertNotIn('opaque', out.getvalue())
        self.assertFalse(any('/control' in path for path in f.calls))
        writes = len(f.writes)
        self.assertTrue(default_reconcile(f).valid)
        self.assertEqual(len(f.writes), writes)

    def test_restore_of_landed_operation_finishes_without_duplicate_append(self):
        f = MutationRepository()
        engine, reference = prepared(f)
        engine.begin(reference, subjects=[], project_wide=True, started_at=NOW)
        self.assertEqual(engine.append(reference).result, 'landed')
        snapshot = capture(f)
        f = restore(snapshot)
        mirror_preflight(f, snapshot['manifest'])
        before = canonical_objects(f)
        head = f.head('records', 'events')
        self.assertTrue(default_reconcile(f).valid)
        self.assertEqual(f.head('records', 'events'), head)
        self.assertEqual(canonical_objects(f), before)
        self.assertTrue(verify_project(f.binding, *f.reader()).valid)

    def test_operator_rejects_incomplete_or_mismatched_all_repository_mirror(self):
        snapshot = capture(MutationRepository())
        for defect in ('missing-control', 'missing-ref', 'wrong-head', 'missing-ancestor',
                       'records-id', 'coverage-id', 'control-id'):
            with self.subTest(defect=defect):
                saved = copy.deepcopy(snapshot)
                f = restore(saved)
                if defect == 'missing-control':
                    saved['manifest']['repositories'] = saved['manifest']['repositories'][:2]
                elif defect == 'missing-ref':
                    del f.values['/repos/acme/records/git/ref/heads/archive/before-recovery']
                elif defect == 'wrong-head':
                    f.set_head('records', 'events', f.root)
                elif defect == 'missing-ancestor':
                    del f.values['/repos/acme/records/git/commits/' + f.root]
                else:
                    f.values['/repos/acme/' + defect.removesuffix('-id')]['id'] += 1000
                with self.assertRaises(ValueError):
                    mirror_preflight(f, saved['manifest'])
                self.assertFalse(f.writes)
                self.assertFalse(f.calls)

    def test_existing_reader_rejects_replacement_data_repository_before_keys(self):
        snapshot = capture(MutationRepository())
        for role in ('records', 'coverage'):
            with self.subTest(role=role):
                f = restore(snapshot)
                f.values['/repos/acme/' + role]['id'] += 1000
                keys, transport = f.reader()
                with self.assertRaises(RecordsError):
                    open_history(f.binding, keys, transport)
                self.assertEqual(f.key_calls, [])
                self.assertFalse(f.writes)

    def test_changed_control_binding_is_not_an_automatic_trust_transfer(self):
        f = restore(capture(MutationRepository()))
        binding = replace(f.binding, repositories=tuple(replace(repo, id=repo.id + 1000)
            if repo.role == 'control' else repo for repo in f.binding.repositories))
        with self.assertRaises(RecordsError):
            open_history(binding, *f.reader())
        self.assertFalse(f.writes)

    def test_missing_key_commit_or_wrong_recovery_material_never_repairs(self):
        snapshot = capture(MutationRepository())
        for defect in ('missing-key-commit', 'wrong-recovery-key'):
            with self.subTest(defect=defect):
                f = restore(snapshot)
                if defect == 'missing-key-commit':
                    del f.values['/repos/acme/records/git/commits/' + f.k]
                else:
                    f.wrapping = b'x' * 32
                with self.assertRaises(RecordsError):
                    open_history(f.binding, *f.reader())
                self.assertFalse(f.writes)

    def test_idle_projection_loss_retains_explicit_m4_recovery_gate(self):
        f = restore(capture(MutationRepository()))
        before = canonical_objects(f)
        f.set_head('records', 'derived', f.commit('records', {}, f.d))
        self.assertFalse(verify_project(f.binding, *f.reader()).valid)
        result = default_reconcile(f)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, 'route-unavailable-proof-required')
        self.assertEqual(canonical_objects(f), before)
        self.assertFalse(f.writes)


class ProtectedReleaseSelectionTests(unittest.TestCase):
    @patch.object(gate.sys, 'version_info', RUNTIME_VERSION)
    def test_explicit_upgrade_and_rollback_repeat_existing_verifier(self):
        # These existing HTTP/crypto fixtures exercise protected selection,
        # not authenticity of a released wheel or a real publisher signature.
        with tempfile.TemporaryDirectory() as directory:
            states = []
            for version in ('0.0.1', '0.0.2'):
                root = Path(directory) / version
                root.mkdir()
                data = prepared_fixture(root)
                prior = data.state / 'wheels' / data.selected['runtime']['wheel']['filename']
                raw = fixture_wheel(version=version, requires=['rfc8785==0.1.4'],
                                    constraints=b'rfc8785==0.1.4\n')
                prior.unlink()
                filename = f'dracla-{version}-py3-none-any.whl'
                (data.state / 'wheels' / filename).write_bytes(raw)
                data.selected['package_version'] = version
                data.selected['runtime']['wheel'] = {'filename': filename, 'sha256': gate.digest(raw)}
                states.append(data)
            identities = []
            for data in (states[0], states[1], states[0]):
                with patch.dict(sys.modules, {'pypi_attestations': data.reader}):
                    runtime, build, parsed = gate.verify(data.state, gate.profile(json.dumps(data.selected).encode()),
                        root=data.root, execute=data.execute, download=lambda url: json.dumps({
                            'id': data.selected['source']['repository_id'],
                            'html_url': data.selected['source']['repository_url'], 'private': False}).encode())
                self.assertEqual(parsed['dracla'][1]['Version'], data.selected['package_version'])
                identities.append(data.selected['runtime']['wheel']['sha256'])
            self.assertNotEqual(identities[0], identities[1])
            self.assertEqual(identities[0], identities[2])
            self.assertEqual([len(data.converted) for data in states], [2, 1])
            # A new wheel beside the retained old protected pins is not an
            # upgrade or rollback. The finite wheel-set check must reject it.
            old, new = states
            old_path = old.state / 'wheels' / old.selected['runtime']['wheel']['filename']
            old_path.write_bytes((new.state / 'wheels' / new.selected['runtime']['wheel']['filename']).read_bytes())
            with self.assertRaises(gate.VerificationError):
                gate.wheel_set(old.state / 'wheels', old.selected, old.runtime)


class InstalledRecoveryTests(unittest.TestCase):
    def test_real_wheel_recovery_upgrade_and_rollback_preserve_canonical_evidence(self):
        # Both versions contain this actual candidate's engines. Their distinct
        # metadata tests selection/reinstallation, not compatibility with an
        # authentic older published release, which remains an external gate.
        code = r'''
import hashlib,importlib.metadata,io,json,pathlib,sys
installed,source,saved,version=sys.argv[1:]
sys.path.insert(0,installed)
from dracla.cli.app import main
from dracla.records.history import verify_project
sys.path.append(source)
from core.tests.test_records_6 import restore,capture,mirror_preflight,canonical_objects
from core.tests import test_records_3 as recovery
from types import SimpleNamespace
assert importlib.metadata.version('dracla')==version
snapshot=json.loads(pathlib.Path(saved).read_text())
f=restore(snapshot);mirror_preflight(f,snapshot['manifest']);before=canonical_objects(f)
out=io.StringIO()
assert main(recovery.TestStoredRecoveryAndCommand().args(f),output=out,
 release_loader=lambda:SimpleNamespace(package_version=version),verify_factory=lambda binding:f.reader())==0,out.getvalue()
assert verify_project(f.binding,*f.reader()).valid
after=canonical_objects(f)
assert all(after[oid]==files for oid,files in before.items())
assert all(pathlib.Path(m.__file__).is_relative_to(pathlib.Path(installed))
 for name,m in sys.modules.items() if name.startswith('dracla.') and getattr(m,'__file__',None))
assert 'Mutation test retention' not in out.getvalue() and 'opaque' not in out.getvalue()
encoded={oid:{path:hashlib.sha256(raw).hexdigest() for path,raw in files.items()}
 for oid,files in after.items()}
pathlib.Path(saved).write_text(json.dumps(capture(f)))
print(json.dumps({'version':version,'writes':len(f.writes),'events_oid':f.head('records','events'),
 'keys_oid':f.head('records','keys'),'canonical_sha256':hashlib.sha256(
 json.dumps(encoded,sort_keys=True).encode()).hexdigest()}))
'''
        with tempfile.TemporaryDirectory(prefix='dracla-m3-6-installed-') as directory:
            work = Path(directory)
            source = work / 'source'
            source.mkdir()
            for name in ('pyproject.toml', 'README.md', 'LICENSE'):
                shutil.copyfile(ROOT / name, source / name)
            shutil.copytree(ROOT / 'core/dracla', source / 'core/dracla',
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            project = (source / 'pyproject.toml').read_text()
            wheels = []
            for version in ('0.0.1', '0.0.2'):
                (source / 'pyproject.toml').write_text(project.replace('version = "0.0.1"',
                                                                    f'version = "{version}"'))
                dist = work / ('dist-' + version)
                built = subprocess.run([sys.executable, '-m', 'hatchling', 'build', '-t', 'wheel', '-d', str(dist)],
                    cwd=source, capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                wheel, = dist.glob('*.whl')
                wheels.append((version, wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()))
            original = MutationRepository()
            prepared(original)
            saved = work / 'encrypted-mirror.json'
            saved.write_text(json.dumps(capture(original)))
            os.chmod(saved, 0o600)
            results = []
            for step, (version, wheel, digest) in enumerate((wheels[0], wheels[1], wheels[0])):
                self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(), digest)
                target = work / f'installed-{step}'
                installed = subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps',
                    '--target', str(target), str(wheel)], capture_output=True, text=True)
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                run = subprocess.run([sys.executable, '-I', '-c', code, str(target), str(ROOT), str(saved), version],
                    cwd=work, capture_output=True, text=True,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                results.append(json.loads(run.stdout))
            self.assertGreater(results[0]['writes'], 0)
            self.assertEqual([row['writes'] for row in results[1:]], [0, 0])
            self.assertEqual(len({row['canonical_sha256'] for row in results}), 1)
            self.assertEqual(len({row['events_oid'] for row in results}), 1)
            self.assertEqual(len({row['keys_oid'] for row in results}), 1)


if __name__ == '__main__':
    unittest.main()
