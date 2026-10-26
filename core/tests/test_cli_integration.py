"""M2/4 installed-package seams and application zero-write evidence."""
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]

# Executed from outside the checkout, importing only the installed wheel.
INSTALLED_PROBE = r'''
import builtins, io, json, os, pathlib, subprocess, sys
from contextlib import ExitStack
from unittest.mock import patch
from dracla.cli.app import main, _COMMANDS
from dracla.cli.config import compose_install
from dracla.cli.release import load_release_policy
from dracla.administration import Administration
from dracla.github_admin import GitHubAdministration, HttpResponse
from dracla.provisioning import FreshObservations, plan_install, plan_resume, administration_scope
import dracla.cli.app
assert pathlib.Path(dracla.cli.app.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
assert {'install','verify'} <= set(_COMMANDS) and all(callable(h) for h in _COMMANDS.values())
compose_install(['github.owner=acme'])  # Load Hydra imports before effect spies.
release=load_release_policy()
original_open, original_io_open, original_os_open=builtins.open,io.open,os.open
calls=[]
mode='absent'
def forbidden(*a,**kw): raise AssertionError('application write/process/network effect')
def safe_open(original):
    def checked(file, mode='r', *a, **kw):
        assert not any(c in mode for c in 'wax+')
        return original(file,mode,*a,**kw)
    return checked
def safe_os_open(path,flags,*a,**kw):
    assert not flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)
    return original_os_open(path,flags,*a,**kw)
def sender(method,url,headers,timeout,*body):
    assert method=='GET' and not body
    assert headers['X-GitHub-Api-Version']=='2022-11-28'
    calls.append((method,url))
    account={'login':'acme','id':7,'type':'User','public_repos':0,
             'owned_private_repos':3 if mode=='collision' else 0}
    if mode=='denied': return HttpResponse(403,{},b'{}')
    if url.endswith('/user') or url.endswith('/users/acme'):
        return HttpResponse(200,{'X-OAuth-Scopes':'repo'},json.dumps(account).encode())
    def repo(role,index):
        return {'name':f'acme-cla-{role}','full_name':f'acme/acme-cla-{role}',
                'id':11+index,'owner':account,'private':True,
                'permissions':{'admin':True,'push':True,'pull':True}}
    if '/user/repos?' in url:
        rows=[repo(role,i) for i,role in enumerate(('records','coverage','control'))] if mode=='collision' else []
        return HttpResponse(200,{},json.dumps(rows).encode())
    if mode=='collision':
        for i,role in enumerate(('records','coverage','control')):
            if url.endswith('/acme-cla-'+role): return HttpResponse(200,{},json.dumps(repo(role,i)).encode())
    return HttpResponse(404,{},b'{}')
def factory(scope):
    adapter=GitHubAdministration(scope,credential_provider=lambda:'SECRET',sender=sender)
    # The actual read adapter also implements the named mutation protocol.
    for name in ('create_private_repository','set_private','rename_branch','list_deploy_keys',
                 'add_deploy_key','put_actions_secret','dispatch_workflow'):
        assert callable(getattr(adapter,name))
    return adapter
before=sorted(str(p) for p in pathlib.Path.cwd().rglob('*'))
with ExitStack() as stack:
    for name in ('mkdir','makedirs','remove','unlink','rename','replace','rmdir','system','fork'):
        if hasattr(os,name): stack.enter_context(patch.object(os,name,forbidden))
    stack.enter_context(patch('builtins.open',safe_open(original_open)))
    stack.enter_context(patch('io.open',safe_open(original_io_open)))
    stack.enter_context(patch('os.open',safe_os_open))
    stack.enter_context(patch('subprocess.Popen',forbidden))
    stack.enter_context(patch('urllib.request.urlopen',forbidden))
    stack.enter_context(patch('urllib.request.build_opener',forbidden))
    stack.enter_context(patch('socket.create_connection',forbidden))
    for current_mode in ('absent','collision','denied'):
        mode=current_mode
        for flags in (['dry_run=true'],['dry_run=true','force=true'],['force=true']):
            out=io.StringIO();start=len(calls)
            result=main(['install','github.owner=acme']+flags,output=out,admin_factory=factory)
            text=out.getvalue()
            assert result==(0 if mode=='absent' and 'dry_run=true' in flags else 2),text
            assert 'SECRET' not in text and 'This deploy key is an integrity credential' in text
            assert 'hosted operator' in text and 'M6; blocked' in text
            if mode=='collision': assert 'provenance verifier unavailable' in text
            assert len(calls)>start
    mode='absent'
    config=compose_install(['github.owner=acme','dry_run=true'])
    from dracla.administration import discover
    scope=administration_scope(config)
    first=plan_install(config,release,discover(factory(scope),scope))
    fresh=FreshObservations(config,load_release_policy(),discover(factory(scope),scope))
    assert first==plan_resume(first,fresh)
    # Invalid resolver, unknown command and release failure must stop before credentials.
    for args in (['install','github.owner=${oc.env:GH_TOKEN}'],['unknown'],['install','github.owner=acme']):
        out=io.StringIO()
        code=main(args,output=out,credential_provider=forbidden,
                  release_loader=lambda: (_ for _ in ()).throw(__import__('dracla.cli.release',fromlist=['ReleaseError']).ReleaseError('Unavailable release evidence')))
        assert code==2 and 'SECRET' not in out.getvalue()
assert sorted(str(p) for p in pathlib.Path.cwd().rglob('*'))==before
print('installed CLI/read/planner/resume/mutation-protocol seam: zero application writes')
'''


INSTALLED_VERIFY_PROBE = r'''
import io,json,os,pathlib,socket,subprocess,sys
from contextlib import ExitStack
from unittest.mock import patch
from dracla.cli.app import main
from dracla.records import OperatorCredentials,RepositoryTransport,WrappedKeys
from dracla.github_admin import HttpResponse
import dracla.records.history
assert pathlib.Path(dracla.records.history.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
fixture=json.loads(sys.stdin.read())
calls=[]
def sender(method,url,headers,timeout,body=None):
    assert method=='GET' and body is None
    path=url.removeprefix('https://api.github.com')
    assert path in fixture
    calls.append(path)
    return HttpResponse(200,{},json.dumps(fixture[path]).encode())
def factory(binding):
    assert binding.owner_id==10 and binding.ids()=={'records':11,'coverage':12,'control':13}
    return (WrappedKeys('recovery',lambda:{'install-1':b'w'*32}),
            RepositoryTransport(OperatorCredentials(lambda:'SECRET',sender=sender)))
def forbidden(*args,**kw):raise AssertionError('verify application write/network/process effect')
args=['verify','project.id=project-1','github.owner=acme','github.owner_id=10',
      'records.name=records','records.id=11','coverage.name=coverage','coverage.id=12',
      'control.name=control','control.id=13']
with ExitStack() as stack:
    for name in ('mkdir','makedirs','remove','unlink','rename','replace','rmdir','system','fork'):
        if hasattr(os,name):stack.enter_context(patch.object(os,name,forbidden))
    stack.enter_context(patch('subprocess.Popen',forbidden))
    stack.enter_context(patch('socket.create_connection',forbidden))
    stack.enter_context(patch('urllib.request.build_opener',forbidden))
    out=io.StringIO()
    assert main(args,output=out,verify_factory=factory)==0,out.getvalue()
    assert 'Verification passed' in out.getvalue()
    assert 'SECRET' not in out.getvalue() and 'Recipient One' not in out.getvalue()
    assert not any('/control' in path for path in calls)
print('installed encrypted verify: complete replay and projections, zero repository writes')
'''


class InstalledCliIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='dracla-m2-4-')
        cls.addClassCleanup(cls.temporary.cleanup)
        base = Path(cls.temporary.name)
        cls.target, cls.work = base / 'installed', base / 'work'
        cls.work.mkdir()
        result = subprocess.run([sys.executable, '-m', 'hatchling', 'build', '-t', 'wheel',
                                 '-d', str(base / 'dist')], cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        wheel, = (base / 'dist').glob('*.whl')
        with zipfile.ZipFile(wheel) as archive:
            assert 'dracla/release-policy.json' not in archive.namelist()
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-index',
                                 '--target', str(cls.target), str(wheel)], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.env = {**os.environ, 'PYTHONPATH': str(cls.target), 'PYTHONDONTWRITEBYTECODE': '1',
                   'GH_TOKEN': 'SECRET', 'GITHUB_TOKEN': 'SECRET'}

    def run_installed(self, argv):
        before = sorted(str(p) for p in self.work.rglob('*'))
        result = subprocess.run(argv, cwd=self.work, env=self.env, capture_output=True, text=True)
        self.assertNotIn('SECRET', result.stdout + result.stderr)
        self.assertEqual(sorted(str(p) for p in self.work.rglob('*')), before)
        return result

    def test_01_development_wheel_failure_precedes_credentials(self):
        for command in ([str(self.target / 'bin/dracla')], [sys.executable, '-m', 'dracla.cli']):
            result = self.run_installed(command + ['install', 'github.owner=acme', 'dry_run=true', 'force=true'])
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('Release evidence is unavailable', result.stdout)

    def test_02_documented_invocations_and_registered_handlers(self):
        from dracla.cli.app import _COMMANDS
        self.assertTrue({'install', 'verify'} <= set(_COMMANDS))
        self.assertTrue(all(callable(handler) for handler in _COMMANDS.values()))
        lines = (ROOT / 'docs/cli.md').read_text().splitlines()
        invocations = [shlex.split(line) for line in lines
                       if line.startswith(('dracla ', 'python -m dracla.cli '))]
        self.assertGreaterEqual(len(invocations), 2)
        for argv in invocations:
            if argv[0] == 'python':
                argv[0] = sys.executable
                name = argv[3]
            else:
                name = argv[1]
                argv[0] = str(self.target / 'bin/dracla')
            self.assertIn(name, _COMMANDS)
            result = self.run_installed(argv[:4] + ['--help'] if name == 'install' and argv[0] == sys.executable
                                        else [argv[0], name, '--help'])
            self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_installed([str(self.target / 'bin/dracla'), 'unknown'])
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unknown command', result.stdout)

    def test_03_complete_installed_fixture_seam_has_zero_writes(self):
        # Populate release declarations only in the disposable installed fixture.
        # The built development wheel remains unchanged and evidence-free.
        from importlib import metadata
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        from dracla.conformance.canonical import canonical_json
        import hashlib
        pending = [metadata.Distribution.at(self.target / 'dracla-0.0.1.dist-info')]
        pins = {}
        while pending:
            for value in pending.pop().requires or ():
                requirement = Requirement(value)
                if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
                    continue
                name = canonicalize_name(requirement.name)
                if name not in pins:
                    distribution = metadata.distribution(name)
                    pins[name] = distribution.version
                    pending.append(distribution)
        constraints = ''.join(f'{name}=={version}\n' for name, version in sorted(pins.items())).encode()
        policy = {'release_policy_version': 1, 'package_version': '0.0.1', 'source_commit_oid': 'a' * 40,
                  'provenance_identity': 'fixture-only-workflow',
                  'dependency_constraints_sha256': 'sha256:' + hashlib.sha256(constraints).hexdigest()}
        (self.target / 'dracla/release-policy.json').write_bytes(canonical_json(policy))
        (self.target / 'dracla/dependency-constraints.txt').write_bytes(constraints)
        result = self.run_installed([sys.executable, '-c', INSTALLED_PROBE, str(self.target)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('zero application writes', result.stdout)
        from core.tests.test_records_1 import EncryptedRepository
        fixture = EncryptedRepository()
        before = sorted(str(p) for p in self.work.rglob('*'))
        result = subprocess.run([sys.executable, '-c', INSTALLED_VERIFY_PROBE, str(self.target)],
                                input=json.dumps(fixture.values), cwd=self.work, env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('installed encrypted verify', result.stdout)
        self.assertNotIn('SECRET', result.stdout + result.stderr)
        self.assertEqual(sorted(str(p) for p in self.work.rglob('*')), before)


if __name__ == '__main__':
    unittest.main()
