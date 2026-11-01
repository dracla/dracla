"""m3/5 external production boundary and concrete credential lifecycle tests.

Deterministic fixtures test rejection/launch mechanics. They are not authentic
PyPI publication, hosted job, App incident or live-capacity evidence.
"""
import base64
import copy
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from dracla.github_admin import HttpResponse
from dracla.records import RecordsError
from dracla.records.github import control_job
from core.tests.test_records_1 import AppFixture, BINDING
from core.tests.test_records_2 import MutationRepository

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_VERSION = (3,12,16)
SPEC = importlib.util.spec_from_file_location('external_release_gate', ROOT / 'control/verify_release.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def encoded(value):
    return json.dumps(value).encode()


def profile():
    oid = '0123456789abcdef' * 2 + '01234567'
    repository = 'https://github.com/dracla/dracla'
    ref = 'refs/tags/v0.0.1'
    def workflow(name):
        path = repository + '/.github/workflows/' + name + '.yml'
        return {'workflow': path, 'commit_oid': oid, 'certificate_identity': path + '@' + ref}
    return {'profile_version': 1, 'package_version': '0.0.1',
        'source': {'repository_url': repository, 'repository_id': 1336037093, 'commit_oid': oid, 'ref': ref},
        'publisher': workflow('release'), 'builder': workflow('build-release'),
        'bootstrap': {'image': 'ghcr.io/dracla/dracla/bootstrap@sha256:' + 'ab' * 32,
                      'trust_root_sha256': 'sha256:' + 'cd' * 32},
        'runtime': {'python_version': '.'.join(map(str, RUNTIME_VERSION)),
            'abi': 'cp' + ''.join(map(str, sys.version_info[:2])), 'platform': 'manylinux_2_36_x86_64',
            'wheel': {'filename': 'dracla-0.0.1-py3-none-any.whl', 'sha256': 'sha256:' + 'ef' * 32},
            'runtime_lock_sha256': 'sha256:' + '12' * 32, 'build_lock_sha256': 'sha256:' + '34' * 32}}


def claim(selected, role, runtime, build):
    source, workflow = selected['source'], selected[role]
    certificate = {'issuer': gate.ISSUER, 'subjectAlternativeName': workflow['certificate_identity'],
        'sourceRepositoryIdentifier': str(source['repository_id']), 'sourceRepositoryURI': source['repository_url'],
        'sourceRepositoryDigest': source['commit_oid'], 'sourceRepositoryRef': source['ref'],
        'runnerEnvironment': 'github-hosted', 'buildSignerURI': workflow['certificate_identity'],
        'buildSignerDigest': workflow['commit_oid'], 'sourceRepositoryOwnerIdentifier': '10', 'buildTrigger':'workflow_dispatch'}
    predicate = {} if role == 'publisher' else {
        'buildDefinition': {'buildType': gate.BUILD_TYPE, 'externalParameters': {'workflow': {
            'repository': source['repository_url'], 'path': '.github/workflows/release.yml', 'ref': source['ref']}},
            'internalParameters': {'github': {'event_name':'workflow_dispatch','repository_id':str(source['repository_id']),
                'repository_owner_id':'10','runner_environment':'github-hosted'}},
            'resolvedDependencies': [{'uri': u, 'digest': {k: v}} for u, k, v in sorted(gate.dependencies(selected, runtime, build))]},
        'runDetails': {'builder': {'id': workflow['workflow'] + '@' + workflow['commit_oid']}}}
    return [{'attestation': {'bundle': {'verificationMaterial': {'tlogEntries': [
        {'inclusionProof': {'checkpoint': {'envelope': 'fixture-verified-by-gh-boundary'}}}]}}},
        'verificationResult': {'signature': {'certificate': certificate},
        'verifiedTimestamps': [{'type': 'Tlog', 'timestamp': '2026-01-01T00:00:00Z', 'uri': 'https://rekor.sigstore.dev'}],
        'statement': {'_type': 'https://in-toto.io/Statement/v1',
            'subject': [{'name': selected['runtime']['wheel']['filename'], 'digest': {'sha256': selected['runtime']['wheel']['sha256'][7:]}}],
            'predicateType': gate.PUBLISH if role == 'publisher' else gate.SLSA, 'predicate': predicate}}}]


def fixture_wheel(*, requires=None, name='dracla', version='0.0.1', constraints=b''):
    dist = name+'-'+version+'.dist-info'
    files = {name+'/__init__.py': b'',
        dist + '/METADATA': ('Metadata-Version: 2.3\nName: '+name+'\nVersion: '+version+'\n').encode(),
        dist + '/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    for requirement in requires or ():
        files[dist + '/METADATA'] += b'Requires-Dist: ' + requirement.encode() + b'\n'
    if name=='dracla':
        files.update({'dracla/dependency-constraints.txt':constraints,'dracla/cli.py':b'def main():\n return 0\n',
                      dist+'/entry_points.txt':b'[console_scripts]\ndracla = dracla.cli:main\n'})
        selected = profile()
        files['dracla/release-policy.json'] = json.dumps({'release_policy_version': 1, 'package_version': version,
            'source_commit_oid': selected['source']['commit_oid'],
            'provenance_identity': selected['builder']['workflow'] + '@' + selected['builder']['commit_oid'],
            'dependency_constraints_sha256': gate.digest(constraints)}, sort_keys=True, separators=(',', ':')).encode()
    rows = [[p, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode(), str(len(raw))]
            for p, raw in files.items()]
    rows.append([dist + '/RECORD', '', ''])
    stream = io.StringIO(); csv.writer(stream).writerows(rows)
    files[dist + '/RECORD'] = stream.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for path, raw in files.items():
            archive.writestr(path, raw)
    return output.getvalue()


def prepared_fixture(directory):
    """HTTP/crypto boundary fixture, not authentic publisher evidence."""
    selected=profile();runtime={'lock_version':1, **{k:selected['runtime'][k] for k in ('python_version','abi','platform')}}
    dependency=fixture_wheel(name='rfc8785',version='0.1.4');raw=fixture_wheel(requires=['rfc8785==0.1.4'],constraints=b'rfc8785==0.1.4\n')
    item={'name':'rfc8785','version':'0.1.4','filename':'rfc8785-0.1.4-py3-none-any.whl','tags':['py3-none-any'],
          'url':'https://files.pythonhosted.org/packages/fixture/rfc8785-0.1.4-py3-none-any.whl','sha256':gate.digest(dependency)}
    runtime['wheels']=[item];build=json.loads((ROOT/'release/build-inputs.lock.json').read_bytes())
    root=Path(directory)/'root.json';root.write_bytes(b'{}'); selected['bootstrap']['trust_root_sha256']=gate.digest(b'{}')
    build['trusted_root']['sha256']=gate.digest(b'{}'); selected['runtime']['runtime_lock_sha256']=gate.digest(encoded(runtime))
    selected['runtime']['build_lock_sha256']=gate.digest(encoded(build)); selected['runtime']['wheel']['sha256']=gate.digest(raw)
    state=Path(directory)/'state'; state.mkdir(mode=0o700);(state/'wheels').mkdir(mode=0o700)
    (state/'runtime-wheels.lock').write_bytes(encoded(runtime));(state/'build-inputs.lock.json').write_bytes(encoded(build))
    (state/'wheels'/item['filename']).write_bytes(dependency);(state/'wheels'/selected['runtime']['wheel']['filename']).write_bytes(raw)
    (state/'build.sigstore.jsonl').write_bytes(b'{"fixture":true}\n');(state/'publish.attestation.json').write_bytes(b'{"fixture":true}')
    converted=[]
    class Reader:
        @staticmethod
        def model_validate_json(raw):
            assert json.loads(raw)=={'fixture':True}; converted.append(raw)
            return SimpleNamespace(to_bundle=lambda:SimpleNamespace(to_json=lambda:'{"converted_fixture":true}'))
    def execute(argv,**kwargs):
        if argv[0]=='/usr/bin/gh':
            role='publisher' if gate.PUBLISH in argv else 'builder'
            assert argv[argv.index('--source-digest')+1]==selected['source']['commit_oid']
            return encoded(claim(selected,role,runtime,build))
        return gate.run(argv,**kwargs)
    return SimpleNamespace(state=state,selected=selected,runtime=runtime,build=build,root=root,
        reader=SimpleNamespace(Attestation=Reader),converted=converted,execute=execute)


def clocked_provider(fixture, runner_clock, elapsed_clock, *, sender=None, margin=60):
    from dracla.records import InstallationCredentials
    return InstallationCredentials(fixture.protected, lambda: fixture.pem,
        sender=fixture.send if sender is None else sender, clock=runner_clock,
        monotonic=elapsed_clock, margin=margin)


def protected_control_config(data):
    from dracla.conformance import Keyring, encode_keyring, wrap_key_copy
    ring = encode_keyring(Keyring(tuple(wrap_key_copy(data.data_keys[cap], project_id='project-1', capability=cap,
        data_kid=data.kid_bytes[cap], wrapper_id='control', wrapper_generation='install-1',
        wrapping_key=data.wrapping) for cap in ('records', 'coverage'))))
    return {'control_version': 1,
        'project': {'project_id': 'project-1', 'owner_id': 10,
            'repositories': [{'role': r.role, 'owner': r.owner, 'name': r.name, 'id': r.id}
                             for r in data.binding.repositories]},
        'installation': {'app_id': 17, 'client_id': 'client-id', 'installation_id': 19, 'owner_id': 10,
            'assignments': [{'project_id': 'project-1', 'repository_ids': [11, 12]}],
            'excluded_repository_ids': [13]},
        'keyrings': {oid: base64.b64encode(ring).decode() for oid in (data.k, data.b)},
        'export_request': None}


def protected_control_run(data):
    from dracla.records.credentials import InstallationCredentials

    app = AppFixture(); revoked = []
    app.patch['/app'] = lambda value: {**value, 'owner': {'id': 10}}
    app.patch['/app/installations/19'] = lambda value: {**value, 'account': {'id': 10}, 'target_id': 10}
    for repo in app.repositories:
        repo['owner']['id'] = 10

    def sender(method, url, headers, timeout, body=None):
        if method == 'DELETE':
            revoked.append(headers['Authorization'])
            return HttpResponse(204, {}, b'')
        return (data.send if '/repos/' in url or url.endswith('/graphql') else
                app.send)(method, url, headers, timeout, body)

    def credentials(protected, key, **kwargs):
        return InstallationCredentials(protected, key, sender=sender, clock=lambda: app.now, **kwargs)

    secrets = dict(DRACLA_TRANSPORT_APP_KEY=app.pem.decode(),
                   DRACLA_CONTROL_KEYS=json.dumps({'install-1': data.wrapping.hex()}),
                   DRACLA_CONTROL_REPOSITORY_ID='13')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'protected.json'; path.write_bytes(encoded(protected_control_config(data)))
        with patch('dracla.records.credentials.InstallationCredentials', credentials), \
                patch('dracla.cli.release.load_release_policy', return_value=SimpleNamespace(package_version='0.0.1')), \
                patch.object(os, 'environ', secrets), patch.object(sys, 'stdout', io.StringIO()) as output:
            result = control_job(str(path), 'reconcile')
    return result, output.getvalue(), revoked


class ProbePeer:
    """Concrete GraphQL ref CAS plus the existing encrypted repository fixture."""
    def __init__(self):
        from dracla.records.credentials import InstallationBinding, InstallationCredentials
        self.data=MutationRepository();self.app=AppFixture();self.updates=[];self.queries=[];self.fault=None;self.query_patch=None
        self.revocations=[];self.revocation_failure=False
        self.credentials_class=InstallationCredentials
        self.protected=InstallationBinding(17,'client-id',19,10,(('project-1',(11,12)),),(13,))
        self.app.patch['/app']=lambda v:{**v,'owner':{'id':10}}
        self.app.patch['/app/installations/19']=lambda v:{**v,'account':{'id':10},'target_id':10}
        for repo in self.app.repositories:repo['owner']['id']=10

    def credentials(self,protected,key,**kwargs):
        return self.credentials_class(protected,key,sender=self.send,clock=lambda:self.app.now,**kwargs)

    def send(self,method,url,headers,timeout,body=None):
        from core.tests.test_records_1 import response
        if method=='DELETE':
            self.revocations.append(headers['Authorization'])
            return HttpResponse(500,{},b'private provider text') if self.revocation_failure else HttpResponse(204,{},b'')
        if url.endswith('/graphql'):
            request=json.loads(body)
            if request['query'].startswith('query('):
                v=request['variables'];repo=next(r for r in self.data.binding.repositories[:2] if r.name==v['name'])
                self.queries.append(v)
                path=f'/repos/acme/{repo.name}/git/ref/'+v['ref'].removeprefix('refs/')
                existing=self.data.values.get(path)
                result={'id':'node-'+str(repo.id),'fullDatabaseId':str(repo.id),'nameWithOwner':'acme/'+repo.name,'isPrivate':True,
                    'ref':None if existing is None else {'target':{'__typename':'Commit','oid':existing['object']['sha']}}}
                return response({'data':{'repository':self.query_patch(result) if self.query_patch else result}})
            if 'UpdateRefsInput' in request['query']:
                value=request['variables']['input'];self.updates.append(copy.deepcopy(value));update=value['refUpdates'][0]
                repo=next(r for r in self.data.binding.repositories[:2] if value['repositoryId']=='node-'+str(r.id))
                path=f'/repos/acme/{repo.name}/git/ref/'+update['name'].removeprefix('refs/')
                before=self.data.values.get(path,{}).get('object',{}).get('sha','0'*40)
                if self.fault=='cleanup-race' and update['afterOid']=='0'*40:
                    self.fault=None
                    newer=self.data.commit(repo.role,{**self.data.files[repo.role,before],'other-probe.txt':b'other writer'},before)
                    self.data.values[path]={'ref':update['name'],'object':{'type':'commit','sha':newer}};before=newer
                if before!=update['beforeOid']:
                    return response({'data':{'updateRefs':None},'errors':[{'type':'UNPROCESSABLE','message':'ref changed'}]})
                if update['afterOid']=='0'*40:self.data.values.pop(path,None)
                else:self.data.values[path]={'ref':update['name'],'object':{'type':'commit','sha':update['afterOid']}}
                mode='lost-delete' if update['afterOid']=='0'*40 else 'lost-create'
                if self.fault==mode:self.fault=None;raise TimeoutError('private provider text')
                if self.fault=='bad-ack':
                    self.fault=None;return response({'data':{'updateRefs':{'clientMutationId':'wrong'}}})
                if self.fault=='null-ack':
                    self.fault=None;return response({'data':None})
                if self.fault in ('create-race','recreate-after-delete') and (update['afterOid']=='0'*40)==(self.fault=='recreate-after-delete'):
                    self.fault=None
                    current=before if update['afterOid']=='0'*40 else update['afterOid']
                    newer=self.data.commit(repo.role,{**self.data.files[repo.role,current],'other-probe.txt':b'other writer'},current)
                    self.data.values[path]={'ref':update['name'],'object':{'type':'commit','sha':newer}}
                return response({'data':{'updateRefs':{'clientMutationId':value['clientMutationId']}}})
        return (self.data.send if '/repos/' in url or url.endswith('/graphql') else self.app.send)(method,url,headers,timeout,body)

    def transport(self):
        from dracla.records import RepositoryTransport
        result=RepositoryTransport(self.credentials(self.protected,lambda:self.app.pem,contents='write'))
        result.authorize(self.data.binding);return result


class ExternalReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.selected = profile()
        self.runtime = json.loads((ROOT / 'release/runtime-wheels.lock').read_text())
        self.build = json.loads((ROOT / 'release/build-inputs.lock.json').read_text())

    @patch.object(gate.sys,'version_info',RUNTIME_VERSION)
    def test_closed_profile_accepts_only_exact_literal_identities(self):
        self.assertEqual(gate.profile(encoded(self.selected)), self.selected)
        cases = []
        for path, value in [(('profile_version',), True), (('extra',), 1),
                (('source', 'repository_id'), True), (('source', 'commit_oid'), '0' * 40),
                (('source', 'ref'), 'refs/heads/../../main'),
                (('source', 'repository_url'), 'https://github.com/dracla/dracla?exec=x'),
                (('bootstrap', 'image'), 'python:latest'), (('runtime', 'wheel', 'filename'), '../payload.whl'),
                (('bootstrap', 'image'), 'ghcr.io/../escape@sha256:'+'ab'*32),
                (('runtime', 'python_version'), '3.13.0'),
                (('source', 'repository_url'), 'https://github.com/../dracla'),
                (('builder', 'workflow'), 'https://github.com/other/repo/.github/workflows/build.yml'),
                (('runtime', 'extra'), 'value')]:
            candidate = copy.deepcopy(self.selected); target = candidate
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value; cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises((gate.VerificationError, ValueError, TypeError)):
                gate.profile(encoded(candidate))
        with self.assertRaises(gate.VerificationError):
            gate.profile(b'{"profile_version":1,"profile_version":1}')

    def test_bounded_http_fetch_rejects_redirects_and_nonliteral_urls(self):
        url='https://api.github.com/repos/dracla/dracla'
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def geturl(self):return url
            def read(self,limit):return b'{}'
        requests=[]
        def send(request,timeout):
            requests.append((request.full_url,request.get_method(),timeout,request.headers))
            return Response()
        with patch.object(gate.urllib.request,'build_opener',return_value=SimpleNamespace(open=send)):
            self.assertEqual(gate.fetch(url),b'{}')
            self.assertEqual(requests[0][:3],(url,'GET',30))
            for forbidden in ('file:///etc/passwd','https://attacker.invalid/script','https://api.github.com/repos/a/b?command=x',
                              'https://api.github.com/repos/../secret'):
                with self.assertRaises(gate.VerificationError):gate.fetch(forbidden)
            with self.assertRaises(gate.VerificationError):gate.fetch(url,1)
            url='https://tmaproduction.blob.core.windows.net/attestations/1336037093/2026/11/01/42.json.sn?sig=a%2Fb'
            self.assertEqual(gate.fetch(url),b'{}')
            self.assertNotIn('Authorization',requests[-1][3])
            for forbidden in (url+'#fragment',url.replace('tmaproduction.','attacker.'),url.replace('https:','http:')):
                with self.assertRaises(gate.VerificationError):gate.fetch(forbidden)
        with self.assertRaises(gate.VerificationError):
            gate.NoRedirect().redirect_request(None,None,302,'redirect',{},'https://attacker.invalid')

    def test_child_process_receives_no_ambient_app_secret_or_import_paths(self):
        with patch.dict(os.environ,{'DRACLA_TRANSPORT_APP_KEY':'fixture-app-key','DRACLA_CONTROL_KEYS':'fixture-keys',
                                   'PYTHONPATH':'/attacker','GH_TOKEN':'fixture-job-token'}):
            result=gate.run([sys.executable,'-I','-c','import json,os;print(json.dumps(dict(os.environ)))'])
            environment=json.loads(result)
            for key in ('DRACLA_TRANSPORT_APP_KEY','DRACLA_CONTROL_KEYS','PYTHONPATH','GH_TOKEN'):
                self.assertNotIn(key,environment)
            with self.assertRaises(gate.VerificationError) as error:
                gate.run([sys.executable,'-I','-c','import sys;sys.stderr.write("private provider value");sys.exit(1)'])
            self.assertEqual(str(error.exception),'production-verification-failed')

    def test_public_github_bundle_transport_binds_repository_and_bounds_decoder(self):
        url = 'https://tmaproduction.blob.core.windows.net/attestations/1336037093/2026/11/01/42.json.sn?se=expiry&sig=a%2Fb'
        attestation = {'repository_id':1336037093,'bundle':None,'bundle_url':url}
        # The actual pinned Snappy decoder is exercised by the offline image
        # probe with authentic public evidence. This fixture isolates bounds.
        calls=[]
        decoder=SimpleNamespace(decompress_raw_len=lambda raw:len(raw),decompress_raw=lambda raw:raw)
        def download(value):calls.append(value);return b'{"mediaType":"fixture"}'
        with patch.dict(sys.modules,{'cramjam':SimpleNamespace(snappy=decoder)}):
            self.assertEqual(gate.github_bundle(attestation,1336037093,download=download),{'mediaType':'fixture'})
            self.assertEqual(calls,[url])
            for invalid in (None,{},dict(attestation,repository_id=10),dict(attestation,bundle_url=None),
                            dict(attestation,bundle_url=url.replace('/1336037093/','/10/')),
                            dict(attestation,bundle_url=url.replace('tmaproduction.blob.core.windows.net','attacker.invalid')),
                            dict(attestation,bundle_url=url.replace('https:','http:')),
                            dict(attestation,bundle_url=url+'#fragment'),dict(attestation,bundle_url=url+'/'*4096)):
                with self.subTest(invalid=invalid),self.assertRaises(gate.VerificationError):
                    gate.github_bundle(invalid,1336037093,download=download)
            self.assertEqual(calls,[url])
            for raw in (b'[]',b'{"x":1,"x":2}',b'x'*(gate.MAX_JSON+1)):
                with self.assertRaises(gate.VerificationError):
                    gate.github_bundle(attestation,1336037093,download=lambda _:raw)
            for length in (0,gate.MAX_JSON+1):
                with patch.object(decoder,'decompress_raw_len',return_value=length), \
                        patch.object(decoder,'decompress_raw') as decompress:
                    with self.assertRaises(gate.VerificationError):
                        gate.github_bundle(attestation,1336037093,download=download)
                    decompress.assert_not_called()

    @patch.object(gate.sys,'version_info',RUNTIME_VERSION)
    def test_fixed_cli_validates_before_prepare_or_secret_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            selected=Path(directory)/'profile.json';selected.write_bytes(encoded(self.selected))
            args=['verify_release.py','prepare','--profile',str(selected),'--state',str(Path(directory)/'state')]
            with patch.object(sys,'argv',args),patch.object(gate,'prepare') as prepare,patch.dict(os.environ,{},clear=True):
                self.assertEqual(gate.main(),0);prepare.assert_called_once()
            with patch.object(sys,'argv',args),patch.object(gate,'prepare') as prepare, \
                    patch.dict(os.environ,{'DRACLA_TRANSPORT_APP_KEY':'must-not-enter-prepare'}),patch.object(sys,'stderr',io.StringIO()):
                self.assertEqual(gate.main(),1);prepare.assert_not_called()
            args[1]='launch';args+=['--configuration','/protected/control.json','--command','reconcile']
            with patch.object(sys,'argv',args),patch.object(gate,'launch') as launch:
                self.assertEqual(gate.main(),0);self.assertEqual(launch.call_args.args[-1],'reconcile')
        with patch.object(sys,'argv',['gate','produce']),patch.object(gate,'produce',side_effect=gate.VerificationError()), \
                patch.object(sys,'stderr',io.StringIO()) as error:
            self.assertEqual(gate.main(),1);self.assertEqual(error.getvalue(),'production-builder-failed\n')
        for mode in ('fetch-inputs','fetch-bootstrap'):
            with patch.object(sys,'argv',['gate',mode]),patch.object(gate,'fetch_inputs') as fetch:
                self.assertEqual(gate.main(),0);fetch.assert_called_once_with(bootstrap=mode=='fetch-bootstrap')

    def test_workflow_keeps_verification_and_secret_steps_in_one_protected_job(self):
        import yaml
        workflow=yaml.load((ROOT/'control/reconcile.yml').read_text(),Loader=yaml.BaseLoader)
        job=workflow['jobs']['control'];steps=job['steps']
        self.assertIn("contains(vars.DRACLA_BOOTSTRAP_IMAGE, '@sha256:')",job['if'])
        self.assertIn('github.event.repository.private == true',job['if'])
        self.assertIn('github.event.repository.default_branch',job['if'])
        self.assertIn('github.workflow_ref',job['if'])
        self.assertNotIn('environment',job)
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        self.assertEqual(workflow['on']['schedule'],[{'cron':'17 3 * * *'}])
        self.assertIn("github.event_name == 'schedule' && 'reconcile'",steps[-1]['env']['COMMAND'])
        secret_steps=[i for i,s in enumerate(steps) if '${{ secrets.' in json.dumps(s)]
        self.assertEqual(secret_steps,[len(steps)-1])
        self.assertEqual(steps[0]['name'],'Validate trusted control workflow context')
        self.assertEqual(steps[1]['uses'],'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1')
        self.assertEqual(steps[1]['with']['ref'],'${{ github.workflow_sha }}')
        self.assertIn('verify-release.sh prepare',steps[-2]['run'])
        self.assertIn('verify-release.sh launch',steps[-1]['run'])
        self.assertNotIn('if',steps[-1])
        self.assertFalse(any('upload-artifact' in s.get('uses','') or 'download-artifact' in s.get('uses','') for s in steps))
        for step in steps:
            if 'uses' in step:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
            if 'run' in step:self.assertNotIn('${{',step['run'])

    def test_workflow_context_guard_rejects_untrusted_fixtures(self):
        import yaml
        workflow=yaml.load((ROOT/'control/reconcile.yml').read_text(),Loader=yaml.BaseLoader)
        guard=workflow['jobs']['control']['steps'][0]
        script=guard['run']
        base={'EVENT_NAME':'workflow_dispatch','REPOSITORY_PRIVATE':'true','REF':'refs/heads/main',
              'DEFAULT_BRANCH':'main','REPOSITORY':'acme/control',
              'WORKFLOW_REF':'acme/control/.github/workflows/reconcile.yml@refs/heads/main',
              'WORKFLOW_SHA':'ab'*20,'COMMAND':'verify',
              'IMAGE':'ghcr.io/dracla/dracla/bootstrap@sha256:'+'cd'*32}
        declared=('EVENT_NAME','REPOSITORY_PRIVATE','REF','DEFAULT_BRANCH','REPOSITORY',
                  'WORKFLOW_REF','WORKFLOW_SHA','COMMAND','IMAGE')
        def run(values):
            environment=dict(os.environ)
            for key in declared:environment.pop(key,None)
            environment.update(values)
            return subprocess.run(['/bin/sh','-eu','-c',script],cwd=ROOT,env=environment,
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        for command in ('verify','reconcile','export','probe'):
            with self.subTest(event='workflow_dispatch',command=command):
                result=run({**base,'COMMAND':command})
                self.assertEqual(result.returncode,0,result.stderr)
        with self.subTest(event='schedule',command='reconcile'):
            result=run({**base,'EVENT_NAME':'schedule','COMMAND':'reconcile'})
            self.assertEqual(result.returncode,0,result.stderr)
        rejected=[]
        rejected.append({**base,'REPOSITORY_PRIVATE':'false'})
        rejected.append({**base,'EVENT_NAME':'push'})
        rejected.append({**base,'REF':'refs/heads/feature',
            'WORKFLOW_REF':'acme/control/.github/workflows/reconcile.yml@refs/heads/feature'})
        rejected.append({**base,'REF':'refs/tags/v0.0.1',
            'WORKFLOW_REF':'acme/control/.github/workflows/reconcile.yml@refs/tags/v0.0.1'})
        rejected.append({**base,'WORKFLOW_REF':'evil/control/.github/workflows/reconcile.yml@refs/heads/main'})
        rejected.append({**base,'WORKFLOW_REF':'acme/control/.github/workflows/other.yml@refs/heads/main'})
        rejected.append({**base,'REPOSITORY':'evil/control'})
        rejected.append({**base,'DEFAULT_BRANCH':''})
        missing_default=dict(base);del missing_default['DEFAULT_BRANCH'];rejected.append(missing_default)
        missing_repository=dict(base);del missing_repository['REPOSITORY'];rejected.append(missing_repository)
        missing=dict(base);del missing['WORKFLOW_SHA'];rejected.append(missing)
        rejected.append({**base,'WORKFLOW_SHA':'not-a-workflow-sha'})
        rejected.append({**base,'COMMAND':'shell'})
        rejected.append({**base,'IMAGE':'ghcr.io/dracla/dracla/bootstrap:latest'})
        for values in rejected:
            with self.subTest(values=values):self.assertNotEqual(run(values).returncode,0)

    def test_hash_bound_locks_close_the_exact_runtime_and_build_inputs(self):
        runtime_raw = (ROOT / 'release/runtime-wheels.lock').read_bytes()
        build_raw = (ROOT / 'release/build-inputs.lock.json').read_bytes()
        self.selected['runtime']['runtime_lock_sha256'] = gate.digest(runtime_raw)
        self.selected['runtime']['build_lock_sha256'] = gate.digest(build_raw)
        self.selected['bootstrap']['trust_root_sha256'] = self.build['trusted_root']['sha256']
        self.assertEqual(gate.locks(runtime_raw, build_raw, self.selected), (self.runtime, self.build))
        for r, b in [(runtime_raw+b' ', build_raw), (runtime_raw, build_raw+b' ')]:
            with self.assertRaises(gate.VerificationError): gate.locks(r, b, self.selected)

    def test_standard_verified_claims_require_both_publisher_and_complete_build(self):
        for role in ('builder', 'publisher'):
            good = claim(self.selected, role, self.runtime, self.build)
            gate.verified_claims(encoded(good), self.selected, self.runtime, self.build, role=role)
            for mutate in [lambda v: v['signature']['certificate'].update(sourceRepositoryIdentifier='999'),
                lambda v: v['signature']['certificate'].update(sourceRepositoryDigest='ab'*20),
                lambda v: v['signature']['certificate'].update(buildSignerDigest='ab'*20),
                lambda v: v['signature']['certificate'].update(runnerEnvironment='self-hosted'),
                lambda v: v['signature']['certificate'].update(issuer='https://attacker.invalid'),
                lambda v: v['signature']['certificate'].update(subjectAlternativeName='https://attacker.invalid/workflow'),
                lambda v: v.update(verifiedTimestamps=[]),
                lambda v: v['verifiedTimestamps'][0].update(type='CurrentTime'),
                lambda v: v['statement']['subject'][0]['digest'].update(sha256='ab'*32),
                lambda v: v['statement']['subject'][0].update(name='dracla-0.0.1-2-py3-none-any.whl'),
                lambda v: v['statement'].update(predicateType=gate.PUBLISH if role=='builder' else gate.SLSA)]:
                bad = copy.deepcopy(good); mutate(bad[0]['verificationResult'])
                with self.subTest(role=role, mutate=mutate), self.assertRaises(gate.VerificationError):
                    gate.verified_claims(encoded(bad), self.selected, self.runtime, self.build, role=role)
        for mutate in [lambda p: p['buildDefinition'].update(buildType='https://attacker.invalid'),
                lambda p: p['buildDefinition']['resolvedDependencies'].pop(),
                lambda p: p['buildDefinition']['resolvedDependencies'].append({'uri':'https://attacker.invalid','digest':{'sha256':'ab'*32}}),
                lambda p: p['runDetails']['builder'].update(id='unreviewed'),
                lambda p: p['buildDefinition']['internalParameters']['github'].update(repository_id='999'),
                lambda p: p['buildDefinition']['internalParameters']['github'].update(event_name='repository_dispatch'),
                lambda p: p['buildDefinition']['externalParameters']['workflow'].update(path='.github/workflows/other.yml')]:
            bad = claim(self.selected, 'builder', self.runtime, self.build)
            mutate(bad[0]['verificationResult']['statement']['predicate'])
            with self.assertRaises(gate.VerificationError):
                gate.verified_claims(encoded(bad), self.selected, self.runtime, self.build, role='builder')

    def test_gh_command_pins_the_crypto_policy_and_uses_no_app_secret(self):
        calls = []
        gate.gh_verify(Path('/private/wheel.whl'), self.selected, Path('/pinned/root.json'), role='builder',
                       bundle=Path('/private/build.json'), execute=lambda argv: calls.append(argv) or b'[]')
        argv = calls[0]
        for flag in ('--custom-trusted-root','--cert-oidc-issuer','--signer-workflow',
                     '--signer-digest','--source-digest','--source-ref','--deny-self-hosted-runners','--bundle'):
            self.assertIn(flag, argv)
        self.assertNotIn('--no-public-good', argv)
        self.assertNotIn('--cert-identity',argv)
        gate.gh_verify(Path('/private/wheel.whl'),self.selected,Path('/pinned/root.json'),role='publisher',
                       execute=lambda argv:calls.append(argv) or b'[]')
        self.assertIn('--cert-identity',calls[1]); self.assertNotIn('--signer-workflow',calls[1])

    def test_missing_or_mixed_inclusion_proofs_are_rejected(self):
        for entries in ([], [{}], [{'inclusionProof': {'checkpoint': {'envelope': 'present'}}}, {}]):
            value=claim(self.selected,'builder',self.runtime,self.build)
            value[0]['attestation']['bundle']['verificationMaterial']['tlogEntries']=entries
            with self.assertRaises(gate.VerificationError):
                gate.verified_claims(encoded(value),self.selected,self.runtime,self.build,role='builder')

    def test_pinned_cli_omitted_null_publish_predicate_is_not_build_evidence(self):
        value=claim(self.selected,'publisher',self.runtime,self.build)
        del value[0]['verificationResult']['statement']['predicate']
        gate.verified_claims(encoded(value),self.selected,self.runtime,self.build,role='publisher')
        with self.assertRaises(gate.VerificationError):
            gate.verified_claims(encoded(value),self.selected,self.runtime,self.build,role='builder')

    def test_swapped_wheels_links_and_unlisted_inputs_fail_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            house = Path(directory); raw = fixture_wheel()
            item = self.selected['runtime']['wheel']; item['sha256'] = gate.digest(raw)
            wheel = house / item['filename']; wheel.write_bytes(raw)
            self.assertEqual(set(gate.wheel_set(house, self.selected, {'wheels': []})), {'dracla'})
            extra = house / 'payload.tar.gz'; extra.write_bytes(b'payload')
            with self.assertRaises(gate.VerificationError): gate.wheel_set(house, self.selected, {'wheels': []})
            extra.unlink(); wheel.write_bytes(raw+b'changed')
            with self.assertRaises(gate.VerificationError): gate.wheel_set(house, self.selected, {'wheels': []})
            wheel.unlink(); wheel.symlink_to('/etc/passwd')
            with self.assertRaises(OSError): gate.wheel_set(house, self.selected, {'wheels': []})

    def test_active_dependency_urls_extras_and_missing_closure_never_reach_pip(self):
        for requirement in ('dracla @ https://attacker.invalid/payload.whl','dracla[unexpected]==0.0.1','unlisted==1.0'):
            with self.subTest(requirement=requirement), tempfile.TemporaryDirectory() as directory:
                house=Path(directory); raw=fixture_wheel(requires=[requirement]); item=self.selected['runtime']['wheel']
                item['sha256']=gate.digest(raw); (house/item['filename']).write_bytes(raw)
                with patch.object(gate,'install') as install, self.assertRaises(gate.VerificationError):
                    gate.wheel_set(house,self.selected,{'wheels':[]})
                install.assert_not_called()

    def test_private_handoff_writes_reject_symlink_and_hardlink_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'target';target.write_bytes(b'preserve')
            destination=Path(directory)/'destination';destination.symlink_to(target)
            with self.assertRaises(OSError): gate.private_write(destination,b'overwrite')
            self.assertEqual(target.read_bytes(),b'preserve');destination.unlink()
            os.link(target,destination)
            with self.assertRaises(gate.VerificationError): gate.private_write(destination,b'overwrite')
            self.assertEqual(target.read_bytes(),b'preserve')

    def test_offline_install_and_wheel_derived_map_detect_environment_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory); house = state / 'wheels'; house.mkdir()
            raw = fixture_wheel(); item = self.selected['runtime']['wheel']; item['sha256'] = gate.digest(raw)
            (house / item['filename']).write_bytes(raw)
            parsed = gate.wheel_set(house, self.selected, {'wheels': []})
            gate.install(state, self.selected, {'wheels': []}, parsed)
            environment = state / 'environment'
            installed = environment / gate.site_path() / 'dracla/cli.py'
            changed = b'raise RuntimeError("tampered")\n'
            installed.write_bytes(changed)
            # Rewriting RECORD as well cannot authorize this new executable.
            record = environment / gate.site_path() / 'dracla-0.0.1.dist-info/RECORD'
            original = record.read_bytes()
            rows = list(csv.reader(io.StringIO(original.decode())))
            for row in rows:
                if row[0] == 'dracla/cli.py':
                    row[1] = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(changed).digest()).rstrip(b'=').decode()
                    row[2] = str(len(changed))
            stream=io.StringIO(); csv.writer(stream).writerows(rows); record.write_text(stream.getvalue())
            with self.assertRaises(gate.VerificationError): gate.check_environment(environment, house, parsed)
            installed.write_bytes(parsed['dracla'][2]['dracla/cli.py'])
            record.write_bytes(original)
            gate.check_environment(environment, house, parsed)
            (environment / gate.site_path() / 'sitecustomize.py').write_text('raise RuntimeError()')
            with self.assertRaises(gate.VerificationError): gate.check_environment(environment, house, parsed)
            (environment / gate.site_path() / 'sitecustomize.py').unlink()
            python=environment/'bin/python';original_python=python.read_bytes();python.write_bytes(b'swapped executable')
            with self.assertRaises(gate.VerificationError): gate.check_environment(environment,house,parsed)
            python.write_bytes(original_python)
            extra=state/'python-copy';extra.write_bytes(original_python);python.unlink();python.symlink_to(extra)
            with self.assertRaises(OSError): gate.check_environment(environment,house,parsed)

    def test_failed_launch_never_executes_package_or_reads_secret_values(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(gate, 'verify', side_effect=gate.VerificationError()) as verify, \
                patch.object(gate.os, 'execve') as execute, patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(gate.VerificationError):
                gate.launch(Path(directory), self.selected, Path('/protected/control.json'), 'verify')
            execute.assert_not_called()
            verify.assert_not_called()
        for value in ('0', 'not-a-number'):
            with patch.object(gate, 'verify') as verify, patch.dict(
                    os.environ, {'DRACLA_CONTROL_REPOSITORY_ID': value}, clear=True):
                with self.assertRaises(gate.VerificationError):
                    gate.launch(Path('/unused'), self.selected, Path('/protected/control.json'), 'verify')
                verify.assert_not_called()

    def test_verified_prepare_downloads_exact_inputs_and_installs_without_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            f=prepared_fixture(directory); destination=Path(directory)/'downloaded';requests=[]
            files={'runtime-wheels.lock':(f.state/'runtime-wheels.lock').read_bytes(),
                   'build-inputs.lock.json':(f.state/'build-inputs.lock.json').read_bytes()}
            artifact=f.selected['runtime']['wheel'];wheel_url='https://files.pythonhosted.org/packages/fixture/'+artifact['filename']
            def download(url,limit=gate.MAX_JSON):
                requests.append(url)
                if url.startswith('https://tmaproduction.blob.core.windows.net/'):
                    return b'{"fixture":true}'
                if '/attestations/' in url:return encoded({'attestations':[{
                    'repository_id':f.selected['source']['repository_id'],'bundle':None,
                    'bundle_url':'https://tmaproduction.blob.core.windows.net/attestations/1336037093/2026/11/01/42.json.sn?sig=fixture'}]})
                if url.startswith('https://api.github.com/repos/'):
                    return encoded({'id':f.selected['source']['repository_id'],'html_url':f.selected['source']['repository_url'],'private':False})
                if url.startswith('https://raw.githubusercontent.com/'):return files[url.rsplit('/',1)[1]]
                if url.startswith('https://pypi.org/pypi/'):
                    return encoded({'urls':[{'filename':artifact['filename'],'packagetype':'bdist_wheel','digests':{'sha256':artifact['sha256'][7:]},'yanked':False,'url':wheel_url}]})
                if url.startswith('https://files.pythonhosted.org/'):
                    return (f.state/'wheels'/url.rsplit('/',1)[1]).read_bytes()
                if url.startswith('https://pypi.org/integrity/'):
                    return encoded({'attestation_bundles':[{'attestations':[{'fixture':True}]}]})
                self.fail('unexpected HTTP request')
            def execute(argv,**kwargs):
                return f.execute(argv,**kwargs)
            real_verify=gate.verify
            def verify(*args,**kwargs):return real_verify(*args,**kwargs,root=f.root)
            decoder=SimpleNamespace(decompress_raw_len=len,decompress_raw=lambda raw:raw)
            with patch.dict(sys.modules,{'pypi_attestations':f.reader,'cramjam':SimpleNamespace(snappy=decoder)}), \
                    patch.object(gate,'verify',verify):
                gate.prepare(destination,f.selected,download=download,execute=execute)
            self.assertTrue(requests[0].startswith('https://api.github.com/repos/'))
            self.assertTrue(f.converted)
            self.assertTrue((destination/'environment'/gate.site_path()/'dracla/__init__.py').is_file())
            self.assertEqual({p.name for p in (destination/'wheels').iterdir()},
                             {artifact['filename'],f.runtime['wheels'][0]['filename']})

    def test_launch_rechecks_real_installed_environment_before_import_and_secret_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            f=prepared_fixture(directory)
            download=lambda url:encoded({'id':f.selected['source']['repository_id'],
                'html_url':f.selected['source']['repository_url'],'private':False})
            def verify(state,selected,execute):
                return real_verify(state,selected,download=download,execute=execute,root=f.root)
            real_verify=gate.verify
            with patch.dict(sys.modules,{'pypi_attestations':f.reader}):
                _,_,parsed=real_verify(f.state,f.selected,download=download,execute=f.execute,root=f.root)
                gate.install(f.state,f.selected,f.runtime,parsed)
                with patch.object(gate,'verify',verify), patch.object(gate.os,'chdir'), \
                        patch.object(gate.os,'execve',side_effect=RuntimeError('stop-before-import')) as execute, \
                        patch.dict(os.environ,{'DRACLA_TRANSPORT_APP_KEY':'fixture-app-key','DRACLA_CONTROL_KEYS':'fixture-keys',
                                              'DRACLA_CONTROL_REPOSITORY_ID':'13',
                                              'DRACLA_CONTROL_WORKFLOW_REF':'acme/control/.github/workflows/reconcile.yml@refs/heads/main',
                                              'DRACLA_CONTROL_WORKFLOW_OID':'ab'*20,
                                              'PYTHONPATH':'/attacker','GH_TOKEN':'fixture-job-token'}):
                    with self.assertRaisesRegex(RuntimeError,'stop-before-import'):
                        gate.launch(f.state,f.selected,Path('/protected/control.json'),'verify',execute=f.execute)
                    binary,argv,environment=execute.call_args.args
                    self.assertEqual(binary,str(f.state/'environment/bin/python'))
                    self.assertEqual(argv[1:3],['-I','-S']);self.assertNotIn('PYTHONPATH',environment);self.assertNotIn('GH_TOKEN',environment)
                    self.assertEqual(environment['DRACLA_TRANSPORT_APP_KEY'],'fixture-app-key')
                    self.assertEqual(environment['DRACLA_CONTROL_REPOSITORY_ID'],'13')
                    self.assertEqual(environment['DRACLA_CONTROL_WORKFLOW_REF'],
                                     'acme/control/.github/workflows/reconcile.yml@refs/heads/main')
                    self.assertEqual(environment['DRACLA_CONTROL_WORKFLOW_OID'],'ab'*20)
                    execute.reset_mock()
                    (f.state/'environment'/gate.site_path()/'dracla/__init__.py').write_bytes(b'changed')
                    with self.assertRaises(gate.VerificationError):
                        gate.launch(f.state,f.selected,Path('/protected/control.json'),'verify',execute=f.execute)
                    execute.assert_not_called()

    def test_source_numeric_identity_is_checked_before_attestation_or_package_access(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory); root = state/'root.json'; root.write_bytes(b'{}')
            self.selected['bootstrap']['trust_root_sha256'] = gate.digest(b'{}')
            for filename, key in [('runtime-wheels.lock','runtime_lock_sha256'),('build-inputs.lock.json','build_lock_sha256')]:
                raw=(ROOT/'release'/filename).read_bytes()
                if filename == 'build-inputs.lock.json':
                    value=json.loads(raw); value['trusted_root']['sha256']=gate.digest(b'{}'); raw=encoded(value)
                (state/filename).write_bytes(raw)
                self.selected['runtime'][key]=gate.digest(raw)
            calls=[]
            def download(url):
                calls.append(url)
                return encoded({'id': 999, 'html_url': self.selected['source']['repository_url'], 'private': False})
            with patch.object(gate, 'wheel_set') as wheels, self.assertRaises(gate.VerificationError):
                gate.verify(state, self.selected, download=download, execute=lambda _: self.fail('verifier invoked'), root=root)
            wheels.assert_not_called(); self.assertEqual(len(calls), 1)


class TransportLifecycleTests(unittest.TestCase):
    def assert_control_recovered(self, data, event, output, revoked):
        from dracla.records import verify_project
        from dracla.records.append import CELL, FENCE, MARKER
        self.assertEqual(output.count('Reconciliation complete'), 1, output)
        self.assertTrue(revoked)
        snapshot = data.engine().snapshot()
        self.assertEqual(sum(record.event.event_id == event.event_id for record in snapshot.records), 1)
        self.assertEqual(data.plain('records', 'operations', data.head('records', 'operations'), CELL)['state'], 'idle')
        self.assertEqual(data.plain('coverage', 'coverage', data.head('coverage', 'coverage'), FENCE)['state'], 'idle')
        self.assertEqual(data.plain('coverage', 'coverage', data.head('coverage', 'coverage'), MARKER), {'ops': {}})
        self.assertTrue(verify_project(data.binding, *data.reader()).valid)

    def test_protected_control_job_recovers_prepared_operation_without_duplicate_event(self):
        data = MutationRepository(); event, artifacts = data.config(); data.engine().prepare(event, artifacts)
        result, output, revoked = protected_control_run(data)
        self.assertEqual(result, 0, output)
        self.assert_control_recovered(data, event, output, revoked)
        writes = len(data.writes)
        result, output, revoked = protected_control_run(data)
        self.assertEqual(result, 0, output)
        self.assert_control_recovered(data, event, output, revoked)
        self.assertEqual(len(data.writes), writes)

    def test_protected_control_job_recovers_prepared_operation_with_existing_fence(self):
        from dracla.conformance.operations import OperationCorruption
        from dracla.records.append import CELL, FENCE, MARKER
        data = MutationRepository(); event, artifacts = data.config(); engine = data.engine()
        reference = engine.prepare(event, artifacts)
        with self.assertRaises(OperationCorruption):
            engine.begin(reference, subjects=[], project_wide=True,
                         started_at='2026-01-01T00:00:00.123456+00:00')
        self.assertEqual(data.plain('records', 'operations', data.head('records', 'operations'), CELL)['state'], 'prepared')
        self.assertEqual(data.plain('coverage', 'coverage', data.head('coverage', 'coverage'), FENCE)['state'], 'mutation')
        self.assertEqual(data.plain('coverage', 'coverage', data.head('coverage', 'coverage'), MARKER), {'ops': {}})
        result, output, revoked = protected_control_run(data)
        self.assertEqual(result, 0, output)
        self.assert_control_recovered(data, event, output, revoked)
        writes = len(data.writes)
        result, output, revoked = protected_control_run(data)
        self.assertEqual(result, 0, output)
        self.assert_control_recovered(data, event, output, revoked)
        self.assertEqual(len(data.writes), writes)

    def test_protected_control_job_recovers_appending_operation_and_repeats_idle(self):
        from dracla.records.append import CELL
        from dracla.records.github import RejectedWrite
        data = MutationRepository(); event, artifacts = data.config(); engine = data.engine()
        reference = engine.prepare(event, artifacts)
        engine.begin(reference, subjects=[], project_wide=True, started_at='2026-01-01T00:00:00Z')
        canonical_head = data.head('records', 'events')
        data.fault = 'other-422'
        with self.assertRaises(RejectedWrite):
            engine.append(reference)
        data.fault = None
        self.assertEqual(data.plain('records', 'operations', data.head('records', 'operations'), CELL)['state'], 'appending')
        self.assertEqual(data.head('records', 'events'), canonical_head)
        result, output, revoked = protected_control_run(data)
        self.assertEqual(result, 0, output)
        self.assert_control_recovered(data, event, output, revoked)
        writes = len(data.writes)
        result, output, revoked = protected_control_run(data)
        self.assertEqual(result, 0, output)
        self.assert_control_recovered(data, event, output, revoked)
        self.assertEqual(len(data.writes), writes)

    def test_revocation_rejects_bad_endpoint_before_io_and_nonempty_success_response(self):
        from dracla.records.credentials import request_json
        calls=[]
        def sender(*args):calls.append(args);return HttpResponse(204,{},b'')
        for path,body in [('/repos/acme/records/git/refs/heads/events',None),('/installation/token',{'unexpected':'body'})]:
            with self.assertRaises(RecordsError):request_json(sender,'DELETE',path,'opaque',body)
        self.assertEqual(calls,[])
        with self.assertRaises(RecordsError) as error:
            request_json(lambda *args:HttpResponse(204,{},b'private provider payload'),'DELETE','/installation/token','opaque')
        self.assertNotIn('private',str(error.exception))
    def test_successor_key_reauthorizes_but_key_retirement_is_not_cached_token_invalidation(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from dracla.administration import RepositoryRef
        from dracla.records import InstallationBinding,InstallationCredentials,ProjectBinding
        for shared in (False,True):
            with self.subTest(shared=shared):
                fixture=AppFixture();old_pem=fixture.pem
                if shared:
                    fixture.protected=InstallationBinding(17,'client-id',19,7,
                        (('project-1',(11,12)),('project-2',(21,22))),(13,23))
                    fixture.repositories += [{'id':n,'private':True,'owner':{'id':7}} for n in (21,22)]
                    successor_binding=ProjectBinding('project-2',7,tuple(RepositoryRef(role,'acme',role+'-2',21+i)
                        for i,role in enumerate(('records','coverage','control'))))
                else:successor_binding=BINDING
                original=fixture.send;revoked=[]
                def send(method,url,headers,timeout,body=None):
                    if method=='DELETE':revoked.append(headers['Authorization']);return HttpResponse(204,{},b'')
                    return original(method,url,headers,timeout,body)
                predecessor=InstallationCredentials(fixture.protected,lambda:old_pem,sender=send,clock=lambda:fixture.now)
                predecessor.authorize(BINDING);token=predecessor.token()
                fixture.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
                fixture.pem=fixture.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
                successor=InstallationCredentials(fixture.protected,lambda:fixture.pem,sender=send,clock=lambda:fixture.now)
                successor.authorize(successor_binding)
                self.assertEqual(fixture.mints[-1]['repository_ids'],list(successor_binding.data_ids))
                self.assertEqual(predecessor.token(),token)  # No false client-side all-token containment claim.
                fixture.now+=3540
                with self.assertRaises(RecordsError):predecessor.token()
                self.assertEqual(len(fixture.mints),4)
                self.assertEqual(successor.token(),'opaque-token-6')
                predecessor.close();successor.close();self.assertEqual(len(revoked),6)

    def test_temporary_branch_challenges_read_back_and_cleanup_without_changing_canonical_refs(self):
        generation=profile()['source']['commit_oid']+'-'+'b'*32
        for fault in (None,'lost-create','lost-delete','lost-cas','bad-ack','null-ack'):
            with self.subTest(fault=fault):
                peer=ProbePeer();transport=peer.transport()
                if fault=='lost-cas':peer.data.fault=fault
                else:peer.fault=fault
                before={key:copy.deepcopy(value) for key,value in peer.data.values.items() if '/git/ref/' in key}
                receipt=transport.challenge(generation)
                self.assertEqual(receipt['temporary_branch_cleanup'],'confirmed')
                self.assertEqual([r['repository_id'] for r in receipt['repositories']],[11,12])
                self.assertEqual({key:value for key,value in peer.data.values.items() if '/git/ref/' in key},before)
                self.assertEqual(len(peer.updates),4)  # No blind replay after a lost acknowledgement.
                for mutation in peer.updates:
                    update=mutation['refUpdates'][0]
                    self.assertEqual(update['name'],'refs/heads/dracla-probe/'+generation)
                    self.assertIs(update['force'],False)
                self.assertEqual(len(peer.data.writes),2)
                for method,path,body in peer.data.writes:
                    files=body['variables']['input']['fileChanges']['additions']
                    self.assertEqual(files,[{'path':'dracla-transport-probe.txt',
                        'contents':base64.b64encode(b'DraCLA transport capability challenge v1\n').decode()}])
                transport.credentials.close();self.assertTrue(peer.revocations)

    def test_probe_cleanup_cas_preserves_a_concurrent_writer(self):
        peer=ProbePeer();transport=peer.transport();peer.fault='cleanup-race'
        generation=profile()['source']['commit_oid']+'-'+'c'*32
        original=peer.data.head('records','events')
        with self.assertRaises(RecordsError):transport.challenge(generation)
        head=peer.data.head('records','dracla-probe/'+generation)
        self.assertEqual(peer.data.files['records',head]['other-probe.txt'],b'other writer')
        self.assertEqual(peer.data.head('records','events'),original)
        self.assertTrue(all(not u['refUpdates'][0]['force'] for u in peer.updates))

    def test_probe_rejects_ref_movement_after_creation_commit_and_cleanup(self):
        for fault in ('create-race','lost-cas-followed-by-newer','recreate-after-delete'):
            with self.subTest(fault=fault):
                peer=ProbePeer();transport=peer.transport();generation=profile()['source']['commit_oid']+'-'+'e'*32
                if fault=='lost-cas-followed-by-newer':peer.data.fault=fault
                else:peer.fault=fault
                before=peer.data.head('records','events')
                with self.assertRaises(RecordsError):transport.challenge(generation)
                self.assertEqual(peer.data.head('records','events'),before)
                # Another writer's head remains; no unguarded deletion follows.
                self.assertIn('/repos/acme/records/git/ref/heads/dracla-probe/'+generation,peer.data.values)

    def test_probe_rejects_malformed_generation_existing_ref_and_wrong_repository_identity(self):
        peer=ProbePeer();transport=peer.transport()
        for generation in ('events','../../events','a'*40,True):
            with self.assertRaises(RecordsError):transport.challenge(generation)
        self.assertEqual(peer.updates,[]);self.assertEqual(peer.queries,[])
        generation=profile()['source']['commit_oid']+'-'+'d'*32
        for mutate in (lambda v:{**v,'fullDatabaseId':'999'},lambda v:{**v,'fullDatabaseId':11},lambda v:{**v,'isPrivate':False},
                       lambda v:None,lambda v:{**v,'ref':{'target':{'__typename':'Blob','oid':'a'*40}}}):
            peer.query_patch=mutate
            with self.assertRaises(RecordsError):transport.challenge(generation)
            self.assertEqual(peer.updates,[])
        peer.query_patch=None
        peer.data.values['/repos/acme/records/git/ref/heads/dracla-probe/'+generation]={
            'ref':'refs/heads/dracla-probe/'+generation,'object':{'type':'commit','sha':peer.data.e}}
        with self.assertRaises(RecordsError):transport.challenge(generation)
        self.assertEqual(peer.updates,[])

    def test_protected_probe_binds_receipt_to_release_workflow_and_replay_after_cleanup(self):
        from dracla.conformance import Keyring,encode_keyring,wrap_key_copy
        for fault in (None,'cleanup-race','key','revocation','workflow','source-meta','replay-divergence',
                      'identity','identity-missing','identity-malformed','identity-out-of-range'):
            with self.subTest(fault=fault):
                peer=ProbePeer();data=peer.data
                if fault=='replay-divergence':
                    files={**data.files['coverage',data.c],'users/00.enc.json':b'corrupt'}
                    corrupt=data.commit('coverage',files,data.c);data.set_head('coverage','coverage',corrupt)
                if fault=='cleanup-race':peer.fault=fault
                peer.revocation_failure=fault=='revocation'
                ring=encode_keyring(Keyring(tuple(wrap_key_copy(data.data_keys[cap],project_id='project-1',capability=cap,
                    data_kid=data.kid_bytes[cap],wrapper_id='control',wrapper_generation='install-1',
                    wrapping_key=data.wrapping) for cap in ('records','coverage'))))
                config={'control_version':1,'project':{'project_id':'project-1','owner_id':10,
                    'repositories':[{'role':r.role,'owner':r.owner,'name':r.name,'id':r.id} for r in data.binding.repositories]},
                    'installation':{'app_id':17,'client_id':'client-id','installation_id':19,'owner_id':10,
                        'assignments':[{'project_id':'project-1','repository_ids':[11,12]}],'excluded_repository_ids':[13]},
                    'keyrings':{oid:base64.b64encode(ring).decode() for oid in (data.k,data.b)},'export_request':None}
                wrapping_reads=[]
                class Secrets(dict):
                    def __getitem__(self,key):
                        if key=='DRACLA_CONTROL_KEYS':
                            wrapping_reads.append(key)
                            assert len(peer.updates)==4
                            assert not any('/git/ref/heads/dracla-probe/' in k for k in data.values)
                        return super().__getitem__(key)
                values=Secrets(DRACLA_TRANSPORT_APP_KEY=peer.app.pem.decode(),
                    DRACLA_CONTROL_KEYS=json.dumps({'install-1':(b'x'*32 if fault=='key' else data.wrapping).hex()}),
                    DRACLA_CONTROL_WORKFLOW_REF=('acme/control/.github/workflows/other.yml@refs/heads/main' if fault=='workflow'
                        else 'AcMe/ConTrol/.github/workflows/reconcile.yml@refs/heads/main'),
                    DRACLA_CONTROL_WORKFLOW_OID='invalid' if fault=='source-meta' else 'ab'*20)
                if fault not in ('identity-missing',):
                    values['DRACLA_CONTROL_REPOSITORY_ID'] = ('999' if fault == 'identity'
                        else 'not-a-number' if fault == 'identity-malformed'
                        else '1' + '0' * 5000 if fault == 'identity-out-of-range' else '13')
                release=SimpleNamespace(package_version='0.0.1',source_commit_oid=profile()['source']['commit_oid'],
                    policy_sha256=gate.digest(b'policy'),provenance_identity=profile()['builder']['workflow']+'@'+profile()['source']['commit_oid'],
                    dependency_constraints_sha256=gate.digest(b'constraints'))
                with tempfile.TemporaryDirectory() as directory:
                    path=Path(directory)/'control.json';path.write_bytes(encoded(config));output=io.StringIO()
                    with patch('dracla.records.credentials.InstallationCredentials',peer.credentials), \
                            patch('dracla.cli.release.load_release_policy',return_value=release), \
                            patch.object(os,'environ',values),patch.object(sys,'stdout',output):
                        self.assertEqual(control_job(str(path),'probe'),1 if fault else 0)
                if fault:
                    self.assertNotIn('opaque-token',output.getvalue())
                    self.assertNotIn(data.wrapping.hex(),output.getvalue())
                else:
                    receipt=json.loads(output.getvalue());self.assertEqual(receipt['repository_ids'],data.binding.ids())
                    self.assertEqual(receipt['workflow']['commit_oid'],'ab'*20)
                    self.assertEqual(receipt['release']['source_commit_oid'],release.source_commit_oid)
                    self.assertEqual(receipt['installation_id'],19);self.assertTrue(wrapping_reads);self.assertTrue(peer.revocations)
                    self.assertNotIn('opaque-token',output.getvalue());self.assertNotIn(data.wrapping.hex(),output.getvalue())
                if fault=='cleanup-race':self.assertEqual(wrapping_reads,[])
                if fault in ('workflow','source-meta','identity','identity-missing','identity-malformed','identity-out-of-range'):
                    self.assertEqual(peer.app.calls,[]);self.assertEqual(wrapping_reads,[])
                if fault in ('identity','identity-missing','identity-malformed','identity-out-of-range'):
                    self.assertIn('Probe unavailable: identity-mismatch', output.getvalue())
                if fault == 'replay-divergence':
                    self.assertIn(data.e, output.getvalue())
                    self.assertIn('projection-or-operation-unavailable', output.getvalue())

    def test_malformed_protected_configuration_and_missing_m5_authority_precede_secrets(self):
        config={'control_version':1,'project':{'project_id':'project-1','owner_id':7,
            'repositories':[{'role':r.role,'owner':r.owner,'name':r.name,'id':r.id} for r in BINDING.repositories]},
            'installation':{'app_id':17,'client_id':'client-id','installation_id':19,'owner_id':7,
                'assignments':[{'project_id':'project-1','repository_ids':[11,12]}],'excluded_repository_ids':[13]},
            'keyrings':{'ab'*20:base64.b64encode(b'{}').decode()},'export_request':None}
        mutations=[lambda c:c.update(control_version=True),lambda c:c['project'].update(module='attacker'),
            lambda c:c['project'].update(repositories=[]),lambda c:c['project']['repositories'][0].update(extra='value'),
            lambda c:c['installation'].update(extra='value'),lambda c:c['installation']['assignments'][0].update(extra='value'),
            lambda c:c.update(keyrings={}),lambda c:c.update(keyrings={'invalid':'not-base64'}),
            lambda c:c.update(export_request={'unexpected':'value'})]
        reads=[]
        class Secrets(dict):
            def __getitem__(self,key):reads.append(key);raise KeyError(key)
        with tempfile.TemporaryDirectory() as directory,patch.object(os,'environ',Secrets(DRACLA_CONTROL_REPOSITORY_ID='13')):
            path=Path(directory)/'protected.json'
            for mutate in mutations:
                value=copy.deepcopy(config);mutate(value);path.write_bytes(encoded(value))
                self.assertEqual(control_job(str(path),'verify'),1)
            path.write_bytes(b'x'*(1024*1024+1));self.assertEqual(control_job(str(path),'verify'),1)
            self.assertEqual(reads,[])
            config['export_request']={'export_version':1,'project_id':'project-1','request_id':'A'*22,
                                      'source_events_oid':'ab'*20,'view':'current'}
            path.write_bytes(encoded(config))
            from dracla.records.exports import export_hosted
            with patch('dracla.records.exports.export_hosted',wraps=export_hosted) as hosted:
                self.assertEqual(control_job(str(path),'export'),1);hosted.assert_called_once()
            with patch('dracla.records.exports.export_hosted',return_value=None):
                self.assertEqual(control_job(str(path),'export'),1)
            self.assertEqual(reads,[])

    def test_token_from_a_rejected_mint_response_is_still_revoked(self):
        fixture=AppFixture(); fixture.patch['/app/installations/19/access_tokens']=lambda v:{**v,'expires_at':'invalid'}
        provider=fixture.provider()
        with self.assertRaises(RecordsError): provider.authorize(BINDING)
        fixture.patch.clear();provider.authorize(BINDING)
        revoked=[]
        provider.sender=lambda method,url,headers,timeout,body=None: revoked.append(headers['Authorization']) or HttpResponse(204,{},b'')
        provider.close(); self.assertEqual(revoked,['Bearer opaque-token-1','Bearer opaque-token-2','Bearer opaque-token-3'])

    def test_bad_mint_clock_and_issuance_bound_block_before_another_token_is_minted(self):
        fixture=AppFixture();provider=fixture.provider();clock=iter([fixture.now]*3+[float('nan')])
        provider._clock=lambda:next(clock)
        with self.assertRaises(RecordsError):provider.authorize(BINDING)
        self.assertEqual(len(fixture.mints),1)
        fixture=AppFixture();provider=fixture.provider();provider._issued={str(i):None for i in range(1000)}
        with self.assertRaises(RecordsError) as error:provider.authorize(BINDING)
        self.assertEqual(error.exception.category,'resource-limit');self.assertEqual(fixture.mints,[])

    def test_protected_job_invokes_real_engines_and_checks_app_before_wrapping_keys(self):
        from dracla.conformance import Keyring, encode_keyring, wrap_key_copy
        from dracla.records.credentials import InstallationCredentials
        from core.tests.test_records_2 import MutationRepository
        for operation, fault in [('verify',None),('reconcile',None),('verify','scope'),
                                 ('verify','key'),('verify','key-format'),('reconcile','key'),('verify','cleanup'),
                                 ('verify','cleanup-exception'),
                                 ('verify','identity'),('reconcile','identity'),
                                 ('verify','identity-missing'),('verify','identity-malformed'),
                                 ('verify','identity-out-of-range'),('reconcile','identity-missing'),
                                 ('reconcile','identity-malformed'),('reconcile','identity-out-of-range'),
                                 ('verify','corrupt'),('reconcile','corrupt')]:
            wrong_scope=fault=='scope'
            with self.subTest(operation=operation,fault=fault):
                data=MutationRepository(); app=AppFixture(); revoked=[]; reads=[]
                if fault == 'corrupt':
                    values = dict(data.files['records', data.d])
                    values['derived/index/00.enc.json'] = b'{}'
                    corrupt_derived = data.commit('records', values, data.d)
                    data.set_head('records', 'derived', corrupt_derived)
                app.patch['/app']=lambda v:{**v,'owner':{'id':10}}
                app.patch['/app/installations/19']=lambda v:{**v,'account':{'id':10},'target_id':10}
                for repo in app.repositories: repo['owner']['id']=10
                if wrong_scope: app.permissions={'contents':'write','metadata':'read','members':'read'}
                def sender(method,url,headers,timeout,body=None):
                    if method=='DELETE':
                        revoked.append(headers['Authorization'])
                        return HttpResponse(500,{},b'private provider text') if fault=='cleanup' else HttpResponse(204,{},b'')
                    return (data.send if '/repos/' in url or url.endswith('/graphql') else app.send)(method,url,headers,timeout,body)
                def credentials(protected,key,**kwargs):
                    result = InstallationCredentials(protected,key,sender=sender,clock=lambda:app.now,**kwargs)
                    if fault == 'cleanup-exception':
                        result.close = lambda: (_ for _ in ()).throw(RuntimeError('private cleanup sentinel'))
                    return result
                ring=encode_keyring(Keyring(tuple(wrap_key_copy(data.data_keys[cap],project_id='project-1',capability=cap,
                    data_kid=data.kid_bytes[cap],wrapper_id='control',wrapper_generation='install-1',
                    wrapping_key=data.wrapping) for cap in ('records','coverage'))))
                config={'control_version':1,'project':{'project_id':'project-1','owner_id':10,
                    'repositories':[{'role':r.role,'owner':r.owner,'name':r.name,'id':r.id} for r in data.binding.repositories]},
                    'installation':{'app_id':17,'client_id':'client-id','installation_id':19,'owner_id':10,
                        'assignments':[{'project_id':'project-1','repository_ids':[11,12]}],'excluded_repository_ids':[13]},
                    'keyrings':{oid:base64.b64encode(ring).decode() for oid in (data.k,data.b)},'export_request':None}
                class Secrets(dict):
                    def __getitem__(self,key):
                        reads.append(key); return super().__getitem__(key)
                secret_values = dict(DRACLA_TRANSPORT_APP_KEY=app.pem.decode(),
                                     DRACLA_CONTROL_KEYS=json.dumps({'install-1':
                                         'invalid' if fault=='key-format' else (b'\xff'*32 if fault=='key' else data.wrapping).hex()}))
                if fault != 'identity-missing':
                    secret_values['DRACLA_CONTROL_REPOSITORY_ID'] = (
                        '999' if fault == 'identity' else 'not-a-number' if fault == 'identity-malformed'
                        else '1' + '0' * 5000 if fault == 'identity-out-of-range' else '13')
                secrets=Secrets(**secret_values)
                with tempfile.TemporaryDirectory() as directory:
                    path=Path(directory)/'protected.json';path.write_bytes(encoded(config))
                    with patch('dracla.records.credentials.InstallationCredentials',credentials), \
                            patch('dracla.cli.release.load_release_policy',return_value=SimpleNamespace(package_version='0.0.1')), \
                            patch.object(os,'environ',secrets), patch.object(sys,'stdout',io.StringIO()) as output:
                        self.assertEqual(control_job(str(path),operation),1 if fault else 0)
                self.assertEqual(data.writes,[])
                if wrong_scope:
                    self.assertNotIn('DRACLA_CONTROL_KEYS',reads)
                elif fault is not None and fault.startswith('identity'):
                    self.assertNotIn('DRACLA_CONTROL_KEYS',reads)
                    self.assertIn('identity-mismatch', output.getvalue())
                elif fault == 'cleanup-exception':
                    self.assertIn('DRACLA_CONTROL_KEYS',reads); self.assertFalse(revoked)
                    self.assertIn('Control cleanup unavailable: records-unavailable', output.getvalue())
                    self.assertNotIn('private cleanup sentinel', output.getvalue())
                else:
                    self.assertIn('DRACLA_CONTROL_KEYS',reads); self.assertTrue(revoked)
                if fault == 'corrupt':
                    self.assertIn(data.e, output.getvalue())
                    if operation == 'verify':
                        self.assertIn(data.c, output.getvalue())
                        self.assertIn(corrupt_derived, output.getvalue())
                        self.assertIn(data.o, output.getvalue())
                        self.assertIn('projection-or-operation-unavailable', output.getvalue())
                    else:
                        self.assertIn('route-unavailable-proof-required', output.getvalue())

    def test_cleanup_revokes_inventory_and_all_known_data_tokens_and_blocks_reuse(self):
        fixture = AppFixture(); original = fixture.send; revoked = []
        def send(method, url, headers, timeout, body=None):
            if method == 'DELETE':
                self.assertEqual(url, 'https://api.github.com/installation/token')
                self.assertIsNone(body)
                revoked.append(headers['Authorization'].removeprefix('Bearer '))
                return HttpResponse(204, {}, b'')
            return original(method, url, headers, timeout, body)
        provider = fixture.provider(); provider.sender = send
        provider.authorize(BINDING); fixture.now += 3540; provider.token(); provider.close()
        self.assertEqual(set(revoked), {'opaque-token-1','opaque-token-2','opaque-token-3','opaque-token-4'})
        with self.assertRaises(RecordsError): provider.token()
        provider.close(); self.assertEqual(len(revoked), 4)

    def test_cleanup_failure_is_retriable_and_never_keeps_cached_authority(self):
        fixture = AppFixture(); provider=fixture.provider(); provider.authorize(BINDING)
        revoked=[]
        provider.sender=lambda method,url,headers,timeout,body=None: revoked.append(headers['Authorization']) or HttpResponse(500,{},b'private provider payload')
        with self.assertRaises(RecordsError) as error: provider.close()
        self.assertEqual(str(error.exception),'records-unavailable'); self.assertEqual(len(revoked),2)
        with self.assertRaises(RecordsError): provider.token()
        provider.sender=lambda *args: HttpResponse(204,{},b'')
        provider.close()

    def test_cleanup_requires_wall_margin_and_elapsed_barrier(self):
        for wall_delta, elapsed, pruned in ((3600, 3600, False), (3660, 3659, False),
                                            (3660, 3660, True), (3661, 3661, True)):
            with self.subTest(wall_delta=wall_delta, elapsed=elapsed):
                fixture = AppFixture(); initial = fixture.now; elapsed_now = [0.0]
                provider = clocked_provider(fixture, lambda: fixture.now, lambda: elapsed_now[0])
                provider.authorize(BINDING); fixture.now = initial + wall_delta; elapsed_now[0] = elapsed
                revoked = []
                def revoke(method, url, headers, timeout, body=None):
                    self.assertEqual(method, 'DELETE')
                    revoked.append(headers['Authorization'])
                    return HttpResponse(204, {}, b'')
                provider.sender = revoke
                provider.close()
                self.assertEqual(len(revoked), 0 if pruned else 2)

    def test_cleanup_keeps_known_token_at_runner_expiry_with_forward_skew(self):
        fixture = AppFixture(); initial = fixture.now
        provider_now, runner_now, elapsed_now = [initial], [initial + 30], [0.0]
        revoked = []
        def sender(method, url, headers, timeout, body=None):
            if method == 'DELETE':
                revoked.append(headers['Authorization'])
                return HttpResponse(204, {}, b'')
            fixture.now = provider_now[0]
            return fixture.send(method, url, headers, timeout, body)
        provider = clocked_provider(fixture, lambda: runner_now[0], lambda: elapsed_now[0], sender=sender)
        first, _ = provider._mint('synthetic-jwt', (11, 12), {'contents': 'read', 'metadata': 'read'})
        provider_now[0] = initial + 3570; runner_now[0] = initial + 3600; elapsed_now[0] = 3600
        second, _ = provider._mint('synthetic-jwt', (11, 12), {'contents': 'read', 'metadata': 'read'})
        self.assertIn(first, provider._issued)
        provider.close()
        self.assertEqual({value.removeprefix('Bearer ') for value in revoked}, {first, second})

    def test_pruning_survives_a_finite_forward_wall_clock_jump(self):
        fixture = AppFixture(); initial = fixture.now
        provider_now, runner_now, elapsed_now = [initial], [initial], [0.0]
        revoked = []
        def sender(method, url, headers, timeout, body=None):
            if method == 'DELETE':
                revoked.append(headers['Authorization'])
                return HttpResponse(204, {}, b'')
            fixture.now = provider_now[0]
            response = fixture.send(method, url, headers, timeout, body)
            if method == 'POST' and len(fixture.mints) == 2:
                value = json.loads(response.body)
                value['expires_at'] = datetime.fromtimestamp(runner_now[0] + 3600, timezone.utc).isoformat()
                return HttpResponse(response.status, response.headers, json.dumps(value).encode())
            return response
        provider = clocked_provider(fixture, lambda: runner_now[0], lambda: elapsed_now[0], sender=sender)
        first, _ = provider._mint('synthetic-jwt', (11, 12), {'contents': 'read', 'metadata': 'read'})
        runner_now[0] = initial + 10000; provider_now[0] = initial + 1; elapsed_now[0] = 1
        second, _ = provider._mint('synthetic-jwt', (11, 12), {'contents': 'read', 'metadata': 'read'})
        self.assertIn(first, provider._issued)
        provider.close()
        self.assertEqual({value.removeprefix('Bearer ') for value in revoked}, {first, second})

    def test_cleanup_after_renewal_ignores_expired_predecessor_tokens(self):
        fixture = AppFixture(); elapsed_now = [0.0]
        provider = clocked_provider(fixture, lambda: fixture.now, lambda: elapsed_now[0]); provider.authorize(BINDING)
        fixture.now += 3540; elapsed_now[0] = 3540; self.assertEqual(provider.token(), 'opaque-token-4')
        fixture.now += 120; elapsed_now[0] = 3660; revoked = []
        def revoke(method, url, headers, timeout, body=None):
            token = headers['Authorization'].removeprefix('Bearer ')
            revoked.append(token)
            return HttpResponse(401 if token in ('opaque-token-1', 'opaque-token-2') else 204, {}, b'')
        provider.sender = revoke
        provider.close()
        self.assertEqual(set(revoked), {'opaque-token-3', 'opaque-token-4'})
        provider.close(); self.assertEqual(len(revoked), 2)

    def test_cleanup_attempts_unknown_expiry_even_after_a_long_delay(self):
        fixture = AppFixture()
        fixture.patch['/app/installations/19/access_tokens'] = lambda value: {**value, 'expires_at': 'unknown'}
        provider = fixture.provider()
        with self.assertRaises(RecordsError): provider.authorize(BINDING)
        fixture.now += 10000; revoked = []
        provider.sender = lambda method, url, headers, timeout, body=None: revoked.append(headers['Authorization']) or HttpResponse(204, {}, b'')
        provider.close()
        self.assertEqual(revoked, ['Bearer opaque-token-1'])

    def test_cleanup_attempts_known_tokens_when_elapsed_proof_is_unusable(self):
        for label, elapsed in (('nonfinite', [float('nan')]), ('backward', [0.0, -1.0]),
                               ('unavailable', RuntimeError('elapsed unavailable'))):
            with self.subTest(label=label):
                fixture = AppFixture(); initial = fixture.now; revoked = []
                if isinstance(elapsed, list):
                    elapsed_clock = lambda: elapsed.pop(0)
                else:
                    elapsed_clock = lambda: (_ for _ in ()).throw(elapsed)
                def sender(method, url, headers, timeout, body=None):
                    if method == 'DELETE':
                        revoked.append(headers['Authorization'])
                        return HttpResponse(204, {}, b'')
                    return fixture.send(method, url, headers, timeout, body)
                provider = clocked_provider(fixture, lambda: fixture.now,
                                            elapsed_clock, sender=sender)
                token, _ = provider._mint('synthetic-jwt', (11, 12),
                                          {'contents': 'read', 'metadata': 'read'})
                fixture.now = initial + 10000
                provider.close()
                self.assertEqual(revoked, ['Bearer ' + token])

    def test_cleanup_attempts_every_token_when_clock_is_unusable(self):
        for now in (float('nan'), None):
            with self.subTest(now=now):
                fixture = AppFixture(); provider = fixture.provider(); provider.authorize(BINDING)
                fixture.now = now; revoked = []
                provider.sender = lambda method, url, headers, timeout, body=None: revoked.append(headers['Authorization']) or HttpResponse(204, {}, b'')
                provider.close()
                self.assertEqual(set(revoked), {'Bearer opaque-token-1', 'Bearer opaque-token-2'})
                with self.assertRaises(RecordsError): provider.token()

    def test_control_job_rejects_executable_dispatch_before_private_key_access(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'control.json'; config.write_text('{}')
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(control_job(str(config), 'verify; execute'),1)
                self.assertEqual(control_job(str(config), 'verify'),1)
            config.unlink(); config.symlink_to('/etc/passwd')
            self.assertEqual(control_job(str(config), 'verify'),1)


if __name__ == '__main__':
    unittest.main()
