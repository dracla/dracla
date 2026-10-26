"""m3/1.1 concrete read transport and credential-boundary regressions."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import unittest
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dracla.administration import RepositoryRef
from dracla.github_admin import HttpResponse
from dracla.records import (InstallationBinding, InstallationCredentials, OperatorCredentials,
                            ProjectBinding, RecordsError, RepositoryTransport, WrappedKeys, open_history)
from dracla.records.credentials import request_json, unique_json

BINDING = ProjectBinding('project-1', 7, tuple(RepositoryRef(role, 'acme', role, 11+i)
                                            for i, role in enumerate(('records', 'coverage', 'control'))))


def response(value, status=200, headers=None):
    return HttpResponse(status, headers or {}, json.dumps(value).encode())


def replace_blob(fixture, repo, commit, path, raw):
    """Replace one fixture blob while preserving its immutable tree identity."""
    prefix = f'/repos/acme/{repo}/git/'
    tree_oid = fixture.values[prefix + 'commits/' + commit]['tree']['sha']
    tree = fixture.values[prefix + 'trees/' + tree_oid + '?recursive=1']
    entry = next(item for item in tree['tree'] if item['path'] == path)
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    entry.update(sha=blob, size=len(raw))
    fixture.values[prefix + 'blobs/' + blob] = {
        'sha': blob, 'size': len(raw), 'encoding': 'base64',
        'content': base64.b64encode(raw).decode(),
    }
    fixture.files[repo, commit][path] = raw


class AppFixture:
    def __init__(self):
        self.now = 1700000000
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        self.calls, self.mints = [], []
        self.patch, self.status, self.links = {}, {}, {}
        self.permissions = {'contents': 'write', 'metadata': 'read'}
        self.repositories = [{'id': n, 'private': True, 'owner': {'id': 7}} for n in (11, 12)]
        self.protected = InstallationBinding(17, 'client-id', 19, 7,
                                             (('project-1', (11, 12)),), (13,))

    def provider(self):
        return InstallationCredentials(self.protected, lambda: self.pem,
                                       sender=self.send, clock=lambda: self.now)

    def send(self, method, url, headers, timeout, body=None):
        path = url.removeprefix('https://api.github.com')
        assert url.startswith('https://api.github.com/')
        assert headers['X-GitHub-Api-Version'] == '2022-11-28'
        assert method == 'GET' or path == '/app/installations/19/access_tokens'
        self.calls.append((method, path))
        token = headers['Authorization'].removeprefix('Bearer ')
        if path == '/app':
            header, payload, signature = token.split('.')
            decode = lambda v: base64.urlsafe_b64decode(v+'='*(-len(v)%4))
            self.key.public_key().verify(decode(signature), (header+'.'+payload).encode(),
                                         padding.PKCS1v15(), hashes.SHA256())
            claims = json.loads(decode(payload))
            assert claims == {'iat': self.now-60, 'exp': self.now+540, 'iss': 'client-id'}
            value = {'id': 17, 'client_id': 'client-id', 'owner': {'id': 7},
                     'permissions': self.permissions, 'events': []}
        elif path.startswith('/app/installations?'):
            value = [{'id': 19}]
        elif path == '/app/installations/19':
            value = {'id': 19, 'app_id': 17, 'account': {'id': 7}, 'target_id': 7,
                     'repository_selection': 'selected', 'suspended_at': None,
                     'permissions': self.permissions, 'events': []}
        elif path == '/app/installations/19/access_tokens':
            request = json.loads(body)
            self.mints.append(request)
            expiry = datetime.fromtimestamp(self.now+3600, timezone.utc).isoformat()
            value = {'token': 'opaque-token-'+str(len(self.mints)), 'expires_at': expiry,
                     'permissions': request['permissions'], 'repository_selection': 'selected'}
        elif path.startswith('/installation/repositories?'):
            page = int(path.rsplit('=', 1)[1])
            value = {'total_count': len(self.repositories),
                     'repositories': self.repositories[(page-1)*100:page*100]}
        else:
            raise AssertionError('unexpected request')
        if path in self.patch:
            value = self.patch[path](copy.deepcopy(value))
        return response(value, self.status.get(path, 201 if method == 'POST' else 200),
                        self.links.get(path))


class TestRecordsCredentials(unittest.TestCase):
    def test_app_checks_grants_then_mints_exact_arrangement_token(self):
        fixture = AppFixture()
        provider = fixture.provider()
        provider.authorize(BINDING)
        self.assertEqual(provider.token(), 'opaque-token-2')
        self.assertEqual(fixture.mints, [
            {'permissions': {'contents': 'read', 'metadata': 'read'}},
            {'permissions': {'contents': 'read', 'metadata': 'read'}, 'repository_ids': [11, 12]}])
        self.assertNotIn('opaque-token', repr(provider))
        self.assertFalse(any('/control' in path for _, path in fixture.calls))

    def test_expiry_rechecks_entire_identity_scope_and_inventory(self):
        fixture = AppFixture()
        provider = fixture.provider()
        provider.authorize(BINDING)
        fixture.now += 3541
        self.assertEqual(provider.token(), 'opaque-token-4')
        self.assertEqual(sum(path == '/app' for _, path in fixture.calls), 2)
        self.assertEqual(len(fixture.mints), 4)

    def test_scope_failures_cannot_reach_key_provider(self):
        cases = [('/app', lambda v: {**v, 'id': True}),
                 ('/app', lambda v: {**v, 'client_id': 'another'}),
                 ('/app', lambda v: {**v, 'owner': {'id': 8}}),
                 ('/app', lambda v: {**v, 'events': ['push']}),
                 ('/app/installations?per_page=100&page=1', lambda v: v+[{'id': 20}]),
                 ('/app/installations/19', lambda v: {**v, 'repository_selection': 'all'}),
                 ('/app/installations/19', lambda v: {**v, 'suspended_at': 'yesterday'}),
                 ('/app/installations/19', lambda v: {**v, 'permissions': {**v['permissions'], 'members': 'read'}})]
        for path, change in cases:
            with self.subTest(path=path):
                fixture = AppFixture()
                fixture.patch[path] = change
                calls = []
                keys = WrappedKeys('control', lambda: calls.append('keys'),
                                   protected_keyrings=lambda _: calls.append('keyring'))
                with self.assertRaises(RecordsError):
                    open_history(BINDING, keys, RepositoryTransport(fixture.provider()))
                self.assertEqual(calls, [])

    def test_exact_complete_private_inventory(self):
        for change in ('extra', 'missing', 'public', 'duplicate', 'wrong-owner'):
            with self.subTest(change=change):
                fixture = AppFixture()
                if change == 'extra': fixture.repositories.append({'id': 13, 'private': True, 'owner': {'id': 7}})
                if change == 'missing': fixture.repositories.pop()
                if change == 'public': fixture.repositories[0]['private'] = False
                if change == 'duplicate': fixture.repositories[1]['id'] = 11
                if change == 'wrong-owner': fixture.repositories[0]['owner']['id'] = True
                with self.assertRaises(RecordsError): fixture.provider().authorize(BINDING)
                self.assertEqual(len(fixture.mints), 1)

    def test_hidden_installation_page_rejected(self):
        fixture = AppFixture()
        fixture.links['/app/installations?per_page=100&page=1'] = {'Link': '<https://api.github.com/app/installations?page=2>; rel="next"'}
        with self.assertRaises(RecordsError): fixture.provider().authorize(BINDING)
        self.assertEqual(fixture.mints, [])

    def test_failed_explicit_reauthorization_revokes_old_cached_token(self):
        fixture = AppFixture()
        provider = fixture.provider()
        provider.authorize(BINDING)
        fixture.pem = b'PRIVATE MATERIAL THAT MUST NEVER APPEAR IN AN ERROR'
        with self.assertRaises(RecordsError) as caught: provider.authorize(BINDING)
        self.assertEqual(str(caught.exception), 'records-unavailable')
        with self.assertRaises(RecordsError): provider.token()

    def test_operator_stable_numeric_identity_and_redaction(self):
        user = {'id': 21, 'login': 'operator'}
        provider = OperatorCredentials(lambda: 'unconventional:opaque', sender=lambda *a: response(user))
        provider.authorize(BINDING)
        user['id'] = 22
        with self.assertRaises(RecordsError): provider.authorize(BINDING)
        with self.assertRaises(RecordsError): provider.token()
        def failure(): raise RuntimeError('PRIVATE')
        provider = OperatorCredentials(failure)
        with self.assertRaises(RecordsError) as caught: provider.authorize(BINDING)
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_response_parser_rejects_duplicates_nonfinite_redirect_and_oversize(self):
        for raw in (b'{"id":1,"id":2}', b'{"x":NaN}', b'\xff'):
            with self.assertRaises(RecordsError): unique_json(raw)
        for status, raw in ((302,b'{}'), (403,b'{"private":"SECRET"}'), (200,b' '*1048577)):
            with self.assertRaises(RecordsError) as caught:
                request_json(lambda *a: HttpResponse(status, {}, raw), 'GET', '/user', 'opaque')
            self.assertNotIn('SECRET', str(caught.exception))


class TestImmutableTransport(unittest.TestCase):
    @staticmethod
    def add_tree(values, number, entries):
        commit = hashlib.sha1(('commit-' + str(number)).encode()).hexdigest()
        tree = hashlib.sha1(('tree-' + str(number)).encode()).hexdigest()
        prefix = '/repos/acme/records/git/'
        values[prefix + 'commits/' + commit] = {'sha': commit, 'parents': [], 'tree': {'sha': tree}}
        values[prefix + 'trees/' + tree + '?recursive=1'] = {
            'sha': tree, 'truncated': False, 'tree': [
                {'path': f'events/{i:04d}.enc.json', 'type': 'blob', 'mode': '100644',
                 'sha': 'd' * 40, 'size': 10} for i in range(entries)]}
        return commit

    def fixture(self):
        raw = b'ciphertext test bytes'
        oid = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        commit, tree = 'a'*40, 'b'*40
        values = {'/user': {'id': 21, 'login': 'operator'}}
        for repo in BINDING.repositories[:2]:
            prefix = f'/repos/{repo.owner}/{repo.name}'
            values[prefix] = {'id': repo.id, 'owner': {'id': 7, 'login': 'acme'}, 'name': repo.name, 'private': True}
            values[prefix+'/git/ref/heads/'+('events' if repo.role=='records' else 'coverage')] = {
                'ref': 'refs/heads/'+('events' if repo.role=='records' else 'coverage'), 'object': {'type': 'commit', 'sha': commit}}
        prefix = '/repos/acme/records'
        values[prefix+'/git/commits/'+commit] = {'sha': commit, 'parents': [], 'tree': {'sha': tree}}
        values[prefix+'/git/trees/'+tree+'?recursive=1'] = {'sha': tree, 'truncated': False,
            'tree': [{'path': 'README.md', 'type': 'blob', 'mode': '100644', 'sha': oid, 'size': len(raw)}]}
        values[prefix+'/git/blobs/'+oid] = {'sha': oid, 'size': len(raw), 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
        calls = []
        def sender(method, url, headers, timeout, body=None):
            self.assertEqual(method, 'GET'); self.assertIsNone(body)
            path = url.removeprefix('https://api.github.com');calls.append(path)
            return response(values[path])
        transport = RepositoryTransport(OperatorCredentials(lambda: 'opaque', sender=sender))
        transport.authorize(BINDING)
        return transport, values, calls, commit, tree, oid, raw

    def test_oid_bound_reads_verify_git_blob_and_cache_only_immutable_objects(self):
        transport, values, calls, commit, tree, oid, raw = self.fixture()
        self.assertEqual(transport.head(BINDING.repo('records'), 'events'), commit)
        self.assertEqual(transport.read(BINDING.repo('records'), commit, 'README.md'), raw)
        self.assertEqual(transport.read(BINDING.repo('records'), commit, 'README.md'), raw)
        self.assertEqual(sum('/git/blobs/' in c for c in calls), 1)
        self.assertEqual(len(transport.ancestry(BINDING.repo('records'), commit)), 1)
        with self.assertRaises(RecordsError): transport.head(BINDING.repo('control'), 'events')

    def test_truncated_tree_merge_symlink_and_blob_tamper_fail_closed(self):
        for kind in ('truncated', 'merge', 'symlink', 'tampered', 'missing'):
            with self.subTest(kind=kind):
                t, v, calls, commit, tree, oid, raw = self.fixture();prefix='/repos/acme/records/git/'
                if kind=='truncated': v[prefix+'trees/'+tree+'?recursive=1']['truncated']=True
                if kind=='merge': v[prefix+'commits/'+commit]['parents']=[{'sha':'c'*40},{'sha':'d'*40}]
                if kind=='symlink': v[prefix+'trees/'+tree+'?recursive=1']['tree'][0]['mode']='120000'
                if kind=='tampered': v[prefix+'blobs/'+oid]['content']=base64.b64encode(b'X'*len(raw)).decode()
                if kind=='missing': v[prefix+'trees/'+tree+'?recursive=1']['tree']=[]
                with self.assertRaises(RecordsError): t.read(BINDING.repo('records'), commit, 'README.md')

    def test_boolean_repository_identity_is_not_numeric_id(self):
        t,v,*_=self.fixture();v['/repos/acme/records']['id']=True
        with self.assertRaises(RecordsError):t.authorize(BINDING)
        with self.assertRaises(RecordsError):t.head(BINDING.repo('records'),'events')

    def test_growing_history_retains_only_linear_tree_metadata(self):
        import gc
        from dracla.records.github import TreeEntry
        transport, values, *_ = self.fixture()
        gc.collect()
        before = sum(type(item) is TreeEntry for item in gc.get_objects())
        for number in range(1, 129):
            commit = self.add_tree(values, number, number)
            self.assertEqual(len(transport.tree(BINDING.repo('records'), commit)), number)
        gc.collect()
        retained = sum(type(item) is TreeEntry for item in gc.get_objects()) - before
        self.assertLessEqual(retained, 256)  # All-history retention previously held 8,256.

    def test_tree_cache_hits_eviction_and_returned_maps_remain_immutable(self):
        transport, values, calls, *_ = self.fixture()
        repo = BINDING.repo('records')
        commits = [self.add_tree(values, number, 1) for number in range(3)]
        first = transport.tree(repo, commits[0])
        second = transport.tree(repo, commits[1])
        self.assertIs(transport.tree(repo, commits[0]), first)
        third = transport.tree(repo, commits[2])  # Evicts second, not recently used first.
        revisited = transport.tree(repo, commits[1])
        self.assertIsNot(revisited, second)
        self.assertEqual(dict(revisited), dict(second))
        self.assertIs(transport.tree(repo, commits[2]), third)
        tree = transport.commit(repo, commits[1]).tree_oid
        self.assertEqual(calls.count('/repos/acme/records/git/trees/' + tree + '?recursive=1'), 2)
        self.assertEqual(dict(second), dict(first))
        with self.assertRaises(TypeError):
            first['another'] = next(iter(first.values()))

    def test_evicted_tree_is_revalidated_even_when_blob_is_cached(self):
        for kind in ('truncated', 'symlink', 'invalid-oid', 'invalid-size'):
            with self.subTest(kind=kind):
                transport, values, calls, commit, tree, oid, raw = self.fixture()
                repo = BINDING.repo('records')
                self.assertEqual(transport.read(repo, commit, 'README.md'), raw)
                for number in range(2):
                    other = self.add_tree(values, number, 1)
                    transport.tree(repo, other)
                response = values['/repos/acme/records/git/trees/' + tree + '?recursive=1']
                if kind == 'truncated': response['truncated'] = True
                if kind == 'symlink': response['tree'][0]['mode'] = '120000'
                if kind == 'invalid-oid': response['tree'][0]['sha'] = 'invalid'
                if kind == 'invalid-size': response['tree'][0]['size'] = True
                for _ in range(2):  # A rejected response must not publish a cached partial tree.
                    with self.assertRaises(RecordsError) as caught:
                        transport.read(repo, commit, 'README.md')
                    self.assertEqual(caught.exception.category, 'invalid-history')
                self.assertEqual(calls.count('/repos/acme/records/git/blobs/' + oid), 1)

    def test_default_limits_allow_more_than_one_million_visited_tree_rows(self):
        transport, values, *_ = self.fixture()
        repo = BINDING.repo('records')
        visited = 0
        for number in range(1, 1501):
            commit = self.add_tree(values, number, number)
            self.assertEqual(len(transport.tree(repo, commit)), number)
            visited += number
            tree = transport.commit(repo, commit).tree_oid
            del values['/repos/acme/records/git/trees/' + tree + '?recursive=1']
        self.assertGreater(visited, 1000000)


class EncryptedRepository:
    """Concrete REST fixture using actual M1 ciphertext, replay and materializers."""
    def __init__(self, *, complete_history=False, rotate=False, extra_rules=False,
                 post_rotate_noop=None, post_rotate_changed=False):
        from pathlib import Path
        from conformance.authoring.histories import History
        from dracla.conformance import (Keyring, CanonicalEventRecord, assemble_derived_projection,
            base64url_encode, canonical_json, decode_decision_fence, decode_inflight_marker,
            encode_keyring, encrypt_artifact, encrypt_json_artifact, event_path, initial_replay_state,
            apply_event, load_release_profile, materialize_coverage, materialize_derived,
            resolve_artifact_identity, wrap_key_copy)
        self.binding = ProjectBinding('project-1', 10, BINDING.repositories)
        self.values, self.calls, self.files, self.serial = {}, [], {}, 100
        self.data_keys = {'records': b'r'*32, 'coverage': b'c'*32}
        self.kid_bytes = {'records': b'r'*16, 'coverage': b'c'*16}
        self.kids = {cap: base64url_encode(kid) for cap, kid in self.kid_bytes.items()}
        self.wrapping = b'w'*32
        self.values['/user'] = {'id': 21, 'login': 'operator'}
        for repo in self.binding.repositories[:2]:
            self.values[f'/repos/acme/{repo.name}'] = {'id': repo.id,
                'owner': {'id': 10, 'login': 'acme'}, 'name': repo.name, 'private': True}
        self.root = self.commit('records', {'README.md': b'Private DraCLA records\n'})
        ring = Keyring(tuple(wrap_key_copy(self.data_keys[cap], project_id='project-1', capability=cap,
            data_kid=self.kid_bytes[cap], wrapper_id='recovery', wrapper_generation='install-1',
            wrapping_key=self.wrapping) for cap in ('records', 'coverage')))
        self.key_files = {'README.md': b'Private DraCLA records\n',
                          '.dracla/recovery/keyring.json': encode_keyring(ring)}
        self.k = self.commit('records', self.key_files, self.root)
        manifest = {'bootstrap_version':1,'project_id':'project-1','install_generation':'install-1',
            'release':{'package_version':'0.1.0','release_policy_sha256':'sha256:'+'a'*64,
                'source_commit_oid':'a'*40,'provenance_identity':'release-workflow',
                'dependency_constraints_sha256':'sha256:'+'b'*64},
            'repository_ids':self.binding.ids(),'records_keyring_candidate_oid':self.k,'current_kids':self.kids}
        self.manifest = canonical_json(manifest)
        self.b = self.commit('records', {**self.key_files, '.dracla/bootstrap.json':self.manifest}, self.k)
        corpus=json.loads((Path(__file__).resolve().parents[2]/'conformance/vectors/events-v1.json').read_text())
        builder=History({e['type']:e for e in corpus['events']})
        event=builder.event('project_connected', 501, **{'payload.bootstrap':{
            'install_generation':'install-1','manifest_commit_oid':self.b,
            'manifest_sha256':'sha256:'+hashlib.sha256(self.manifest).hexdigest(),
            'records_keyring_candidate_oid':self.k,'repository_ids':self.binding.ids(),'current_kids':self.kids}})
        self.event = event
        self.generations={'generations_version':1, **{cap:event.event_id for cap in
            ('derived_index','status_detail','reader_authority')}}
        def encrypt(role,branch,path,value):
            cap='coverage' if role=='coverage' else 'records'
            return encrypt_json_artifact(value,project_id='project-1',
                identity=resolve_artifact_identity(role,branch,path),kid=self.kid_bytes[cap],key=self.data_keys[cap])
        self.encrypt = encrypt
        event_files={'README.md':b'Private DraCLA records\n',
            event_path(event.event_id):encrypt('records','events',event_path(event.event_id),event.to_dict()),
            'config/project.enc.json':encrypt('records','events','config/project.enc.json',event.to_dict()['payload']['project_configuration']),
            'config/materialization-generations.enc.json':encrypt('records','events','config/materialization-generations.enc.json',self.generations)}
        self.e=self.commit('records',event_files,self.root)
        self.state=apply_event(initial_replay_state('project-1',self.root), CanonicalEventRecord(event,self.e,self.root))
        if complete_history:
            content=b'Test agreement\n';digest='sha256:'+hashlib.sha256(content).hexdigest()
            publication=builder.event('agreement_published',502,**{'payload.digest':digest,'payload.snapshot_sha256':digest})
            metadata={'metadata_version':1,**publication.to_dict()['target'],**{k:publication.to_dict()['payload'][k]
                for k in ('recipient','ref','content_commit_oid','digest','snapshot_sha256')}}
            self.append(publication,(),{
                publication.payload['snapshot_content_path']:content,
                publication.payload['snapshot_metadata_path']:canonical_json(metadata)})
            self.append(builder.event('agreement_activated',503,**{'payload.published_event_id':publication.event_id}))
            self.append(builder.event('acceptance',504,self.e,**{'target.digest':digest}),('derived_index','status_detail'))
            self.append(builder.event('revocation',505,self.e),('derived_index','status_detail'))
            self.append(builder.event('exemption',506),('derived_index','status_detail'))
            self.append(builder.event('records_reader_authorized',507),('reader_authority',))
            config=event.to_dict()['payload']['project_configuration'];config['retention_statement']='Updated retention'
            changed=builder.event('config_updated',508,**{'payload.project_configuration':config})
            self.append(changed,(),{'config/project.enc.json':encrypt('records','events','config/project.enc.json',config)})
        if extra_rules:
            rule=builder.event('exemption_rule_configured',601)
            self.append(rule,('status_detail',))
            self.append(builder.exemption_materialization_event(rule,'add',None),('derived_index','status_detail'))
            self.append(builder.event('exemption_rule_withdrawn',602,**{'target.rule_event_id':rule.event_id}),('status_detail',))
            self.append(builder.event('exemption_rule_withdrawn',603,**{'target.rule_event_id':rule.event_id}),('status_detail',))
            rule=builder.event('exemption_rule_configured',604)
            self.append(rule,('status_detail',))
            self.append(builder.exemption_materialization_event(rule,'add',None,**{
                'target.subject.github_user_id':8,'payload.membership_evidence.github_user_id':8}),('derived_index','status_detail'))
            self.append(builder.event('exemption_rule_withdrawn',605,**{'target.rule_event_id':rule.event_id}),('derived_index','status_detail'))
            rule=builder.event('records_reader_rule_configured',606)
            self.append(rule,('reader_authority',))
            self.append(builder.reader_materialization_event(rule,'add',None),('reader_authority',))
            self.append(builder.event('records_reader_withdrawn',607,**{'target.source_event_id':rule.event_id}),('reader_authority',))
            self.append(builder.event('records_reader_withdrawn',608,**{'target.source_event_id':rule.event_id}))
            self.append(builder.event('records_reader_rule_withdrawn',609,**{'target.rule_event_id':rule.event_id}),('reader_authority',))
            self.append(builder.event('records_reader_rule_withdrawn',610,**{'target.rule_event_id':rule.event_id}))
        if rotate:
            next_keys={'records':b'R'*32,'coverage':b'C'*32}
            next_kids={'records':b'R'*16,'coverage':b'C'*16}
            retained=ring.keys+tuple(wrap_key_copy(next_keys[cap],project_id='project-1',capability=cap,
                data_kid=next_kids[cap],wrapper_id='recovery',wrapper_generation='install-1',
                wrapping_key=self.wrapping) for cap in ('records','coverage'))
            candidate=self.commit('records',{**self.key_files,'.dracla/bootstrap.json':self.manifest,
                '.dracla/recovery/keyring.json':encode_keyring(Keyring(retained))},self.b)
            self.append(builder.event('keyring_activated',509,**{'payload.generation':2,
                'payload.keys_commit_oid':candidate,'payload.current_kids':{
                    cap:base64url_encode(kid) for cap,kid in next_kids.items()}}))
            self.data_keys=next_keys;self.kid_bytes=next_kids
            self.b=candidate
        if post_rotate_noop == 'reader':
            self.append(builder.event('records_reader_withdrawn',611,**{
                'target.source_event_id':rule.event_id}))
        elif post_rotate_noop == 'rule':
            self.append(builder.event('records_reader_rule_withdrawn',612,**{
                'target.rule_event_id':rule.event_id}))
        if post_rotate_changed:
            self.append(builder.event('records_reader_withdrawn',613,**{
                'target.source_event_id':rule.event_id}),('reader_authority',))
        marker,fence=decode_inflight_marker(canonical_json({'ops':{}})),decode_decision_fence(canonical_json({'state':'idle','generation':0}))
        coverage=materialize_coverage(self.state,(marker,fence),canonical_oid=self.e,
            built_at='2026-01-01T00:00:00Z',dracla_version='test-1').to_dict()
        covfiles={path:encrypt('coverage','coverage',path,value) for path,value in coverage.items()}
        covfiles['.dracla/bootstrap.json']=self.manifest
        self.c=self.commit('coverage',covfiles)
        profile=load_release_profile();plain=materialize_derived(self.state,profile=profile)
        derived={path:encrypt_artifact(raw,project_id='project-1',identity=resolve_artifact_identity('records','derived',path),
            kid=self.kid_bytes['records'],key=self.data_keys['records']) for path,raw in plain.plaintext_files().items()}
        assembled=assemble_derived_projection(plain,canonical_oid=self.e,generations=self.generations,
            encrypted_shards=derived,profile=profile)
        derived['derived/state.enc.json']=encrypt('records','derived','derived/state.enc.json',assembled.state_dict())
        self.d=self.commit('records',derived)
        self.o=self.commit('records',{'prepared-operation.enc.json':encrypt('records','operations','prepared-operation.enc.json',{'state':'idle','generation':0})})
        for repo,branch,oid in [('records','events',self.e),('records','keys',self.b),
                               ('records','derived',self.d),('records','operations',self.o),('coverage','coverage',self.c)]:
            self.values[f'/repos/acme/{repo}/git/ref/heads/{branch}']={'ref':'refs/heads/'+branch,'object':{'type':'commit','sha':oid}}

    def append(self,event,affected=(),artifacts=None):
        from dracla.conformance import CanonicalEventRecord,apply_event,event_path
        files=copy.deepcopy(self.files['records',self.e]);parent=self.e
        files[event_path(event.event_id)]=self.encrypt('records','events',event_path(event.event_id),event.to_dict())
        files.update(artifacts or {})
        if affected:
            self.generations.update({name:event.event_id for name in affected})
            files['config/materialization-generations.enc.json']=self.encrypt('records','events',
                'config/materialization-generations.enc.json',self.generations)
        self.e=self.commit('records',files,parent)
        self.state=apply_event(self.state,CanonicalEventRecord(event,self.e,parent))

    def commit(self,repo,files,parent=None):
        self.serial+=1;oid=f'{self.serial:040x}';tree=f'{self.serial+10000:040x}'
        prefix=f'/repos/acme/{repo}/git/'
        self.files[repo,oid]=copy.deepcopy(files)
        entries=[]
        for path,raw in files.items():
            blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            entries.append({'path':path,'mode':'100644','type':'blob','sha':blob,'size':len(raw)})
            self.values[prefix+'blobs/'+blob]={'sha':blob,'size':len(raw),'encoding':'base64','content':base64.b64encode(raw).decode()}
        self.values[prefix+'trees/'+tree+'?recursive=1']={'sha':tree,'truncated':False,'tree':entries}
        self.values[prefix+'commits/'+oid]={'sha':oid,'tree':{'sha':tree},'parents':[] if parent is None else [{'sha':parent}]}
        return oid

    def send(self,method,url,headers,timeout,body=None):
        if method!='GET' or body is not None:raise AssertionError('repository write in verify')
        path=url.removeprefix('https://api.github.com');self.calls.append(path)
        return response(self.values[path]) if path in self.values else response({},404)

    def reader(self):
        self.key_calls=[]
        def keys():self.key_calls.append(True);return {'install-1':self.wrapping}
        return WrappedKeys('recovery',keys),RepositoryTransport(OperatorCredentials(lambda:'opaque',sender=self.send))


class TestEncryptedHistory(unittest.TestCase):
    def test_full_encrypted_bootstrap_replay_and_all_stored_projections(self):
        from dracla.records import verify_project
        f=EncryptedRepository();keys,transport=f.reader()
        result=verify_project(f.binding,keys,transport)
        self.assertTrue(result.valid,result.discrepancies)
        self.assertEqual(result.source_oid,f.e)
        self.assertEqual(len(f.key_calls),1)
        self.assertFalse(any('/control' in path for path in f.calls))

    def test_scope_identity_fails_before_unwrap(self):
        f=EncryptedRepository();f.values['/repos/acme/records']['private']=False
        keys,transport=f.reader()
        with self.assertRaises(RecordsError):open_history(f.binding,keys,transport)
        self.assertEqual(f.key_calls,[])

    def test_authenticated_plaintext_type_aliases_are_not_clean(self):
        from dracla.conformance import (canonical_json, decrypt_json_artifact,
                                        parse_canonical_json, resolve_artifact_identity)
        from dracla.records import verify_project

        f = EncryptedRepository()
        path = 'agreements/active.enc.json'
        active = decrypt_json_artifact(f.files['coverage', f.c][path],
            expected_project_id='project-1',
            expected_identity=resolve_artifact_identity('coverage', 'coverage', path),
            keys={f.kids['coverage']: f.data_keys['coverage']})
        active['projection_format'] = True
        files = copy.deepcopy(f.files['coverage', f.c])
        files[path] = f.encrypt('coverage', 'coverage', path, active)
        f.c = f.commit('coverage', files)
        f.values['/repos/acme/coverage/git/ref/heads/coverage']['object']['sha'] = f.c
        result = verify_project(f.binding, *f.reader())
        self.assertFalse(result.valid)

        f = EncryptedRepository()
        path = 'config/project.enc.json'
        config = decrypt_json_artifact(f.files['records', f.e][path],
            expected_project_id='project-1',
            expected_identity=resolve_artifact_identity('records', 'events', path),
            keys={f.kids['records']: f.data_keys['records']})
        config['required_fields'][0]['required'] = 1
        replace_blob(f, 'records', f.e, path, f.encrypt('records', 'events', path, config))
        with self.assertRaises(RecordsError): open_history(f.binding, *f.reader())

        f = EncryptedRepository(complete_history=True)
        path = 'derived/index/07.enc.json'
        index = decrypt_json_artifact(f.files['records', f.d][path],
            expected_project_id='project-1',
            expected_identity=resolve_artifact_identity('records', 'derived', path),
            keys={f.kids['records']: f.data_keys['records']})
        index['7']['exempt'] = 1
        index_raw = f.encrypt('records', 'derived', path, index)
        state_path = 'derived/state.enc.json'
        state = decrypt_json_artifact(f.files['records', f.d][state_path],
            expected_project_id='project-1',
            expected_identity=resolve_artifact_identity('records', 'derived', state_path),
            keys={f.kids['records']: f.data_keys['records']})
        state['shard_digests']['derived_index']['07'] = 'sha256:' + hashlib.sha256(index_raw).hexdigest()
        replace_blob(f, 'records', f.d, path, index_raw)
        replace_blob(f, 'records', f.d, state_path,
                     f.encrypt('records', 'derived', state_path, state))
        result = verify_project(f.binding, *f.reader())
        self.assertFalse(result.valid)

        f = EncryptedRepository(complete_history=True)
        metadata_commit = next(oid for (repo, oid), files in f.files.items()
                               if repo == 'records' and any(p.endswith('.meta.json') for p in files))
        metadata_path = next(p for p in f.files['records', metadata_commit] if p.endswith('.meta.json'))
        metadata = parse_canonical_json(f.files['records', metadata_commit][metadata_path])
        metadata['metadata_version'] = True
        replace_blob(f, 'records', metadata_commit, metadata_path, canonical_json(metadata))
        with self.assertRaises(RecordsError): open_history(f.binding, *f.reader())


class TestVerifyCommand(unittest.TestCase):
    def args(self, fixture):
        b=fixture.binding
        return ['verify','project.id='+b.project_id,'github.owner=acme','github.owner_id=10']+[
            value for repo in b.repositories for value in (repo.role+'.name='+repo.name,repo.role+'.id='+str(repo.id))]

    def test_real_command_uses_complete_encrypted_transport_and_redacted_output(self):
        import io
        from dracla.cli.app import main
        f=EncryptedRepository();out=io.StringIO()
        code=main(self.args(f),output=out,release_loader=lambda:None,verify_factory=lambda b:f.reader())
        self.assertEqual(code,0,out.getvalue());self.assertIn(f.e,out.getvalue())
        self.assertIn('Verification passed',out.getvalue())
        self.assertNotIn('Recipient One',out.getvalue());self.assertNotIn('PRIVATE',out.getvalue())

    def test_invalid_secret_override_stops_before_release_credentials_or_keys(self):
        import io
        from dracla.cli.app import main
        calls=[];f=EncryptedRepository();out=io.StringIO()
        code=main(self.args(f)+['recovery.key=PRIVATE'],output=out,
            release_loader=lambda:calls.append('release'),verify_factory=lambda b:calls.append('keys'))
        self.assertEqual(code,2);self.assertEqual(calls,[]);self.assertNotIn('PRIVATE',out.getvalue())

    def test_release_failure_precedes_authorization(self):
        import io
        from dracla.cli.app import main
        from dracla.cli.release import ReleaseError
        calls=[];f=EncryptedRepository();out=io.StringIO()
        def release():raise ReleaseError('Unavailable release evidence')
        code=main(self.args(f),output=out,release_loader=release,verify_factory=lambda b:calls.append('keys'))
        self.assertEqual(code,2);self.assertEqual(calls,[])


class TestHistoryRejections(unittest.TestCase):
    def point(self,f,repo,branch,oid):
        f.values[f'/repos/acme/{repo}/git/ref/heads/{branch}']['object']['sha']=oid

    def test_invalid_bootstrap_ancestry_event_and_atomic_side_artifacts_return_no_state(self):
        from dracla.conformance import event_path
        for failure in ('missing-key-parent','coverage-manifest','two-events','changed-config',
                        'wrong-generation','extra-file','deleted-readme','empty-append'):
            with self.subTest(failure=failure):
                f=EncryptedRepository()
                if failure=='missing-key-parent':f.values[f'/repos/acme/records/git/commits/{f.b}']['parents']=[]
                elif failure=='coverage-manifest':
                    files=f.files['coverage',f.c];files['.dracla/bootstrap.json']=b'{}';self.point(f,'coverage','coverage',f.commit('coverage',files))
                else:
                    files=copy.deepcopy(f.files['records',f.e]);parent=f.root
                    if failure=='two-events':files['events/XX/YY/extra.enc.json']=files[event_path(f.event.event_id)]
                    if failure=='changed-config':
                        config=f.event.to_dict()['payload']['project_configuration'];config['retention_statement']='UNEXPECTED PRIVATE VALUE'
                        files['config/project.enc.json']=f.encrypt('records','events','config/project.enc.json',config)
                    if failure=='wrong-generation':
                        gen={**f.generations,'reader_authority':'a'*43}
                        files['config/materialization-generations.enc.json']=f.encrypt('records','events','config/materialization-generations.enc.json',gen)
                    if failure=='extra-file':files['unexpected.txt']=b'private'
                    if failure=='deleted-readme':del files['README.md']
                    if failure=='empty-append':parent=f.e
                    self.point(f,'records','events',f.commit('records',files,parent))
                keys,transport=f.reader()
                with self.assertRaises(RecordsError) as caught:open_history(f.binding,keys,transport)
                self.assertNotIn('PRIVATE',str(caught.exception));self.assertNotIn('private',str(caught.exception))

    def test_wrong_recovery_key_and_install_generation_fail_closed(self):
        for generation in ('wrong-key','wrong-generation'):
            f=EncryptedRepository();keys,transport=f.reader()
            keys=WrappedKeys('recovery',lambda:{'install-1':b'x'*32} if generation=='wrong-key' else {'other':f.wrapping})
            with self.assertRaises(RecordsError):open_history(f.binding,keys,transport)

    def test_all_projection_classes_shards_and_operational_cells_are_checked(self):
        from dracla.records import verify_project
        cases=[('coverage','coverage','users/31.enc.json',{}),
               ('records','derived','derived/reader-authority/31.enc.json',{'private':'SECRET'}),
               ('records','derived','derived/index/31.enc.json',{'private':'SECRET'}),
               ('records','derived','derived/status-detail/31.enc.json',{'private':'SECRET'}),
               ('records','operations','prepared-operation.enc.json',{'state':'prepared','generation':0})]
        for repo,branch,path,value in cases:
            with self.subTest(path=path):
                f=EncryptedRepository();oid={'coverage':f.c,'derived':f.d,'operations':f.o}[branch]
                files=copy.deepcopy(f.files[repo,oid]);files[path]=f.encrypt(repo,branch,path,value)
                if repo=='coverage' and path=='users/31.enc.json':
                    # A correctly re-encrypted empty shard can still be canonical.
                    files[path]=f.encrypt(repo,branch,path,{'31':{'unexpected':'SECRET'}})
                self.point(f,repo,branch,f.commit(repo,files));keys,transport=f.reader()
                result=verify_project(f.binding,keys,transport)
                self.assertFalse(result.valid);self.assertNotIn('SECRET',repr(result))


class TestReaderAuthorization(unittest.TestCase):
    def snapshot(self,kind='individual'):
        from dataclasses import replace
        from dracla.conformance import ReaderSource
        f=EncryptedRepository();keys,transport=f.reader();snapshot=open_history(f.binding,keys,transport)
        team=None if kind=='individual' else {'organization_id':41,'team_id':42,'slug_snapshot':'team-one'}
        source=ReaderSource(f.event.event_id,kind,team,{21:'operator'},
                            {21:f.event.event_id} if kind=='continuous_team' else {})
        return replace(snapshot,state=replace(snapshot.state,reader_source_records={f.event.event_id:source}))

    def test_current_individual_snapshot_and_continuous_sources(self):
        from dracla.records import authorize_reader
        for kind in ('individual','snapshot','continuous_team'):
            with self.subTest(kind=kind):
                s=self.snapshot(kind);calls=[]
                def member(*args):calls.append(args);return True
                self.assertTrue(authorize_reader(s,21,member))
                self.assertEqual(calls,[(41,42,21)] if kind=='continuous_team' else [])
                self.assertFalse(authorize_reader(s,22,member))

    def test_continuous_departure_unknown_and_withdrawal_deny(self):
        from dataclasses import replace
        from dracla.records import authorize_reader
        s=self.snapshot('continuous_team')
        self.assertFalse(authorize_reader(s,21,lambda *a:False))
        def unknown(*args):raise RuntimeError('SECRET')
        with self.assertRaises(RecordsError) as caught:authorize_reader(s,21,unknown)
        self.assertNotIn('SECRET',str(caught.exception))
        self.assertFalse(authorize_reader(replace(s,state=replace(s.state,reader_source_records={})),21,lambda *a:True))
        with self.assertRaises(RecordsError):authorize_reader(s,True,lambda *a:True)


class TestHistoricalPackages(unittest.TestCase):
    def test_multiple_event_packages_replay_and_key_activation_preserves_old_decryption(self):
        from dracla.records import verify_project,authorize_reader
        for rotate in (False,True):
            with self.subTest(rotate=rotate):
                f=EncryptedRepository(complete_history=True,rotate=rotate);keys,transport=f.reader()
                snapshot=open_history(f.binding,keys,transport)
                self.assertEqual(len(snapshot.records),9 if rotate else 8)
                self.assertTrue(authorize_reader(snapshot,7,lambda *args:False))
                self.assertFalse(authorize_reader(snapshot,21,lambda *args:True))
                result=verify_project(f.binding,*f.reader())
                self.assertTrue(result.valid,result.discrepancies)
                self.assertEqual(len(snapshot.keys['records']),2 if rotate else 1)

    def test_repeated_reader_withdrawals_after_rotation_keep_inherited_generation(self):
        from dracla.records import verify_project
        for kind in ('reader', 'rule'):
            with self.subTest(kind=kind):
                f=EncryptedRepository(complete_history=True,extra_rules=True,rotate=True,
                                      post_rotate_noop=kind)
                result=verify_project(f.binding,*f.reader())
                self.assertTrue(result.valid,result.discrepancies)

    def test_changed_generation_artifact_after_rotation_requires_current_kid(self):
        from dracla.conformance import encrypt_json_artifact,resolve_artifact_identity
        f=EncryptedRepository(complete_history=True,extra_rules=True,rotate=True,
                              post_rotate_changed=True)
        path='config/materialization-generations.enc.json'
        old_raw=encrypt_json_artifact(f.generations | {'generations_version':1},
            project_id='project-1',identity=resolve_artifact_identity('records','events',path),
            kid=b'r'*16,key=b'r'*32)
        replace_blob(f,'records',f.e,path,old_raw)
        with self.assertRaises(RecordsError):open_history(f.binding,*f.reader())


class TestCredentialRenewalAndBounds(unittest.TestCase):
    def test_unauthorized_read_reauthenticates_stable_operator_before_single_retry(self):
        seen=[];repo=BINDING.repo('records')
        def send(method,url,headers,timeout,body=None):
            path=url.removeprefix('https://api.github.com');seen.append(path)
            if path=='/user':return response({'id':21,'login':'operator'})
            if path.endswith('/git/ref/heads/events'):
                if seen.count(path)==1:return response({},401)
                return response({'ref':'refs/heads/events','object':{'type':'commit','sha':'a'*40}})
            current=next(r for r in BINDING.repositories if path=='/repos/acme/'+r.name)
            return response({'id':current.id,'owner':{'id':7,'login':'acme'},'name':current.name,'private':True})
        t=RepositoryTransport(OperatorCredentials(lambda:'opaque',sender=send));t.authorize(BINDING)
        self.assertEqual(t.head(repo,'events'),'a'*40)
        self.assertEqual(seen.count('/user'),2)
        self.assertEqual(seen.count('/repos/acme/records/git/ref/heads/events'),2)

    def test_warmed_immutable_caches_require_current_binding(self):
        t,v,calls,commit,tree,oid,raw=TestImmutableTransport().fixture()
        t.commit(BINDING.repo('records'),commit)
        t.tree(BINDING.repo('records'),commit)
        t.ancestry(BINDING.repo('records'),commit)
        t.read(BINDING.repo('records'),commit,'README.md')
        warm_count=len(calls)
        t.commit(BINDING.repo('records'),commit)
        t.tree(BINDING.repo('records'),commit)
        t.ancestry(BINDING.repo('records'),commit)
        t.read(BINDING.repo('records'),commit,'README.md')
        self.assertEqual(len(calls),warm_count)
        v['/repos/acme/records']['private']=False
        with self.assertRaises(RecordsError):t.authorize(BINDING)
        self.assertIsNone(t.binding)
        request_count=len(calls)
        foreign=RepositoryRef('records','acme','foreign',999)
        for operation in (
                lambda:t.commit(BINDING.repo('records'),commit),
                lambda:t.tree(BINDING.repo('records'),commit),
                lambda:t.ancestry(BINDING.repo('records'),commit),
                lambda:t.read(BINDING.repo('records'),commit,'README.md'),
                lambda:t.commit(foreign,commit)):
            with self.assertRaises(RecordsError):operation()
        self.assertEqual(len(calls),request_count)

    def test_failed_scope_cannot_reach_cached_recovery_provider(self):
        f=EncryptedRepository();keys,t=f.reader()
        t.authorize(f.binding)
        t.read(f.binding.repo('records'),f.k,'.dracla/recovery/keyring.json')
        f.values['/repos/acme/records']['private']=False
        with self.assertRaises(RecordsError):t.authorize(f.binding)
        self.assertIsNone(t.binding)
        with self.assertRaises(RecordsError):keys.at(f.binding,t,f.k)
        self.assertEqual(f.key_calls,[])

    def test_unauthorized_read_rechecks_data_repository_scope_before_retry(self):
        for defect in ('records-id', 'coverage-id', 'records-owner', 'records-public', 'coverage-name'):
            with self.subTest(defect=defect):
                seen=[];repo=BINDING.repo('records')
                metadata = {
                    '/repos/acme/records': {'id': 11, 'owner': {'id': 7, 'login': 'acme'},
                                           'name': 'records', 'private': True},
                    '/repos/acme/coverage': {'id': 12, 'owner': {'id': 7, 'login': 'acme'},
                                            'name': 'coverage', 'private': True},
                }
                def send(method, url, headers, timeout, body=None):
                    path=url.removeprefix('https://api.github.com');seen.append(path)
                    if path=='/user':return response({'id':21,'login':'operator'})
                    if path in metadata:return response(metadata[path])
                    if path.endswith('/git/ref/heads/events'):
                        if seen.count(path)==1:return response({},401)
                        return response({'ref':'refs/heads/events','object':{'type':'commit','sha':'a'*40}})
                    raise AssertionError(path)
                t=RepositoryTransport(OperatorCredentials(lambda:'opaque',sender=send));t.authorize(BINDING)
                if defect=='records-id':metadata['/repos/acme/records']['id']=111
                if defect=='coverage-id':metadata['/repos/acme/coverage']['id']=112
                if defect=='records-owner':metadata['/repos/acme/records']['owner']['id']=8
                if defect=='records-public':metadata['/repos/acme/records']['private']=False
                if defect=='coverage-name':metadata['/repos/acme/coverage']['name']='renamed'
                with self.assertRaises(RecordsError):t.head(repo,'events')
                self.assertIsNone(t.binding)
                self.assertEqual(seen.count('/repos/acme/records/git/ref/heads/events'),1)

    def test_metadata_scope_authorization_failure_does_not_recurse_or_retry(self):
        seen=[];repo=BINDING.repo('records')
        def send(method, url, headers, timeout, body=None):
            path=url.removeprefix('https://api.github.com');seen.append(path)
            if path=='/user':return response({'id':21,'login':'operator'})
            if path=='/repos/acme/records':
                if seen.count(path)==2:return response({},403)
                return response({'id':11,'owner':{'id':7,'login':'acme'},'name':'records','private':True})
            if path=='/repos/acme/coverage':
                return response({'id':12,'owner':{'id':7,'login':'acme'},'name':'coverage','private':True})
            if path.endswith('/git/ref/heads/events'):
                return response({},401) if seen.count(path)==1 else response(
                    {'ref':'refs/heads/events','object':{'type':'commit','sha':'a'*40}})
            raise AssertionError(path)
        t=RepositoryTransport(OperatorCredentials(lambda:'opaque',sender=send));t.authorize(BINDING)
        with self.assertRaises(RecordsError):t.head(repo,'events')
        self.assertIsNone(t.binding)
        self.assertEqual(seen.count('/user'),2)
        self.assertEqual(seen.count('/repos/acme/records/git/ref/heads/events'),1)

    def test_shared_app_inventory_is_complete_but_operation_token_is_arrangement_scoped(self):
        f=AppFixture();extra=tuple(('other-'+str(n),(100+n*2,101+n*2)) for n in range(50))
        f.protected=InstallationBinding(17,'client-id',19,7,f.protected.assignments+extra,(13,))
        f.repositories.extend({'id':n,'private':True,'owner':{'id':7}} for n in range(100,200))
        p=f.provider();p.authorize(BINDING)
        self.assertTrue(any('page=2' in path for _,path in f.calls))
        self.assertEqual(f.mints[-1]['repository_ids'],[11,12])

    def test_bad_token_expiry_and_clock_never_yield_a_cached_token(self):
        for value in ('2000-01-01T00:00:00Z','2099-01-01T00:00:00Z','bad',None):
            f=AppFixture();f.patch['/app/installations/19/access_tokens']=lambda v:{**v,'expires_at':value}
            with self.assertRaises(RecordsError):f.provider().authorize(BINDING)
        f=AppFixture();p=f.provider();p.authorize(BINDING);f.now=float('nan')
        with self.assertRaises(RecordsError):p.token()

    def test_wrong_keyring_generation_is_checked_even_with_an_available_unwrap_key(self):
        f=EncryptedRepository();keys,transport=f.reader();transport.authorize(f.binding)
        with self.assertRaises(RecordsError):keys.at(f.binding,transport,f.k,expected_generation='other')

    def test_explicit_limits_and_cycle_are_fail_closed(self):
        t,v,calls,commit,tree,oid,raw=TestImmutableTransport().fixture()
        t.max_blob_bytes=1
        with self.assertRaises(RecordsError):t.read(BINDING.repo('records'),commit,'README.md')
        v['/repos/acme/records/git/commits/'+commit]['parents']=[{'sha':commit}]
        t=RepositoryTransport(t.credentials,max_commits=2)
        t.authorize(BINDING)
        with self.assertRaises(RecordsError):t.ancestry(BINDING.repo('records'),commit)


class TestContinuousHistoricalRelations(unittest.TestCase):
    def test_first_add_membership_withdrawal_and_repeatable_generation_noops(self):
        from dracla.records import verify_project
        f=EncryptedRepository(complete_history=True,extra_rules=True,rotate=True)
        result=verify_project(f.binding,*f.reader())
        self.assertTrue(result.valid,result.discrepancies)


class TestControlHistory(unittest.TestCase):
    def test_control_wrapper_and_read_scoped_app_use_same_authentication_and_replay(self):
        from dracla.conformance import Keyring,encode_keyring,wrap_key_copy
        from dracla.records import verify_project
        f=EncryptedRepository();app=AppFixture()
        app.protected=InstallationBinding(17,'client-id',19,10,(('project-1',(11,12)),),(13,))
        app.patch['/app']=lambda v:{**v,'owner':{'id':10}}
        app.patch['/app/installations/19']=lambda v:{**v,'account':{'id':10},'target_id':10}
        for repo in app.repositories:repo['owner']['id']=10
        def sender(method,url,headers,timeout,body=None):
            if '/repos/' in url:return f.send(method,url,headers,timeout,body)
            return app.send(method,url,headers,timeout,body)
        credentials=InstallationCredentials(app.protected,lambda:app.pem,sender=sender,clock=lambda:app.now)
        ring=encode_keyring(Keyring(tuple(wrap_key_copy(f.data_keys[cap],project_id='project-1',capability=cap,
            data_kid=f.kid_bytes[cap],wrapper_id='control',wrapper_generation='install-1',
            wrapping_key=f.wrapping) for cap in ('records','coverage'))))
        keys=WrappedKeys('control',lambda:{'install-1':f.wrapping},protected_keyrings=lambda oid:ring)
        result=verify_project(f.binding,keys,RepositoryTransport(credentials))
        self.assertTrue(result.valid,result.discrepancies)
        self.assertEqual(app.mints[-1],{'permissions':{'contents':'read','metadata':'read'},'repository_ids':[11,12]})
        self.assertFalse(any('/control' in path for path in f.calls))

    def test_data_key_reuse_across_capabilities_is_rejected(self):
        from dracla.conformance import Keyring,encode_keyring,wrap_key_copy
        f=EncryptedRepository();keys,t=f.reader();t.authorize(f.binding)
        ring=encode_keyring(Keyring(tuple(wrap_key_copy(b'r'*32,project_id='project-1',capability=cap,
            data_kid=f.kid_bytes[cap],wrapper_id='recovery',wrapper_generation='install-1',
            wrapping_key=f.wrapping) for cap in ('records','coverage'))))
        candidate=f.commit('records',{'.dracla/recovery/keyring.json':ring},f.b)
        with self.assertRaises(RecordsError):keys.at(f.binding,t,candidate)


class TestWrappedKeysScope(unittest.TestCase):
    def control_transport(self, fixture):
        app=AppFixture()
        app.protected=InstallationBinding(17,'client-id',19,10,(('project-1',(11,12)),),(13,))
        app.patch['/app']=lambda v:{**v,'owner':{'id':10}}
        app.patch['/app/installations/19']=lambda v:{**v,'account':{'id':10},'target_id':10}
        for repo in app.repositories:repo['owner']['id']=10
        def sender(method,url,headers,timeout,body=None):
            return (fixture.send if '/repos/' in url else app.send)(method,url,headers,timeout,body)
        credentials=InstallationCredentials(app.protected,lambda:app.pem,sender=sender,clock=lambda:app.now)
        return RepositoryTransport(credentials),app

    def control_keys(self, fixture, provider_calls, protected_calls):
        from dracla.conformance import Keyring,encode_keyring,wrap_key_copy
        ring=encode_keyring(Keyring(tuple(wrap_key_copy(fixture.data_keys[cap],project_id='project-1',
            capability=cap,data_kid=fixture.kid_bytes[cap],wrapper_id='control',
            wrapper_generation='install-1',wrapping_key=fixture.wrapping) for cap in ('records','coverage'))))
        return WrappedKeys('control',lambda:provider_calls.append(True) or {'install-1':fixture.wrapping},
            protected_keyrings=lambda _:protected_calls.append(True) or ring)

    def test_wrapped_keys_rejects_unbound_failed_and_foreign_bindings_before_providers(self):
        f=EncryptedRepository();provider_calls=[];protected_calls=[]
        keys=self.control_keys(f,provider_calls,protected_calls)
        transport,app=self.control_transport(f)
        with self.assertRaises(RecordsError):keys.at(f.binding,transport,f.k)
        transport.authorize(f.binding)
        foreign=(ProjectBinding('foreign-project',10,BINDING.repositories),
                 ProjectBinding('project-1',11,BINDING.repositories),
                 ProjectBinding('project-1',10,tuple((RepositoryRef(r.role,r.owner,r.name,r.id+10)
                     for r in BINDING.repositories))))
        for binding in foreign:
            with self.subTest(binding=binding):
                with self.assertRaises(RecordsError):keys.at(binding,transport,f.k)
        app.patch['/app']=lambda v:{**v,'owner':{'id':8}}
        with self.assertRaises(RecordsError):transport.authorize(f.binding)
        self.assertIsNone(transport.binding)
        with self.assertRaises(RecordsError):keys.at(f.binding,transport,f.k)
        self.assertEqual(provider_calls,[])
        self.assertEqual(protected_calls,[])

    def test_wrapped_keys_rejects_opposite_wrapper_modes_before_providers(self):
        f=EncryptedRepository();provider_calls=[];protected_calls=[]
        control_keys=self.control_keys(f,provider_calls,protected_calls)
        operator_transport=f.reader()[1];operator_transport.authorize(f.binding)
        with self.assertRaises(RecordsError):control_keys.at(f.binding,operator_transport,f.k)
        control_transport,_=self.control_transport(f);control_transport.authorize(f.binding)
        recovery_keys=WrappedKeys('recovery',lambda:provider_calls.append(True) or {'install-1':f.wrapping})
        with self.assertRaises(RecordsError):recovery_keys.at(f.binding,control_transport,f.k)
        self.assertEqual(provider_calls,[])
        self.assertEqual(protected_calls,[])

    def test_exact_control_binding_and_mode_still_unwrap(self):
        f=EncryptedRepository();provider_calls=[];protected_calls=[]
        keys=self.control_keys(f,provider_calls,protected_calls)
        transport,_=self.control_transport(f);transport.authorize(f.binding)
        result=keys.at(f.binding,transport,f.k)
        self.assertEqual(result['records'][f.kids['records']],f.data_keys['records'])
        self.assertEqual(result['coverage'][f.kids['coverage']],f.data_keys['coverage'])
        self.assertEqual(provider_calls,[True]);self.assertEqual(protected_calls,[True])


class TestKeyLifecycle(unittest.TestCase):
    def ring(self, fixture):
        from dracla.conformance import decode_keyring
        return decode_keyring(fixture.files['records', fixture.b]['.dracla/recovery/keyring.json'],
            expected_project_id='project-1', allowed_capabilities={'records', 'coverage'},
            allowed_wrappers={'recovery'}, known_generations={'recovery': ('install-1',)})

    def candidate(self, fixture, ring):
        from dracla.conformance import encode_keyring
        candidate = fixture.commit('records', {**fixture.files['records', fixture.b],
            '.dracla/recovery/keyring.json': encode_keyring(ring)}, fixture.b)
        fixture.values['/repos/acme/records/git/ref/heads/keys']['object']['sha'] = candidate
        return candidate

    def activate(self, fixture, candidate, kids):
        from pathlib import Path
        from conformance.authoring.histories import History
        values = json.loads((Path(__file__).resolve().parents[2]/'conformance/vectors/events-v1.json').read_text())
        builder = History({event['type']: event for event in values['events']})
        event = builder.event('keyring_activated', 750, **{'payload.generation': 3,
            'payload.keys_commit_oid': candidate, 'payload.current_kids': dict(kids)})
        fixture.append(event)
        fixture.values['/repos/acme/records/git/ref/heads/events']['object']['sha'] = fixture.e

    def test_activation_rejects_backward_retired_alias_and_unchanged_keys(self):
        from dracla.conformance import Keyring, base64url_encode, wrap_key_copy
        for defect in ('backward', 'retired-kids', 'retired-bytes', 'unchanged'):
            with self.subTest(defect=defect):
                f = EncryptedRepository(complete_history=True, rotate=True)
                ring = self.ring(f)
                kids = dict(f.state.current_kids)
                if defect == 'backward':
                    candidate = f.values['/repos/acme/records/git/commits/'+f.b]['parents'][0]['sha']
                    kids = f.kids
                else:
                    if defect == 'retired-kids':
                        kids = f.kids
                    if defect == 'retired-bytes':
                        alias = wrap_key_copy(b'r'*32, project_id='project-1', capability='records',
                            data_kid=b'Z'*16, wrapper_id='recovery', wrapper_generation='install-1',
                            wrapping_key=f.wrapping)
                        ring = Keyring(ring.keys+(alias,))
                        kids['records'] = base64url_encode(b'Z'*16)
                    candidate = self.candidate(f, ring)
                self.activate(f, candidate, kids)
                with self.assertRaises(RecordsError):
                    open_history(f.binding, *f.reader())

    def test_one_capability_successor_keeps_other_key_and_historical_decryption(self):
        from dracla.conformance import Keyring, base64url_encode, wrap_key_copy
        f = EncryptedRepository(complete_history=True, rotate=True)
        successor = wrap_key_copy(b'T'*32, project_id='project-1', capability='records',
            data_kid=b'T'*16, wrapper_id='recovery', wrapper_generation='install-1', wrapping_key=f.wrapping)
        candidate = self.candidate(f, Keyring(self.ring(f).keys+(successor,)))
        # A staged descendant never chooses current keys on its own.
        snapshot = open_history(f.binding, *f.reader())
        self.assertEqual(snapshot.state.current_kids, f.state.current_kids)
        kids = {**f.state.current_kids, 'records': base64url_encode(b'T'*16)}
        self.activate(f, candidate, kids)
        snapshot = open_history(f.binding, *f.reader())
        self.assertEqual(snapshot.state.current_kids, kids)
        self.assertEqual(snapshot.keys['records'][kids['records']], b'T'*32)
        self.assertEqual(len(snapshot.records), 10)

    def rewrap(self, fixture, *, defect=None):
        from dracla.conformance import (Keyring, base64url_decode, wrap_key_copy, unwrap_key_copy)
        raw = []
        for copy in self.ring(fixture).keys:
            key = unwrap_key_copy(copy, expected_project_id='project-1', expected_capability=copy.capability,
                                  wrapping_keys={('recovery', 'install-1'): fixture.wrapping})
            if (defect == 'missing-current' and copy.capability == 'records'
                    and copy.data_kid == fixture.state.current_kids['records']):
                continue
            if copy.capability == 'records' and copy.data_kid == fixture.kids['records']:
                if defect == 'missing-history':
                    continue
                if defect == 'changed-history':
                    key = b'x'*32
            raw.append((copy.capability, base64url_decode(copy.data_kid, expected_length=16), key))
        rings = {wrapper: Keyring(tuple(wrap_key_copy(key, project_id='project-1', capability=cap,
            data_kid=kid, wrapper_id=wrapper, wrapper_generation='successor-1', wrapping_key=b'n'*32)
            for cap, kid, key in raw)) for wrapper in ('recovery', 'control')}
        candidate = self.candidate(fixture, rings['recovery'])
        return candidate, rings['control']

    def test_successor_only_recovery_and_control_wrappers_verify_complete_rotated_history(self):
        from dracla.conformance import encode_keyring
        from dracla.records import verify_project
        for mode in ('recovery', 'control'):
            with self.subTest(mode=mode):
                f = EncryptedRepository(complete_history=True, rotate=True)
                candidate, control_ring = self.rewrap(f)
                if mode == 'recovery':
                    keys = WrappedKeys('recovery', lambda: {'successor-1': b'n'*32})
                    transport = f.reader()[1]
                else:
                    app = AppFixture()
                    app.protected = InstallationBinding(17, 'client-id', 19, 10,
                                                        (('project-1', (11, 12)),), (13,))
                    app.patch['/app'] = lambda v: {**v, 'owner': {'id': 10}}
                    app.patch['/app/installations/19'] = lambda v: {**v, 'account': {'id': 10}, 'target_id': 10}
                    for repo in app.repositories:
                        repo['owner']['id'] = 10
                    def sender(method, url, headers, timeout, body=None):
                        return (f.send if '/repos/' in url else app.send)(method, url, headers, timeout, body)
                    credentials = InstallationCredentials(app.protected, lambda: app.pem,
                                                          sender=sender, clock=lambda: app.now)
                    keys = WrappedKeys('control', lambda: {'successor-1': b'n'*32},
                        protected_keyrings=lambda oid: encode_keyring(control_ring) if oid == candidate else b'')
                    transport = RepositoryTransport(credentials)
                snapshot = open_history(f.binding, keys, transport)
                self.assertEqual(snapshot.state.current_kids, f.state.current_kids)
                self.assertEqual(snapshot.keys['records'][f.kids['records']], b'r'*32)
                report = verify_project(f.binding, keys, transport)
                self.assertTrue(report.valid, report.discrepancies)

    def test_successor_wrapper_cannot_replace_missing_or_changed_historical_key_bytes(self):
        for defect in ('missing-history', 'missing-current', 'changed-history', 'wrong-wrapper'):
            with self.subTest(defect=defect):
                f = EncryptedRepository(complete_history=True, rotate=True)
                self.rewrap(f, defect=defect)
                key = b'x'*32 if defect == 'wrong-wrapper' else b'n'*32
                keys = WrappedKeys('recovery', lambda: {'successor-1': key})
                with self.assertRaises(RecordsError):
                    open_history(f.binding, keys, f.reader()[1])

    def test_rewrap_cannot_change_bootstrap_manifest_or_project_context(self):
        from dracla.conformance import Keyring, canonical_json, wrap_key_copy
        for defect in ('manifest', 'project'):
            with self.subTest(defect=defect):
                f = EncryptedRepository(rotate=True)
                candidate, _ = self.rewrap(f)
                if defect == 'manifest':
                    files = copy.deepcopy(f.files['records', candidate])
                    manifest = json.loads(f.manifest)
                    manifest['release']['provenance_identity'] = 'different-install'
                    files['.dracla/bootstrap.json'] = canonical_json(manifest)
                    latest = f.commit('records', files, candidate)
                    f.values['/repos/acme/records/git/ref/heads/keys']['object']['sha'] = latest
                else:
                    foreign = wrap_key_copy(b'r'*32, project_id='other-project', capability='records',
                        data_kid=b'r'*16, wrapper_id='recovery', wrapper_generation='successor-1',
                        wrapping_key=b'n'*32)
                    self.candidate(f, Keyring((foreign,)))
                keys = WrappedKeys('recovery', lambda: {'successor-1': b'n'*32})
                with self.assertRaises(RecordsError):
                    open_history(f.binding, keys, f.reader()[1])


class TestVerifyInputAndFailures(unittest.TestCase):
    def test_recovery_prompt_is_private_and_never_accepts_duplicate_or_invalid_key_material(self):
        import warnings
        from getpass import GetPassWarning
        from unittest.mock import patch
        from dracla.cli.config import ConfigError,prompt_recovery_keys
        with patch('getpass.getpass',return_value=json.dumps({'install-1':'77'*32})):
            self.assertEqual(prompt_recovery_keys(),{'install-1':b'w'*32})
        for value in ('{"install-1":"PRIVATE"}','{"g":"77","g":"88"}','[]','x'*65537):
            with self.subTest(value=value[:20]),patch('getpass.getpass',return_value=value):
                with self.assertRaises(ConfigError) as caught:prompt_recovery_keys()
                self.assertNotIn('PRIVATE',str(caught.exception))
        def nonprivate(*args):warnings.warn('no private terminal',GetPassWarning)
        with patch('getpass.getpass',side_effect=nonprivate):
            with self.assertRaises(ConfigError):prompt_recovery_keys()

    def test_real_default_operator_command_and_failed_projection_exit_codes(self):
        import io
        from unittest.mock import patch
        from dracla.cli.app import main
        f=EncryptedRepository();out=io.StringIO();original=OperatorCredentials
        def operator(provider):return original(provider,sender=f.send)
        args=TestVerifyCommand().args(f)
        with patch('dracla.records.OperatorCredentials',side_effect=operator),patch(
                'getpass.getpass',return_value=json.dumps({'install-1':'77'*32})):
            self.assertEqual(main(args,output=out,release_loader=lambda:None,
                                  credential_provider=lambda:'opaque'),0,out.getvalue())
        f.values['/repos/acme/records/git/ref/heads/operations']['object']['sha']='f'*40
        out=io.StringIO()
        self.assertEqual(main(args,output=out,release_loader=lambda:None,verify_factory=lambda b:f.reader()),2)
        self.assertIn('Verification incomplete',out.getvalue())
        def secret_failure(binding):raise RuntimeError('PRIVATE KEY')
        out=io.StringIO()
        self.assertEqual(main(args,output=out,release_loader=lambda:None,verify_factory=secret_failure),1)
        self.assertNotIn('PRIVATE',out.getvalue())
        f.values['/repos/acme/records']['private']=False;out=io.StringIO()
        self.assertEqual(main(args,output=out,release_loader=lambda:None,verify_factory=lambda b:f.reader()),2)
        self.assertIn('identity-mismatch',out.getvalue())

    def test_closed_identity_overrides_and_exact_numeric_forms(self):
        from dracla.cli.config import ConfigError,compose_verify
        f=EncryptedRepository();args=TestVerifyCommand().args(f)[1:]
        for overrides in (args+['github.owner=again'],args[:-1],['not-an-override'],
                          [v.replace('records.id=11','records.id=01') for v in args],
                          [v.replace('coverage.id=12','coverage.id=11') for v in args]):
            with self.assertRaises(ConfigError):compose_verify(overrides)
        weird=[v.replace('project.id=project-1','project.id=opaque=identity') for v in args]
        self.assertEqual(compose_verify(weird).project_id,'opaque=identity')


class TestTransportResponseRejection(unittest.TestCase):
    def test_malformed_refs_parents_trees_and_blobs_cannot_return_partial_bytes(self):
        for defect in ('invalid-oid','ref-shape','missing-ref','parents-type','missing-parent',
                       'too-many-entries','duplicate-path','missing-tree','bad-path',
                       'blob-size-type','missing-blob','bad-base64','short-blob'):
            with self.subTest(defect=defect):
                t,v,calls,commit,tree,oid,raw=TestImmutableTransport().fixture();prefix='/repos/acme/records/git/'
                if defect=='invalid-oid':
                    v[prefix+'ref/heads/events']['object']['sha']='not-an-oid'
                if defect=='ref-shape':v[prefix+'ref/heads/events']['object']['type']='tag'
                if defect=='missing-ref':del v[prefix+'ref/heads/events']['object']
                if defect=='parents-type':v[prefix+'commits/'+commit]['parents']=''
                if defect=='missing-parent':del v[prefix+'commits/'+commit]['parents']
                if defect=='too-many-entries':t.max_entries=1;v[prefix+'trees/'+tree+'?recursive=1']['tree']*=2
                if defect=='duplicate-path':v[prefix+'trees/'+tree+'?recursive=1']['tree']*=2
                if defect=='missing-tree':del v[prefix+'trees/'+tree+'?recursive=1']['tree']
                if defect=='bad-path':v[prefix+'trees/'+tree+'?recursive=1']['tree'][0]['path']='../escape'
                if defect=='blob-size-type':v[prefix+'blobs/'+oid]['size']=True
                if defect=='missing-blob':del v[prefix+'blobs/'+oid]['content']
                if defect=='bad-base64':v[prefix+'blobs/'+oid]['content']='!!!'
                if defect=='short-blob':v[prefix+'blobs/'+oid]['content']=base64.b64encode(b'x').decode()
                with self.assertRaises(RecordsError):
                    if defect.endswith('ref') or defect in ('invalid-oid','ref-shape'):t.head(BINDING.repo('records'),'events')
                    else:t.read(BINDING.repo('records'),commit,'README.md')

    def test_nested_tree_rows_are_not_files_and_branch_scope_is_closed(self):
        t,v,calls,commit,tree,oid,raw=TestImmutableTransport().fixture()
        v['/repos/acme/records/git/trees/'+tree+'?recursive=1']['tree'].append(
            {'path':'directory','mode':'040000','type':'tree','sha':'c'*40})
        self.assertEqual(t.read(BINDING.repo('records'),commit,'README.md'),raw)
        self.assertNotIn('directory',t.tree(BINDING.repo('records'),commit))
        self.assertNotIn('opaque',repr(t));self.assertNotIn('opaque',repr(t.credentials))
        for repo,branch in ((BINDING.repo('coverage'),'events'),(BINDING.repo('records'),'coverage'),(BINDING.repo('records'),'unknown')):
            with self.assertRaises(RecordsError):t.head(repo,branch)
        with self.assertRaises(RecordsError):RepositoryTransport(t.credentials,max_entries=0)

    def test_network_errors_and_invalid_url_or_operator_identity_are_redacted(self):
        def network(*args):raise TimeoutError('PRIVATE')
        with self.assertRaises(RecordsError) as caught:request_json(network,'GET','/user','opaque')
        self.assertNotIn('PRIVATE',str(caught.exception))
        for path in ('https://evil.test','//evil.test/path','/user#fragment','/user\nHeader:injected'):
            with self.assertRaises(RecordsError):request_json(network,'GET',path,'opaque')
        p=OperatorCredentials(lambda:'opaque',sender=lambda *args:response({'id':True,'login':'operator'}))
        with self.assertRaises(RecordsError):p.authorize(BINDING)

    def test_unexpected_inventory_count_and_incomplete_pages_fail_before_data_token(self):
        for count,repos in ((True,[]),(3,[]),(1,[{'id':11,'private':True,'owner':{'id':7}},
                                                {'id':12,'private':True,'owner':{'id':7}}])):
            f=AppFixture();f.patch['/installation/repositories?per_page=100&page=1']=lambda v:{'total_count':count,'repositories':repos}
            with self.assertRaises(RecordsError):f.provider().authorize(BINDING)
            self.assertEqual(len(f.mints),1)

    def test_bound_owner_is_checked_before_app_key_access(self):
        f=AppFixture();calls=[]
        p=InstallationCredentials(f.protected,lambda:calls.append('private-key'),sender=f.send)
        with self.assertRaises(RecordsError):p.authorize(ProjectBinding('project-1',8,BINDING.repositories))
        self.assertEqual(calls,[])


if __name__ == '__main__':
    unittest.main()
