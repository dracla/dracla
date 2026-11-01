#!/usr/bin/env python3
"""External production gate. Run only from the adopter-pinned bootstrap image.

No downloaded DraCLA module is imported until launch() has rechecked both the
release evidence and the wheel-derived installed file map. Network and process
boundaries are injectable for concrete negative tests, not executable config.
"""
from __future__ import annotations

import argparse
import base64
import configparser
import csv
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import urllib.error
import urllib.request
import venv
import zipfile

if sys.argv[1:] not in (['fetch-inputs'], ['fetch-bootstrap']):
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.tags import parse_tag, sys_tags
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.version import Version

HERE = Path(__file__).resolve().parent
BUILD_TYPE = 'https://actions.github.io/buildtypes/workflow/v1'
SLSA = 'https://slsa.dev/provenance/v1'
PUBLISH = 'https://docs.pypi.org/attestations/publish/v1'
ISSUER = 'https://token.actions.githubusercontent.com'
MAX_JSON = 8 * 1024 * 1024
MAX_WHEEL = 64 * 1024 * 1024
PIP_VERSION = '26.2.1'
IMAGE_PATTERN = (r'(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?/)?'
                 r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*'
                 r'@sha256:[0-9a-f]{64}')


class VerificationError(ValueError):
    """Fixed diagnostics; neither provider payloads nor secret values escape."""


def require(condition):
    if not condition:
        raise VerificationError('production-verification-failed')


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    require(len(raw) <= MAX_JSON)
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def regular(path, limit=MAX_WHEEL):
    """Do not follow even the final component of an attacker-swapped file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit)
        raw = stream.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        stream.truncate(0)
        stream.write(raw)


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys.split()))
    return value


def profile(raw):
    value = decode(raw)
    closed(value, 'profile_version package_version source publisher builder bootstrap runtime')
    closed(value['source'], 'repository_url repository_id commit_oid ref')
    closed(value['bootstrap'], 'image trust_root_sha256')
    closed(value['runtime'], 'python_version abi platform wheel runtime_lock_sha256 build_lock_sha256')
    closed(value['runtime']['wheel'], 'filename sha256')
    for role in ('publisher', 'builder'):
        closed(value[role], 'workflow commit_oid certificate_identity')
    require(type(value['profile_version']) is int and type(value['source']['repository_id']) is int)
    require(value['profile_version'] == 1 and value['source']['repository_id'] > 0)
    source = value['source']
    require(type(value['package_version']) is str and len(value['package_version']) <= 128)
    require(re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', source['repository_url']) is not None)
    require(re.fullmatch(r'refs/(tags|heads)/[A-Za-z0-9][A-Za-z0-9._/-]*', source['ref']) is not None)
    require(re.fullmatch(IMAGE_PATTERN, value['bootstrap']['image']) is not None)
    require(len(set(value['bootstrap']['image'].split('@sha256:')[1])) > 1)
    require(all(part not in ('.', '..') for part in source['repository_url'].split('/')[3:]))
    limits = [(source['repository_url'], 512), (source['ref'], 512), (value['bootstrap']['image'], 1024),
              (value['runtime']['python_version'], 32), (value['runtime']['abi'], 16),
              (value['runtime']['platform'], 128), (value['runtime']['wheel']['filename'], 255)]
    for role in ('publisher', 'builder'):
        limits += [(value[role]['workflow'], 1024), (value[role]['certificate_identity'], 2048)]
    require(all(type(text) is str and 0 < len(text) <= limit for text, limit in limits))
    for text in (source['commit_oid'], value['publisher']['commit_oid'], value['builder']['commit_oid']):
        require(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', text) is not None and len(set(text)) > 1)
    require(str(Version(value['package_version'])) == value['package_version'])
    for selector in (source['ref'],):
        require(not any(part in ('', '.', '..') for part in selector.split('/')))
        require(not selector.endswith(('.lock', '/')) and '..' not in selector and '@{' not in selector)
    for role in ('publisher', 'builder'):
        workflow = value[role]
        require(re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', workflow['workflow']) is not None)
        require(workflow['workflow'].startswith(source['repository_url'] + '/.github/workflows/'))
        require(workflow['certificate_identity'] == workflow['workflow'] + '@' + source['ref'])
        require(workflow['commit_oid'] == source['commit_oid'])
    for pin in (value['bootstrap']['trust_root_sha256'], value['runtime']['wheel']['sha256'],
                value['runtime']['runtime_lock_sha256'], value['runtime']['build_lock_sha256']):
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', pin) is not None and len(set(pin.split(':')[1])) > 1)
    require(value['runtime']['python_version'] == '.'.join(map(str, sys.version_info[:3])))
    require(value['runtime']['abi'] == 'cp' + ''.join(map(str, sys.version_info[:2])))
    require(value['runtime']['python_version'] == '3.12.16' and value['runtime']['abi'] == 'cp312')
    require(value['runtime']['platform'] == 'manylinux_2_36_x86_64' and sys.platform == 'linux')
    require(os.uname().machine == 'x86_64')
    require(re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', value['runtime']['wheel']['filename']) is not None)
    name, version, _, tags = parse_wheel_filename(value['runtime']['wheel']['filename'])
    require(name == 'dracla' and str(version) == value['package_version'] and tags & set(sys_tags()))
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise VerificationError('production-verification-failed')


def fetch(url, limit=MAX_JSON):
    ordinary = re.fullmatch(r'https://(?:api\.github\.com|raw\.githubusercontent\.com|pypi\.org|files\.pythonhosted\.org)/[A-Za-z0-9._/+:\-]+', url)
    bundle = re.fullmatch(r'https://tmaproduction\.blob\.core\.windows\.net/attestations/[1-9][0-9]*/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]+\.json\.sn\?[A-Za-z0-9%=&+_.:\-]+', url)
    require(ordinary is not None or bundle is not None)
    require(all(part not in ('', '.', '..') for part in url.split('/')[3:]))
    request = urllib.request.Request(url, headers={'User-Agent': 'DraCLA-external-verifier',
                                                  'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url)
        data = response.read(limit + 1)
    require(len(data) <= limit)
    return data


def github_bundle(attestation, repository_id, *, download=fetch):
    """GitHub's public bundle URL carries raw Snappy, never API credentials."""
    from cramjam import snappy
    require(type(attestation) is dict and attestation.get('repository_id') == repository_id)
    url = attestation.get('bundle_url')
    require(type(url) is str and len(url) <= 4096)
    require(re.fullmatch(r'https://tmaproduction\.blob\.core\.windows\.net/attestations/' + str(repository_id)
            + r'/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]+\.json\.sn\?[A-Za-z0-9%=&+_.:\-]+', url) is not None)
    raw = download(url)
    require(len(raw) <= MAX_JSON and 0 < snappy.decompress_raw_len(raw) <= MAX_JSON)
    bundle = decode(bytes(snappy.decompress_raw(raw)))
    require(type(bundle) is dict)
    return bundle


def run(argv, *, cwd=None):
    # No ambient Python, loader, gh alias/config, credentials or executable path.
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp',
                   'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                   'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_CONFIG_FILE': '/dev/null',
                   'GH_CONFIG_DIR': '/nonexistent', 'GH_NO_UPDATE_NOTIFIER': '1'}
    result = subprocess.run(argv, cwd=cwd, env=environment, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=180, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON)
    return result.stdout


def entries(items):
    require(type(items) is list and 0 < len(items) <= 100)
    names, filenames = set(), set()
    for item in items:
        closed(item, 'name version filename tags url sha256')
        name, version, _, tags = parse_wheel_filename(item['filename'])
        require(name == item['name'] == canonicalize_name(item['name'], validate=True))
        require(str(version) == item['version'] and name not in names and item['filename'] not in filenames)
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', item['filename']) is not None)
        require(type(item['tags']) is list and sorted(map(str, tags)) == item['tags'])
        require(bool(tags & set(sys_tags())) and re.fullmatch(r'sha256:[0-9a-f]{64}', item['sha256']) is not None)
        require(item['url'].startswith('https://files.pythonhosted.org/packages/') and item['url'].endswith('/' + item['filename']))
        names.add(name); filenames.add(item['filename'])
    return items


def locks(runtime_raw, build_raw, selected):
    require(digest(runtime_raw) == selected['runtime']['runtime_lock_sha256'])
    require(digest(build_raw) == selected['runtime']['build_lock_sha256'])
    runtime = closed(decode(runtime_raw), 'lock_version python_version abi platform wheels')
    require(type(runtime['lock_version']) is int and runtime['lock_version'] == 1)
    require(all(runtime[k] == selected['runtime'][k] for k in ('python_version', 'abi', 'platform')))
    entries(runtime['wheels']); require(all(w['name'] != 'dracla' for w in runtime['wheels']))
    build = closed(decode(build_raw), 'lock_version container build_wheels bootstrap_wheels actions gh trusted_root')
    require(type(build['lock_version']) is int and build['lock_version'] == 1)
    require(re.fullmatch(r'python@sha256:[0-9a-f]{64}', build['container']) is not None)
    entries(build['build_wheels']); entries(build['bootstrap_wheels'])
    require(any(w['name'] == 'pip' and w['version'] == PIP_VERSION for w in build['build_wheels']))
    require(type(build['actions']) is dict and set(build['actions']) == {
        'actions/checkout', 'actions/attest', 'actions/upload-artifact',
        'actions/download-artifact', 'pypa/gh-action-pypi-publish'})
    require(all(re.fullmatch(r'[0-9a-f]{40}', v) for v in build['actions'].values()))
    closed(build['trusted_root'], 'url sha256')
    require(build['trusted_root']['sha256'] == selected['bootstrap']['trust_root_sha256'])
    return runtime, build


def dependencies(selected, runtime, build):
    """The exact SLSA resolvedDependencies set produced from consumed bytes."""
    source = selected['source']
    result = [('git+' + source['repository_url'] + '@' + source['ref'], 'gitCommit', source['commit_oid'])]
    for name, key in (('runtime-wheels.lock', 'runtime_lock_sha256'), ('build-inputs.lock.json', 'build_lock_sha256')):
        result.append((source['repository_url'] + '/release/' + name, 'sha256', selected['runtime'][key][7:]))
    result.append(('pkg:docker/python', 'sha256', build['container'].split(':')[1]))
    for wheel in runtime['wheels'] + build['build_wheels']:
        result.append((wheel['url'], 'sha256', wheel['sha256'][7:]))
    for action in ('actions/checkout', 'actions/attest', 'actions/upload-artifact'):
        result.append(('https://github.com/' + action, 'gitCommit', build['actions'][action]))
    return set(result)


def statement(result, selected, role, predicate_type):
    value = result['verificationResult']
    log_entries = result['attestation']['bundle']['verificationMaterial']['tlogEntries']
    require(type(log_entries) is list and bool(log_entries) and all(
        type(entry.get('inclusionProof')) is dict
        and type(entry['inclusionProof'].get('checkpoint', {}).get('envelope')) is str
        and entry['inclusionProof']['checkpoint']['envelope']
        for entry in log_entries))
    cert = value['signature']['certificate']
    source, workflow = selected['source'], selected[role]
    require(cert['issuer'] == ISSUER and cert['subjectAlternativeName'] == workflow['certificate_identity'])
    require(cert['sourceRepositoryIdentifier'] == str(source['repository_id']))
    require(cert['sourceRepositoryURI'] == source['repository_url'] and cert['sourceRepositoryDigest'] == source['commit_oid'])
    require(cert['sourceRepositoryRef'] == source['ref'] and cert['runnerEnvironment'] == 'github-hosted')
    require(cert['buildSignerURI'] == workflow['certificate_identity'] and cert['buildSignerDigest'] == workflow['commit_oid'])
    witnessed = [t for t in value['verifiedTimestamps'] if t['type'] == 'Tlog']
    require(bool(witnessed))
    for timestamp in witnessed:
        time = datetime.fromisoformat(timestamp['timestamp'].replace('Z', '+00:00'))
        require(time.tzinfo is not None and datetime(2020, 1, 1, tzinfo=timezone.utc) <= time <= datetime.now(timezone.utc))
    claim = value['statement']
    require(claim['_type'] == 'https://in-toto.io/Statement/v1' and claim['predicateType'] == predicate_type)
    require(claim['subject'] == [{'name': selected['runtime']['wheel']['filename'],
                                  'digest': {'sha256': selected['runtime']['wheel']['sha256'][7:]}}])
    # The pinned CLI's protobuf JSON output omits a null/empty publish
    # predicate. It remains null in the verified statement model; build
    # evidence still requires its complete non-null predicate below.
    return claim.get('predicate')


def verified_claims(output, selected, runtime, build, *, role):
    results = decode(output)
    require(type(results) is list and 0 < len(results) <= 100)
    # A matching verified attestation is enough; unrelated valid historical
    # attestations returned by GitHub do not authorize a different candidate.
    for result in results:
        try:
            predicate = statement(result, selected, role, SLSA if role == 'builder' else PUBLISH)
            if role == 'publisher':
                require(predicate in ({}, None))
            else:
                definition = predicate['buildDefinition']
                require(definition['buildType'] == BUILD_TYPE)
                wf = selected['builder']['workflow']
                require(definition['externalParameters'] == {'workflow': {
                    'repository': selected['source']['repository_url'],
                    'path': selected['publisher']['workflow'].split(selected['source']['repository_url'] + '/')[1],
                    'ref': selected['source']['ref']}})
                context = closed(definition['internalParameters'], 'github')['github']
                closed(context, 'event_name repository_id repository_owner_id runner_environment')
                cert = result['verificationResult']['signature']['certificate']
                require(context['repository_id'] == str(selected['source']['repository_id'])
                        and context['repository_owner_id'] == cert['sourceRepositoryOwnerIdentifier']
                        and re.fullmatch(r'[1-9][0-9]*', context['repository_owner_id']) is not None
                        and context['runner_environment'] == 'github-hosted'
                        and context['event_name'] == cert['buildTrigger']
                        and context['event_name'] in ('create', 'release', 'push', 'workflow_dispatch'))
                require(predicate['runDetails']['builder']['id'] == wf + '@' + selected['builder']['commit_oid'])
                actual = []
                for item in definition['resolvedDependencies']:
                    require(set(item) == {'uri', 'digest'} and len(item['digest']) == 1)
                    algorithm, value = next(iter(item['digest'].items()))
                    actual.append((item['uri'], algorithm, value))
                require(len(actual) == len(set(actual)) and set(actual) == dependencies(selected, runtime, build))
            return
        except (VerificationError, KeyError, TypeError, ValueError):
            continue
    require(False)


def gh_verify(wheel, selected, root, *, role, bundle=None, execute=run):
    workflow = selected[role]
    args = ['/usr/bin/gh', 'attestation', 'verify', str(wheel), '--format', 'json',
            '--custom-trusted-root', str(root), '--cert-oidc-issuer', ISSUER,
            '--repo',
            selected['source']['repository_url'].removeprefix('https://github.com/'),
            '--signer-digest', workflow['commit_oid'], '--source-digest', selected['source']['commit_oid'],
            '--source-ref', selected['source']['ref'], '--deny-self-hosted-runners',
            '--predicate-type', SLSA if role == 'builder' else PUBLISH]
    # gh makes these flags mutually exclusive. Each branch enforces the exact
    # workflow/ref identity; the verified certificate is also checked above.
    args += (['--signer-workflow', workflow['certificate_identity'].removeprefix('https://github.com/')]
             if role == 'builder' else ['--cert-identity', workflow['certificate_identity']])
    if bundle is not None:
        args += ['--bundle', str(bundle)]
    return execute(args)


def wheel_contents(raw, filename):
    """Validate ZIP paths, types, metadata and wheel RECORD before installation."""
    name, version, _, _ = parse_wheel_filename(filename)
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(len(archive.infolist()) <= 20000 and sum(i.file_size for i in archive.infolist()) <= 256 * 1024 * 1024)
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            require(not path.is_absolute() and all(p not in ('', '.', '..') for p in info.filename.rstrip('/').split('/')))
            require('\\' not in info.filename and not info.flag_bits & 1)
            mode = info.external_attr >> 16
            require(not stat.S_ISLNK(mode) and (stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)))
            if info.is_dir():
                continue
            require(info.filename not in result and not info.filename.endswith(('.pyc', '.pth')))
            require('.data/' not in info.filename)  # This selected profile needs no relocation/hooks.
            result[info.filename] = archive.read(info)
    roots = {p.split('/')[0] for p in result if p.endswith('.dist-info/METADATA')}
    require(len(roots) == 1)
    dist = roots.pop()
    metadata = BytesParser().parsebytes(result[dist + '/METADATA'])
    require(canonicalize_name(metadata['Name']) == name and Version(metadata['Version']) == version)
    require(BytesParser().parsebytes(result[dist + '/WHEEL'])['Wheel-Version'] == '1.0')
    record = list(csv.reader(io.StringIO(result[dist + '/RECORD'].decode())))
    require(len(record) == len(result) and {r[0] for r in record} == set(result))
    for path, hashed, size in record:
        if path == dist + '/RECORD':
            require(hashed == size == '')
        else:
            require(hashed == 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(result[path]).digest()).rstrip(b'=').decode())
            require(size == str(len(result[path])))
    return dist, metadata, result


def wheel_set(wheelhouse, selected, runtime):
    expected = {w['filename']: w for w in runtime['wheels']}
    expected[selected['runtime']['wheel']['filename']] = {'name': 'dracla', 'version': selected['package_version'],
        **selected['runtime']['wheel']}
    require(set(p.name for p in wheelhouse.iterdir()) == set(expected))
    parsed = {}
    for filename, item in expected.items():
        raw = regular(wheelhouse / filename)
        require(digest(raw) == item['sha256'])
        parsed[item['name']] = wheel_contents(raw, filename)
    # A finite closure check, not a package resolver. Extras and direct URLs are
    # outside this tested profile. Every selected wheel must be reachable.
    pending, seen = ['dracla'], set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for text in parsed[name][1].get_all('Requires-Dist', []):
            req = Requirement(text)
            if req.marker and not req.marker.evaluate({**default_environment(), 'extra': ''}):
                continue
            require(req.url is None and not req.extras)
            dep = canonicalize_name(req.name)
            require(dep in parsed and req.specifier.contains(parsed[dep][1]['Version'], prereleases=True))
            pending.append(dep)
    require(seen == set(parsed))
    constraints = parsed['dracla'][2]['dracla/dependency-constraints.txt'].decode()
    require(constraints == ''.join(w['name'] + '==' + w['version'] + '\n' for w in sorted(runtime['wheels'], key=lambda w: w['name'])))
    policy_raw = parsed['dracla'][2]['dracla/release-policy.json']
    policy = closed(decode(policy_raw), 'release_policy_version package_version source_commit_oid provenance_identity dependency_constraints_sha256')
    require(policy_raw == json.dumps(policy, sort_keys=True, separators=(',', ':')).encode())
    require(type(policy['release_policy_version']) is int and policy['release_policy_version'] == 1)
    require(policy['package_version'] == selected['package_version']
            and policy['source_commit_oid'] == selected['source']['commit_oid']
            and policy['provenance_identity'] == selected['builder']['workflow'] + '@' + selected['builder']['commit_oid']
            and policy['dependency_constraints_sha256'] == digest(constraints.encode()))
    return parsed


def verify(state, selected, *, download=fetch, execute=run, root=Path('/opt/dracla/trusted_root.json')):
    require(not state.is_symlink() and stat.S_IMODE(state.stat().st_mode) == 0o700)
    require(digest(regular(root)) == selected['bootstrap']['trust_root_sha256'])
    # gh consumes one standard TrustedRoot JSON object per newline. Keep the
    # protected hash on the original snapshot, then adapt only its whitespace.
    gh_root = state / 'trusted_root.jsonl'
    private_write(gh_root, (json.dumps(decode(regular(root)), separators=(',', ':')) + '\n').encode())
    runtime, build = locks(regular(state / 'runtime-wheels.lock'), regular(state / 'build-inputs.lock.json'), selected)
    repo = decode(download('https://api.github.com/repos/' + selected['source']['repository_url'].removeprefix('https://github.com/')))
    require(type(repo['id']) is int and repo['id'] == selected['source']['repository_id'])
    require(repo['html_url'] == selected['source']['repository_url'] and repo['private'] is False)
    wheelhouse = state / 'wheels'
    parsed = wheel_set(wheelhouse, selected, runtime)
    wheel = wheelhouse / selected['runtime']['wheel']['filename']
    verified_claims(gh_verify(wheel, selected, gh_root, role='builder', bundle=state / 'build.sigstore.jsonl', execute=execute),
                    selected, runtime, build, role='builder')
    # This API only converts a format. gh authenticates the resulting bundle.
    from pypi_attestations import Attestation
    attestation = Attestation.model_validate_json(regular(state / 'publish.attestation.json'))
    bundle = state / 'publish.sigstore.json'
    private_write(bundle, attestation.to_bundle().to_json().encode())
    verified_claims(gh_verify(wheel, selected, gh_root, role='publisher', bundle=bundle, execute=execute),
                    selected, runtime, build, role='publisher')
    return runtime, build, parsed


def config_bytes():
    return ('home = ' + str(Path(sys.executable).resolve().parent) + '\n'
            'include-system-site-packages = false\n'
            'version = ' + '.'.join(map(str, sys.version_info[:3])) + '\n').encode()


def site_path():
    return Path('lib/python' + '.'.join(map(str, sys.version_info[:2])) + '/site-packages')


def installed_map(environment, wheelhouse, parsed):
    """Expected contents come from wheels, not the installed RECORD or flags.

    Pinned pip supplies its own script template. No wheel module or entry point
    runs while generating these expected bytes. RECORD is validated separately
    against this map because pip legitimately rewrites its rows and ordering.
    """
    from importlib.metadata import version
    from pip._internal.operations.install.wheel import PipScriptMaker
    from pip._internal.models.direct_url import DirectUrl
    require(version('pip') == PIP_VERSION)
    site = site_path()
    expected = {'bin/python': regular(Path(sys.executable).resolve()), 'pyvenv.cfg': config_bytes()}
    records = []
    for name, (dist, _, files) in parsed.items():
        record_path = str(site / dist / 'RECORD')
        records.append(record_path)
        for path, raw in files.items():
            if path != dist + '/RECORD':
                destination = str(site / path)
                require(destination not in expected)
                expected[destination] = raw
        for filename, raw in [('INSTALLER', b'pip\n'), ('REQUESTED', b'')]:
            expected[str(site / dist / filename)] = raw
        wheel = next(p for p in wheelhouse.iterdir() if parse_wheel_filename(p.name)[0] == name)
        direct = {'url': wheel.absolute().as_uri(), 'archive_info': {
            'hash': 'sha256=' + digest(regular(wheel))[7:], 'hashes': {'sha256': digest(regular(wheel))[7:]}}}
        expected[str(site / dist / 'direct_url.json')] = DirectUrl.from_dict(direct).to_json().encode()
        if dist + '/entry_points.txt' in files:
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(files[dist + '/entry_points.txt'].decode())
            # Other groups are metadata (e.g. cffi's setuptools plugin), never
            # executable hooks of this installer or runtime launcher.
            for group in ('console_scripts', 'gui_scripts'):
                if group not in parser:
                    continue
                with tempfile.TemporaryDirectory(prefix='dracla-script-template-') as directory:
                    maker = PipScriptMaker(None, directory)
                    maker.executable = str(environment / 'bin/python')
                    maker.clobber, maker.variants, maker.set_mode = True, {''}, True
                    for entry, target in parser[group].items():
                        require(re.fullmatch(r'[A-Za-z0-9_-]+', entry) is not None)
                        generated = maker.make(entry + ' = ' + target, options={'gui': group == 'gui_scripts'})
                        require(len(generated) == 1)
                        destination = 'bin/' + Path(generated[0]).name
                        require(destination not in expected)
                        expected[destination] = regular(generated[0])
    return expected, records


def check_environment(environment, wheelhouse, parsed):
    require(environment.is_absolute() and not environment.is_symlink())
    require(stat.S_IMODE(environment.stat().st_mode) == 0o700)
    expected, records = installed_map(environment, wheelhouse, parsed)
    directories = {str(parent) for relative in set(expected) | set(records)
                   for parent in Path(relative).parents if str(parent) != '.'}
    directories.update({'include', 'include/python' + '.'.join(map(str, sys.version_info[:2]))})
    actual = set()
    for directory, dirs, files in os.walk(environment, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            require(not path.is_symlink() and str(path.relative_to(environment)) in directories)
        for name in files:
            path = Path(directory) / name
            relative = str(path.relative_to(environment))
            require(relative in expected or relative in records)
            raw = regular(path)
            if relative in expected:
                require(raw == expected[relative])
            if path.stat().st_mode & 0o111:
                require(relative.startswith('bin/') or relative.endswith(('.so', '.dylib')))
            actual.add(relative)
    require(actual == set(expected) | set(records))
    # A RECORD row is not evidence for a file. It must instead match the map
    # above, including every wheel member and pinned-pip generated file.
    for record in records:
        rows = list(csv.reader(io.StringIO(regular(environment / record).decode())))
        seen = set()
        for path, hashed, size in rows:
            absolute = Path(os.path.normpath(str(environment / site_path() / path)))
            require(absolute.is_relative_to(environment))
            relative = str(absolute.relative_to(environment))
            require(relative not in seen and relative in actual)
            seen.add(relative)
            if relative == record:
                require(hashed == size == '')
            else:
                raw = expected[relative]
                require(hashed == 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode())
                require(size == str(len(raw)))
        dist = Path(record).parent.name
        required = {str(site_path() / p) for _, (_, _, files) in parsed.items() for p in files if p.startswith(dist + '/')}
        require(required <= seen)


def install(state, selected, runtime, parsed, *, execute=run):
    environment = state / 'environment'
    require(not environment.exists() and not environment.is_symlink())
    venv.EnvBuilder(with_pip=False, symlinks=False).create(environment)
    os.chmod(environment, 0o700)
    for path in (environment / 'bin').iterdir():
        if path.name != 'python':
            path.unlink()
    if (environment / 'lib64').is_symlink():
        (environment / 'lib64').unlink()
    (environment / 'pyvenv.cfg').write_bytes(config_bytes())
    requirements = state / 'install.requirements'
    wheels = runtime['wheels'] + [selected['runtime']['wheel']]
    private_write(requirements, ''.join((state / 'wheels' / w['filename']).absolute().as_uri()
                                       + ' --hash=' + w['sha256'] + '\n' for w in wheels).encode())
    execute([sys.executable, '-I', '-m', 'pip', '--isolated', '--python', str(environment / 'bin/python'),
             'install', '--no-index', '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-compile',
             '--no-warn-script-location', '-r', str(requirements)])
    check_environment(environment, state / 'wheels', parsed)


def prepare(state, selected, *, download=fetch, execute=run):
    require(not state.exists() and not state.is_symlink())
    state.mkdir(mode=0o700, parents=False)
    source = selected['source']
    repository = source['repository_url'].removeprefix('https://github.com/')
    identity = decode(download('https://api.github.com/repos/' + repository))
    require(identity['id'] == source['repository_id'] and identity['html_url'] == source['repository_url']
            and identity['private'] is False)
    origin = 'https://raw.githubusercontent.com/' + repository + '/' + source['commit_oid'] + '/release/'
    for name in ('runtime-wheels.lock', 'build-inputs.lock.json'):
        private_write(state / name, download(origin + name))
    runtime, _ = locks(regular(state / 'runtime-wheels.lock'), regular(state / 'build-inputs.lock.json'), selected)
    (state / 'wheels').mkdir(mode=0o700)
    artifact = selected['runtime']['wheel']
    release = decode(download('https://pypi.org/pypi/dracla/' + selected['package_version'] + '/json'))
    matches = [u for u in release['urls'] if u['filename'] == artifact['filename'] and u['packagetype'] == 'bdist_wheel'
               and u['digests']['sha256'] == artifact['sha256'][7:] and u['yanked'] is False]
    require(len(matches) == 1)
    for item in runtime['wheels'] + [{'url': matches[0]['url'], **artifact}]:
        raw = download(item['url'], MAX_WHEEL)
        require(digest(raw) == item['sha256'])
        private_write(state / 'wheels' / item['filename'], raw)
    wheel = state / 'wheels' / artifact['filename']
    # Public source evidence is retrieved without credentials. Standard
    # bundles are transport data; gh supplies their crypto authority.
    attestations = decode(download('https://api.github.com/repos/' + repository + '/attestations/' + artifact['sha256']))['attestations']
    require(type(attestations) is list and 0 < len(attestations) <= 100)
    bundles = bytearray()
    for attestation in attestations:
        entry = (json.dumps(github_bundle(attestation, source['repository_id'], download=download)) + '\n').encode()
        require(len(bundles) + len(entry) <= MAX_JSON)
        bundles.extend(entry)
    private_write(state / 'build.sigstore.jsonl', bundles)
    evidence = decode(download('https://pypi.org/integrity/dracla/' + selected['package_version'] + '/' + artifact['filename'] + '/provenance'))
    attestations = [a for group in evidence['attestation_bundles'] for a in group['attestations']]
    require(len(attestations) == 1)
    private_write(state / 'publish.attestation.json', json.dumps(attestations[0]).encode())
    runtime, _, parsed = verify(state, selected, download=download, execute=execute)
    install(state, selected, runtime, parsed, execute=execute)


def launch(state, selected, configuration, operation, *, execute=run):
    require(operation in ('verify', 'reconcile', 'export', 'probe'))
    execution_repository_id = os.environ.get('DRACLA_CONTROL_REPOSITORY_ID')
    require(type(execution_repository_id) is str
            and re.fullmatch(r'[1-9][0-9]*', execution_repository_id) is not None)
    _, _, parsed = verify(state, selected, execute=execute)
    environment = state / 'environment'
    check_environment(environment, state / 'wheels', parsed)
    # Fixed trusted code and only this explicit site directory enter isolated
    # Python. -S prevents site hooks; -I prevents current-dir/user/PYTHONPATH input.
    code = ('import sys; sys.path.insert(0, sys.argv.pop(1)); '
            'from dracla.records.github import control_job; '
            'raise SystemExit(control_job(sys.argv[1], sys.argv[2]))')
    allowed = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent',
               'PYTHONDONTWRITEBYTECODE': '1'}
    for key in ('DRACLA_TRANSPORT_APP_KEY', 'DRACLA_CONTROL_KEYS'):
        require(key in os.environ)
        allowed[key] = os.environ[key]
    allowed['DRACLA_CONTROL_REPOSITORY_ID'] = execution_repository_id
    for key in ('DRACLA_CONTROL_WORKFLOW_REF', 'DRACLA_CONTROL_WORKFLOW_OID'):
        if key in os.environ:
            allowed[key] = os.environ[key]
    os.chdir('/')
    os.execve(str(environment / 'bin/python'), [str(environment / 'bin/python'), '-I', '-S', '-c', code,
              str(environment / site_path()), str(configuration), operation], allowed)


def produce():
    """Fixed offline builder command inside the hash-pinned Python container."""
    import tomllib
    source, inputs, output = Path('/source'), Path('/inputs'), Path('/output')
    oid = os.environ['DRACLA_SOURCE_OID']
    repository = os.environ['DRACLA_SOURCE_REPOSITORY']
    ref = os.environ['DRACLA_SOURCE_REF']
    require(re.fullmatch(r'[0-9a-f]{40}', oid) is not None)
    require(oid == os.environ['DRACLA_WORKFLOW_OID'])
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) is not None)
    require(re.fullmatch(r'refs/(heads|tags)/[A-Za-z0-9._/-]+', ref) is not None)
    require(os.environ['DRACLA_WORKFLOW_REF'] == repository + '/.github/workflows/release.yml@' + ref)
    context = {name: os.environ['DRACLA_' + name.upper()] for name in
               ('event_name', 'repository_id', 'repository_owner_id', 'runner_environment')}
    require(context['event_name'] in ('create', 'release', 'push', 'workflow_dispatch')
            and context['runner_environment'] == 'github-hosted'
            and re.fullmatch(r'[1-9][0-9]*', context['repository_id']) is not None
            and re.fullmatch(r'[1-9][0-9]*', context['repository_owner_id']) is not None)
    runtime_raw, build_raw = regular(source / 'release/runtime-wheels.lock'), regular(source / 'release/build-inputs.lock.json')
    runtime, build = decode(runtime_raw), decode(build_raw)
    # Each installed input was hash-checked before the network was disabled.
    # Check the complete consumed directory again, including duplicate shared
    # wheels only once, before generating claims from these actual bytes.
    consumed = {w['filename']: w for w in entries(build['build_wheels'])}
    consumed.update({w['filename']: w for w in entries(runtime['wheels'])})
    require({p.name for p in (inputs / 'wheels').iterdir()} == set(consumed))
    for filename, item in consumed.items():
        require(digest(regular(inputs / 'wheels' / filename)) == item['sha256'])
    for action, sha in build['actions'].items():
        files = (source / '.github/workflows').glob('*.yml')
        require(any((action + '@' + sha) in regular(p).decode() for p in files))
    work = Path('/work/source')
    require(not work.exists())
    work.mkdir(parents=True)
    for name in ('pyproject.toml', 'README.md', 'LICENSE'):
        shutil.copyfile(source / name, work / name)
    shutil.copytree(source / 'core', work / 'core', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    version = tomllib.loads(regular(work / 'pyproject.toml').decode())['project']['version']
    constraints = ''.join(w['name'] + '==' + w['version'] + '\n' for w in runtime['wheels']).encode()
    (work / 'core/dracla/dependency-constraints.txt').write_bytes(constraints)
    policy = {'release_policy_version': 1, 'package_version': version, 'source_commit_oid': oid,
              'provenance_identity': 'https://github.com/' + repository + '/.github/workflows/build-release.yml@' + oid,
              'dependency_constraints_sha256': digest(constraints)}
    (work / 'core/dracla/release-policy.json').write_text(json.dumps(policy, sort_keys=True, separators=(',', ':')))
    run([sys.executable, '-I', '-m', 'hatchling', 'build', '-t', 'wheel', '-d', str(output)], cwd=work)
    wheels = list(output.glob('*.whl')); require(len(wheels) == 1)
    wheel = wheels[0]
    selected = {'source': {'repository_url': 'https://github.com/' + repository, 'commit_oid': oid, 'ref': ref},
                'builder': {'workflow': 'https://github.com/' + repository + '/.github/workflows/build-release.yml', 'commit_oid': oid},
                'runtime': {'runtime_lock_sha256': digest(runtime_raw), 'build_lock_sha256': digest(build_raw)}}
    definition = {'buildType': BUILD_TYPE, 'externalParameters': {'workflow': {
        'repository': selected['source']['repository_url'], 'path': '.github/workflows/release.yml', 'ref': ref}},
        'internalParameters': {'github': context},
        'resolvedDependencies': [{'uri': uri, 'digest': {algorithm: value}}
                                 for uri, algorithm, value in sorted(dependencies(selected, runtime, build))]}
    predicate = {'buildDefinition': definition, 'runDetails': {'builder': {'id':
        selected['source']['repository_url'] + '/.github/workflows/build-release.yml@' + oid}}}
    (output / 'provenance.json').write_text(json.dumps(predicate, sort_keys=True))
    # Test the produced wheel, with exactly the runtime wheels, in a separate
    # no-pip environment. The builder remains the test harness, not the code
    # under test. No network or build backend is available to this installation.
    selected.update({'package_version': version})
    selected['runtime']['wheel'] = {'filename': wheel.name, 'sha256': digest(regular(wheel))}
    wheelhouse = Path('/work/test/wheels'); wheelhouse.mkdir(parents=True)
    for item in runtime['wheels']:
        shutil.copyfile(inputs / 'wheels' / item['filename'], wheelhouse / item['filename'])
    shutil.copyfile(wheel, wheelhouse / wheel.name)
    parsed = wheel_set(wheelhouse, selected, runtime)
    install(wheelhouse.parent, selected, runtime, parsed)
    # The command loads the installed package's real policy/closure seam.
    code = ('import sys; sys.path.insert(0,sys.argv[1]); '
            'from dracla.cli.release import load_release_policy; load_release_policy(); '
            'from dracla.records import verify_project; '
            'from dracla.records.reconcile import reconcile_project; '
            'from dracla.records.exports import export_hosted')
    run([str(wheelhouse.parent / 'environment/bin/python'), '-I', '-S', '-c', code,
         str(wheelhouse.parent / 'environment' / site_path())], cwd=Path('/'))
    # Existing packaging tests start fresh child interpreters. Give the builder
    # harness their exact runtime dependencies; never add build tools to the
    # separately checked production installation.
    harness_requirements = wheelhouse.parent / 'harness.requirements'
    harness_requirements.write_text(''.join(str(inputs / 'wheels' / item['filename'])
        + ' --hash=' + item['sha256'] + '\n' for item in runtime['wheels']))
    run([sys.executable, '-I', '-m', 'pip', '--isolated', 'install', '--no-index', '--no-deps',
         '--only-binary=:all:', '--require-hashes', '--no-compile', '-r', str(harness_requirements)])
    test_code = ('import sys,unittest; sys.path.insert(0,sys.argv.pop(1)); '
                 'sys.path.insert(1,"/source"); '
                 'suite=unittest.defaultTestLoader.loadTestsFromNames('
                 '["core.tests.test_records_"+str(i) for i in range(1,6)]); '
                 'result=unittest.TextTestRunner().run(suite); '
                 'raise SystemExit(not result.wasSuccessful())')
    run([sys.executable, '-I', '-c', test_code, str(wheelhouse.parent / 'environment' / site_path())], cwd=Path('/'))
    (output / 'producer-validation.json').write_text(json.dumps({'wheel': wheel.name,
        'sha256': digest(regular(wheel)), 'installed_policy_and_engine_imports': 'passed', 'installed_m3_tests': 'passed',
        'authentic_publish_and_production_gate': 'not-run'}))


def fetch_inputs(*, bootstrap=False):
    """Non-secret image/builder setup using only the pinned Python stdlib.

    The lock is protected source, not a downloaded allow-list. Network ends
    before these bytes are installed or any build backend is invoked.
    """
    source, inputs = Path('/source'), Path('/inputs')
    inputs.mkdir(mode=0o700, exist_ok=False)
    (inputs / 'wheels').mkdir(mode=0o700)
    build = decode(regular(source / 'release/build-inputs.lock.json'))
    runtime = decode(regular(source / 'release/runtime-wheels.lock'))
    groups = build['bootstrap_wheels'] if bootstrap else build['build_wheels']
    selected = groups if bootstrap else groups + runtime['wheels']
    unique = {w['filename']: w for w in selected}
    for filename, item in unique.items():
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', filename) is not None)
        raw = fetch(item['url'], MAX_WHEEL)
        require(digest(raw) == item['sha256'])
        (inputs / 'wheels' / filename).write_bytes(raw)
    requirements = {w['filename']: w for w in groups}
    (inputs / 'tools.requirements').write_text(''.join(
        str(inputs / 'wheels' / filename) + ' --hash=' + w['sha256'] + '\n'
        for filename, w in sorted(requirements.items())))
    if bootstrap:
        import tarfile
        # The release asset can redirect to GitHub's asset CDN; its immutable
        # hash, not the redirect target or server filename, is authority.
        require(re.fullmatch(r'https://github\.com/cli/cli/releases/download/v[0-9.]+/gh_[0-9.]+_linux_amd64\.tar\.gz', build['gh']['url']) is not None)
        with urllib.request.urlopen(build['gh']['url'], timeout=30) as response:
            raw = response.read(MAX_WHEEL + 1)
        require(len(raw) <= MAX_WHEEL and digest(raw) == build['gh']['sha256'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            member = archive.getmember('gh_' + build['gh']['version'] + '_linux_amd64/bin/gh')
            require(member.isfile() and member.size <= MAX_WHEEL)
            binary = archive.extractfile(member).read(MAX_WHEEL + 1)
        Path('/usr/bin/gh').write_bytes(binary); Path('/usr/bin/gh').chmod(0o755)
        root = fetch(build['trusted_root']['url'])
        require(digest(root) == build['trusted_root']['sha256'])
        Path('/opt/dracla/trusted_root.json').write_bytes(root)


def main():
    if sys.argv[1:] in (['fetch-inputs'], ['fetch-bootstrap']):
        fetch_inputs(bootstrap=sys.argv[1] == 'fetch-bootstrap')
        return 0
    if sys.argv[1:] == ['produce']:
        try:
            produce()
            return 0
        except Exception:
            print('production-builder-failed', file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'launch'))
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--configuration', type=Path)
    parser.add_argument('--command', choices=('verify', 'reconcile', 'export', 'probe'), default='verify')
    args = parser.parse_args()
    try:
        selected = profile(regular(args.profile, MAX_JSON))
        require(args.state.is_absolute() and all(p not in ('..', '.') for p in args.state.parts))
        if args.operation == 'prepare':
            require('DRACLA_TRANSPORT_APP_KEY' not in os.environ and 'DRACLA_CONTROL_KEYS' not in os.environ)
            prepare(args.state, selected)
        else:
            require(args.configuration is not None and args.configuration.is_absolute())
            launch(args.state, selected, args.configuration, args.command)
    except Exception:
        print('production-verification-failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
