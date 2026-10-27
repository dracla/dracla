"""Bounded immutable GitHub reads, separate from provisioning authority."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from dracla.administration import RepositoryRef, numeric_id
from .credentials import (AuthorizationFailure, ProjectBinding, RecordsError,
                          opaque_token, request_json, unique_json)
from dracla.github_admin import API_ORIGIN, API_VERSION, HttpResponse


class HeadConflict(RecordsError):
    """A definite rejected conditional write; read again before recomputing."""


class IndeterminateWrite(RecordsError):
    """The write might have landed. Never repeat it without immutable readback."""


class RejectedWrite(RecordsError):
    """A definite provider rejection, with no provider text in diagnostics."""


def object_id(value: object) -> str:
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value) is None:
        raise RecordsError("invalid-history")
    return value


def repository_path(value: object) -> str:
    if (type(value) is not str or not value or value.startswith('/')
            or any(x in ('', '.', '..') for x in value.split('/'))
            or any(ord(c) < 32 or c in '\\\x7f' for c in value)):
        raise RecordsError("invalid-history")
    return value


@dataclass(frozen=True)
class TreeEntry:
    oid: str
    size: int


@dataclass(frozen=True)
class Commit:
    oid: str
    parents: tuple[str, ...]
    tree_oid: str


class RepositoryTransport:
    """Read immutable objects with bounded responses and two cached trees.

    Expanded trees use an immutable least-recently-used cache. Earlier returned
    maps remain valid after eviction; a later read revalidates the full response.
    """

    def __init__(self, credentials, *, max_commits: int = 100000, max_entries: int = 100000,
                 max_blob_bytes: int = 512000):
        if any(type(x) is not int or x <= 0
               for x in (max_commits, max_entries, max_blob_bytes)):
            raise RecordsError("invalid-configuration")
        self.credentials, self.max_commits = credentials, max_commits
        self.max_entries, self.max_blob_bytes = max_entries, max_blob_bytes
        self.binding: ProjectBinding | None = None
        self._commits, self._trees, self._blobs = {}, OrderedDict(), {}
        self._events_oid = None

    def at_events(self, oid: str):
        """Read a real immutable candidate history without publishing its ref.

        This view shares immutable object caches and normal authorization.
        Its selected events head is read-only; other branch heads stay live.
        """
        view = copy.copy(self)
        view._events_oid = object_id(oid)
        return view

    def __repr__(self):
        return f"RepositoryTransport(mode={self.credentials.mode!r})"

    def _get(self, path, *, retry_authorization=True):
        try:
            return request_json(self.credentials.sender, 'GET', path, self.credentials.token())
        except AuthorizationFailure:
            if self.binding is None or not retry_authorization:
                raise
            self.authorize(self.binding)
            return request_json(self.credentials.sender, 'GET', path, self.credentials.token())

    def _path(self, repo: RepositoryRef):
        if self.binding is None or repo not in self.binding.repositories[:2]:
            raise RecordsError('scope-mismatch')
        return f'/repos/{repo.owner}/{repo.name}'

    def authorize(self, binding: ProjectBinding):
        self.binding = None
        self.credentials.authorize(binding)
        self.binding = binding
        try:
            for repo in binding.repositories[:2]:
                value = self._get(self._path(repo), retry_authorization=False)
                if (numeric_id(value['id']) != repo.id or numeric_id(value['owner']['id']) != binding.owner_id
                        or value['owner']['login'].casefold() != repo.owner
                        or value['name'].casefold() != repo.name or value['private'] is not True):
                    raise RecordsError('identity-mismatch')
        except RecordsError:
            self.binding = None
            raise
        except (KeyError, TypeError, AttributeError, ValueError):
            self.binding = None
            raise RecordsError('identity-mismatch') from None

    def head(self, repo: RepositoryRef, branch: str):
        if branch not in ('events', 'keys', 'operations', 'derived', 'coverage'):
            raise RecordsError('scope-mismatch')
        if (repo.role == 'coverage') != (branch == 'coverage'):
            raise RecordsError('scope-mismatch')
        path = self._path(repo)
        if branch == 'events' and self._events_oid is not None:
            return self._events_oid
        try:
            value = self._get(path + '/git/ref/heads/' + branch)
            if value['ref'] != 'refs/heads/' + branch or value['object']['type'] != 'commit':
                raise RecordsError('invalid-history')
            return object_id(value['object']['sha'])
        except (KeyError, TypeError):
            raise RecordsError('invalid-history') from None

    def commit(self, repo: RepositoryRef, oid: str):
        path = self._path(repo)
        key = repo.id, object_id(oid)
        if key not in self._commits:
            try:
                value = self._get(path + '/git/commits/' + oid)
                if type(value['parents']) is not list:
                    raise RecordsError('invalid-history')
                parents = tuple(object_id(p['sha']) for p in value['parents'])
                if value['sha'] != oid or len(parents) > 1:
                    raise RecordsError('invalid-history')
                self._commits[key] = Commit(oid, parents, object_id(value['tree']['sha']))
            except (KeyError, TypeError):
                raise RecordsError('invalid-history') from None
        return self._commits[key]

    def ancestry(self, repo: RepositoryRef, head: str):
        result, seen, oid = [], set(), object_id(head)
        while True:
            if oid in seen or len(result) >= self.max_commits:
                raise RecordsError('resource-limit')
            seen.add(oid)
            commit = self.commit(repo, oid)
            result.append(commit)
            if not commit.parents:
                return tuple(reversed(result))
            oid = commit.parents[0]

    def tree(self, repo: RepositoryRef, commit_oid: str) -> Mapping[str, TreeEntry]:
        commit = self.commit(repo, commit_oid)
        key = repo.id, commit.tree_oid
        if key not in self._trees:
            try:
                value = self._get(self._path(repo) + '/git/trees/' + commit.tree_oid + '?recursive=1')
                if value['sha'] != commit.tree_oid or value['truncated'] is not False or type(value['tree']) is not list:
                    raise RecordsError('invalid-history')
                if len(value['tree']) > self.max_entries:
                    raise RecordsError('resource-limit')
                files, paths = {}, set()
                for item in value['tree']:
                    path = repository_path(item['path'])
                    if path in paths:
                        raise RecordsError('invalid-history')
                    paths.add(path)
                    object_id(item['sha'])
                    if item['type'] == 'tree' and item['mode'] == '040000':
                        continue
                    if (item['type'] != 'blob' or item['mode'] != '100644'
                            or type(item['size']) is not int or item['size'] < 0):
                        raise RecordsError('invalid-history')
                    files[path] = TreeEntry(item['sha'], item['size'])
                self._trees[key] = MappingProxyType(files)
                if len(self._trees) > 2:
                    self._trees.popitem(last=False)
            except (KeyError, TypeError):
                raise RecordsError('invalid-history') from None
        self._trees.move_to_end(key)
        return self._trees[key]

    def read(self, repo: RepositoryRef, commit_oid: str, path: str) -> bytes:
        path = repository_path(path)
        entry = self.tree(repo, commit_oid).get(path)
        if entry is None:
            raise RecordsError('invalid-history')
        if entry.size > self.max_blob_bytes:
            raise RecordsError('resource-limit')
        key = repo.id, entry.oid
        if key not in self._blobs:
            try:
                value = self._get(self._path(repo) + '/git/blobs/' + entry.oid)
                if (value['sha'] != entry.oid or type(value['size']) is not int or value['size'] != entry.size
                        or value['encoding'] != 'base64' or type(value['content']) is not str):
                    raise RecordsError('invalid-history')
                content = value['content'].replace('\n', '')
                raw = base64.b64decode(content, validate=True)
                if len(raw) != entry.size or base64.b64encode(raw).decode() != content:
                    raise RecordsError('invalid-history')
                algorithm = hashlib.sha1 if len(entry.oid) == 40 else hashlib.sha256
                actual = algorithm(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                if actual != entry.oid:
                    raise RecordsError('invalid-history')
                self._blobs[key] = raw
            except (KeyError, TypeError, ValueError):
                raise RecordsError('invalid-history') from None
        return self._blobs[key]

    def _mutation(self, method, path, body, *, graphql=False, ref_update=False):
        """Send once. Reads, not a generic HTTP retry, resolve uncertainty."""
        if self._events_oid is not None:
            raise RecordsError('scope-mismatch')
        token = opaque_token(self.credentials.token())
        raw = json.dumps(body, separators=(',', ':')).encode()
        try:
            response = self.credentials.sender(method, API_ORIGIN + path,
                {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': API_VERSION, 'User-Agent': 'DraCLA-records'}, 10.0, raw)
        except Exception:
            raise IndeterminateWrite() from None
        if not isinstance(response, HttpResponse) or len(response.body) > 1024 * 1024:
            raise IndeterminateWrite()
        if response.status in (401, 403):
            raise AuthorizationFailure()
        try:
            value = unique_json(response.body)
        except RecordsError:
            raise IndeterminateWrite() from None
        if ref_update and (response.status == 409 or response.status == 422
                and type(value) is dict and value.get('message') == 'Update is not a fast forward'):
            raise HeadConflict('snapshot-changed')
        if response.status >= 500 or response.status in (408, 429):
            raise IndeterminateWrite()
        if response.status != (200 if graphql or method == 'PATCH' else 201):
            raise RejectedWrite()
        if type(value) is not dict:
            raise IndeterminateWrite()
        if graphql and value.get('errors'):
            # Execution errors can include null data after a successful write.
            # Only an omitted data member proves a pre-execution request error.
            # Do not infer absence or head conflict from provider error text.
            if 'data' in value:
                raise IndeterminateWrite()
            raise RejectedWrite()
        return value

    def _write_files(self, files):
        if not isinstance(files, Mapping) or not files or len(files) > self.max_entries:
            raise RecordsError('invalid-configuration')
        result = {}
        for path, raw in files.items():
            path = repository_path(path)
            if type(raw) is not bytes or len(raw) > self.max_blob_bytes:
                raise RecordsError('resource-limit')
            result[path] = raw
        return result

    def verify_commit_files(self, repo, oid, expected_parent, files):
        """Verify the whole resulting tree, including every unchanged file."""
        commit = self.commit(repo, object_id(oid))
        if commit.parents != (object_id(expected_parent),):
            raise RecordsError('invalid-history')
        before, after = self.tree(repo, expected_parent), self.tree(repo, oid)
        if set(after) != set(before) | set(files):
            raise RecordsError('invalid-history')
        for path in after:
            if path in files:
                if self.read(repo, oid, path) != files[path]:
                    raise RecordsError('invalid-history')
            elif before[path] != after[path]:
                raise RecordsError('invalid-history')
        return oid

    def create_event_commit(self, repo, parent, files):
        """Create unattached Git objects; only update_events publishes them."""
        if repo.role != 'records':
            raise RecordsError('scope-mismatch')
        files = self._write_files(files)
        parent = object_id(parent)
        base = self.commit(repo, parent)
        entries = []
        for path, raw in sorted(files.items()):
            value = self._mutation('POST', self._path(repo) + '/git/blobs',
                                   {'encoding': 'base64', 'content': base64.b64encode(raw).decode()})
            try:
                oid = object_id(value['sha'])
                algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
                if oid != algorithm(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest():
                    raise RecordsError('invalid-history')
            except (KeyError, TypeError):
                raise RecordsError('invalid-history') from None
            entries.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': oid})
        try:
            tree = self._mutation('POST', self._path(repo) + '/git/trees',
                                  {'base_tree': base.tree_oid, 'tree': entries})
            tree_oid = object_id(tree['sha'])
            commit = self._mutation('POST', self._path(repo) + '/git/commits',
                {'message': 'DraCLA canonical event', 'tree': tree_oid, 'parents': [parent]})
            oid = object_id(commit['sha'])
        except (KeyError, TypeError):
            raise IndeterminateWrite() from None
        return self.verify_commit_files(repo, oid, parent, files)

    def update_events(self, repo, oid):
        if repo.role != 'records':
            raise RecordsError('scope-mismatch')
        oid = object_id(oid)
        value = self._mutation('PATCH', self._path(repo) + '/git/refs/heads/events',
                               {'sha': oid, 'force': False}, ref_update=True)
        if (value.get('ref') != 'refs/heads/events' or type(value.get('object')) is not dict
                or value['object'].get('sha') != oid or value['object'].get('type') != 'commit'):
            raise IndeterminateWrite()
        return oid

    def conditional_commit(self, repo, branch, expected_head, files):
        """One branch-wide CAS, with exact immutable recovery after lost reply.

        Callers authenticate all transition inputs at expected_head. This
        adapter verifies transport identity and the complete resulting tree;
        it does not turn a blob SHA into a branch-head precondition.
        """
        if (repo.role, branch) not in (('records', 'operations'), ('records', 'derived'),
                                       ('coverage', 'coverage')):
            raise RecordsError('scope-mismatch')
        from dracla.conformance import resolve_artifact_identity
        files = self._write_files(files)
        for path in files:
            try:
                resolve_artifact_identity(repo.role, branch, path)
            except ValueError:
                raise RecordsError('scope-mismatch') from None
        expected_head = object_id(expected_head)
        self._path(repo)
        if self.head(repo, branch) != expected_head:
            raise HeadConflict('snapshot-changed')
        body = {'query': 'mutation($input:CreateCommitOnBranchInput!){'
                'createCommitOnBranch(input:$input){commit{oid}}}',
                'variables': {'input': {'branch': {'repositoryNameWithOwner': f'{repo.owner}/{repo.name}',
                'branchName': branch}, 'expectedHeadOid': expected_head,
                'message': {'headline': 'DraCLA conditional state transition'},
                'fileChanges': {'additions': [{'path': path, 'contents': base64.b64encode(raw).decode()}
                                             for path, raw in sorted(files.items())]}}}}
        try:
            value = self._mutation('POST', '/graphql', body, graphql=True)
            try:
                oid = object_id(value['data']['createCommitOnBranch']['commit']['oid'])
            except (KeyError, TypeError, RecordsError):
                raise IndeterminateWrite() from None
            return self.verify_commit_files(repo, oid, expected_head, files)
        except IndeterminateWrite:
            # Discover only the direct successor of this expected head. A
            # descendant with superficially equal files is not this transition.
            history = self.ancestry(repo, self.head(repo, branch))
            for commit in history:
                if commit.parents == (expected_head,):
                    try:
                        return self.verify_commit_files(repo, commit.oid, expected_head, files)
                    except RecordsError:
                        break
            raise IndeterminateWrite() from None
