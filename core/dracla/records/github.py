"""Bounded immutable GitHub reads, separate from provisioning authority."""
from __future__ import annotations

import base64
import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from dracla.administration import RepositoryRef, numeric_id
from .credentials import AuthorizationFailure, ProjectBinding, RecordsError, request_json


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
    """Read immutable objects within per-response and total traversal budgets.

    Keep only two expanded trees. ``max_entries`` bounds one tree response;
    ``max_tree_entries`` bounds fresh tree rows over this transport's lifetime,
    including refetches after eviction. Use a fresh transport for an independent
    operation. An exhausted traversal returns resource-limit, never partial data.
    """

    def __init__(self, credentials, *, max_commits: int = 100000, max_entries: int = 100000,
                 max_blob_bytes: int = 512000, max_tree_entries: int = 1000000):
        if any(type(x) is not int or x <= 0
               for x in (max_commits, max_entries, max_blob_bytes, max_tree_entries)):
            raise RecordsError("invalid-configuration")
        self.credentials, self.max_commits = credentials, max_commits
        self.max_entries, self.max_blob_bytes = max_entries, max_blob_bytes
        self.max_tree_entries, self._tree_entries_read = max_tree_entries, 0
        self.binding: ProjectBinding | None = None
        self._commits, self._trees, self._blobs = {}, OrderedDict(), {}

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
        try:
            value = self._get(self._path(repo) + '/git/ref/heads/' + branch)
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
                if self._tree_entries_read + len(value['tree']) > self.max_tree_entries:
                    raise RecordsError('resource-limit')
                self._tree_entries_read += len(value['tree'])
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
