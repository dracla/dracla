"""Candidate-pinned commitments to actual project data-key bytes."""
from __future__ import annotations

import hashlib
import hmac
import re

from dracla.conformance import base64url_decode, canonical_json, parse_canonical_json
from dracla.conformance.keyrings import CAPABILITIES
from .credentials import RecordsError

KEY_BINDINGS_PATH = '.dracla/key-bindings.json'


def key_fingerprint(project_id, capability, data_kid, key):
    """Commit to one high-entropy key and its exact authorization context."""
    try:
        if (type(project_id) is not str or not project_id
                or type(capability) is not str or capability not in CAPABILITIES
                or type(key) is not bytes or len(key) != 32):
            raise ValueError()
        base64url_decode(data_kid, expected_length=16)
        context = canonical_json({'purpose': 'dracla-data-key-binding-v1',
            'project_id': project_id, 'capability': capability, 'data_kid': data_kid})
        return 'sha256:' + hmac.new(key, context, hashlib.sha256).hexdigest()
    except Exception:
        raise RecordsError('invalid-key') from None


def encode_key_bindings(project_id, keys):
    """Encode the complete retained capability/key-ID map for a candidate."""
    try:
        if set(keys) - CAPABILITIES:
            raise ValueError()
        entries = [{'capability': cap, 'data_kid': kid,
                    'fingerprint': key_fingerprint(project_id, cap, kid, key)}
                   for cap, values in keys.items() for kid, key in values.items()]
        entries.sort(key=lambda entry: (entry['capability'], entry['data_kid']))
        raw = canonical_json({'bindings_version': 1, 'project_id': project_id, 'bindings': entries})
        decode_key_bindings(raw, project_id=project_id,
                            pairs={(entry['capability'], entry['data_kid']) for entry in entries})
        return raw
    except Exception:
        raise RecordsError('invalid-key') from None


def decode_key_bindings(raw, *, project_id, pairs):
    """Validate canonical proof bytes against the entire pinned recovery ring."""
    try:
        value = parse_canonical_json(raw)
        if (type(value) is not dict or set(value) != {'bindings_version', 'project_id', 'bindings'}
                or type(value['bindings_version']) is not int or value['bindings_version'] != 1
                or type(project_id) is not str or not project_id or value['project_id'] != project_id
                or type(value['bindings']) is not list or not value['bindings']):
            raise ValueError()
        result = {}
        order = []
        for entry in value['bindings']:
            if type(entry) is not dict or set(entry) != {'capability', 'data_kid', 'fingerprint'}:
                raise ValueError()
            cap, kid, digest = entry['capability'], entry['data_kid'], entry['fingerprint']
            if (type(cap) is not str or cap not in CAPABILITIES or type(digest) is not str
                    or re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is None):
                raise ValueError()
            base64url_decode(kid, expected_length=16)
            pair = cap, kid
            if pair in result:
                raise ValueError()
            result[pair] = digest
            order.append(pair)
        if order != sorted(order) or set(result) != set(pairs):
            raise ValueError()
        return result
    except Exception:
        raise RecordsError('invalid-key') from None


def verify_key_bindings(raw, *, project_id, pairs, keys, selected):
    """Check both selected capabilities, including IDs unchanged by activation."""
    try:
        proof = decode_key_bindings(raw, project_id=project_id, pairs=pairs)
        if set(selected) != CAPABILITIES:
            raise ValueError()
        for cap, kid in selected.items():
            actual = key_fingerprint(project_id, cap, kid, keys[cap][kid])
            if not hmac.compare_digest(proof[cap, kid], actual):
                raise ValueError()
    except Exception:
        raise RecordsError('invalid-key') from None
