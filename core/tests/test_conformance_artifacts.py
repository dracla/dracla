"""Revision-13 canonical JSON and artifact-identity contract tests."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance.artifacts import (  # noqa: E402
    ArtifactIdentityError,
    override_key,
    resolve_artifact_identity,
    segment,
)
from dracla.conformance.canonical import (  # noqa: E402
    CanonicalJsonError,
    MAX_SAFE_INTEGER,
    NonCanonicalJsonError,
    canonical_json,
    parse_canonical_json,
)

VECTORS = Path(__file__).parent / "vectors" / "artifact-identities-v1.json"
EVENT_ID = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


class TestCanonicalJson(unittest.TestCase):
    def test_orders_members_and_emits_utf8_without_trailing_bytes(self):
        value = {"z": 0, "a": "€", "list": [3, 2, 1]}
        encoded = b'{"a":"\xe2\x82\xac","list":[3,2,1],"z":0}'
        self.assertEqual(canonical_json(value), encoded)
        self.assertEqual(parse_canonical_json(encoded), value)

    def test_does_not_normalize_unicode(self):
        self.assertNotEqual(canonical_json("é"), canonical_json("e\u0301"))

    def test_rejects_noncanonical_and_duplicate_input(self):
        with self.assertRaises(NonCanonicalJsonError):
            parse_canonical_json(b'{"z":0, "a":1}')
        with self.assertRaises(CanonicalJsonError):
            parse_canonical_json(b'{"a":1,"a":2}')
        with self.assertRaises(CanonicalJsonError):
            parse_canonical_json(b"\xef\xbb\xbf{}")

    def test_rejects_values_outside_the_shared_json_model(self):
        self.assertEqual(canonical_json(1.5), b"1.5")
        self.assertEqual(parse_canonical_json(b"1.5"), 1.5)
        with self.assertRaises(CanonicalJsonError):
            canonical_json((1, 2))
        with self.assertRaises(CanonicalJsonError):
            canonical_json(MAX_SAFE_INTEGER + 1)
        with self.assertRaises(CanonicalJsonError):
            canonical_json(1e20)
        with self.assertRaises(CanonicalJsonError):
            parse_canonical_json(b"100000000000000000000")

    def test_deep_input_uses_the_public_error_boundary(self):
        value = None
        for _ in range(2_000):
            value = [value]
        with self.assertRaises(CanonicalJsonError):
            canonical_json(value)

        encoded = b"[" * 2_000 + b"null" + b"]" * 2_000
        with self.assertRaises(CanonicalJsonError):
            parse_canonical_json(encoded)


class TestArtifactIdentities(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_every_v1_identity_table_row_has_a_golden_vector(self):
        self.assertEqual(len(self.vectors["identities"]), 16)
        for repository, branch, path, kind, capability in self.vectors["identities"]:
            with self.subTest(repository=repository, branch=branch, path=path):
                identity = resolve_artifact_identity(repository, branch, path)
                self.assertEqual(identity.repository_role, repository)
                self.assertEqual(identity.artifact_kind, kind)
                self.assertEqual(identity.capability, capability)
                self.assertEqual(identity.schema_version, 1)
                self.assertEqual(identity.logical_id, f"{branch}:{path}")

    def test_dynamic_path_relations_fail_closed(self):
        invalid = [
            ("records", "events", f"events/ZZ/EC/{EVENT_ID}.enc.json"),
            ("records", "events", f"events/AA/EC/{EVENT_ID}=.enc.json"),
            ("records", "derived", "derived/index/32.enc.json"),
            ("records", "derived", "derived/exports/short.enc.json"),
            ("coverage", "derived", "derived/index/00.enc.json"),
            ("coverage", "events", "config/project.enc.json"),
            ("records", "events", "/config/project.enc.json"),
            ("records", "events", "config/../project.enc.json"),
        ]
        for repository, branch, path in invalid:
            with self.subTest(repository=repository, branch=branch, path=path):
                with self.assertRaises(ArtifactIdentityError):
                    resolve_artifact_identity(repository, branch, path)

    def test_segment_vectors_are_exact_and_unpadded(self):
        for vector in self.vectors["segments"]:
            with self.subTest(value=vector["value"]):
                self.assertEqual(segment(vector["value"]), vector["token"])
                self.assertNotIn("=", vector["token"])

    def test_override_key_is_jcs_bound_and_validated(self):
        vector = self.vectors["override_key"]
        key = override_key(
            repository_id=vector["repository_id"],
            pull_request_number=vector["pull_request_number"],
            subject_user_id=vector["subject_user_id"],
            tree_oid=vector["tree_oid"],
        )
        self.assertEqual(key, vector["key"])
        self.assertEqual(len(key), 43)
        self.assertNotEqual(
            key,
            override_key(
                repository_id=123,
                pull_request_number=7,
                subject_user_id=457,
                tree_oid="a" * 40,
            ),
        )
        with self.assertRaises(ArtifactIdentityError):
            override_key(
                repository_id=0,
                pull_request_number=7,
                subject_user_id=456,
                tree_oid="a" * 40,
            )
        with self.assertRaises(ArtifactIdentityError):
            override_key(
                repository_id=123,
                pull_request_number=7,
                subject_user_id=456,
                tree_oid="A" * 40,
            )
        with self.assertRaises(ArtifactIdentityError):
            override_key(
                repository_id=123,
                pull_request_number=7,
                subject_user_id=456,
                tree_oid="a" * 39,
            )
        self.assertEqual(
            len(
                override_key(
                    repository_id=123,
                    pull_request_number=7,
                    subject_user_id=456,
                    tree_oid="a" * 64,
                )
            ),
            43,
        )


if __name__ == "__main__":
    unittest.main()
