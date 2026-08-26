"""Revision-13 encrypted-artifact envelope contract tests."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    ArtifactAuthenticationError,
    ArtifactEnvelopeContextError,
    ArtifactEnvelopeFormatError,
    ArtifactIdentity,
    Base64UrlError,
    UnknownArtifactKeyError,
    artifact_aad,
    base64url_decode,
    base64url_encode,
    canonical_json,
    decrypt_artifact,
    decrypt_json_artifact,
    encrypt_artifact,
    encrypt_json_artifact,
    resolve_artifact_identity,
)

VECTORS = Path(__file__).parent / "vectors" / "artifact-envelope-v1.json"
IDENTITIES = Path(__file__).parent / "vectors" / "artifact-identities-v1.json"
ENVELOPE_FIELDS = {
    "algorithm",
    "artifact_kind",
    "ciphertext",
    "envelope_version",
    "kid",
    "logical_id",
    "nonce",
    "project_id",
    "schema_version",
}


class TestArtifactEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.key = bytes.fromhex(cls.vector["key_hex"])
        cls.kid = bytes.fromhex(cls.vector["kid_hex"])
        cls.nonce = bytes.fromhex(cls.vector["nonce_hex"])
        cls.kid_text = base64url_encode(cls.kid)
        cls.identity = resolve_artifact_identity(
            cls.vector["repository_role"],
            cls.vector["branch"],
            cls.vector["path"],
        )
        cls.envelope = cls.vector["envelope_utf8"].encode("utf-8")
        cls.plaintext = cls.vector["plaintext_utf8"].encode("utf-8")

    def decrypt(self, envelope: bytes | None = None, **changes):
        arguments = {
            "expected_project_id": self.vector["project_id"],
            "expected_identity": self.identity,
            "keys": {self.kid_text: self.key},
        }
        arguments.update(changes)
        return decrypt_artifact(
            self.envelope if envelope is None else envelope, **arguments
        )

    def mutate(self, **changes) -> bytes:
        envelope = json.loads(self.envelope)
        envelope.update(changes)
        return canonical_json(envelope)

    def test_independent_golden_vector_is_exact(self):
        self.assertEqual(
            artifact_aad(
                project_id=self.vector["project_id"],
                identity=self.identity,
                kid=self.kid,
            ),
            self.vector["aad_utf8"].encode("utf-8"),
        )
        with patch(
            "dracla.conformance.envelope.secrets.token_bytes",
            return_value=self.nonce,
        ) as token_bytes:
            encrypted = encrypt_artifact(
                self.plaintext,
                project_id=self.vector["project_id"],
                identity=self.identity,
                kid=self.kid,
                key=self.key,
            )
        token_bytes.assert_called_once_with(12)
        self.assertEqual(encrypted, self.envelope)
        self.assertEqual(
            json.loads(encrypted)["ciphertext"],
            self.vector["ciphertext_base64url"],
        )
        self.assertEqual(self.decrypt(), self.plaintext)
        self.assertEqual(
            decrypt_json_artifact(
                self.envelope,
                expected_project_id=self.vector["project_id"],
                expected_identity=self.identity,
                keys={self.kid_text: self.key},
            ),
            {"agreement": "v1", "enabled": True},
        )

    def test_all_sixteen_identity_rows_round_trip(self):
        vectors = json.loads(IDENTITIES.read_text(encoding="utf-8"))
        self.assertEqual(len(vectors["identities"]), 16)
        for repository, branch, path, kind, _capability in vectors["identities"]:
            identity = resolve_artifact_identity(repository, branch, path)
            plaintext = b"safe,csv\n" if kind == "export-csv" else b"{}"
            with self.subTest(kind=kind), patch(
                "dracla.conformance.envelope.secrets.token_bytes",
                return_value=self.nonce,
            ):
                envelope = encrypt_artifact(
                    plaintext,
                    project_id="project-alpha",
                    identity=identity,
                    kid=self.kid,
                    key=self.key,
                )
                self.assertEqual(
                    decrypt_artifact(
                        envelope,
                        expected_project_id="project-alpha",
                        expected_identity=identity,
                        keys={self.kid_text: self.key},
                    ),
                    plaintext,
                )
                self.assertEqual(set(json.loads(envelope)), ENVELOPE_FIELDS)

    def test_metadata_is_bound_to_caller_derived_context(self):
        with self.assertRaises(ArtifactEnvelopeContextError):
            self.decrypt(expected_project_id="other-project")
        other = resolve_artifact_identity("coverage", "coverage", "source.enc.json")
        with self.assertRaises(ArtifactEnvelopeContextError):
            self.decrypt(expected_identity=other)
        for field, value in (
            ("project_id", "other-project"),
            ("artifact_kind", "canonical-event"),
            ("logical_id", "events:config/other.enc.json"),
            ("schema_version", 2),
        ):
            with self.subTest(field=field), self.assertRaises(
                ArtifactEnvelopeContextError
            ):
                self.decrypt(self.mutate(**{field: value}))

    def test_unknown_key_wrong_key_and_tampering_are_rejected(self):
        with self.assertRaises(UnknownArtifactKeyError):
            self.decrypt(keys={})
        with self.assertRaises(ArtifactAuthenticationError):
            self.decrypt(keys={self.kid_text: b"x" * 32})
        ciphertext = bytearray(
            base64url_decode(json.loads(self.envelope)["ciphertext"])
        )
        ciphertext[0] ^= 1
        with self.assertRaises(ArtifactAuthenticationError):
            self.decrypt(self.mutate(ciphertext=base64url_encode(bytes(ciphertext))))

    def test_envelope_bytes_and_members_are_strict(self):
        variants = [
            self.envelope + b"\n",
            self.envelope.replace(b'{"algorithm"', b'{ "algorithm"', 1),
            self.envelope.replace(
                b'{"algorithm":"A256GCM",',
                b'{"algorithm":"A256GCM","algorithm":"A256GCM",',
                1,
            ),
        ]
        for envelope in variants:
            with self.subTest(envelope=envelope), self.assertRaises(
                ArtifactEnvelopeFormatError
            ):
                self.decrypt(envelope)

        missing = json.loads(self.envelope)
        missing.pop("nonce")
        extra = {**json.loads(self.envelope), "repository_id": 123}
        for envelope in (canonical_json(missing), canonical_json(extra)):
            with self.assertRaises(ArtifactEnvelopeFormatError):
                self.decrypt(envelope)

    def test_versions_algorithm_types_and_encodings_are_strict(self):
        format_changes = (
            {"envelope_version": 2},
            {"algorithm": "AES-GCM"},
            {"envelope_version": True},
            {"kid": self.kid_text + "="},
            {"kid": base64url_encode(b"short")},
            {"nonce": base64url_encode(b"short")},
            {"ciphertext": base64url_encode(b"short")},
        )
        for changes in format_changes:
            with self.subTest(changes=changes), self.assertRaises(
                ArtifactEnvelopeFormatError
            ):
                self.decrypt(self.mutate(**changes))

    def test_json_plaintext_must_be_canonical_before_and_after_encryption(self):
        with self.assertRaises(ArtifactEnvelopeFormatError):
            encrypt_artifact(
                b'{"z":0, "a":1}',
                project_id="project-alpha",
                identity=self.identity,
                kid=self.kid,
                key=self.key,
            )

        metadata = json.loads(self.vector["aad_utf8"])
        ciphertext = AESGCM(self.key).encrypt(
            self.nonce, b'{"z":0, "a":1}', self.vector["aad_utf8"].encode()
        )
        envelope = canonical_json(
            {
                **metadata,
                "nonce": base64url_encode(self.nonce),
                "ciphertext": base64url_encode(ciphertext),
            }
        )
        with self.assertRaises(ArtifactEnvelopeFormatError):
            self.decrypt(envelope)

    def test_json_helper_and_csv_exact_byte_contracts_are_separate(self):
        with patch(
            "dracla.conformance.envelope.secrets.token_bytes",
            return_value=self.nonce,
        ):
            encrypted = encrypt_json_artifact(
                {"z": 0, "a": 1},
                project_id="project-alpha",
                identity=self.identity,
                kid=self.kid,
                key=self.key,
            )
        self.assertEqual(
            decrypt_json_artifact(
                encrypted,
                expected_project_id="project-alpha",
                expected_identity=self.identity,
                keys={self.kid_text: self.key},
            ),
            {"a": 1, "z": 0},
        )

        csv_identity = resolve_artifact_identity(
            "records",
            "derived",
            "derived/exports/AAECAwQFBgcICQoLDA0ODw.enc.csv",
        )
        with self.assertRaises(ArtifactEnvelopeContextError):
            encrypt_json_artifact(
                {},
                project_id="project-alpha",
                identity=csv_identity,
                kid=self.kid,
                key=self.key,
            )
        with self.assertRaises(ArtifactEnvelopeContextError):
            decrypt_json_artifact(
                self.envelope,
                expected_project_id="project-alpha",
                expected_identity=csv_identity,
                keys={self.kid_text: self.key},
            )
        for invalid in (
            b"\xff",
            b"\xef\xbb\xbfsafe,csv\n",
            b"=1+1,safe\r\n",
            b'"+cmd",safe\r\n',
            b"-1,safe\r\n",
            b'"@SUM(A1:A2)",safe\r\n',
            b"\tpayload,safe\r\n",
            b'"\rpayload",safe\r\n',
            b'"\npayload",safe\r\n',
            b'"unterminated,safe\r\n',
            b'sa"fe,value\r\n',
            b'"safe"x,value\r\n',
        ):
            with self.assertRaises(ArtifactEnvelopeFormatError):
                encrypt_artifact(
                    invalid,
                    project_id="project-alpha",
                    identity=csv_identity,
                    kid=self.kid,
                    key=self.key,
                )

        safe_csv_values = (
            b"name,value\r\nuser,'=1+1\r\n",
            b'"""safe""",value\r\n',
            b',safe\r\n\r\nsafe,"value"\r\n',
            b'safe,"value"\n',
            b"a" * 131_073 + b",safe\r",
        )
        for safe_csv in safe_csv_values:
            with self.subTest(size=len(safe_csv)), patch(
                "dracla.conformance.envelope.secrets.token_bytes",
                return_value=self.nonce,
            ):
                encrypted_csv = encrypt_artifact(
                    safe_csv,
                    project_id="project-alpha",
                    identity=csv_identity,
                    kid=self.kid,
                    key=self.key,
                )
                self.assertEqual(
                    decrypt_artifact(
                        encrypted_csv,
                        expected_project_id="project-alpha",
                        expected_identity=csv_identity,
                        keys={self.kid_text: self.key},
                    ),
                    safe_csv,
                )

    def test_key_material_and_base64url_validation_fail_closed(self):
        for kid, key in ((b"short", self.key), (self.kid, b"short")):
            with self.assertRaises(ArtifactEnvelopeFormatError):
                encrypt_artifact(
                    self.plaintext,
                    project_id="project-alpha",
                    identity=self.identity,
                    kid=kid,
                    key=key,
                )
        with self.assertRaises(ArtifactEnvelopeFormatError):
            self.decrypt(keys={self.kid_text: b"short"})
        with self.assertRaises(Base64UrlError):
            base64url_decode("AA==")

    def test_public_type_and_closed_identity_boundaries_are_explicit(self):
        with self.assertRaises(TypeError):
            base64url_encode(bytearray(b"not-bytes"))
        with self.assertRaises(Base64UrlError):
            base64url_decode(b"not-text")
        with self.assertRaises(Base64UrlError):
            base64url_decode("*")
        with self.assertRaises(Base64UrlError):
            base64url_decode("AA", expected_length=2)

        with self.assertRaises(ArtifactEnvelopeContextError):
            artifact_aad(
                project_id="project-alpha", identity=object(), kid=self.kid
            )
        unknown = ArtifactIdentity(
            "records", "events", "config/unknown.enc.json", "unknown", "records"
        )
        with self.assertRaises(ArtifactEnvelopeContextError):
            artifact_aad(
                project_id="project-alpha", identity=unknown, kid=self.kid
            )
        forged = ArtifactIdentity(
            self.identity.repository_role,
            self.identity.branch,
            self.identity.path,
            self.identity.artifact_kind,
            "coverage",
        )
        with self.assertRaises(ArtifactEnvelopeContextError):
            artifact_aad(
                project_id="project-alpha", identity=forged, kid=self.kid
            )
        with self.assertRaises(ArtifactEnvelopeContextError):
            artifact_aad(project_id="", identity=self.identity, kid=self.kid)
        with self.assertRaises(TypeError):
            encrypt_artifact(
                "not-bytes",
                project_id="project-alpha",
                identity=self.identity,
                kid=self.kid,
                key=self.key,
            )
        with self.assertRaises(TypeError):
            self.decrypt(keys=[])


if __name__ == "__main__":
    unittest.main()
