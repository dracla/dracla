"""Revision-13 wrapped-key and canonical-keyring contract tests."""

from __future__ import annotations

import json
import sys
import unittest
from collections import defaultdict
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dracla.conformance import (  # noqa: E402
    KeyringAuthenticationError,
    KeyringContextError,
    KeyringFormatError,
    Keyring,
    UnknownWrappingKeyError,
    WRAPPER_CAPABILITIES,
    WrappedKeyCopy,
    base64url_encode,
    canonical_json,
    decode_keyring,
    encode_keyring,
    unwrap_key_copy,
    wrap_key_copy,
    wrapped_key_aad,
)

VECTORS = Path(__file__).parent / "vectors" / "wrapped-key-v1.json"


class TestWrappedKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.data_key = bytes.fromhex(cls.vector["data_key_hex"])
        cls.data_kid = bytes.fromhex(cls.vector["data_kid_hex"])
        cls.wrapping_key = bytes.fromhex(cls.vector["wrapping_key_hex"])
        cls.nonce = bytes.fromhex(cls.vector["nonce_hex"])
        cls.generation = cls.vector["wrapper_generation"]

    def wrap(self, **changes):
        arguments = {
            "project_id": self.vector["project_id"],
            "capability": self.vector["capability"],
            "data_kid": self.data_kid,
            "wrapper_id": self.vector["wrapper_id"],
            "wrapper_generation": self.generation,
            "wrapping_key": self.wrapping_key,
        }
        arguments.update(changes)
        data_key = arguments.pop("data_key", self.data_key)
        with patch(
            "dracla.conformance.keyrings.secrets.token_bytes", return_value=self.nonce
        ):
            return wrap_key_copy(data_key, **arguments)

    def decode(self, data, **changes):
        arguments = {
            "expected_project_id": self.vector["project_id"],
            "allowed_capabilities": {"records", "coverage"},
            "allowed_wrappers": {
                "portal-records",
                "portal-coverage",
                "enforcer-coverage",
                "control",
                "recovery",
            },
            "known_generations": {
                "portal-records": {self.generation},
                "portal-coverage": {self.generation},
                "enforcer-coverage": {self.generation},
                "control": {self.generation},
                "recovery": {self.generation},
            },
        }
        arguments.update(changes)
        return decode_keyring(data, **arguments)

    def test_independent_golden_vector_is_exact(self):
        copy = self.wrap()
        expected_wrapped = AESGCM(self.wrapping_key).encrypt(
            self.nonce,
            self.data_key,
            self.vector["aad_utf8"].encode(),
        )
        self.assertEqual(
            base64url_encode(expected_wrapped), self.vector["wrapped_key_base64url"]
        )
        self.assertEqual(wrapped_key_aad(copy), self.vector["aad_utf8"].encode())
        self.assertEqual(copy.canonical_bytes, self.vector["copy_utf8"].encode())
        self.assertEqual(copy.wrapped_key, self.vector["wrapped_key_base64url"])
        self.assertEqual(
            encode_keyring([copy]), self.vector["keyring_utf8"].encode()
        )
        self.assertEqual(
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability=self.vector["capability"],
                wrapping_keys={
                    (self.vector["wrapper_id"], self.generation): self.wrapping_key
                },
            ),
            self.data_key,
        )
        decoded = self.decode(self.vector["keyring_utf8"].encode())
        self.assertEqual(decoded.keys, (copy,))
        self.assertEqual(decoded.canonical_bytes, self.vector["keyring_utf8"].encode())

    def test_public_type_and_length_boundaries_fail_closed(self):
        for project_id in ("", None, 123):
            with self.subTest(project_id=project_id), self.assertRaises(
                KeyringContextError
            ):
                self.wrap(project_id=project_id)
        for generation in ("", None, 123):
            with self.subTest(generation=generation), self.assertRaises(
                KeyringContextError
            ):
                self.wrap(wrapper_generation=generation)

        invalid_wrap_values = (
            ("data_key", bytearray(self.data_key)),
            ("data_key", b"short"),
            ("data_kid", bytearray(self.data_kid)),
            ("data_kid", b"short"),
            ("wrapping_key", bytearray(self.wrapping_key)),
            ("wrapping_key", b"short"),
        )
        for name, value in invalid_wrap_values:
            with self.subTest(name=name, value=value), self.assertRaises(
                KeyringFormatError
            ):
                self.wrap(**{name: value})

        copy = self.wrap()
        invalid_model = json.loads(copy.canonical_bytes)
        invalid_model["data_kid"] = self.data_kid
        with self.assertRaises(KeyringFormatError):
            WrappedKeyCopy(**invalid_model)
        with self.assertRaises(KeyringFormatError):
            wrapped_key_aad(object())
        with self.assertRaises(KeyringFormatError):
            encode_keyring([object()])
        with self.assertRaises(KeyringFormatError):
            Keyring([object()])
        with self.assertRaises(KeyringFormatError):
            Keyring(None)
        self.assertEqual(encode_keyring(Keyring((copy,))), encode_keyring([copy]))
        for invalid in (None, b"not-copies"):
            with self.assertRaises(TypeError):
                encode_keyring(invalid)

        with self.assertRaises(KeyringContextError):
            unwrap_key_copy(
                copy,
                expected_project_id="other-project",
                expected_capability="records",
                wrapping_keys={(copy.wrapper_id, copy.wrapper_generation): self.wrapping_key},
            )
        with self.assertRaises(KeyringContextError):
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="coverage",
                wrapping_keys={(copy.wrapper_id, copy.wrapper_generation): self.wrapping_key},
            )
        with self.assertRaises(TypeError):
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys=[],
            )

        class DisappearingKeys(dict):
            def __contains__(self, key):
                return True

            def __getitem__(self, key):
                raise KeyError(key)

        with self.assertRaises(UnknownWrappingKeyError):
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys=DisappearingKeys(),
            )

    def test_decode_inputs_and_allowed_context_collections_are_strict(self):
        copy = self.wrap()
        encoded = encode_keyring([copy])
        for kwargs in (
            {"allowed_capabilities": "records"},
            {"allowed_capabilities": ["invalid"]},
            {"allowed_capabilities": [[]]},
            {"allowed_wrappers": "portal-records"},
            {"allowed_wrappers": ["invalid"]},
            {"allowed_wrappers": [[]]},
            {"known_generations": []},
            {"known_generations": {"invalid": {self.generation}}},
            {"known_generations": {"portal-records": "generation-1"}},
            {"known_generations": {"portal-records": {""}}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(
                (TypeError, KeyringContextError)
            ):
                self.decode(encoded, **kwargs)

        with self.assertRaises(TypeError):
            self.decode(bytearray(encoded))
        for malformed in (
            canonical_json("scalar"),
            canonical_json({"keyring_version": 1, "keys": {}}),
            canonical_json({"keyring_version": "1", "keys": []}),
        ):
            with self.assertRaises(KeyringFormatError):
                self.decode(malformed)

        invalid_entry = json.loads(encoded)
        invalid_entry["keys"][0]["nonce"] = 123
        with self.assertRaises(KeyringFormatError):
            self.decode(canonical_json(invalid_entry))

        class DisappearingGenerations(dict):
            def __contains__(self, key):
                return True

            def __getitem__(self, key):
                raise KeyError(key)

        with self.assertRaises(KeyringContextError):
            self.decode(encoded, known_generations=DisappearingGenerations())

        first = self.wrap()
        second = self.wrap(data_kid=b"j" * 16, wrapper_generation="generation-2")
        ordered = sorted((first, second), key=lambda item: item.canonical_bytes)
        reverse = {
            "keyring_version": 1,
            "keys": [
                json.loads(ordered[1].canonical_bytes),
                json.loads(ordered[0].canonical_bytes),
            ],
        }
        with self.assertRaises(KeyringFormatError):
            self.decode(
                canonical_json(reverse),
                known_generations={
                    wrapper: {"generation-1", "generation-2"}
                    for wrapper in (
                        "portal-records",
                        "portal-coverage",
                        "enforcer-coverage",
                        "control",
                        "recovery",
                    )
                },
            )

    def test_all_valid_pairs_round_trip(self):
        pairs = {
            "records": ("portal-records", "control", "recovery"),
            "coverage": ("portal-coverage", "enforcer-coverage", "control", "recovery"),
        }
        for capability, wrappers in pairs.items():
            for wrapper_id in wrappers:
                with self.subTest(capability=capability, wrapper_id=wrapper_id):
                    copy = self.wrap(capability=capability, wrapper_id=wrapper_id)
                    encoded = encode_keyring([copy])
                    parsed = self.decode(encoded)
                    self.assertEqual(parsed.keys, (copy,))
                    self.assertEqual(
                        unwrap_key_copy(
                            copy,
                            expected_project_id=self.vector["project_id"],
                            expected_capability=capability,
                            wrapping_keys={
                                (wrapper_id, self.generation): self.wrapping_key
                            },
                        ),
                        self.data_key,
                    )

    def test_rotation_and_canonical_order_are_deterministic(self):
        first = self.wrap()
        second = self.wrap(
            data_kid=b"j" * 16,
            wrapper_generation="generation-2",
        )
        forward = encode_keyring([first, second])
        reverse = encode_keyring([second, first])
        self.assertEqual(forward, reverse)
        parsed = self.decode(
            forward,
            known_generations={
                "portal-records": {"generation-1", "generation-2"},
                "portal-coverage": {"generation-1", "generation-2"},
                "enforcer-coverage": {"generation-1", "generation-2"},
                "control": {"generation-1", "generation-2"},
                "recovery": {"generation-1", "generation-2"},
            },
        )
        self.assertEqual(
            parsed.keys,
            tuple(sorted((first, second), key=lambda c: c.canonical_bytes)),
        )

    def test_closed_schema_context_and_generation_validation(self):
        copy = self.wrap()
        root = json.loads(encode_keyring([copy]))
        cases = [
            ({"keyring_version": 2}, KeyringFormatError),
            ({"keyring_version": True}, KeyringFormatError),
            ({"extra": 1}, KeyringFormatError),
        ]
        for change, error in cases:
            with self.subTest(change=change), self.assertRaises(error):
                value = dict(root)
                value.update(change)
                self.decode(canonical_json(value))

        missing_root_member = dict(root)
        missing_root_member.pop("keys")
        with self.assertRaises(KeyringFormatError):
            self.decode(canonical_json(missing_root_member))

        missing_entry_member = dict(root)
        missing_entry = dict(missing_entry_member["keys"][0])
        missing_entry.pop("wrapped_key")
        missing_entry_member["keys"] = [missing_entry]
        with self.assertRaises(KeyringFormatError):
            self.decode(canonical_json(missing_entry_member))

        extra_entry_member = dict(root)
        extra_entry = {**extra_entry_member["keys"][0], "unexpected": 1}
        extra_entry_member["keys"] = [extra_entry]
        with self.assertRaises(KeyringFormatError):
            self.decode(canonical_json(extra_entry_member))

        entry_changes = [
            ({"wrap_version": 2}, KeyringFormatError),
            ({"algorithm": "AES-GCM"}, KeyringFormatError),
            ({"capability": "unknown"}, KeyringContextError),
            ({"wrapper_id": "unknown"}, KeyringContextError),
            ({"wrapper_generation": "not-known"}, KeyringContextError),
            ({"project_id": "other-project"}, KeyringContextError),
            ({"data_kid": copy.data_kid + "="}, KeyringFormatError),
            ({"nonce": base64url_encode(b"short")}, KeyringFormatError),
            ({"wrapped_key": base64url_encode(b"short")}, KeyringFormatError),
        ]
        for change, error in entry_changes:
            with self.subTest(change=change), self.assertRaises(error):
                value = dict(root)
                value["keys"] = [{**value["keys"][0], **change}]
                self.decode(canonical_json(value))

        for bad in (
            canonical_json({"keyring_version": 1, "keys": []}) + b"\n",
            b'{"keyring_version":1,"keys": [ ]}',
        ):
            with self.assertRaises(KeyringFormatError):
                self.decode(bad)

    def test_rejects_duplicates_pairings_order_and_unknown_wrapping_keys(self):
        copy = self.wrap()
        duplicate = replace(copy, wrapper_generation="generation-2")
        with self.assertRaises(KeyringFormatError):
            encode_keyring([copy, duplicate])

        root = json.loads(encode_keyring([copy]))
        with self.assertRaises(KeyringFormatError):
            self.decode(
                canonical_json(
                    {**root, "keys": [root["keys"][0], root["keys"][0]]}
                )
            )

        with self.assertRaises(KeyringContextError):
            self.wrap(capability="records", wrapper_id="portal-coverage")
        with self.assertRaises(TypeError):
            WRAPPER_CAPABILITIES["portal-coverage"] = frozenset({"records"})  # type: ignore[index]
        self.assertEqual(WRAPPER_CAPABILITIES["portal-coverage"], {"coverage"})
        with self.assertRaises(KeyringContextError):
            self.wrap(capability="records", wrapper_id="portal-coverage")
        with self.assertRaises(KeyringContextError):
            self.decode(encode_keyring([copy]), allowed_capabilities={"coverage"})
        with self.assertRaises(KeyringContextError):
            self.decode(encode_keyring([copy]), allowed_wrappers={"portal-coverage"})
        with self.assertRaises(KeyringContextError):
            self.decode(encode_keyring([copy]), known_generations={})

        fallback = defaultdict(lambda: self.wrapping_key)
        with self.assertRaises(UnknownWrappingKeyError):
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys=fallback,
            )
        self.assertEqual(fallback, {})
        with self.assertRaises(UnknownWrappingKeyError):
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys={},
            )

        with self.assertRaises(KeyringAuthenticationError):
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys={(copy.wrapper_id, copy.wrapper_generation): b"x" * 32},
            )

    def test_tampering_never_leaks_key_material_and_models_are_immutable(self):
        copy = self.wrap()
        encoded = encode_keyring([copy])
        self.assertNotIn(self.data_key.hex().encode(), encoded)
        self.assertNotIn(self.wrapping_key.hex().encode(), encoded)
        self.assertNotIn(self.data_key, encoded)
        self.assertNotIn(self.wrapping_key, encoded)
        with self.assertRaises(FrozenInstanceError):
            copy.project_id = "other"  # type: ignore[misc]

        value = json.loads(encoded)
        ciphertext = value["keys"][0]["wrapped_key"]
        value["keys"][0]["wrapped_key"] = ciphertext[:-1] + (
            "A" if ciphertext[-1] != "A" else "B"
        )
        with self.assertRaises(KeyringAuthenticationError):
            unwrap_key_copy(
                WrappedKeyCopy(**value["keys"][0]),
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys={
                    (copy.wrapper_id, copy.wrapper_generation): self.wrapping_key
                },
            )
        try:
            unwrap_key_copy(
                copy,
                expected_project_id=self.vector["project_id"],
                expected_capability="records",
                wrapping_keys={(copy.wrapper_id, copy.wrapper_generation): b"x" * 32},
            )
        except KeyringAuthenticationError as error:
            self.assertNotIn(self.data_key.hex(), str(error))
            self.assertNotIn(self.wrapping_key.hex(), str(error))


if __name__ == "__main__":
    unittest.main()
