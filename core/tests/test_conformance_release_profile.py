"""Installed profile closure and every limit's exact boundary."""

import copy
import unittest
from dataclasses import FrozenInstanceError

from dracla.conformance.release_profile import (
    DERIVED_CLASSES, ReleaseProfile, ReleaseProfileError, load_release_profile,
)
from dracla.conformance.canonical import canonical_json


class TestReleaseProfile(unittest.TestCase):
    def setUp(self):
        self.profile = load_release_profile()
        self.value = self.profile.to_dict()

    def test_checked_in_numeric_profile_and_canonical_roundtrip(self):
        self.assertEqual(self.value, {
            "profile_version": 1, "shard_count": 32,
            "max_prepared_operation_bytes": 1048576,
            "max_shard_ciphertext_bytes": {"derived_index": 65536,
                "status_detail": 262144, "reader_authority": 262144},
            "max_reader_source_members": 512, "max_bulk_shards_per_operation": 32,
            "max_mutation_retries": 3, "max_subrequests_per_request": 49,
            "max_continuous_reader_rules": 10, "max_continuous_exemption_rules": 32,
            "max_reader_cursor_entries": 2048, "max_state_ciphertext_bytes": 32768})
        self.assertEqual(load_release_profile(self.profile.canonical_bytes()), self.profile)
        self.assertEqual(self.profile.canonical_bytes(), canonical_json(self.value))
        with self.assertRaises(FrozenInstanceError):
            self.profile._value = {}
        self.value["max_mutation_retries"] = 99
        self.assertEqual(self.profile.limit("max_mutation_retries"), 3)

    def test_request_budget_includes_locked_reader_cold_path(self):
        cold_path = 39 + self.profile.limit("max_continuous_reader_rules")
        self.assertEqual(cold_path, 49)
        self.profile.check("max_subrequests_per_request", cold_path)
        with self.assertRaises(ReleaseProfileError):
            self.profile.check("max_subrequests_per_request", 50)

    def test_every_limit_at_minus_one_equal_and_plus_one(self):
        for name, limit in self.value.items():
            if name in {"profile_version", "shard_count"}:
                continue
            cases = [(kind, maximum) for kind, maximum in limit.items()] if type(limit) is dict else [(None, limit)]
            for kind, maximum in cases:
                with self.subTest(limit=name, derived_class=kind):
                    self.profile.check(name, maximum - 1, derived_class=kind)
                    self.profile.check(name, maximum, derived_class=kind)
                    for actual in [maximum + 1, -1, True, 1.5, "1", None]:
                        with self.assertRaises(ReleaseProfileError):
                            self.profile.check(name, actual, derived_class=kind)

    def test_every_root_member_is_required_and_unknowns_are_rejected(self):
        for field in self.value:
            value = copy.deepcopy(self.value)
            del value[field]
            with self.assertRaises(ReleaseProfileError):
                ReleaseProfile(value)
        for extra in ["coverage", "unlimited", "unknown"]:
            with self.assertRaises(ReleaseProfileError):
                ReleaseProfile({**self.value, extra: 1})
        for value in [None, [], "profile", True]:
            with self.assertRaises(ReleaseProfileError):
                ReleaseProfile(value)

    def test_invalid_scalar_profiles_and_fixed_values(self):
        for field in self.value:
            if field == "max_shard_ciphertext_bytes":
                continue
            for invalid in [0, -1, True, None, 1.2, "unlimited", 2**53]:
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ReleaseProfileError):
                    ReleaseProfile({**self.value, field: invalid})
        for field, invalid in [("profile_version", 2), ("shard_count", 16),
                               ("max_continuous_reader_rules", 9),
                               ("max_continuous_reader_rules", 11),
                               ("max_subrequests_per_request", 50),
                               ("max_subrequests_per_request", 51)]:
            with self.assertRaises(ReleaseProfileError):
                ReleaseProfile({**self.value, field: invalid})

    def test_coverage_cap_and_misclassified_limits_are_unrepresentable(self):
        for limits in [{}, {"coverage": 4096}, {**self.value["max_shard_ciphertext_bytes"], "coverage": 4096}, []]:
            with self.assertRaises(ReleaseProfileError):
                ReleaseProfile({**self.value, "max_shard_ciphertext_bytes": limits})
        for name in DERIVED_CLASSES:
            for invalid in [0, -1, True, "unlimited", None, 2**53]:
                limits = dict(self.value["max_shard_ciphertext_bytes"], **{name: invalid})
                with self.assertRaises(ReleaseProfileError):
                    ReleaseProfile({**self.value, "max_shard_ciphertext_bytes": limits})
        for name, kind in [("coverage", None), ("max_shard_ciphertext_bytes", "coverage"),
                            ("max_shard_ciphertext_bytes", None), ("max_mutation_retries", "derived_index")]:
            with self.assertRaises(ReleaseProfileError):
                self.profile.limit(name, derived_class=kind)

    def test_profile_json_must_be_exact_canonical_bytes(self):
        for data in [b"{}", b'{"profile_version":1,"profile_version":1}',
                     self.profile.canonical_bytes() + b"\n", b"not-json", "not-bytes"]:
            with self.assertRaises(ReleaseProfileError):
                load_release_profile(data)
