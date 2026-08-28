# M1 Conformance Verification Matrix

This matrix records the automated evidence currently landed for the M1
conformance-kernel slices. A row is passing only when the referenced test
command passes against the checked-in implementation.

| Slice | Requirement / HLD contract | Automated evidence | Result |
|---|---|---|---|
| M1-1 | RFC 8785 canonical JSON, duplicate rejection, safe-number boundary | `core/tests/test_conformance_artifacts.py::TestCanonicalJson` | PASS |
| M1-1 | Closed artifact identity namespace, path relations, segment and override-key derivation | `core/tests/test_conformance_artifacts.py::TestArtifactIdentities` | PASS |
| M1-2 | A256GCM artifact AAD, fixed metadata binding, nonce and ciphertext/tag encoding | `core/tests/test_conformance_envelope.py::TestArtifactEnvelope::test_independent_golden_vector_is_exact` | PASS |
| M1-2 | Strict envelope schema, encoding, plaintext, context, key lookup, authentication and tamper rejection | `core/tests/test_conformance_envelope.py::TestArtifactEnvelope` | PASS |
| M1-3 | Wrapped-key AAD, fixed-nonce AES-256-GCM bytes, individual copy and keyring bytes | `core/tests/test_conformance_keyrings.py::TestWrappedKeys::test_independent_golden_vector_is_exact`; `core/tests/vectors/wrapped-key-v1.json` | PASS |
| M1-3 | Every valid records/coverage wrapper pair round-trips through unwrap | `core/tests/test_conformance_keyrings.py::TestWrappedKeys::test_all_valid_pairs_round_trip` | PASS |
| M1-3 | Multiple data `kid` values and wrapper generations; canonical order independent of input order | `core/tests/test_conformance_keyrings.py::TestWrappedKeys::test_rotation_and_canonical_order_are_deterministic` | PASS |
| M1-3 | Closed schema, versions, algorithms, capabilities, wrappers, project context and generations reject invalid input | `core/tests/test_conformance_keyrings.py::TestWrappedKeys::test_closed_schema_context_and_generation_validation` | PASS |
| M1-3 | Duplicate identities, wrong pairings, unknown wrapping keys and authentication failures reject fail-closed | `core/tests/test_conformance_keyrings.py::TestWrappedKeys::test_rejects_duplicates_pairings_order_and_unknown_wrapping_keys` | PASS |
| M1-3 | Immutable models, exact canonical bytes, length/padding/tamper checks, and secret-safe output | `core/tests/test_conformance_keyrings.py::TestWrappedKeys::test_tampering_never_leaks_key_material_and_models_are_immutable` | PASS |

Focused command: `PYTHONPATH=core .venv/bin/python -m unittest core/tests/test_conformance_keyrings.py -v` (8 passed).
Complete Python suite: `PYTHONPATH=core .venv/bin/python -m unittest discover -s core/tests -t .` (70 passed, 9 integration skips).
